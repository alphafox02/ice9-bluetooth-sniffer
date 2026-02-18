/*
 * Copyright 2024 ICE9 Consulting LLC
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SoapySDR/Device.h>
#include <SoapySDR/Formats.h>
#include <SoapySDR/Version.h>

#include "sdr.h"

double soapy_gain_val = 40.0;

extern sig_atomic_t running;
extern pid_t self_pid;
extern unsigned channels;
extern float samp_rate;
extern unsigned center_freq;
extern int verbose;

static int use_cs16 = 0;  // Flag for CS16 fallback mode

void soapy_list(void) {
    size_t length;
    SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

    for (size_t i = 0; i < length; ++i) {
        char *driver = NULL;
        char *label = NULL;

        // Find driver and label in kwargs
        for (size_t j = 0; j < results[i].size; ++j) {
            if (strcmp(results[i].keys[j], "driver") == 0)
                driver = results[i].vals[j];
            if (strcmp(results[i].keys[j], "label") == 0)
                label = results[i].vals[j];
        }

        printf("interface {value=soapy-%zu}{display=ICE9 Bluetooth (%s%s%s)}\n",
               i,
               driver ? driver : "SoapySDR",
               label ? " - " : "",
               label ? label : "");
    }

    SoapySDRKwargsList_clear(results, length);
}

SoapySDRDevice *soapy_setup(int id) {
    SoapySDRDevice *device;
    size_t length;
    char **formats;
    size_t num_formats;

    SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

    if (id < 0 || (size_t)id >= length) {
        SoapySDRKwargsList_clear(results, length);
        errx(1, "Invalid SoapySDR device index: %d (found %zu devices)", id, length);
    }

    device = SoapySDRDevice_make(&results[id]);
    SoapySDRKwargsList_clear(results, length);

    if (device == NULL)
        errx(1, "Unable to open SoapySDR device: %s", SoapySDRDevice_lastError());

    // Check supported formats and prefer CS8
    formats = SoapySDRDevice_getStreamFormats(device, SOAPY_SDR_RX, 0, &num_formats);
    use_cs16 = 1;  // Default to CS16 if CS8 not found
    for (size_t i = 0; i < num_formats; ++i) {
        if (strcmp(formats[i], SOAPY_SDR_CS8) == 0) {
            use_cs16 = 0;
            break;
        }
    }
    SoapySDRStrings_clear(&formats, num_formats);

    if (verbose)
        printf("SoapySDR: using %s format\n", use_cs16 ? "CS16" : "CS8");

    // Configure the device
    if (SoapySDRDevice_setSampleRate(device, SOAPY_SDR_RX, 0, samp_rate) != 0)
        errx(1, "Unable to set SoapySDR sample rate: %s", SoapySDRDevice_lastError());

    if (SoapySDRDevice_setFrequency(device, SOAPY_SDR_RX, 0, center_freq * 1e6, NULL) != 0)
        errx(1, "Unable to set SoapySDR frequency: %s", SoapySDRDevice_lastError());

    // Try to set gain, but don't fail if it doesn't work (some devices have different gain APIs)
    if (SoapySDRDevice_setGain(device, SOAPY_SDR_RX, 0, soapy_gain_val) != 0) {
        if (verbose)
            warnx("Unable to set SoapySDR gain (continuing anyway)");
    }

    // Set bandwidth to match sample rate
    if (SoapySDRDevice_setBandwidth(device, SOAPY_SDR_RX, 0, samp_rate) != 0) {
        if (verbose)
            warnx("Unable to set SoapySDR bandwidth (continuing anyway)");
    }

    return device;
}

// Process CS16 samples and convert to CS8
static void soapy_rx_cs16(int16_t *in, int8_t *out, size_t num_samples) {
    for (size_t i = 0; i < num_samples * 2; ++i) {
        // Scale from 16-bit to 8-bit (divide by 256)
        out[i] = (int8_t)(in[i] >> 8);
    }
}

void *soapy_stream_thread(void *arg) {
    SoapySDRDevice *device = (SoapySDRDevice *)arg;
    SoapySDRStream *stream;
    size_t channel = 0;
    int flags;
    long long time_ns;
    const char *format;
    size_t mtu;

    // Try CS8 first (preferred), fall back to CS16 if not supported
    if (!use_cs16) {
        format = SOAPY_SDR_CS8;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL) {
            if (verbose)
                warnx("CS8 stream failed, falling back to CS16");
            use_cs16 = 1;
        }
    } else {
        stream = NULL;
    }

    // Use CS16 if CS8 failed or wasn't supported
    if (use_cs16) {
        format = SOAPY_SDR_CS16;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL)
            errx(1, "Unable to setup SoapySDR stream: %s", SoapySDRDevice_lastError());
    }

    if (verbose)
        printf("SoapySDR: streaming with %s format\n", format);

    // Get the MTU (maximum transfer unit) for buffer sizing
    mtu = SoapySDRDevice_getStreamMTU(device, stream);
    if (mtu == 0)
        mtu = 65536;  // Default fallback

    // Activate the stream
    if (SoapySDRDevice_activateStream(device, stream, 0, 0, 0) != 0)
        errx(1, "Unable to activate SoapySDR stream: %s", SoapySDRDevice_lastError());

    // Allocate conversion buffer for CS16 mode
    int16_t *cs16_buf = NULL;
    if (use_cs16) {
        cs16_buf = malloc(mtu * 2 * sizeof(int16_t));
        if (cs16_buf == NULL)
            errx(1, "Unable to allocate CS16 buffer");
    }

    while (running) {
        sample_buf_t *s = malloc(sizeof(*s) + mtu * 2 * sizeof(int8_t));
        if (s == NULL) {
            warnx("Unable to allocate sample buffer");
            break;
        }

        void *buffs[1];
        int ret;

        if (use_cs16) {
            buffs[0] = cs16_buf;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
            if (ret > 0) {
                soapy_rx_cs16(cs16_buf, s->samples, ret);
            }
        } else {
            buffs[0] = s->samples;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
        }

        if (ret < 0) {
            if (ret == SOAPY_SDR_TIMEOUT) {
                free(s);
                continue;
            }
            if (ret == SOAPY_SDR_OVERFLOW) {
                if (verbose)
                    warnx("SoapySDR overflow");
                free(s);
                continue;
            }
            warnx("SoapySDR read error: %d", ret);
            free(s);
            break;
        }

        s->num = ret;
        if (running)
            push_samples(s);
        else
            free(s);
    }

    free(cs16_buf);

    SoapySDRDevice_deactivateStream(device, stream, 0, 0);
    SoapySDRDevice_closeStream(device, stream);

    running = 0;
    kill(self_pid, SIGINT);

    return NULL;
}

int soapy_set_gain_runtime(void *dev, double gain) {
    SoapySDRDevice *device = (SoapySDRDevice *)dev;
    int rc = SoapySDRDevice_setGain(device, SOAPY_SDR_RX, 0, gain);
    if (rc == 0)
        soapy_gain_val = gain;
    return rc;
}

void soapy_close(SoapySDRDevice *device) {
    SoapySDRDevice_unmake(device);
}
