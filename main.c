/*
 * Copyright 2022 ICE9 Consulting LLC
 */

#define _GNU_SOURCE
#include <complex.h>
#include <err.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <liquid/liquid.h>

#include "bladerf.h"
#include "bluetooth.h"
#include "btbb/btbb.h"
#include "burst_catcher.h"
#include "fft.h"
#include "fsk.h"
#include "hackrf.h"
#include "pcap.h"
#include "sdr.h"
#include "usrp.h"
#ifdef HAVE_SOAPYSDR
#include "soapysdr.h"
#endif
#ifdef HAVE_GPS
#include "gps_tag.h"
#endif
#ifdef HAVE_ZMQ
#include "control.h"
#endif

#include "pfbch2.h"

#ifdef USE_OPENCL_PFB
void init_pfb_gpu(int16_t *h_sub, unsigned M, unsigned m, unsigned h_sub_len);
int8_t *get_next_raw_buffer(void);
#endif

#define C_FEK_BLOCKING_QUEUE_IMPLEMENTATION
#define C_FEK_FAIR_LOCK_IMPLEMENTATION
#include "blocking_queue.h"

// only needed on macOS
#include "pthread_barrier.h"

float samp_rate = 0.f;
unsigned channels = 96;
int live_ch[40] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
};
unsigned first_live = UINT_MAX, last_live = 0;;
unsigned center_freq = 2441;
pcap_t *pcap = NULL;
char *base_name = NULL;
int live = 0;
FILE *in = NULL;
char *serial = NULL;
char *usrp_serial = NULL;
int bladerf_num = -1;
#ifdef HAVE_SOAPYSDR
int soapy_num = -1;
#endif
int verbose = 0;
int stats = 0;
int check_crc = 0;
#ifdef HAVE_ZMQ
int zmq_pub_active = 0;
int zmq_connect_mode = 0;
char *zmq_endpoint = NULL;
char *zmq_curve_keyfile = NULL;
char *sensor_id = NULL;
pthread_t control_thread;
int restart_requested = 0;
char **restart_argv = NULL;
#endif
#ifdef HAVE_GPS
int gpsd_active = 0;
#endif

unsigned long crc_total = 0;
unsigned long crc_valid_count = 0;
unsigned long crc_invalid_count = 0;

volatile sig_atomic_t running = 1;
pid_t self_pid;

unsigned sps(void) { return (unsigned)(samp_rate / channels / 1e6f * 2.0f); }

const float sym_rate = 1e6f;
const float lp_cutoff = 0.75f; // cutoff in MHz
const unsigned m = 4; // magical polyphase filter bank number (filter half-length)

#define AGC_BUFFER_SIZE 4096
#define BATCH_SIZE 4096
typedef struct _agc_buffer_t {
    float complex buffer[AGC_BUFFER_SIZE];
} agc_buffer_t;
agc_buffer_t *agc_live = NULL, *agc_dead = NULL;
unsigned agc_live_size = 0, agc_dead_size = 0;
agc_buffer_t *agc_buffers;
unsigned live_buf = 0;

#ifdef USE_FFTW
pthread_t fft_thread;
#else
pthread_t agc_dispatcher;
#endif
pthread_mutex_t agc_dispatch_mutex;
pthread_cond_t fft_done_cond;
pthread_cond_t dispatch_done_cond;
pthread_t *agc_threads;
pthread_mutex_t agc_buf_mutex;
pthread_cond_t agc_buf_ready, agc_buf_done;
pthread_barrier_local_t agc_barrier;
unsigned long agc_start, agc_end;

static burst_catcher_t *catcher = NULL;
static pfbch2_t magic;

#define SAMPLES_QUEUE_SIZE 16384
Blocking_Queue samples_queue;
pthread_t channelizer;

#define BURST_QUEUE_SIZE 64
Blocking_Queue bursts;
pthread_t burst_processor;

pthread_t spewer;

// vectorized int16 -> float complex conversion
#if defined(__SSE4_1__)
#include <smmintrin.h>
static inline void convert_i16_to_fc(int16_t *in, float complex *out, unsigned n) {
    unsigned i = 0;
    const __m128 scale = _mm_set1_ps(1.0f / 32768.0f);

    /* process 2 complex values per iteration (4 int16 -> 4 float) */
    for (; i + 2 <= n; i += 2) {
        __m128i v16 = _mm_loadl_epi64((__m128i*)&in[2*i]);
        __m128i v32 = _mm_cvtepi16_epi32(v16);
        __m128 vf = _mm_mul_ps(_mm_cvtepi32_ps(v32), scale);
        _mm_storeu_ps((float*)&out[i], vf);
    }
    /* handle odd remainder */
    for (; i < n; ++i)
        out[i] = in[2*i] / 32768.f + in[2*i + 1] / 32768.f * I;
}
#else
static inline void convert_i16_to_fc(int16_t *in, float complex *out, unsigned n) {
    unsigned i;
    for (i = 0; i < n; ++i)
        out[i] = in[2*i] / 32768.f + in[2*i + 1] / 32768.f * I;
}
#endif

// special case for all channels
void pfbch_execute_block_96(int8_t *samples, float complex *buf, unsigned buf_pos) {
    int16_t out[96*2];

    pfbch2_execute(&magic, samples, out);
    convert_i16_to_fc(out, &buf[96 * buf_pos], 96);
}

void pfbch_execute_block(int8_t *samples, float complex *buf, unsigned buf_pos) {
    int16_t out[96*2];

    pfbch2_execute(&magic, samples, out);
    convert_i16_to_fc(out, &buf[channels * buf_pos], channels);
}

void push_samples(sample_buf_t *buf) {
    if (blocking_queue_add(&samples_queue, buf) == BQ_FULL) {
        if (verbose)
            printf("WARNING: dropped samples on the floor. try fewer channels or a bigger buffer.\n");
        free(buf);
    }
}

static inline unsigned long now_us(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long)now.tv_sec * 1000000lu + (unsigned long)now.tv_nsec / 1000lu;
}

unsigned long ch_sum = 0;

static void *fft;
static float complex *fft_out;
static unsigned long ch_start = 0;

void fft_done(void *f, void *out) {
    pthread_mutex_lock(&agc_dispatch_mutex);
    while (running && fft_out != NULL)
        pthread_cond_wait(&dispatch_done_cond, &agc_dispatch_mutex);
    if (!running) {
        pthread_mutex_unlock(&agc_dispatch_mutex);
        return;
    }
    fft = f;
    fft_out = out;
    pthread_cond_signal(&fft_done_cond);
    pthread_mutex_unlock(&agc_dispatch_mutex);
}

static double _convert_stats(double in, char *prefix_out) {
    if (in < 1e3) {
        *prefix_out = ' ';
        return in;
    }
    if (in < 1e6) {
        *prefix_out = 'k';
        return in / 1e3;
    }
    if (in < 1e9) {
        *prefix_out = 'M';
        return in / 1e6;
    }
    *prefix_out = 'G';
    return in / 1e9;
}

void agc_submit(float complex *fft_out) {
    const unsigned avg_count = 100;
    static unsigned long sum = 0;
    static unsigned sum_count = 0;
    unsigned i, j;

    for (i = 0; i < channels; ++i)
        for (j = 0; j < BATCH_SIZE; ++j)
            agc_live[i].buffer[j] = fft_out[j * channels + i] / (float)channels;

    if (stats) {
        unsigned long now = now_us();
        ch_sum += now - ch_start;
        ch_start = now;
    }

    pthread_mutex_lock(&agc_buf_mutex);
    while (running && agc_dead != NULL)
        pthread_cond_wait(&agc_buf_done, &agc_buf_mutex);
    if (!running) {
        pthread_mutex_unlock(&agc_buf_mutex);
        pthread_exit(NULL);
    }

    agc_dead = agc_live;
    agc_dead_size = BATCH_SIZE; //agc_live_size;
    live_buf = 1 - live_buf;
    agc_live = &agc_buffers[channels * live_buf];
    agc_live_size = 0;
    pthread_cond_broadcast(&agc_buf_ready);
    pthread_mutex_unlock(&agc_buf_mutex);

    if (stats) {
        sum += agc_end - agc_start;
        if (++sum_count == avg_count) {
            double eff_samp_rate = (last_live - first_live + 1) * AGC_BUFFER_SIZE * avg_count * 2e6 / sum;
            double rel_rate = eff_samp_rate / ((channels-2) * 2e6);
            double ch_samp_rate = AGC_BUFFER_SIZE * channels / 2 * avg_count * 1e6 / ch_sum;
            double ch_rel_rate = ch_samp_rate / samp_rate;
            char prefix = ' ', agc_prefix = ' ';
            ch_samp_rate = _convert_stats(ch_samp_rate, &prefix);
            eff_samp_rate = _convert_stats(eff_samp_rate, &agc_prefix);
            printf("ch %5.1f %csamp/sec (%3.0f%% realtime); agc %5.1f %csamp/sec (%3.0f%% realtime)\n", ch_samp_rate, prefix, 100 * ch_rel_rate, eff_samp_rate, agc_prefix, 100.0 * rel_rate);
            if (rel_rate < 0.99)
                printf("AGC is too slow, use fewer channels\n");
            if (ch_rel_rate < 0.99)
                printf("Channelizer too slow, use fewer channels\n");
            if (check_crc && crc_total > 0) {
                double valid_pct = (100.0 * crc_valid_count) / crc_total;
                printf("CRC: %lu valid, %lu invalid (%.1f%% valid)\n",
                       crc_valid_count, crc_invalid_count, valid_pct);
            }
            sum_count = sum = ch_sum = 0;
        }
        agc_start = now_us();
    }
}

#ifndef USE_FFTW
void *agc_dispatcher_thread(void *arg) {
    static float complex my_fft[96 * BATCH_SIZE];

    while (running) {
        pthread_mutex_lock(&agc_dispatch_mutex);
        while (running && fft_out == NULL)
            pthread_cond_wait(&fft_done_cond, &agc_dispatch_mutex);
        if (!running) {
            pthread_mutex_unlock(&agc_dispatch_mutex);
            pthread_exit(NULL);
        }
        memcpy(my_fft, fft_out, BATCH_SIZE * channels * sizeof(float complex));
        release_buffer(fft);
        fft_out = NULL;
        pthread_cond_signal(&dispatch_done_cond);
        pthread_mutex_unlock(&agc_dispatch_mutex);

        agc_submit(my_fft);
    }
    return NULL;
}
#endif

#ifdef USE_OPENCL_PFB
void *channelizer_thread(void *arg) {
    sample_buf_t *samples = NULL;
    int8_t *raw_buf = get_next_raw_buffer();
    unsigned raw_pos = 0;
    unsigned stride = channels;  /* M/2 complex int8 pairs = M bytes */

    while (running) {
        if (blocking_queue_take(&samples_queue, &samples) != 0)
            return NULL;

        /* total steps in this sample buffer */
        unsigned total_steps = samples->num / (channels / 2);
        unsigned src_pos = 0;

        while (running && src_pos < total_steps) {
            /* copy as many steps as fit in current batch */
            unsigned remaining_in_batch = BATCH_SIZE - raw_pos;
            unsigned remaining_in_src = total_steps - src_pos;
            unsigned chunk = remaining_in_batch < remaining_in_src
                           ? remaining_in_batch : remaining_in_src;

            memcpy(&raw_buf[raw_pos * stride],
                   &samples->samples[src_pos * stride],
                   chunk * stride);
            raw_pos += chunk;
            src_pos += chunk;

            if (raw_pos == BATCH_SIZE) {
                raw_buf = get_next_raw_buffer();
                raw_pos = 0;
            }
        }

        free(samples);
    }
    return NULL;
}
#else
void *channelizer_thread(void *arg) {
    unsigned i;
    sample_buf_t *samples = NULL;
    float complex *fft_in = get_next_buffer();
    unsigned fft_in_pos = 0;

    while (running) {
        // get next samples
        if (blocking_queue_take(&samples_queue, &samples) != 0)
            return NULL;

        if (channels == 96) {
            for (i = 0; running && i + channels / 2 <= samples->num; i += channels / 2) {
                pfbch_execute_block_96(&samples->samples[2*i], fft_in, fft_in_pos);
                if (++fft_in_pos == BATCH_SIZE) {
                    fft_in = get_next_buffer();
                    fft_in_pos = 0;
                }
            }
        } else {
            // channelize them
            for (i = 0; running && i + channels / 2 <= samples->num; i += channels / 2) {
                pfbch_execute_block(&samples->samples[2*i], fft_in, fft_in_pos);
                if (++fft_in_pos == BATCH_SIZE) {
                    fft_in = get_next_buffer();
                    fft_in_pos = 0;
                }
            }
        }

        free(samples);
    }
    return NULL;
}
#endif

void *agc_thread(void *id_ptr) {
    unsigned id = (uintptr_t)id_ptr;
    unsigned i;
    burst_t *burst = calloc(1, sizeof(*burst));

    while (running) {
        pthread_mutex_lock(&agc_buf_mutex);
        while (running && agc_dead == NULL)
            pthread_cond_wait(&agc_buf_ready, &agc_buf_mutex);
        pthread_mutex_unlock(&agc_buf_mutex);
        if (!running)
            goto out;

        for (i = 0; i < agc_dead_size; ++i) {
            if (burst_catcher_execute(&catcher[id], &agc_dead[live_ch[id]].buffer[i], burst)) {
                if (burst->len < 132) { // FIXME
                    burst_destroy(burst);
                    memset(burst, 0, sizeof(*burst));
                } else {
                    if (blocking_queue_add(&bursts, burst) == BQ_FULL) {
                        if (verbose)
                            printf("WARNING: dropped burst on the floor. try fewer channels.\n");
                        burst_destroy(burst);
                        memset(burst, 0, sizeof(*burst));
                    } else {
                        burst = calloc(1, sizeof(*burst));
                    }
                }
            }
        }

        if (!running)
            goto out;

        if (pthread_barrier_local_wait(&agc_barrier) == 1) {
            // we're the lucky thread!
            if (stats)
                agc_end = now_us();
            pthread_mutex_lock(&agc_buf_mutex);
            agc_dead = NULL;
            agc_dead_size = 0;
            pthread_cond_signal(&agc_buf_done);
            pthread_mutex_unlock(&agc_buf_mutex);
        }
        if (!running)
            goto out;
        pthread_barrier_local_wait(&agc_barrier);
    }
out:
    free(burst);
    return NULL;
}

int queue_empty(volatile Blocking_Queue *q) {
    return q->queue_size == 0;
}

void *spewer_thread(void *in_ptr) {
    size_t r;
    FILE *in = (FILE *)in_ptr;

    sample_buf_t *samples = malloc(sizeof(*samples) + sizeof(int8_t) * 2 * channels * AGC_BUFFER_SIZE);
    while (running && (r = fread(&samples->samples, sizeof(int8_t) * 2 * channels * AGC_BUFFER_SIZE, 1, in)) > 0) {
        samples->num = channels * AGC_BUFFER_SIZE;
        if (blocking_queue_put(&samples_queue, samples) != 0) {
            free(samples);
            return NULL;
        }
        samples = malloc(sizeof(*samples) + sizeof(int8_t) * 2 * channels * AGC_BUFFER_SIZE);
    }
    free(samples);

    while (running && !queue_empty(&samples_queue))
        ;
    running = 0;
    kill(self_pid, SIGINT);

    return NULL;
}

void *burst_processor_thread(void *arg) {
    fsk_demod_t fsk;
    burst_t *burst;

    fsk_demod_init(&fsk);

    while (running) {
        if (blocking_queue_take(&bursts, &burst) != 0)
            goto out;

        fsk_demod(&fsk, burst->burst, burst->len, burst->freq, &burst->packet);

        if (burst->packet.demod != NULL && burst->packet.bits != NULL) {
            uint32_t lap = 0xffffffff, aa = 0xffffffff;
            bluetooth_detect(burst->packet.bits, burst->packet.bits_len, burst->packet.demod, burst->len, burst->packet.silence, burst->freq, burst->rssi_db, burst->noise_db, burst->timestamp, &lap, &aa);

            if (verbose) {
                printf("burst %4u-%04u, %d samps, rssi %f dB, noise %f dB ", burst->freq, burst->num, burst->len, burst->rssi_db, burst->noise_db);
                printf("cfo %f deviation %f ", burst->packet.cfo, burst->packet.deviation);
                if (lap != 0xffffffff)
                    printf("lap %06x", lap);
                if (aa != 0xffffffff)
                    printf("aa %08x", aa);
                printf("\n");
            }

            if (base_name != NULL) {
                char *filename;
                FILE *out;

                /* burst */
                if (asprintf(&filename, "%s-%04u-%04u.fc32", base_name, burst->freq, burst->num) < 0)
                    err(1, "asprintf failed");
                out = fopen(filename, "w");
                if (out == NULL)
                    err(1, "Unable to create file %s", filename);
                free(filename);
                fwrite(burst->burst, sizeof(float complex), burst->len, out);
                fclose(out);

                /* demoded samples */
                if (asprintf(&filename, "%s-%04u-%04u.f32", base_name, burst->freq, burst->num) < 0)
                    err(1, "asprintf failed");
                out = fopen(filename, "w");
                if (out == NULL)
                    err(1, "Unable to create file %s", filename);
                free(filename);
                fwrite(burst->packet.demod, sizeof(float), burst->len, out);
                fclose(out);

                /* cfo / maybe other metadata? */
                if (asprintf(&filename, "%s-%04u-%04u.txt", base_name, burst->freq, burst->num) < 0)
                    err(1, "asprintf failed");
                out = fopen(filename, "w");
                if (out == NULL)
                    err(1, "Unable to create file %s", filename);
                free(filename);
                fprintf(out, "cfo=%f\n", burst->packet.cfo);
                fprintf(out, "silence=%u\n", burst->packet.silence);
                if (lap != 0xffffffff)
                    fprintf(out, "lap=%06x\n", lap);
                if (aa != 0xffffffff)
                    fprintf(out, "aa=%08x\n", aa);
                fclose(out);
            }
        }
        burst_destroy(burst);
        free(burst);
    }
out:
    fsk_demod_destroy(&fsk);
    return NULL;
}

#ifdef HAVE_ZMQ
void set_all_squelch(float threshold) {
    unsigned i;
    sql = threshold;
    for (i = first_live; i <= last_live; ++i)
        burst_catcher_set_squelch(&catcher[i], threshold);
}
#endif

void init_threads(int launch_spewer) {
    uintptr_t i;
    unsigned active_channels = 0;
    pthread_mutex_init(&agc_dispatch_mutex, NULL);
    pthread_mutex_init(&agc_buf_mutex, NULL);
    pthread_cond_init(&fft_done_cond, NULL);
    pthread_cond_init(&dispatch_done_cond, NULL);
    pthread_cond_init(&agc_buf_ready, NULL);
    pthread_cond_init(&agc_buf_done, NULL);
    for (i = 0; i < 40; ++i)
        if (live_ch[i] >= 0)
            ++active_channels;
    pthread_barrier_local_init(&agc_barrier, NULL, active_channels);
    blocking_queue_init(&samples_queue, launch_spewer ? 16 : SAMPLES_QUEUE_SIZE);
    blocking_queue_init(&bursts, BURST_QUEUE_SIZE);
    agc_threads = calloc(40, sizeof(*agc_threads));
    pthread_create(&channelizer, NULL, channelizer_thread, NULL);
#ifdef USE_FFTW
    pthread_create(&fft_thread, NULL, fft_thread_main, NULL);
#else
    pthread_create(&agc_dispatcher, NULL, agc_dispatcher_thread, NULL);
#endif
#ifdef __linux__
    pthread_setname_np(channelizer, "channelizer");
#ifdef USE_FFTW
    pthread_setname_np(fft_thread, "fft");
#else
    pthread_setname_np(agc_dispatcher, "agc-dispatcher");
#endif
#endif
    for (i = first_live; i <= last_live; ++i) {
        pthread_create(&agc_threads[i], NULL, agc_thread, (void *)i);
#ifdef __linux__
        char name[32];
        snprintf(name, sizeof(name), "agc-%04lu", 2402+i*2);
        pthread_setname_np(agc_threads[i], name);
#endif
    }
    pthread_create(&burst_processor, NULL, burst_processor_thread, NULL);
#ifdef __linux__
    pthread_setname_np(burst_processor, "burst_processor");
#endif
    if (launch_spewer) {
        pthread_create(&spewer, NULL, spewer_thread, (void *)in);
#ifdef __linux__
        pthread_setname_np(spewer, "spewer");
#endif
    }
}

void deinit_threads(int join_spewer) {
    uintptr_t i;
    running = 0;

    blocking_queue_close(&samples_queue);

    if (join_spewer)
        pthread_join(spewer, NULL);

    pthread_join(channelizer, NULL);

    pthread_mutex_lock(&agc_buf_mutex);
    pthread_cond_broadcast(&agc_buf_ready);
    pthread_cond_signal(&agc_buf_done);
    pthread_mutex_unlock(&agc_buf_mutex);
    pthread_barrier_local_shutdown(&agc_barrier);
    for (i = first_live; i <= last_live; ++i)
        pthread_join(agc_threads[i], NULL);

    blocking_queue_close(&bursts);
    pthread_join(burst_processor, NULL);
}

void sig(int signo) {
    running = 0;
}

void parse_options(int argc, char **argv);

int main(int argc, char **argv) {
    unsigned i;
    // char *out_filename = NULL;
    hackrf_device *hackrf = NULL;
    struct bladerf *bladerf = NULL;
    uhd_usrp_handle usrp = NULL;
    pthread_t bladerf_thread, usrp_thread;
#ifdef HAVE_SOAPYSDR
    SoapySDRDevice *soapy = NULL;
    pthread_t soapy_thread;
#endif

    signal(SIGINT, sig);
    signal(SIGTERM, sig);
    signal(SIGPIPE, sig);
    self_pid = getpid();

    // enables , separator in printf
    setlocale(LC_NUMERIC, "");

#ifdef HAVE_ZMQ
    control_save_argv(argc, argv);
#endif

    parse_options(argc, argv);

#ifdef HAVE_ZMQ
    if (zmq_pub_active) {
        if (zmq_pub_init(zmq_endpoint, zmq_curve_keyfile, zmq_connect_mode) != 0)
            errx(1, "Failed to %s ZMQ PUB socket on %s",
                 zmq_connect_mode ? "connect" : "bind", zmq_endpoint);
        if (sensor_id == NULL) {
            sensor_id = malloc(256);
            if (gethostname(sensor_id, 256) != 0)
                snprintf(sensor_id, 256, "sensor");
            /* Avoid 24-byte length (ambiguous with GPS frame) */
            if (strlen(sensor_id) == 24)
                strcat(sensor_id, "-");
        }
        fprintf(stderr, "ZMQ PUB: %s (%s) sensor-id=%s\n", zmq_endpoint,
                zmq_connect_mode ? "connect" : "bind", sensor_id);
    }
#endif

#ifdef HAVE_GPS
    if (gpsd_active) {
        if (gps_tag_init() != 0)
            errx(1, "Failed to connect to gpsd");
        fprintf(stderr, "GPS: connected to gpsd\n");
    }
#endif

    if (live) {
        // TODO select first available interface
        if (bladerf_num >= 0)
            bladerf = bladerf_setup(bladerf_num);
        else if (usrp_serial != NULL)
            usrp = usrp_setup(usrp_serial);
#ifdef HAVE_SOAPYSDR
        else if (soapy_num >= 0)
            soapy = soapy_setup(soapy_num);
#endif
        else
            hackrf = hackrf_setup();
    }
    gen_syndrome_map(1);
    bluetooth_init();
    window_dotprod_init();

    unsigned h_len = 2*channels*m + 1;
    float *h = malloc(sizeof(float) * h_len);
    liquid_firdes_kaiser(h_len, lp_cutoff/(float)channels, 60.0f, 0.0f, h);
    pfbch2_init(&magic, channels, m, h);
#ifdef USE_OPENCL_PFB
    init_pfb_gpu(magic.h_sub, channels, m, magic.h_sub_len);
#endif
    init_fft(channels, BATCH_SIZE);
    free(h);

    agc_buffers = malloc(2 * channels * sizeof(*agc_buffers));
    agc_live = &agc_buffers[channels * live_buf];

    catcher = calloc(40, sizeof(burst_catcher_t));
    for (i = 0; i < channels; ++i) {
        unsigned freq = center_freq + (i < channels / 2 ? i : -channels + i);
        if ((freq & 1) == 0 && freq >= 2402 && freq <= 2480) {
            unsigned ch_num = (freq - 2402) / 2;
            if (ch_num < first_live) first_live = ch_num;
            if (ch_num > last_live)  last_live  = ch_num;
            live_ch[ch_num] = i;
        }
    }
    for (i = first_live; i <= last_live; ++i)
        burst_catcher_create(&catcher[i], 2402 + i * 2);

    init_threads(!live);

#ifdef HAVE_ZMQ
    if (zmq_pub_active && zmq_connect_mode) {
        char *ctrl_ep = control_derive_endpoint(zmq_endpoint);
        sdr_handle_t sdr = { .type = SDR_NONE, .handle = NULL };
        if (hackrf != NULL)      { sdr.type = SDR_HACKRF;  sdr.handle = hackrf; }
        else if (bladerf != NULL) { sdr.type = SDR_BLADERF; sdr.handle = bladerf; }
        else if (usrp != NULL)    { sdr.type = SDR_USRP;    sdr.handle = usrp; }
#ifdef HAVE_SOAPYSDR
        else if (soapy != NULL)   { sdr.type = SDR_SOAPY;   sdr.handle = soapy; }
#endif
        control_set_sdr(sdr);
        if (control_init(ctrl_ep, zmq_curve_keyfile, sensor_id) == 0) {
            pthread_create(&control_thread, NULL, control_loop, NULL);
            fprintf(stderr, "C2: control channel connecting to %s\n", ctrl_ep);
        }
        free(ctrl_ep);
    }
#endif

    if (live) {
        if (hackrf != NULL)
            hackrf_start_rx(hackrf, hackrf_rx_cb, NULL);
        else if (usrp != NULL)
            pthread_create(&usrp_thread, NULL, usrp_stream_thread, (void *)usrp);
#ifdef HAVE_SOAPYSDR
        else if (soapy != NULL)
            pthread_create(&soapy_thread, NULL, soapy_stream_thread, (void *)soapy);
#endif
        else
            pthread_create(&bladerf_thread, NULL, bladerf_stream_thread, (void *)bladerf);
    }

    while (running) {
        if (live && hackrf != NULL && !hackrf_is_streaming(hackrf))
            break;
        pause();
    }
    running = 0;

    if (live) {
        if (hackrf != NULL)
            hackrf_stop_rx(hackrf);
        else if (usrp != NULL)
            ; // do nothing (stream is stopped in thread)
#ifdef HAVE_SOAPYSDR
        else if (soapy != NULL)
            ; // do nothing (stream is stopped in thread)
#endif
        else
            bladerf_enable_module(bladerf, BLADERF_MODULE_RX, false);
    }

    deinit_threads(!live);

    if (live) {
        if (hackrf != NULL) {
            hackrf_close(hackrf);
            hackrf_exit();
        } else if (usrp != NULL) {
            pthread_join(usrp_thread, NULL);
            usrp_close(usrp);
#ifdef HAVE_SOAPYSDR
        } else if (soapy != NULL) {
            pthread_join(soapy_thread, NULL);
            soapy_close(soapy);
#endif
        } else {
            pthread_join(bladerf_thread, NULL);
            bladerf_close(bladerf);
        }
    }

    if (pcap)
        pcap_close(pcap);

#ifdef HAVE_GPS
    if (gpsd_active)
        gps_tag_close();
#endif

#ifdef HAVE_ZMQ
    if (zmq_pub_active && zmq_connect_mode) {
        control_shutdown();
        pthread_join(control_thread, NULL);
        control_close();
    }
    if (zmq_pub_active)
        zmq_pub_close();
    free(zmq_endpoint);
    free(zmq_curve_keyfile);
#endif

    for (i = first_live; i <= last_live; ++i)
        burst_catcher_destroy(&catcher[i]);
    free(catcher);

#ifdef USE_OPENCL_PFB
    deinit_vkfft();
#endif
    pfbch2_release(&magic);

#ifdef HAVE_ZMQ
    if (restart_requested && restart_argv) {
        char exe[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe, PATH_MAX - 1);
        if (len > 0) {
            exe[len] = '\0';
            fprintf(stderr, "C2: restarting with new parameters...\n");
            execv(exe, restart_argv);
            perror("execv failed");
        }
    }
#endif

    return 0;
}
