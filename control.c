/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <zmq.h>
#include "cJSON.h"
#include "control.h"

/* externs from main.c */
extern volatile sig_atomic_t running;
extern unsigned center_freq;
extern unsigned channels;
extern unsigned long crc_total;
extern unsigned long crc_valid_count;
extern unsigned long crc_invalid_count;
extern pid_t self_pid;

/* externs from SDR backends (gain values) */
extern unsigned vga_gain;
extern unsigned lna_gain;
extern int bladerf_gain_val;
extern float usrp_gain_val;
#ifdef HAVE_SOAPYSDR
extern double soapy_gain_val;
#endif
extern float sql;

/* extern from main.c for squelch dispatch */
extern void set_all_squelch(float threshold);

/* restart globals in main.c */
extern int restart_requested;
extern char **restart_argv;

/* SDR gain runtime functions from backends */
extern int hackrf_set_gain_runtime(void *dev, int new_lna, int new_vga);
extern int bladerf_set_gain_runtime(void *dev, int gain);
extern int usrp_set_gain_runtime(void *dev, double gain);
#ifdef HAVE_SOAPYSDR
extern int soapy_set_gain_runtime(void *dev, double gain);
#endif

#ifdef HAVE_GPS
#include "gps_tag.h"
extern int gpsd_active;
#endif

static void *ctrl_ctx = NULL;
static void *ctrl_dealer = NULL;
static volatile int ctrl_running = 0;
static sdr_handle_t current_sdr = { .type = SDR_NONE, .handle = NULL };
static int saved_argc = 0;
static char **saved_argv = NULL;
static char ctrl_sensor_id[256] = {0};
static struct timespec ctrl_start_time;

#define HEARTBEAT_INTERVAL 5

static int parse_curve_keyfile(const char *path, char *public_key, char *secret_key) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[256];
    int got_pub = 0, got_sec = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (strncmp(line, "public_key=", 11) == 0) {
            strncpy(public_key, line + 11, 40);
            public_key[40] = '\0';
            got_pub = 1;
        } else if (strncmp(line, "secret_key=", 11) == 0) {
            strncpy(secret_key, line + 11, 40);
            secret_key[40] = '\0';
            got_sec = 1;
        }
    }
    fclose(f);
    return (got_pub && got_sec) ? 0 : -1;
}

void control_save_argv(int argc, char **argv) {
    saved_argc = argc;
    saved_argv = malloc(sizeof(char *) * (argc + 1));
    for (int i = 0; i < argc; i++)
        saved_argv[i] = strdup(argv[i]);
    saved_argv[argc] = NULL;
}

char *control_derive_endpoint(const char *data_endpoint) {
    char *ep = strdup(data_endpoint);
    char *colon = strrchr(ep, ':');
    if (colon) {
        int port = atoi(colon + 1);
        int new_port = port + 1;
        size_t prefix_len = (size_t)(colon - ep + 1);
        char *new_ep = malloc(prefix_len + 12);
        memcpy(new_ep, ep, prefix_len);
        snprintf(new_ep + prefix_len, 12, "%d", new_port);
        free(ep);
        return new_ep;
    }
    free(ep);
    return strdup(data_endpoint);
}

int control_init(const char *control_endpoint, const char *curve_keyfile,
                 const char *sensor_id) {
    ctrl_ctx = zmq_ctx_new();
    if (!ctrl_ctx)
        return -1;

    ctrl_dealer = zmq_socket(ctrl_ctx, ZMQ_DEALER);
    if (!ctrl_dealer) {
        zmq_ctx_destroy(ctrl_ctx);
        ctrl_ctx = NULL;
        return -1;
    }

    /* Set identity so ROUTER can route replies back to us */
    zmq_setsockopt(ctrl_dealer, ZMQ_IDENTITY, sensor_id, strlen(sensor_id));

    int hwm = 100;
    zmq_setsockopt(ctrl_dealer, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    zmq_setsockopt(ctrl_dealer, ZMQ_RCVHWM, &hwm, sizeof(hwm));

    /* CurveZMQ: sensor is CURVE client, dashboard is CURVE server */
    if (curve_keyfile) {
        char public_key[41], secret_key[41];
        if (parse_curve_keyfile(curve_keyfile, public_key, secret_key) != 0) {
            fprintf(stderr, "C2: failed to read CURVE keys from %s\n", curve_keyfile);
            zmq_close(ctrl_dealer);
            zmq_ctx_destroy(ctrl_ctx);
            ctrl_dealer = NULL;
            ctrl_ctx = NULL;
            return -1;
        }
        /* Generate ephemeral client keypair */
        char client_pub[41], client_sec[41];
        zmq_curve_keypair(client_pub, client_sec);
        /* Server's public key is the one from the keyfile */
        zmq_setsockopt(ctrl_dealer, ZMQ_CURVE_SERVERKEY, public_key, 40);
        zmq_setsockopt(ctrl_dealer, ZMQ_CURVE_PUBLICKEY, client_pub, 40);
        zmq_setsockopt(ctrl_dealer, ZMQ_CURVE_SECRETKEY, client_sec, 40);
    }

    if (zmq_connect(ctrl_dealer, control_endpoint) != 0) {
        fprintf(stderr, "C2: failed to connect to %s\n", control_endpoint);
        zmq_close(ctrl_dealer);
        zmq_ctx_destroy(ctrl_ctx);
        ctrl_dealer = NULL;
        ctrl_ctx = NULL;
        return -1;
    }

    strncpy(ctrl_sensor_id, sensor_id, sizeof(ctrl_sensor_id) - 1);
    clock_gettime(CLOCK_MONOTONIC, &ctrl_start_time);
    ctrl_running = 1;
    return 0;
}

void control_set_sdr(sdr_handle_t sdr) {
    current_sdr = sdr;
}

void control_shutdown(void) {
    ctrl_running = 0;
}

void control_close(void) {
    if (ctrl_dealer) {
        zmq_close(ctrl_dealer);
        ctrl_dealer = NULL;
    }
    if (ctrl_ctx) {
        zmq_ctx_destroy(ctrl_ctx);
        ctrl_ctx = NULL;
    }
}

static const char *sdr_type_str(sdr_type_t t) {
    switch (t) {
        case SDR_HACKRF:  return "hackrf";
        case SDR_BLADERF: return "bladerf";
        case SDR_USRP:    return "usrp";
        case SDR_SOAPY:   return "soapy";
        default:          return "unknown";
    }
}

static void send_heartbeat(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "heartbeat");
    cJSON_AddStringToObject(root, "sensor_id", ctrl_sensor_id);
    cJSON_AddStringToObject(root, "sdr", sdr_type_str(current_sdr.type));
    cJSON_AddNumberToObject(root, "center_freq", center_freq);
    cJSON_AddNumberToObject(root, "channels", channels);

    /* Gain: SDR-specific */
    cJSON *gain = cJSON_CreateObject();
    switch (current_sdr.type) {
        case SDR_HACKRF:
            cJSON_AddNumberToObject(gain, "lna", lna_gain);
            cJSON_AddNumberToObject(gain, "vga", vga_gain);
            break;
        case SDR_BLADERF:
            cJSON_AddNumberToObject(gain, "value", bladerf_gain_val);
            break;
        case SDR_USRP:
            cJSON_AddNumberToObject(gain, "value", usrp_gain_val);
            break;
#ifdef HAVE_SOAPYSDR
        case SDR_SOAPY:
            cJSON_AddNumberToObject(gain, "value", soapy_gain_val);
            break;
#endif
        default:
            cJSON_AddNumberToObject(gain, "value", 0);
            break;
    }
    cJSON_AddItemToObject(root, "gain", gain);

    cJSON_AddNumberToObject(root, "squelch", sql);

    /* Packet rate and CRC stats */
    static unsigned long last_crc_total = 0;
    static struct timespec last_rate_time = {0};
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed = (now.tv_sec - last_rate_time.tv_sec) +
                     (now.tv_nsec - last_rate_time.tv_nsec) / 1e9;
    double pkt_rate = 0;
    if (elapsed > 0 && last_rate_time.tv_sec > 0) {
        unsigned long delta = crc_total - last_crc_total;
        pkt_rate = delta / elapsed;
    }
    last_crc_total = crc_total;
    last_rate_time = now;

    cJSON_AddNumberToObject(root, "total_pkts", (double)crc_total);
    cJSON_AddNumberToObject(root, "pkt_rate", round(pkt_rate * 10) / 10);

    double crc_pct = 0;
    if (crc_valid_count + crc_invalid_count > 0)
        crc_pct = 100.0 * crc_valid_count / (crc_valid_count + crc_invalid_count);
    cJSON_AddNumberToObject(root, "crc_pct", round(crc_pct * 10) / 10);

    /* Uptime */
    long uptime = now.tv_sec - ctrl_start_time.tv_sec;
    cJSON_AddNumberToObject(root, "uptime", uptime);

    /* GPS */
#ifdef HAVE_GPS
    if (gpsd_active) {
        gps_fix_t fix;
        gps_tag_get_fix(&fix);
        if (fix.valid && (fix.latitude != 0 || fix.longitude != 0)) {
            cJSON *gps = cJSON_CreateArray();
            cJSON_AddItemToArray(gps, cJSON_CreateNumber(fix.latitude));
            cJSON_AddItemToArray(gps, cJSON_CreateNumber(fix.longitude));
            cJSON_AddItemToArray(gps, cJSON_CreateNumber(fix.altitude));
            cJSON_AddItemToObject(root, "gps", gps);
        }
    }
#endif

    char *json_str = cJSON_PrintUnformatted(root);
    zmq_send(ctrl_dealer, json_str, strlen(json_str), ZMQ_DONTWAIT);
    free(json_str);
    cJSON_Delete(root);
}

static void send_response(const char *req_id, const char *status, const char *message) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "response");
    if (req_id)
        cJSON_AddStringToObject(root, "req_id", req_id);
    cJSON_AddStringToObject(root, "status", status);
    cJSON_AddStringToObject(root, "message", message);

    char *json_str = cJSON_PrintUnformatted(root);
    zmq_send(ctrl_dealer, json_str, strlen(json_str), ZMQ_DONTWAIT);
    free(json_str);
    cJSON_Delete(root);
}

static void handle_set_gain(cJSON *root, const char *req_id) {
    if (!current_sdr.handle) {
        send_response(req_id, "error", "no SDR active");
        return;
    }

    int rc = -1;
    char msg[128];

    switch (current_sdr.type) {
        case SDR_HACKRF: {
            cJSON *j_lna = cJSON_GetObjectItem(root, "lna");
            cJSON *j_vga = cJSON_GetObjectItem(root, "vga");
            int new_lna = j_lna ? j_lna->valueint : -1;
            int new_vga = j_vga ? j_vga->valueint : -1;
            rc = hackrf_set_gain_runtime(current_sdr.handle, new_lna, new_vga);
            if (rc == 0)
                snprintf(msg, sizeof(msg), "hackrf gain set: lna=%u vga=%u", lna_gain, vga_gain);
            else
                snprintf(msg, sizeof(msg), "hackrf gain set failed");
            break;
        }
        case SDR_BLADERF: {
            cJSON *j_gain = cJSON_GetObjectItem(root, "gain");
            if (!j_gain) { send_response(req_id, "error", "missing gain"); return; }
            rc = bladerf_set_gain_runtime(current_sdr.handle, j_gain->valueint);
            if (rc == 0) {
                bladerf_gain_val = j_gain->valueint;
                snprintf(msg, sizeof(msg), "bladerf gain set to %d", bladerf_gain_val);
            } else
                snprintf(msg, sizeof(msg), "bladerf gain set failed");
            break;
        }
        case SDR_USRP: {
            cJSON *j_gain = cJSON_GetObjectItem(root, "gain");
            if (!j_gain) { send_response(req_id, "error", "missing gain"); return; }
            rc = usrp_set_gain_runtime(current_sdr.handle, j_gain->valuedouble);
            if (rc == 0) {
                usrp_gain_val = (float)j_gain->valuedouble;
                snprintf(msg, sizeof(msg), "usrp gain set to %.1f", usrp_gain_val);
            } else
                snprintf(msg, sizeof(msg), "usrp gain set failed");
            break;
        }
#ifdef HAVE_SOAPYSDR
        case SDR_SOAPY: {
            cJSON *j_gain = cJSON_GetObjectItem(root, "gain");
            if (!j_gain) { send_response(req_id, "error", "missing gain"); return; }
            rc = soapy_set_gain_runtime(current_sdr.handle, j_gain->valuedouble);
            if (rc == 0) {
                soapy_gain_val = j_gain->valuedouble;
                snprintf(msg, sizeof(msg), "soapy gain set to %.1f", soapy_gain_val);
            } else
                snprintf(msg, sizeof(msg), "soapy gain set failed");
            break;
        }
#endif
        default:
            send_response(req_id, "error", "unknown SDR type");
            return;
    }

    fprintf(stderr, "C2: %s\n", msg);
    send_response(req_id, rc == 0 ? "ok" : "error", msg);
}

static void handle_set_squelch(cJSON *root, const char *req_id) {
    cJSON *j_threshold = cJSON_GetObjectItem(root, "threshold");
    if (!j_threshold) {
        send_response(req_id, "error", "missing threshold");
        return;
    }
    float threshold = (float)j_threshold->valuedouble;
    if (threshold > -5.0f || threshold < -100.0f) {
        send_response(req_id, "error", "threshold out of range (-100 to -5)");
        return;
    }
    set_all_squelch(threshold);
    char msg[64];
    snprintf(msg, sizeof(msg), "squelch set to %.1f dB", threshold);
    fprintf(stderr, "C2: %s\n", msg);
    send_response(req_id, "ok", msg);
}

static void handle_restart(cJSON *root, const char *req_id) {
    cJSON *j_freq = cJSON_GetObjectItem(root, "center_freq");
    cJSON *j_chan = cJSON_GetObjectItem(root, "channels");

    if (!j_freq && !j_chan) {
        send_response(req_id, "error", "restart requires center_freq or channels");
        return;
    }

    if (!saved_argv) {
        send_response(req_id, "error", "argv not saved, cannot restart");
        return;
    }

    /* Build new argv from saved, replacing -c and -C values */
    int max_argc = saved_argc + 5;
    char **new_argv = malloc(sizeof(char *) * ((size_t)max_argc + 1));
    int new_argc = 0;
    int replaced_c = 0, replaced_C = 0;

    static char freq_buf[32];
    static char chan_buf[32];
    if (j_freq)
        snprintf(freq_buf, sizeof(freq_buf), "%d", j_freq->valueint);
    if (j_chan)
        snprintf(chan_buf, sizeof(chan_buf), "%d", j_chan->valueint);

    for (int i = 0; i < saved_argc; i++) {
        if ((strcmp(saved_argv[i], "-c") == 0 ||
             strncmp(saved_argv[i], "--center-freq", 13) == 0) && j_freq) {
            new_argv[new_argc++] = saved_argv[i];
            if (strchr(saved_argv[i], '=') == NULL && i + 1 < saved_argc) {
                i++; /* skip old value */
            }
            new_argv[new_argc++] = freq_buf;
            replaced_c = 1;
        } else if ((strcmp(saved_argv[i], "-C") == 0 ||
                    strncmp(saved_argv[i], "--channels", 10) == 0) && j_chan) {
            new_argv[new_argc++] = saved_argv[i];
            if (strchr(saved_argv[i], '=') == NULL && i + 1 < saved_argc) {
                i++; /* skip old value */
            }
            new_argv[new_argc++] = chan_buf;
            replaced_C = 1;
        } else {
            new_argv[new_argc++] = saved_argv[i];
        }
    }

    /* Append flags that weren't in original argv */
    if (j_freq && !replaced_c) {
        new_argv[new_argc++] = "-c";
        new_argv[new_argc++] = freq_buf;
    }
    if (j_chan && !replaced_C) {
        new_argv[new_argc++] = "-C";
        new_argv[new_argc++] = chan_buf;
    }
    new_argv[new_argc] = NULL;

    /* Send ack before dying */
    send_response(req_id, "ok", "restarting");

    /* Give ZMQ time to flush */
    usleep(100000);

    /* Signal restart */
    restart_argv = new_argv;
    restart_requested = 1;
    running = 0;

    /* Wake main from pause() */
    kill(self_pid, SIGINT);
}

static void dispatch_command(const void *data, size_t len) {
    cJSON *root = cJSON_ParseWithLength(data, len);
    if (!root) return;

    const cJSON *j_cmd = cJSON_GetObjectItem(root, "cmd");
    const cJSON *j_req = cJSON_GetObjectItem(root, "req_id");
    if (!cJSON_IsString(j_cmd)) {
        cJSON_Delete(root);
        return;
    }

    const char *cmd = j_cmd->valuestring;
    const char *req_id = cJSON_IsString(j_req) ? j_req->valuestring : NULL;

    if (strcmp(cmd, "set_gain") == 0) {
        handle_set_gain(root, req_id);
    } else if (strcmp(cmd, "set_squelch") == 0) {
        handle_set_squelch(root, req_id);
    } else if (strcmp(cmd, "get_status") == 0) {
        send_heartbeat();
    } else if (strcmp(cmd, "restart") == 0) {
        handle_restart(root, req_id);
    } else {
        send_response(req_id, "error", "unknown command");
    }

    cJSON_Delete(root);
}

void *control_loop(void *arg) {
    (void)arg;
    struct timespec last_heartbeat = {0};

    /* Send initial heartbeat immediately */
    send_heartbeat();
    clock_gettime(CLOCK_MONOTONIC, &last_heartbeat);

    while (ctrl_running && running) {
        zmq_pollitem_t poll_item = { ctrl_dealer, 0, ZMQ_POLLIN, 0 };
        int rc = zmq_poll(&poll_item, 1, 1000); /* 1 second timeout */

        if (rc > 0 && (poll_item.revents & ZMQ_POLLIN)) {
            zmq_msg_t msg;
            zmq_msg_init(&msg);
            if (zmq_msg_recv(&msg, ctrl_dealer, 0) >= 0) {
                dispatch_command(zmq_msg_data(&msg), zmq_msg_size(&msg));
            }
            zmq_msg_close(&msg);
        }

        /* Send heartbeat every HEARTBEAT_INTERVAL seconds */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - last_heartbeat.tv_sec >= HEARTBEAT_INTERVAL) {
            send_heartbeat();
            last_heartbeat = now;
        }
    }

    return NULL;
}
