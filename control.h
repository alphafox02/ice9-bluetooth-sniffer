/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#ifndef __CONTROL_H__
#define __CONTROL_H__

#include <stdint.h>

typedef enum {
    SDR_HACKRF = 0,
    SDR_BLADERF,
    SDR_USRP,
    SDR_SOAPY,
    SDR_NONE
} sdr_type_t;

typedef struct {
    sdr_type_t type;
    void *handle;
} sdr_handle_t;

/* Save original argv before getopt permutes it */
void control_save_argv(int argc, char **argv);

/* Initialize DEALER socket connecting to dashboard ROUTER.
 * control_endpoint: e.g. "tcp://collector:5556"
 * curve_keyfile: same file used for data PUB, or NULL
 * sensor_id: identity string for DEALER socket
 * Returns 0 on success, -1 on failure. */
int control_init(const char *control_endpoint, const char *curve_keyfile,
                 const char *sensor_id);

/* Set the SDR handle so control module can issue gain changes */
void control_set_sdr(sdr_handle_t sdr);

/* Run the control loop (blocking, call from a dedicated thread) */
void *control_loop(void *arg);

/* Signal the control loop to stop */
void control_shutdown(void);

/* Close and destroy control sockets/context */
void control_close(void);

/* Derive control endpoint from data endpoint (port + 1) */
char *control_derive_endpoint(const char *data_endpoint);

#endif
