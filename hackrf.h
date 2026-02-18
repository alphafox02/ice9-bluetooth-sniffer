/*
 * Copyright 2022 ICE9 Consulting LLC
 */

#ifndef __OUR_HACKRF_H__
#define __OUR_HACKRF_H__

#include <libhackrf/hackrf.h>

extern unsigned vga_gain;
extern unsigned lna_gain;

void hackrf_list(void);
hackrf_device *hackrf_setup(void);
int hackrf_rx_cb(hackrf_transfer *t);
int hackrf_set_gain_runtime(void *dev, int new_lna, int new_vga);

#endif
