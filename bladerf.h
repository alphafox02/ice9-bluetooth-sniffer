/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __BLADERF_H__
#define __BLADERF_H__

#include <libbladeRF.h>

extern int bladerf_gain_val;

void bladerf_list(void);
struct bladerf *bladerf_setup(int id);
void *bladerf_stream_thread(void *arg);
int bladerf_set_gain_runtime(void *dev, int gain);

#endif
