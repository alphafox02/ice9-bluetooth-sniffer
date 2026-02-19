/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"

#ifdef HAVE_GPS
#include "gps_tag.h"
extern int gpsd_active;
#endif

#ifdef HAVE_ZMQ
#include <zmq.h>

static void *zmq_ctx = NULL;
static void *zmq_pub = NULL;
extern char *sensor_id;
#endif

struct _pcap_t {
    FILE *f;
};

typedef struct __attribute__((packed)) _pcap_hdr_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct __attribute__((packed)) _pcaprec_hdr_t {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct __attribute__((packed)) _pcap_le_header_t {
    uint8_t rf_channel;
    int8_t signal_power;
    int8_t noise_power;
    uint8_t aa_offenses;
    uint32_t ref_aa;
    uint16_t flags;
} pcap_le_header_t;

#define LE_DEWHITENED         0x0001
#define LE_SIGNAL_POWER_VALID 0x0002
#define LE_NOISE_POWER_VALID  0x0004
#define LE_CRC_CHECKED        0x0400  // CRC validation was performed (bit 10)
#define LE_CRC_VALID          0x0800  // CRC is valid (only meaningful with LE_CRC_CHECKED) (bit 11)


#if !defined( DLT_BLUETOOTH_LE_LL_WITH_PHDR )
#define DLT_BLUETOOTH_LE_LL_WITH_PHDR 256
#endif

#if !defined( DLT_BLUETOOTH_BREDR_BB )
#define DLT_BLUETOOTH_BREDR_BB 255
#endif

#define DLT_PPI 192

/* Classic BT BR/EDR baseband header (DLT 255, Wireshark-compatible) */
typedef struct __attribute__((packed)) _pcap_bredr_bb_header_t {
    uint8_t rf_channel;
    int8_t signal_power;
    int8_t noise_power;
    uint8_t access_code_offenses;
    uint8_t payload_transport_rate;
    uint8_t corrected_header_bits;
    int16_t corrected_payload_bits;
    uint32_t lap;
    uint32_t ref_lap_uap;
    uint32_t bt_header;
    uint16_t flags;
} pcap_bredr_bb_header_t;

#define BREDR_SIGNAL_POWER_VALID   0x0004
#define BREDR_NOISE_POWER_VALID    0x0008

/* ZMQ packet type prefix bytes */
#define ZMQ_PKT_TYPE_BLE  0x00
#define ZMQ_PKT_TYPE_BT   0x01

/* PPI (Per-Packet Information) header structures */
typedef struct __attribute__((packed)) _ppi_header_t {
    uint8_t  pph_version;       /* 0 */
    uint8_t  pph_flags;         /* 0 */
    uint16_t pph_len;           /* total PPI header length */
    uint32_t pph_dlt;           /* encapsulated DLT */
} ppi_header_t;

/* PPI field header (TLV) */
typedef struct __attribute__((packed)) _ppi_field_header_t {
    uint16_t pfh_type;          /* field type */
    uint16_t pfh_datalen;       /* field data length (excluding this header) */
} ppi_field_header_t;

/* PPI-GPS geotag (field type 30002) */
#define PPI_FIELD_GPS 30002

typedef struct __attribute__((packed)) _ppi_gps_t {
    uint8_t  geotag_ver;        /* 2 */
    uint8_t  geotag_pad;        /* 0 */
    uint16_t geotag_len;        /* 24 */
    uint32_t present_flags;     /* bitmask of present fields */
    uint32_t gps_flags;         /* GPS fix flags */
    uint32_t lat;               /* fixed-point latitude */
    uint32_t lon;               /* fixed-point longitude */
    uint32_t alt;               /* fixed-point altitude */
} ppi_gps_t;

/* PPI-GPS present flags (bit positions per PPI geolocation spec) */
#define PPI_GPS_FLAG_GPSFLAGS 0x00000001  /* bit 0: GPSFlags field present */
#define PPI_GPS_FLAG_LAT      0x00000002  /* bit 1: latitude */
#define PPI_GPS_FLAG_LON      0x00000004  /* bit 2: longitude */
#define PPI_GPS_FLAG_ALT      0x00000008  /* bit 3: altitude */

/* Convert double to PPI fixed3_7 format (for lat/lon, unsigned with +180 offset) */
static uint32_t ppi_fixed3_7(double val) {
    return (uint32_t)((val + 180.0) * 1e7);
}

/* Convert double to PPI fixed6_4 format (for altitude, unsigned with +180000m offset) */
static uint32_t ppi_fixed6_4(double val) {
    return (uint32_t)((val + 180000.0) * 1e4);
}

/* Size of minimal PPI header (no fields) */
#define PPI_HDR_SIZE sizeof(ppi_header_t)

/* Size of PPI header with GPS field */
#define PPI_GPS_SIZE (sizeof(ppi_header_t) + sizeof(ppi_field_header_t) + sizeof(ppi_gps_t))

pcap_t *pcap_open(char *path) {
    pcap_t *p;
    /* Always use PPI to support mixed BLE + Classic BT per-packet DLT */
    uint32_t dlt = DLT_PPI;
    uint32_t snaplen = PPI_GPS_SIZE + 4 + 2 + 255 + 3;

    pcap_hdr_t h = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .snaplen = snaplen,
        .network = dlt,
    };

    FILE *f = fopen(path, "w");
    if (f == NULL)
        return NULL;
    p = malloc(sizeof(*p));
    p->f = f;

    // write header
    fwrite(&h, sizeof(h), 1, p->f);

    return p;
}

void pcap_close(pcap_t *p) {
    fclose(p->f);
    free(p);
}

#ifdef HAVE_ZMQ
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

int zmq_pub_init(const char *endpoint, const char *curve_keyfile) {
    zmq_ctx = zmq_ctx_new();
    if (!zmq_ctx)
        return -1;
    zmq_pub = zmq_socket(zmq_ctx, ZMQ_PUB);
    if (!zmq_pub) {
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
        return -1;
    }
    int sndhwm = 1000;
    zmq_setsockopt(zmq_pub, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));

    if (curve_keyfile) {
        char public_key[41], secret_key[41];
        if (parse_curve_keyfile(curve_keyfile, public_key, secret_key) != 0) {
            fprintf(stderr, "Failed to read CURVE keys from %s\n", curve_keyfile);
            zmq_close(zmq_pub);
            zmq_ctx_destroy(zmq_ctx);
            zmq_pub = NULL;
            zmq_ctx = NULL;
            return -1;
        }
        int server = 1;
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_SERVER, &server, sizeof(server));
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_SECRETKEY, secret_key, 40);
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_PUBLICKEY, public_key, 40);
        fprintf(stderr, "ZMQ CURVE: encrypted (server key: %.8s...)\n", public_key);
    }

    if (zmq_connect(zmq_pub, endpoint) != 0) {
        zmq_close(zmq_pub);
        zmq_ctx_destroy(zmq_ctx);
        zmq_pub = NULL;
        zmq_ctx = NULL;
        return -1;
    }
    return 0;
}

void zmq_pub_close(void) {
    if (zmq_pub) {
        zmq_close(zmq_pub);
        zmq_pub = NULL;
    }
    if (zmq_ctx) {
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
    }
}

/* Generic ZMQ publisher: type_byte + pcaprec_hdr + link-layer header + data */
static void zmq_pub_raw(uint8_t type_byte, pcaprec_hdr_t *ph,
                         void *ll_hdr, unsigned ll_len,
                         uint8_t *data, unsigned data_len,
                         zmq_gps_frame_t *gps) {
    if (!zmq_pub)
        return;
    unsigned msg_len = 1 + sizeof(*ph) + ll_len + data_len;
    uint8_t *buf = malloc(msg_len);
    if (!buf)
        return;
    buf[0] = type_byte;
    memcpy(buf + 1, ph, sizeof(*ph));
    memcpy(buf + 1 + sizeof(*ph), ll_hdr, ll_len);
    if (data_len)
        memcpy(buf + 1 + sizeof(*ph) + ll_len, data, data_len);

    if (sensor_id)
        zmq_send(zmq_pub, sensor_id, strlen(sensor_id), ZMQ_DONTWAIT | ZMQ_SNDMORE);
    if (gps)
        zmq_send(zmq_pub, gps, sizeof(*gps), ZMQ_DONTWAIT | ZMQ_SNDMORE);
    zmq_send(zmq_pub, buf, msg_len, ZMQ_DONTWAIT);
    free(buf);
}
#endif

void pcap_write_ble(pcap_t *p, ble_packet_t *b) {
    uint16_t flags = LE_DEWHITENED | LE_SIGNAL_POWER_VALID | LE_NOISE_POWER_VALID;

    if (b->crc_checked) {
        flags |= LE_CRC_CHECKED;
        if (b->crc_valid)
            flags |= LE_CRC_VALID;
    }

    pcap_le_header_t le_header = {
        .rf_channel = (b->freq - 2402) / 2,
        .signal_power = b->rssi_db,
        .noise_power = b->noise_db,
        .flags = flags,
    };

    unsigned ble_payload_len = b->len + sizeof(le_header);

    /* Always PPI-wrapped for PCAP file (supports mixed BLE + Classic BT) */
    unsigned ppi_len = PPI_HDR_SIZE;
#ifdef HAVE_GPS
    gps_fix_t fix = {0};
    if (gpsd_active)
        gps_tag_get_fix(&fix);
    if (fix.valid)
        ppi_len = PPI_GPS_SIZE;
#endif

    ppi_header_t ppi_hdr = {
        .pph_version = 0,
        .pph_flags = 0,
        .pph_len = ppi_len,
        .pph_dlt = DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    };

    pcaprec_hdr_t pcap_header = {
        .ts_sec   = b->timestamp.tv_sec,
        .ts_usec  = b->timestamp.tv_nsec/1000,
        .incl_len = ppi_len + ble_payload_len,
        .orig_len = ppi_len + ble_payload_len,
    };

    if (p) {
        fwrite(&pcap_header, sizeof(pcap_header), 1, p->f);
        fwrite(&ppi_hdr, sizeof(ppi_hdr), 1, p->f);
#ifdef HAVE_GPS
        if (fix.valid) {
            ppi_field_header_t fld_hdr = {
                .pfh_type = PPI_FIELD_GPS,
                .pfh_datalen = sizeof(ppi_gps_t),
            };
            ppi_gps_t gps = {
                .geotag_ver = 2,
                .geotag_pad = 0,
                .geotag_len = sizeof(ppi_gps_t),
                .present_flags = PPI_GPS_FLAG_GPSFLAGS | PPI_GPS_FLAG_LAT | PPI_GPS_FLAG_LON | PPI_GPS_FLAG_ALT,
                .gps_flags = 0,
                .lat = ppi_fixed3_7(fix.latitude),
                .lon = ppi_fixed3_7(fix.longitude),
                .alt = ppi_fixed6_4(fix.altitude),
            };
            fwrite(&fld_hdr, sizeof(fld_hdr), 1, p->f);
            fwrite(&gps, sizeof(gps), 1, p->f);
        }
#endif
        fwrite(&le_header, sizeof(le_header), 1, p->f);
        fwrite(b->data, b->len, 1, p->f);
        fflush(p->f);
    }

#ifdef HAVE_ZMQ
    {
        /* ZMQ: type-prefixed PCAP record (no PPI -- dashboard handles routing) */
        pcaprec_hdr_t zmq_ph = {
            .ts_sec   = b->timestamp.tv_sec,
            .ts_usec  = b->timestamp.tv_nsec/1000,
            .incl_len = ble_payload_len,
            .orig_len = ble_payload_len,
        };
        zmq_gps_frame_t *gps_ptr = NULL;
#ifdef HAVE_GPS
        zmq_gps_frame_t gps_frame;
        if (fix.valid) {
            gps_frame.latitude = fix.latitude;
            gps_frame.longitude = fix.longitude;
            gps_frame.altitude = fix.altitude;
            gps_ptr = &gps_frame;
        }
#endif
        zmq_pub_raw(ZMQ_PKT_TYPE_BLE, &zmq_ph,
                     &le_header, sizeof(le_header),
                     b->data, b->len, gps_ptr);
    }
#endif
}

void pcap_write_bt(pcap_t *p, classic_bt_packet_t *bt) {
    pcap_bredr_bb_header_t hdr = {0};

    hdr.rf_channel = bt->freq - 2402;  /* Classic BT: 0-78 */
    hdr.signal_power = bt->rssi_db;
    hdr.noise_power = bt->noise_db;
    hdr.access_code_offenses = bt->ac_errors;
    hdr.corrected_payload_bits = -1;
    hdr.lap = bt->lap;
    hdr.flags = BREDR_SIGNAL_POWER_VALID | BREDR_NOISE_POWER_VALID;

    unsigned payload_len = bt->has_header ? 7 : 0;
    unsigned total_len = sizeof(hdr) + payload_len;

    /* Always PPI-wrapped for PCAP file */
    unsigned ppi_len = PPI_HDR_SIZE;
#ifdef HAVE_GPS
    gps_fix_t fix = {0};
    if (gpsd_active)
        gps_tag_get_fix(&fix);
    if (fix.valid)
        ppi_len = PPI_GPS_SIZE;
#endif

    ppi_header_t ppi_hdr = {
        .pph_version = 0,
        .pph_flags = 0,
        .pph_len = ppi_len,
        .pph_dlt = DLT_BLUETOOTH_BREDR_BB,
    };

    pcaprec_hdr_t pcap_header = {
        .ts_sec   = bt->timestamp.tv_sec,
        .ts_usec  = bt->timestamp.tv_nsec/1000,
        .incl_len = ppi_len + total_len,
        .orig_len = ppi_len + total_len,
    };

    if (p) {
        fwrite(&pcap_header, sizeof(pcap_header), 1, p->f);
        fwrite(&ppi_hdr, sizeof(ppi_hdr), 1, p->f);
#ifdef HAVE_GPS
        if (fix.valid) {
            ppi_field_header_t fld_hdr = {
                .pfh_type = PPI_FIELD_GPS,
                .pfh_datalen = sizeof(ppi_gps_t),
            };
            ppi_gps_t gps = {
                .geotag_ver = 2,
                .geotag_pad = 0,
                .geotag_len = sizeof(ppi_gps_t),
                .present_flags = PPI_GPS_FLAG_GPSFLAGS | PPI_GPS_FLAG_LAT | PPI_GPS_FLAG_LON | PPI_GPS_FLAG_ALT,
                .gps_flags = 0,
                .lat = ppi_fixed3_7(fix.latitude),
                .lon = ppi_fixed3_7(fix.longitude),
                .alt = ppi_fixed6_4(fix.altitude),
            };
            fwrite(&fld_hdr, sizeof(fld_hdr), 1, p->f);
            fwrite(&gps, sizeof(gps), 1, p->f);
        }
#endif
        fwrite(&hdr, sizeof(hdr), 1, p->f);
        if (payload_len)
            fwrite(bt->raw_header, payload_len, 1, p->f);
        fflush(p->f);
    }

#ifdef HAVE_ZMQ
    {
        pcaprec_hdr_t zmq_ph = {
            .ts_sec   = bt->timestamp.tv_sec,
            .ts_usec  = bt->timestamp.tv_nsec/1000,
            .incl_len = total_len,
            .orig_len = total_len,
        };
        zmq_gps_frame_t *gps_ptr = NULL;
#ifdef HAVE_GPS
        zmq_gps_frame_t gps_frame;
        if (fix.valid) {
            gps_frame.latitude = fix.latitude;
            gps_frame.longitude = fix.longitude;
            gps_frame.altitude = fix.altitude;
            gps_ptr = &gps_frame;
        }
#endif
        zmq_pub_raw(ZMQ_PKT_TYPE_BT, &zmq_ph,
                     &hdr, sizeof(hdr),
                     bt->has_header ? bt->raw_header : NULL, payload_len,
                     gps_ptr);
    }
#endif
}
