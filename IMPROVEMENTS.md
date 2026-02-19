# BLE Detection Improvements

## Overview

This document describes improvements made to ice9-bluetooth-sniffer:

1. Optional CRC-24 validation with Wireshark integration
2. Access Address correlator for dramatically improved packet detection
3. OpenCL GPU acceleration for the polyphase channelizer + FFT
4. Distance estimation from TX Power Level + RSSI
5. IRK-based RPA resolution for tracking devices with rotating MACs
6. Multi-sensor multilateration for BLE device position estimation
7. Classic Bluetooth (BR/EDR) detection pipeline with UAP estimation
8. SQLite device database for cross-session persistence
9. Device alerting (new-device, watch file, commands, webhooks)

## Changes Made

### 1. Optional CRC-24 Validation

**Problem:**
The original implementation did not validate BLE CRC-24 checksums, so
there was no way to distinguish packets with bit errors from clean ones.

**Solution:**
Implemented CRC-24 validation with PCAP flag support for Wireshark:

- CRC-24/BLE algorithm (polynomial x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1)
- Reflected polynomial implementation (0xDA6000) with reflected init
- Init value: 0x555555 for advertising channels, lower 24 bits of AA for data channels
- Optional via `--check-crc` flag (default: OFF for backward compatibility)
- Sets PCAP flags LE_CRC_CHECKED and LE_CRC_VALID for Wireshark

**Live Testing Results (USRP B210, USB 3.0):**
- CRC valid rate depends on channel count and signal strength
- At 48 channels: ~71% valid (best), at 40 channels: ~57% valid
- See section 3 (Channel Count Sensitivity) for details

**Usage:**
```bash
# Without CRC checking (default, backward compatible)
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap

# With CRC checking
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap --check-crc

# With CRC checking and statistics
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap --check-crc --stats
```

**Statistics Output:**
When both `--check-crc` and `--stats` are enabled, periodic output includes:
```
CRC: 404 valid, 164 invalid (71.1% valid)
```

### 2. Access Address Correlator (Addresses Issue #34)

**Problem:**
The original BLE detection relies on a strict preamble check: the first 6
sliced bits must show a perfect alternating pattern before the access address
is even examined. Without symbol timing recovery (the symsync code in fsk.c
is commented out), the bit slicer often samples at the wrong phase, corrupting
the preamble and causing the entire packet to be missed.

Analysis of the example capture data from issue #34 confirmed this: of 38
bursts that were clearly BLE advertising packets, only 1 (3%) was detected
by the original preamble-first method. The remaining 37 failed at the
preamble check despite containing valid BLE data.

**Solution:**
Implemented an Access Address correlator that works on the analog FM-demodulated
signal before bit slicing. This bypasses the preamble check entirely and finds
packets by matching the known BLE advertising access address (0x8E89BED6)
pattern directly in the continuous signal.

The correlator:
- Pre-computes an AA template at startup (+1/-1 values, 2 samples per symbol)
- Slides the template across the entire demod signal using normalized
  cross-correlation
- If the best score exceeds 0.6, tries both sample phases for bit extraction
- Accepts packets with up to 4 bit errors in the AA (hamming distance <= 4)
- Falls back gracefully: the original preamble method runs first, and the
  correlator only activates when preamble detection fails

**Prototype Validation (Issue #34 Data):**

| Method | Detected | Rate |
|--------|----------|------|
| Original (preamble-first) | 1/38 | 3% |
| AA Correlator | 35/38 | 92% |

The 3 undetected bursts had correlation scores below 0.5 (likely non-BLE
or severely corrupted). All 35 detected bursts decoded to valid BLE PDU
types (ADV_NONCONN_IND, SCAN_REQ, ADV_IND).

**Live Capture Results (USRP B210, -C 40, 30 seconds):**

| Version | Packets | Improvement |
|---------|---------|-------------|
| Original | 185 | -- |
| With AA correlator | 512 | +177% (2.8x) |

**Performance:**
- Template pre-computed at startup (negligible cost)
- Correlator is O(n*64) per burst where n = burst length in samples
- Only runs when preamble method fails (zero overhead for already-detected packets)
- Maintains 100% realtime at 40 Msamp/sec on USB 3.0

**Acknowledgment:**
This improvement was made possible by the example capture data posted in
issue #34, which provided the real-world burst samples needed to diagnose
the preamble detection bottleneck and validate the correlator approach.

### 3. OpenCL GPU Acceleration

**Problem:**
The CPU-based polyphase filterbank channelizer (PFBCH2) is the main
throughput bottleneck. At high channel counts, the per-sample dot
products and FFT consume most of the processing budget, limiting
realtime performance.

**Solution:**
Moved both the PFB filterbank and FFT to the GPU, running in a pipeline:

- Custom OpenCL kernel for PFB dot products, followed by VkFFT for the FFT
- Both run on the GPU in the same command queue; data stays in GPU memory
- Double-buffered: one batch processes on GPU while the next fills on CPU
- Pre-roll mechanism preserves window history across batch boundaries
- Auto-detected at build time; no runtime flags needed
- Falls back to FFTW when OpenCL is not available

**Additional SIMD improvements:**
- AVX2 runtime dispatch for the CPU dot product (window.c), with SSE2 fallback
- SSE4.1 vectorized int16-to-float conversion in the CPU channelizer path
- Fixed a bug in the scalar fallback that used the real buffer for both
  real and imaginary accumulation

**Testing Results (USRP B210, USB 3.0):**

*Intel UHD integrated GPU:*

| Channels | Throughput | CRC Valid Rate |
|----------|-----------|----------------|
| 40 | 100% realtime | ~57% |
| 48 | ~98% realtime | ~71% |

*NVIDIA GeForce RTX 3060 Laptop GPU:*

| Channels | Throughput | CRC Valid Rate |
|----------|-----------|----------------|
| 48 | 100% realtime | ~75% |
| 52 | 100% realtime | ~3% |
| 56 | 100% realtime | ~1.5% |
| 60 | 100% realtime | ~82% |

With the RTX 3060, the GPU has significant headroom (AGC reports 300%+
realtime). The channelizer is no longer the bottleneck at any channel
count the USRP B210 supports.

CRC validation rates match the CPU-only path exactly, confirming the
GPU implementation produces correct output.

**GPU Compatibility:**
The implementation uses standard OpenCL 1.2 and should work with any
OpenCL-capable GPU:
- **NVIDIA**: Requires proprietary driver (includes OpenCL ICD). Tested.
- **AMD**: Should work via ROCm or AMDGPU-PRO driver. Not yet tested.
- **Intel**: Works with Intel OpenCL runtime (intel-opencl-icd). Tested.

On Linux, ensure the appropriate OpenCL ICD is installed:
```bash
# NVIDIA (installed with driver)
ls /etc/OpenCL/vendors/nvidia.icd

# AMD
sudo apt install rocm-opencl-icd    # or amdgpu-pro

# Intel
sudo apt install intel-opencl-icd
```

**Channel Count Sensitivity:**
Testing revealed that certain channel counts produce poor CRC validation
rates regardless of CPU or GPU path. This is a characteristic of the
PFBCH2 filterbank, not a bug in the GPU implementation:

| Channels | CRC Valid Rate | Notes |
|----------|---------------|-------|
| 40 | ~57% | Good |
| 44 | ~2% | Poor |
| 48 | ~71% | Good |
| 52 | ~3% | Poor |
| 56 | ~1.5% | Poor |
| 60 | ~82% | Best (slightly exceeds B210 analog BW) |

Recommended channel counts: 40, 48, or 60 (with capable GPU).

**Heavy RF Environment Test (NVIDIA RTX 3060, 60 channels):**

| Metric | Value |
|--------|-------|
| Duration | ~5 minutes |
| Channels | 60 |
| Total packets | 29,296 |
| CRC valid | 15,227 (52.0%) |
| CRC invalid | 14,069 |
| Channelizer | 60.0 Msamp/sec (100% realtime) |
| AGC headroom | ~280-315 Msamp/sec (245-270% realtime) |
| Overflows | 0 |

In a congested RF environment the CRC valid rate drops from ~82% to ~52%
due to collisions and multipath, but the channelizer maintains 100%
realtime with zero drops. The GPU has substantial headroom even under
heavy load.

**Files modified (sections 1-3):**
- **bluetooth.c**: CRC-24 algorithm, CRC validation logic, AA correlator
- **bluetooth.h**: Added `bluetooth_init()` declaration, CRC fields to `ble_packet_t`, updated `bluetooth_detect()` signature
- **main.c**: Added `bluetooth_init()` call, CRC statistics globals, pass demod signal to detector, GPU channelizer thread
- **options.c**: Added `--check-crc` command-line option
- **pcap.c**: Added CRC PCAP flags, conditional flag setting
- **opencl/fft.c**: GPU PFB+FFT kernel (new file)
- **opencl/fft.h**: GPU PFB+FFT header (new file)
- **window.c**: AVX2 runtime dispatch, SSE2 madd optimization, scalar bug fix
- **window.h**: Added `window_dotprod_init()` declaration
- **CMakeLists.txt**: OpenCL auto-detection and build integration

**Backward compatibility:** All changes are fully backward compatible.
CRC validation is OFF by default (requires `--check-crc` flag). PCAP format
unchanged when CRC checking is disabled. No breaking changes to the CLI.

### 4. Distance Estimation from TX Power + RSSI

**Problem:**
The dashboard shows RSSI but provides no intuitive sense of how far away
a device is.

**Solution:**
Implemented distance estimation using the log-distance path loss model
for BLE at 2.4 GHz. For any device advertising TX Power Level (AD type
0x0A, defined in CSS Part A, Section 1.5), the dashboard computes:

```
measured = tx_power - 41       (estimated RSSI at 1 meter for BLE 2.4 GHz)
distance = 10 ^ ((measured - rssi_avg) / (10 * n))    (default n=2.0, free space)
```

The path loss exponent `n` defaults to 2.0 (free space) and can be adjusted
via `--path-loss-exp` on the dashboard (typical indoor: 2.5-3.5).

- Shows as a "dist" column in the device table (e.g. `~1.4m`)
- Included in CSV export (`est_dist` column) and SSE/JSON API
- Only shown when TX Power Level is advertised; blank otherwise
- Uses averaged RSSI for stability

**Limitations:** Free-space path loss (n=2.0) is optimistic indoors.
Real-world distances will be longer due to walls, reflections, and
body absorption. The estimate is useful for relative comparison
(closer vs farther) rather than precise ranging.

**Live Testing Results (USRP B210, 60 channels):**
95 out of 473 detected devices advertised TX Power Level and received
distance estimates. Nearby devices (phones, laptops on the same desk)
showed 0.2-1.5m, consistent with the test environment.

### 5. IRK-Based RPA Resolution

**Problem:**
BLE devices using Resolvable Private Addresses (RPAs) rotate their MAC
address periodically (typically every 15 minutes). Each rotation creates
a new device entry in the dashboard, fragmenting the view and inflating
device counts.

**Solution:**
Implemented the BT Core Spec `ah()` function (Vol 3, Part H, Section
2.2.2) to resolve RPAs against known Identity Resolving Keys (IRKs).
When `--irk-file` is provided, the dashboard checks each incoming RPA
against all loaded IRKs. Matching addresses are merged into a single
device entry keyed by the identity label.

The `ah()` function: `AES-128-ECB(IRK, 0x00*13 || prand)`, taking the
last 3 bytes of the ciphertext as the hash. An RPA is verified by
splitting the 6-byte address into `prand` (bytes 0-2, top 2 bits = 01)
and `hash` (bytes 3-5), then checking if `ah(IRK, prand) == hash`.

**IRK file format** (one per line):
```
my-phone:ec0234a357c8ad05341010a60a397d9b
work-laptop:aabbccddeeff00112233445566778899
```

On Linux, IRKs for paired devices are in
`/var/lib/bluetooth/<adapter>/<device>/info` under `[IdentityResolvingKey]`.

**Dashboard behavior:**
- Resolved devices show with identity label instead of MAC (e.g. `[my-phone]`)
- Highlighted green to distinguish from unresolved RPAs (yellow)
- Address rotation count displayed (e.g. `(3 addrs)`)
- All packet counts, RSSI, and timestamps merge into a single entry
- Included in CSV export (`identity`, `rpa_count` columns)

**Dependencies:** Requires the `cryptography` Python package, but only
when `--irk-file` is actually used. No new dependencies otherwise.

**Usage:**
```bash
python3 tools/zmq_web_dashboard.py tcp://localhost:5555 --irk-file irks.txt
```

### 6. Multi-Sensor Multilateration

**Problem:**
The dashboard already supports multiple ZMQ sensor endpoints, but treats
them as interchangeable packet sources. There is no way to determine
*where* a BLE device is located, even when multiple sensors with known
GPS positions observe the same device at different signal strengths.

**Solution:**
Implemented sensor identification, per-sensor RSSI tracking, and
multilateration (position estimation from distance circles).

**Sniffer side (`--sensor-id`):**
- New `--sensor-id NAME` flag sets the sensor identity string
- Defaults to hostname if not specified
- Sensor ID is prepended as the first ZMQ frame in every message
- Backward compatible: old subscribers that read the last frame still work

**Dashboard side:**
- Frame parser handles all 4 ZMQ frame formats (legacy 1-frame, legacy
  2-frame GPS, new 2-frame with sensor ID, new 3-frame with both)
- Dashboard binds SUB socket; sensors connect to it
- Per-sensor state tracking: GPS position, packet count, last seen
- Per-device-per-sensor RSSI tracking for distance estimation
- New `/api/sensors` endpoint returns sensor positions and stats

**Multilateration algorithm:**
- Per-sensor distance from RSSI: `d = 10^((tx_power - 41 - rssi) / (10*n))`
  where n is the path loss exponent (default 2.0 for free space)
- Weight: `min(packet_count, 100) / 100` (more observations = more reliable)
- 2+ sensors: Gauss-Newton iterative weighted least squares in local
  meter coordinates (lat/lon converted to meters from centroid, solve,
  convert back)
- Uncertainty: weighted RMS of distance residuals (meters)
- Only computed for devices advertising TX Power Level (AD type 0x0A)

**Map visualization (Leaflet.js):**
- Sensor markers: orange labeled pins at each sensor's GPS position
- Device markers: colored circles at estimated position
  - Green: 3+ sensors (best confidence)
  - Yellow: 2 sensors
- Dashed uncertainty circles showing estimated error radius
- Tooltips with device name/MAC, distance, and sensor count
- Stale entries removed automatically

**New dashboard CLI args:**
- `--sensor-pos LABEL:LAT,LON` (repeatable) -- static position for
  sensors without GPS
- `--path-loss-exp N` (default 2.0) -- path loss exponent for distance
  estimation. Free space = 2.0, typical indoor = 2.5-3.5

**Synthetic test results:**
- 3 sensors in equilateral triangle, device at center: 0m error
- 2 sensors, device between them: ~26m error (expected with only 2 circles)
- 1 sensor: no position estimate (requires minimum 2)

**Performance:**
- C side: one additional small `zmq_send()` per packet (sensor ID frame)
- Dashboard: per-packet dict lookup for sensor RSSI tracking
- Multilateration math runs once per second in the SSE path, only for
  devices with TX Power seen by 2+ sensors
- No measurable throughput impact

**Usage:**
```bash
# Dashboard (binds, sensors connect to it):
python3 tools/zmq_web_dashboard.py tcp://*:5555 \
    --gps --sensor-pos lobby:37.7751,-122.4190

# Sensor 1 (has GPS):
ice9-bluetooth -l -c 2441 -C 60 --zmq tcp://collector:5555 --check-crc --sensor-id roof

# Sensor 2 (no GPS, static position set on dashboard):
ice9-bluetooth -l -c 2441 -C 60 --zmq tcp://collector:5555 --check-crc --sensor-id lobby
```

## Files Modified (Multilateration)

- **options.c**: Added `--sensor-id` long option
- **main.c**: `sensor_id` global, hostname default
- **pcap.c**: Prepend sensor ID frame in ZMQ publish functions
- **tools/zmq_web_dashboard.py**: Frame parser, per-endpoint sockets,
  sensor state tracking, multilateration algorithm, map visualization,
  new CLI args (`--sensor-pos`, `--path-loss-exp`)

### 7. Classic Bluetooth (BR/EDR) Detection Pipeline

**Problem:**
The sniffer already detected Classic BT sync words and extracted 24-bit LAPs
(`btbb_find_ac()` in `btbb/btbb.c`), but only printed them in verbose mode.
No PCAP output, no ZMQ publishing, no dashboard display.

**Solution:**
Wired Classic BT through the full pipeline alongside BLE:

**C side:**
- New `classic_bt_packet_t` struct in `bluetooth.h` (LAP, AC errors, RSSI,
  noise, frequency, timestamp, 54-bit raw header)
- `btbb_find_ac_offset()` wrapper that returns the bit offset of the sync
  word (needed to extract the 54 header bits that follow the 64-bit AC)
- `pcap_write_bt()` writes DLT_BLUETOOTH_BREDR_BB (255) headers compatible
  with Wireshark's BR/EDR baseband dissector
- PCAP always uses PPI encapsulation (DLT 192) with per-packet DLT field
  to distinguish BLE (256) vs Classic BT (255) in the same file
- ZMQ messages carry a 1-byte type prefix (0x00=BLE, 0x01=BT) for protocol
  discrimination. Backward compatible with legacy subscribers.

**Dashboard side:**
- `parse_bt_packet()` parser for BREDR_BB headers
- Classic BT devices tracked alongside BLE, keyed by `bt:xx:xx:xx` (LAP)
- Protocol column with color-coded badges (blue=BLE, orange=BT)
- Protocol filter dropdown (all / BLE only / BT only)
- Summary breakdown by protocol

**UAP Estimation:**
For Classic BT devices, the dashboard reverses the HEC (Header Error Check)
LFSR to recover the 8-bit Upper Address Part (UAP):

1. Extract 54-bit FEC-encoded header from after the sync word
2. For each of 64 possible CLK1-6 whitening values:
   - De-whiten 54 bits using the BT data whitening LFSR (x^7 + x^4 + 1)
   - FEC decode via 1/3 majority voting (54 -> 18 bits)
   - Split into 10-bit header payload + 8-bit HEC
   - Reverse the HEC LFSR (g(D) = D^8 + D^7 + D^5 + D^2 + D + 1) to
     recover the candidate UAP
3. Accumulate votes across packets. The correct UAP consistently appears
   while wrong CLK1-6 values produce random candidates.
4. Converge when the top candidate exceeds expected noise floor.

The reverse HEC function matches libbtbb's `uap_from_hec()`: the BT spec
initializes the HEC LFSR with `reverse(UAP)`, so the result must be
bit-reversed after unwinding. Convergence typically occurs in 5-10 packets
for strong signals.

**Live Testing Results (USRP B210, 60 channels, 15 seconds):**

| Metric | Value |
|--------|-------|
| BLE devices | 39 |
| Classic BT devices | 5 |
| UAP converged (100%) | 3 (in 6-1142 packets) |
| UAP converging | 1 (55%, 112 packets) |
| BLE CRC valid rate | ~82% (unaffected by BT additions) |

**Files modified:**
- **bluetooth.h**: `classic_bt_packet_t` struct, `pcap_write_bt()` declaration
- **bluetooth.c**: `bluetooth_detect()` builds Classic BT packets, extracts
  raw header bits
- **btbb/btbb.h**: `btbb_find_ac_offset()` declaration
- **btbb/btbb.c**: `btbb_find_ac_offset()` wrapper
- **pcap.c**: `pcap_write_bt()`, always-PPI output, ZMQ type prefix byte
- **pcap.h**: `pcap_write_bt()` declaration
- **tools/zmq_web_dashboard.py**: `UAPEstimator` class, `parse_bt_packet()`,
  protocol UI, mixed BLE/BT PCAP writing
- **tools/zmq_subscriber.py**: Type prefix byte handling

### 8. SQLite Device Database

**Problem:**
Each dashboard session starts with no memory of previously seen devices.
There is no way to distinguish genuinely new devices from known ones, and
no persistence of device metadata across sessions.

**Solution:**
Added a `DeviceDB` class backed by SQLite (stdlib, no new dependency):

- Default path: `~/.cache/ice9-bt-sniffer/devices.db` (outside repo)
- WAL mode + `PRAGMA synchronous=NORMAL` for non-blocking writes
- Thread-safe with `threading.Lock`
- Schema: `devices` table (dev_key, protocol, first/last seen, name, mfr,
  identity, total packets, best RSSI, services) and `sessions` table
- `is_new(dev_key)` checks an in-memory set of all known keys (fast, no query)
- `upsert()` uses INSERT ON CONFLICT UPDATE, commits every 100 changes
- Session tracking: records start/end time for each dashboard run

**Integration:**
- Enabled by default (opt-out via `--no-db`)
- Custom path via `--db FILE`
- "NEW" badge on devices not seen in any previous session
- `first_ever` timestamp in API response and CSV export
- Shutdown: updates session end time, commits, closes

**Database growth:** One row per unique device (not per packet). Typical
environments produce a few hundred to a few thousand unique devices over
months of use, resulting in a database well under 1 MB.

### 9. Device Alerting

**Problem:**
No way to be notified when a specific device appears or when a never-before-seen
device enters the monitored area.

**Solution:**
Added an `AlertManager` class with three alert sources and four alert actions:

**Alert sources:**
- `--alert-file FILE`: watch list with one MAC, LAP (`bt:xx:xx:xx`), or
  identity label (`[my-phone]`) per line
- `--alert-new`: triggers for any device not in the SQLite database
  (requires DB to be enabled)
- Browser watch: click "watch" button in UI to add to in-session watch list

**Alert actions:**
- `--alert-cmd CMD`: shell command with environment variables
  (`ALERT_MAC`, `ALERT_NAME`, `ALERT_MFR`, `ALERT_RSSI`, `ALERT_PROTOCOL`,
  `ALERT_REASON`, `ALERT_IDENTITY`)
- `--alert-webhook URL`: HTTP POST with JSON body
- Browser notification via SSE push

**Rate limiting:** `--alert-cooldown N` (default 300 seconds) per device
prevents alert storms.

**RPA handling:** When IRKs are loaded, resolved devices use their identity
label as the device key, so RPA rotations do not trigger repeat alerts.
Without IRKs, each new random MAC is treated as a new device.

## References

- Bluetooth Core Specification Volume 6, Part B, Section 3.1.1 (CRC)
- Bluetooth Core Specification Volume 2, Part B, Section 7.1.1 (HEC generation)
- Bluetooth Core Specification Volume 2, Part B, Section 7.2 (Data whitening)
- Bluetooth Core Specification Volume 3, Part H, Section 2.2.2 (RPA resolution, `ah()` function)
- Bluetooth Core Specification Supplement, Part A, Section 1.5 (TX Power Level AD type)
- Log-distance path loss model (free space, n=2.0) for 2.4 GHz BLE
- PCAP DLT_BLUETOOTH_LE_LL_WITH_PHDR (256) format specification
- PCAP DLT_BLUETOOTH_BREDR_BB (255) format specification
- PCAP PPI (DLT 192) Per-Packet Information header format
