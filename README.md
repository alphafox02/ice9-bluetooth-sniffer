# ICE9 Bluetooth Sniffer

Wireshark-compatible Bluetooth sniffer supporting multiple SDR platforms.
Captures BLE and classic Bluetooth (BR) packets across multiple channels
simultaneously using a polyphase channelizer.

## Supported Hardware

| SDR | Interface Flag | Bandwidth | Notes |
|-----|---------------|-----------|-------|
| bladeRF 2.0 | `-i bladerf0` | Up to 96 MHz (all-channel) | Only device supporting `-a` mode |
| HackRF One | `-i hackrf-SERIAL` | 4-60 MHz | Default if no `-i` specified |
| USRP (B200/B210) | `-i usrp-MODEL-SERIAL` | 4-56 MHz | Example: `-i usrp-B210-FCO2P05` |
| SoapySDR | `-i soapy-N` | 4-60 MHz | Generic SDR support (if compiled with SoapySDR) |

To list available SDR devices:

    ice9-bluetooth --extcap-interfaces

## Dependencies

This tool requires libliquid, libhackrf, libbladerf, libuhd, and
libfftw3. On Debian-based systems:

    sudo apt install libliquid-dev libhackrf-dev libbladerf-dev libuhd-dev libfftw3-dev

Optional GPU acceleration (OpenCL):

    sudo apt install ocl-icd-opencl-dev

Optional SoapySDR support:

    sudo apt install libsoapysdr-dev

Optional ZeroMQ for network packet streaming:

    sudo apt install libzmq3-dev

Optional GPS tagging (requires gpsd running):

    sudo apt install libgps-dev

**Web dashboard** (`tools/zmq_web_dashboard.py`) requires `pyzmq`:

    pip install pyzmq

Optional RPA resolution (`--irk-file`) requires `cryptography`:

    pip install cryptography

On macOS, fftw3 is not required and [Homebrew](https://brew.sh/) is the
recommended package manager:

    brew install liquid-dsp hackrf libbladerf uhd

This code is untested against MacPorts. The deps can be installed with:

    port install liquid-dsp hackrf bladeRF uhd

## Building and Installing

    mkdir build
    cd build
    cmake ..
    make
    make install

The `install` target will copy the binary into `/usr/local/bin` (by
default) and will attempt to install into the system Wireshark directory
on Linux if detected. Use `ice9-bluetooth --install` to install the
binary into your local extcap dir (`$HOME/.config/wireshark/extcap`). An
`uninstall` target is also provided as a convenience.

## Usage

### Command-Line Options

```
Mandatory (pick one input source):
    -f, --file=FILE         Read input from fc32 file
    -l, --capture           Capture live from SDR

Mandatory (pick one channel mode):
    -a, --all-channels      All-channel sniffing (96 channels, requires bladeRF 2.0)
        or
    -c, --center-freq=FREQ  Center frequency in MHz (2400-2480, default: 2441)
    -C, --channels=CHAN     Number of channels (4-96, divisible by 4)

Optional:
    -w, --fifo=OUTPUT       Output pcap to file or FIFO
    -i IFACE                SDR device to use (see Supported Hardware above)
    -r, --check-crc         Enable BLE CRC-24 validation
    -s, --stats             Print performance stats periodically
    -v, --verbose           Print detailed info about captured bursts
    -I, --install           Install into Wireshark extcap folder
    -G, --gpsd              Tag packets with GPS coordinates from gpsd
    -Z, --zmq=ENDPOINT     Stream packets to collector (e.g. tcp://collector:5555)
    -K, --zmq-curve-key=FILE  Enable CURVE encryption (requires key file)
        --sensor-id=NAME      Sensor identity for multi-sensor deployments
```

### Examples

Capture 40 channels centered on 2441 MHz using a USRP B210:

    ice9-bluetooth -l -i usrp-B210-FCO2P05 -c 2441 -C 40 -w capture.pcap

Capture using HackRF with performance stats:

    ice9-bluetooth -l -c 2441 -C 20 -w capture.pcap -s

All-channel capture with bladeRF 2.0:

    ice9-bluetooth -l -i bladerf0 -a -w all_channels.pcap

Capture with CRC validation and verbose output:

    ice9-bluetooth -l -c 2441 -C 40 -w capture.pcap --check-crc -v -s

Read from a previously recorded IQ file:

    ice9-bluetooth -f recording.fc32 -c 2441 -C 20 -w output.pcap

Stream packets over ZMQ to a remote collector:

    ice9-bluetooth -l -c 2441 -C 40 --zmq tcp://collector:5555

Stream with CURVE encryption:

    python3 tools/zmq_keygen.py server.key
    ice9-bluetooth -l -c 2441 -C 40 --zmq tcp://collector:5555 --zmq-curve-key server.key

### Channel Count Guidelines

The `-C` flag controls how many 2 MHz channels the polyphase channelizer
creates. More channels = more spectrum coverage = more packets captured,
but requires more CPU. Each channel is 2 MHz wide.

| Channels | Bandwidth | BLE Coverage | Notes |
|----------|-----------|--------------|-------|
| 4 | 4 MHz | ~5% | Minimal, mostly for testing |
| 20 | 20 MHz | ~25% | Good starting point for HackRF |
| 40 | 40 MHz | ~50% | Recommended: good CRC rates (~57%) |
| 48 | 48 MHz | ~60% | Recommended: good CRC rates (~71%) |
| 56 | 56 MHz | ~70% | Near full coverage |
| 60 | 60 MHz | ~75% | Recommended: best CRC rates (~82%), needs discrete GPU |
| 80 | 80 MHz | 100% | Full BLE band (2400-2480 MHz) |
| 96 | 96 MHz | 100% | Full band with margin (bladeRF only) |

**Note:** The polyphase channelizer produces best results at certain
channel counts. Tested CRC validation rates by channel count:

| Channels | CRC Valid Rate | Notes |
|----------|---------------|-------|
| 40 | ~57% | Good |
| 44 | ~2% | Poor |
| 48 | ~71% | Good |
| 52 | ~3% | Poor |
| 56 | ~1.5% | Poor |
| 60 | ~82% | Best (slightly exceeds B210 analog BW) |

This is a characteristic of the PFBCH2 filterbank at certain sizes, not
a bug in the software. For best results, use `-C 40`, `-C 48`, or `-C 60`.

Check if your system can keep up using the `-s` flag. The channelizer
throughput should show >= 100% realtime.

### Wireshark Integration

To use in Wireshark, plug in your SDR and launch Wireshark. Scroll to the
bottom of the interfaces list in the main window and you should see "ICE9
Bluetooth: hackrf-$serial" (or similar) listed. Click the gear icon to
the left of it to configure, but the defaults should get you BLE
packets (if your system is fast enough).

### Benchmarking

You can benchmark channelizer performance by demodulating random bytes:

    ice9-bluetooth -f /dev/urandom -s -C 20

On macOS:

    ice9-bluetooth -f /dev/random -s -C 20

Start with 20 channels and observe the performance relative to real time.
Increase the channel count until throughput drops below 100%.

## Technical Details

### CRC Validation

The `--check-crc` flag enables BLE CRC-24 validation. This sets the
appropriate PCAP flags so Wireshark can display CRC status per packet.
Packets with valid CRCs are marked accordingly; packets with invalid
CRCs (typically from bit errors due to weak signals) are still captured
and written to the PCAP file.

### GPU Acceleration (OpenCL)

When built with OpenCL support (auto-detected by cmake), the polyphase
filterbank channelizer and FFT are run entirely on the GPU using
OpenCL and VkFFT. This offloads the main CPU bottleneck to the
GPU, freeing CPU cycles for burst processing.

No runtime flags are needed -- GPU acceleration is used automatically
when available. If OpenCL is not found at build time, the build falls
back to FFTW for CPU-based FFT.

Build with GPU acceleration:

    sudo apt install ocl-icd-opencl-dev
    mkdir build && cd build
    cmake ..    # OpenCL detected automatically
    make

Build without GPU acceleration:

    cmake .. -DUSE_OPENCL_FFT=OFF
    make

The GPU backend uses standard OpenCL 1.2 and works with NVIDIA
(proprietary driver), AMD (ROCm or AMDGPU-PRO), and Intel (intel-opencl-icd)
GPUs. On Linux, ensure the appropriate OpenCL ICD is installed for your GPU.

Tested on NVIDIA GeForce RTX 3060 (100% realtime at 60 channels, 300%+
AGC headroom) and Intel UHD integrated graphics (~98% realtime at 48 channels).

### ZMQ Packet Streaming

When built with libzmq, the `--zmq` flag streams each captured BLE/BT
packet over a ZMQ PUB socket to a central collector. Each message is a
raw PCAP record (packet header + RF Info header + payload). Sensors
always connect out to the collector; the collector (dashboard or
subscriber) binds and listens. A C2 control channel is automatically
established on data_port + 1 for remote sensor management.

    # Collector (dashboard) -- binds on port 5555, C2 on 5556:
    python3 tools/zmq_web_dashboard.py tcp://*:5555

    # Sensor(s) -- connect to the collector:
    ice9-bluetooth -l -c 2441 -C 40 --zmq tcp://collector:5555
    ice9-bluetooth -l -c 2441 -C 40 --zmq tcp://collector:5555 --sensor-id roof

A lightweight subscriber is also included in `tools/zmq_subscriber.py`:

    # Receive and display packets:
    python3 tools/zmq_subscriber.py tcp://*:5555

    # Write received packets to a PCAP file:
    python3 tools/zmq_subscriber.py tcp://*:5555 -w output.pcap

**CURVE Encryption:** Streams can be encrypted using CurveZMQ
(Curve25519 + ChaCha20-Poly1305). Generate a keypair and distribute:

    python3 tools/zmq_keygen.py server.key
    # server.key      -> both sniffer and collector (keep secret)
    # server.key.pub  -> not needed separately (key is in server.key)

    # Sensor:
    ice9-bluetooth -l ... --zmq tcp://collector:5555 --zmq-curve-key server.key

    # Collector:
    python3 tools/zmq_web_dashboard.py tcp://*:5555 --server-key server.key

Requires pyzmq built with libsodium for CURVE support (`pip install pyzmq`).

### Web Dashboard

A real-time web dashboard is included in `tools/zmq_web_dashboard.py`. It
subscribes to one or more ZMQ PUB endpoints and presents a Kismet-style
device list with live updating, BLE device fingerprinting, and aggregate
summaries.

**Quick start:**

    # Start the dashboard (binds on port 5555, C2 on 5556):
    pip install pyzmq   # only dependency
    python3 tools/zmq_web_dashboard.py tcp://*:5555

    # Start sensor(s) -- connect to the dashboard:
    ice9-bluetooth -l -c 2441 -C 40 --zmq tcp://dashboard:5555 --check-crc -s

    # Open http://localhost:8099 in a browser

**Features:**

- **Live device table** with MAC, manufacturer, device name, RSSI, PDU type,
  packet count, and first/last seen timestamps
- **BLE device fingerprinting**: parses advertising data (AD structures) to
  extract manufacturer (from company IDs), device names, appearance, TX power,
  and 16-bit service UUIDs (both UUID lists and Service Data)
- **CRC-gated device tracking**: when `--check-crc` is enabled on the sniffer,
  only CRC-valid packets create device entries -- eliminates phantom devices
  from corrupted packets. Backward compatible when CRC checking is off.
- **Distance estimation**: estimates range from TX power + RSSI using a
  log-distance path loss model. Shows automatically for any device advertising
  TX Power Level (AD type 0x0A).
- **RPA resolution**: `--irk-file` merges rotating BLE Resolvable Private
  Addresses into a single device entry when the Identity Resolving Key is
  known. Uses the BT Core Spec `ah()` function (AES-128-ECB). Resolved
  devices are highlighted green with a count of observed MAC rotations.
- **Classic BT support**: detects Classic Bluetooth (BR/EDR) LAP addresses
  alongside BLE. Displays both protocols with color-coded badges (blue=BLE,
  orange=BT) and protocol filter dropdown.
- **UAP estimation**: for Classic BT devices, reverses the HEC (Header Error
  Check) LFSR to recover the Upper Address Part (UAP) from accumulated
  packet headers. Converges in as few as 5-10 packets for strong signals.
- **Device database**: SQLite persistence across sessions (`--db`, `--no-db`).
  Tracks first-ever-seen timestamps and marks genuinely new devices with a
  "NEW" badge. Database stored at `~/.cache/ice9-bt-sniffer/devices.db`.
- **Device alerting**: `--alert-new` fires alerts for never-before-seen
  devices (uses the SQLite database). `--alert-file` watches for specific
  MACs/identities. Alert actions: shell command (`--alert-cmd`), HTTP
  webhook (`--alert-webhook`), and browser notifications.
- **Summary tab**: breakdowns by manufacturer, MAC address type, PDU type,
  protocol, and GATT services; top talkers list; channel activity heatmap
- **Privacy mode**: MAC addresses masked by default (toggle in UI)
- **PCAP recording**: `--write` flag to simultaneously save to a PCAP file.
  Uses PPI (DLT 192) encapsulation with per-packet DLT to support mixed
  BLE + Classic BT packets in the same file.
- **GPS mapping**: `--gps` flag enables GPS column and live map display
  (requires gpsd running, GPS coordinates embedded in PPI-wrapped PCAPs)
- **CURVE encryption**: `--server-key` flag for encrypted ZMQ connections
- **Multi-sensor multilateration**: when 2+ sensors with known GPS positions
  observe the same device, estimates device position on the map using weighted
  least squares. Sensors identified by `--sensor-id` on the sniffer side,
  positions from GPS or `--sensor-pos` on the dashboard.
- **Multi-sensor**: accepts multiple ZMQ endpoints for distributed deployments

**Dashboard options:**

```
python3 tools/zmq_web_dashboard.py [endpoints...] [options]

  -p, --port PORT           HTTP port (default: 8099)
  -w, --write FILE          Also write packets to PCAP file
  --gps                     Enable GPS column and map display
  --server-key FILE         Server key file for CURVE encryption
  --update-bt-db            Download/refresh Bluetooth numbers database
  --irk-file FILE           File of IRKs for RPA resolution (label:hex per line)
  --sensor-pos LABEL:LAT,LON  Static sensor position (repeatable)
  --path-loss-exp N         Path loss exponent (default: 2.0, indoor: 2.5-3.5)
  --db FILE                 SQLite database path (default: ~/.cache/ice9-bt-sniffer/devices.db)
  --no-db                   Disable persistent device database
  --alert-file FILE         Watch file (one MAC/LAP/identity per line)
  --alert-cmd CMD           Shell command on alert (env vars: ALERT_MAC, ALERT_NAME, etc.)
  --alert-new               Alert on never-before-seen devices (requires database)
  --alert-webhook URL       HTTP POST URL for alert notifications
  --alert-cooldown N        Seconds between re-alerts for same device (default: 300)
```

**Examples:**

    # Dashboard with GPS and PCAP recording:
    python3 tools/zmq_web_dashboard.py tcp://*:5555 --gps -w capture.pcap

    # Dashboard with encryption:
    python3 tools/zmq_web_dashboard.py tcp://*:5555 --server-key server.key

    # Update Bluetooth device database (downloads latest from Nordic Semiconductor):
    python3 tools/zmq_web_dashboard.py tcp://localhost:5555 --update-bt-db

    # RPA resolution with Identity Resolving Keys:
    python3 tools/zmq_web_dashboard.py tcp://localhost:5555 --irk-file irks.txt

    # Multi-sensor multilateration with static positions:
    python3 tools/zmq_web_dashboard.py tcp://sensor1:5555 tcp://sensor2:5555 \
        --sensor-pos roof:37.7749,-122.4194 --sensor-pos lobby:37.7751,-122.4190

    # Multi-sensor with GPS (sensors have gpsd running):
    python3 tools/zmq_web_dashboard.py tcp://sensor1:5555 tcp://sensor2:5555 --gps

    # Alert on new devices with a shell command:
    python3 tools/zmq_web_dashboard.py tcp://localhost:5555 \
        --alert-new --alert-cmd 'echo "$ALERT_MAC $ALERT_PROTOCOL" >> /tmp/alerts.log'

    # Watch for specific devices and send webhook:
    python3 tools/zmq_web_dashboard.py tcp://localhost:5555 \
        --alert-file watchlist.txt --alert-webhook http://localhost:9000/alert

    # Disable persistent database (ephemeral session):
    python3 tools/zmq_web_dashboard.py tcp://localhost:5555 --no-db

**Bluetooth Numbers Database:**

The dashboard includes hardcoded lookup tables for common BLE manufacturer
company IDs and 16-bit service UUIDs (Apple, Samsung, Google, Bose, Tile,
Fitbit, etc.). For broader coverage, use `--update-bt-db` to download the
community-maintained [Nordic Semiconductor Bluetooth numbers database](https://github.com/NordicSemiconductor/bluetooth-numbers-database)
(MIT licensed). This caches ~4000 company IDs and ~125 service UUIDs to
`~/.cache/ice9-bt-sniffer/`. Cached data is loaded automatically on
subsequent runs; hardcoded entries take priority for curated short names.

### GPS Tagging

When built with libgps (`sudo apt install libgps-dev`) and a gpsd instance
is running, the sniffer can tag each captured packet with the current GPS
position. GPS coordinates are embedded in the PCAP using the PPI (Per-Packet
Information) header format, compatible with Wireshark and Kismet.

    # Start gpsd (example with USB GPS):
    sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

    # Capture with GPS tagging:
    ice9-bluetooth -l -c 2441 -C 40 --gpsd --zmq tcp://collector:5555 --check-crc

    # Dashboard with GPS map:
    python3 tools/zmq_web_dashboard.py tcp://*:5555 --gps

The `--gps` flag on the web dashboard enables a live map tab showing device
locations. GPS fixes are polled from gpsd at 1 Hz with a local cache to
avoid redundant queries.

### Architecture

```
+----------------------------+
|  polyphase channelizer     |
|  1 x N MHz -> N x 2 MHz   |
+-------+------+-------+----+
        |      |       |
        |      |       |
  +-----v----+ | +-----v-----+
  | thread 1 | | | thread 2  |
  +----------+ | +-----------+
               |                  output:
               | +-----------+    bursts
      ...      +-> thread N  |
                 +-----------+

         burst queue
              |
  +-----------v-------------+
  |    burst processor      |
  | FM demod / BT detection |
  +-------------------------+
```

Complex IQ samples come in from file or SDR and are fed into a polyphase
channelizer. This splits the N MHz input into N channels at 2 MHz wide.
These channelized samples are fed to N threads that each process one
channel. Each thread runs a "burst catcher" that uses Liquid's AGC to
capture bursts and feeds them via a queue to the burst processor.

The burst processor takes the complex IQ bursts, FM demodulates them,
performs carrier frequency offset (CFO) correction, normalizes them,
and performs hard bit decisions. These bit buffers are fed into the
Bluetooth detectors. First we attempt to detect BR packets using
libbtbb's techniques (borrowed from Ubertooth and gr-bluetooth).
If that fails, we then try to detect BLE packets.

## Bugs

This code is naughty and occasionally needs to be killed with prejudice
(`kill -9`). This happens most often in benchmark mode.

## Author

This code was written by Mike Ryan of ICE9 Consulting LLC. For more
information visit https://ice9.us/
