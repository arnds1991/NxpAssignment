# ethsniff

Command-line Ethernet frame sniffer written in C. Captures live traffic via
libpcap and prints structured, human-readable dissection of every frame.

Developed and tested on **Linux only.** 

---

## Prerequisites

| Linux | kernel ≥ 3.0 |
| C compiler | C11 | `gcc` or `clang` |
| CMake | ≥ 3.16 | build system |
| libpcap | any recent | capture library (`libpcap-dev` on Debian/Ubuntu) |

---

## Build

```bash
sudo apt-get install -y build-essential cmake libpcap-dev
cmake -S . -B build && cmake --build build -j
```

---

## Usage

```bash
# To understand the usage
./build/ethsniff -h

# Capture on eth0 (requires root or CAP_NET_RAW)
sudo ./build/ethsniff -i eth0

```

---

## Functional testing

Inject one frame of every supported type plus error demonstration frames:

```bash
# Terminal 1 – capture
sudo ./build/ethsniff -i eth0

# Terminal 2 – inject 24 test frames (20 protocol + 4 error demos)
sudo ./build/send_frames eth0
```

### send_frames modes

**Typed-frame mode (default)** — sends one frame of every supported protocol type
(24 frames total, 10 ms inter-frame gap):

```bash
sudo ./build/send_frames eth0
```

**Performance test** — three successive bursts at 3 000 fps → 10 000 fps → max rate;
run ethsniff on the same interface first:

```bash
sudo ./build/send_frames eth0 --perf-test
```

| Option | Description |
|---|---|
| `-p, --perf-test` | 3-phase performance test |
| `-h, --help` | Show usage |

The 4 error demonstration frames deliberately trigger dissector error paths
and will appear in ethsniff output with an `[ERROR]` tag:

| Frame | Error triggered |
|---|---|
| IPv4 with IHL=1 | `DISSECT_ERR_BAD_IPV4` |
| IPv4/TCP with 4-byte TCP stub | `DISSECT_ERR_TRUNC_TCP` |
| IPv4/UDP with 4-byte UDP stub | `DISSECT_ERR_TRUNC_UDP` |
| IPv4/ICMP with 4-byte ICMP stub | `DISSECT_ERR_TRUNC_ICMP` |

---

## Example output

The full output of a `send_frames` functional test run is in
[`Example_Output.txt`](Example_Output.txt). A subset is shown below:

```
============================== Frame #1 ─ 17:23:08.221608 =====================================
  Captured 54 bytes (wire: 54)
  [ETH]  src=42:21:66:c5:e9:46  dst=ff:ff:ff:ff:ff:ff  EtherType=0x0800 (IPv4)
  [IPv4] src=10.0.0.1         dst=10.0.0.2         TTL= 64  proto=6(TCP)
         DSCP=0  ECN=0  total_len=40
  [TCP]  src_port=12345  dst_port=80     flags=[SYN]
         seq=16909060    ack=0           window=65535
===================================================================
============================== Frame #7 ─ 17:23:08.296899 =====================================
  Captured 42 bytes (wire: 42)
  [ETH]  src=42:21:66:c5:e9:46  dst=ff:ff:ff:ff:ff:ff  EtherType=0x0806 (ARP)
  [ARP]  op=1(request)  sender=aa:bb:cc:11:22:33(192.168.1.10)  target=00:00:00:00:00:00(192.168.1.20)
===================================================================
```

[`Flood_Output.txt`](Flood_Output.txt) contains the results of a basic stress
test (`send_frames --perf-test` sustained at max rate). The session summary at
the end shows some statistics.

---

## Supported protocols

| Layer | Protocols |
|---|---|
| L2 | Ethernet II, 802.1Q VLAN, QinQ (802.1ad) |
| L3 | IPv4, IPv6, ARP |
| L4 | TCP, UDP, ICMP, ICMPv6 (+ NDP: RS/RA/NS/NA) |
| App | DoIP (ISO 13400-2), SOME/IP-SD (AUTOSAR) |
| Recognized (EtherType name only, not dissected) | LLDP, PTP |

---

## Architecture overview

ethsniff uses a three-thread pipeline to decouple capture from output:

- **Capture thread** — calls libpcap and pushes raw frames into `raw_ring` (`RAW_RING_SIZE` slots).
- **Format thread** — pops frames, runs the protocol dissectors, formats them as text, and pushes strings into `str_ring` (`STR_RING_SIZE` slots).
- **IO thread** — drains `str_ring` with `fwrite`, flushing stdout in batches.

Both rings are fixed-size lock-based circular buffers. If a ring is full the pushing thread drops the frame and increments a counter. A session summary (frame count, peak ring occupancy, drop counts, kernel stats) is printed to stderr when ethsniff exits.

See [Detailed_Design.md](Detailed_Design.md) for a full design walkthrough.

---

## Known limitations

- IPv6 extension headers not parsed. (only the fixed 40-byte header is parsed)
- TCP options not decoded (MSS, SACK, timestamps)
- Maximum 2 VLAN tags;
- Fixed-size ring buffers — can be configured using macros
- Live capture only; no `.pcap` file input or output
- Output throughput is bounded by terminal `fwrite` latency.
- Redirecting the logs to a file gives better results.

---

