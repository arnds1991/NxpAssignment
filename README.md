# ethsniff

Command-line Ethernet frame sniffer written in C. Captures live traffic via
libpcap and prints structured, human-readable dissection of every frame.

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| C compiler | C11 | `gcc` or `clang` |
| CMake | ≥ 3.16 | build system |
| libpcap | any recent | capture library (`libpcap-dev` on Debian/Ubuntu) |

---

## Build

**Linux**
```bash
sudo apt-get install -y build-essential cmake libpcap-dev
cmake -S . -B build && cmake --build build -j
```

**macOS**
```bash
brew install cmake libpcap
cmake -S . -B build && cmake --build build -j
```

On macOS, `send_frames` uses BPF (`/dev/bpf*`) instead of `AF_PACKET`.
Both tools build and run on Linux and macOS.

---

## Usage

```bash
# Capture on eth0 (requires root or CAP_NET_RAW)
sudo ./build/ethsniff -i eth0

---

## Functional testing

Inject one frame of every supported type plus error demonstration frames:

```bash
# Terminal 1 – capture
sudo ./build/ethsniff -i eth0

# Terminal 2 – inject 24 test frames (20 protocol + 4 error demos)
sudo ./build/send_frames eth0
```

On macOS, `send_frames` uses BPF instead of `AF_PACKET`; run as root or
grant `/dev/bpf*` read/write permissions. The `sendmmsg` batch path used by
the performance test is Linux-only; on macOS the single-frame write path is
used instead.

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

```
============================== Frame #1 ─ 21:00:52.905015 =====================================
  Captured 54 bytes (wire: 54)
  [ETH]  src=aa:bb:cc:11:22:33  dst=ff:ff:ff:ff:ff:ff  EtherType=0x0800 (IPv4)
  [IPv4] src=10.0.0.1         dst=10.0.0.2         TTL= 64  proto=6(TCP)
         DSCP=0  ECN=0  total_len=40
  [TCP]  src_port=12345  dst_port=80     flags=[SYN]
         seq=16909060    ack=0           window=65535
===================================================================
```

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

- **Capture thread** — calls libpcap and pushes raw frames into `raw_ring` (512 slots).
- **Format thread** — pops frames, runs the protocol dissectors, formats them as text, and pushes strings into `str_ring` (18 000 slots).
- **IO thread** — drains `str_ring` with `fwrite`, flushing stdout in batches.

Both rings are fixed-size lock-based circular buffers. If a ring is full the pushing thread drops the frame and increments a counter. A session summary (frame count, peak ring occupancy, drop counts, kernel stats) is printed to stderr when ethsniff exits.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full design walkthrough.

---

## Known limitations

- IPv6 extension headers not walked (only the fixed 40-byte header is parsed)
- TCP options not decoded (MSS, SACK, timestamps)
- Fragmented IP: L4 header is absent in non-first fragments
- Maximum 2 VLAN tags; MPLS, GRE, and tunnels are not dissected
- Fixed-size ring buffers — sustained high frame rates may cause drops
- Live capture only; no `.pcap` file input or output
- Output throughput is bounded by terminal `fwrite` latency

### Error cases that `send_frames` cannot demonstrate

The following dissector error paths exist in `dissect.c` but cannot be
triggered via raw socket injection because the NIC hardware pads all
outgoing frames to the Ethernet minimum of 64 bytes, so the truncated
payload always arrives with enough bytes to pass the dissector's length
checks:

| Error | Why it cannot be injected |
|---|---|
| `DISSECT_ERR_BAD_ARP` | ARP needs < 28 bytes; NIC padding gives receiver ≥ 50 bytes (64 − 14) |
| `DISSECT_ERR_BAD_IPV6` | IPv6 needs < 40 bytes; NIC padding gives receiver ≥ 50 bytes |
| `DISSECT_ERR_TRUNC_ICMPv6` | ICMPv6 needs < 8 bytes; after IPv6(40), NIC padding leaves ≥ 10 bytes |
| L2 truncated (< 14 bytes) | NIC always pads to 64 bytes minimum |



---

## Dependencies

- [libpcap](https://www.tcpdump.org/)
- POSIX pthreads
