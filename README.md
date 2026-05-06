# ethsniff

Command-line Ethernet frame sniffer written in C. Captures live traffic via
libpcap and prints structured, human-readable dissection of every frame.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed design overview.

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

---

## Usage

```bash
# Capture on eth0 (requires root or CAP_NET_RAW)
sudo ./build/ethsniff -i eth0

# Grant capability once to avoid running as root
sudo setcap cap_net_raw,cap_net_admin=eip ./build/ethsniff
./build/ethsniff -i eth0
```

---

## Functional testing

Inject one frame of every supported type onto a live interface:

```bash
# Terminal 1 – capture
sudo ./build/ethsniff -i eth0

# Terminal 2 – inject 20 test frames
sudo ./build/send_frames eth0
```

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
| L2 | Ethernet II, 802.1Q VLAN, QinQ (802.1ad), LLDP, PTP |
| L3 | IPv4, IPv6, ARP |
| L4 | TCP, UDP, ICMP, ICMPv6 (+ NDP: RS/RA/NS/NA) |
| App | DoIP (ISO 13400-2), SOME/IP-SD (AUTOSAR) |

---

## Known limitations

- IPv6 extension headers not walked (only fixed 40-byte header parsed)
- TCP options not decoded (MSS, SACK, timestamps)
- Fragmented IP: inner L4 header absent in non-first fragments
- Maximum 2 VLAN tags; MPLS/GRE/tunnels not dissected
- Fixed 512-slot ring buffer — sustained bursts may drop frames
- Live capture only; no `.pcap` file output

---

## Dependencies

- [libpcap](https://www.tcpdump.org/)
- POSIX pthreads
