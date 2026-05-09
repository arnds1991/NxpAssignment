# ethsniff — Architecture

## Runtime pipeline

```mermaid
flowchart LR
    NIC["Network Interface"]
    pcap["pcap_loop()\ncapture thread"]
    raw["Raw ring\nRAW_RING_SIZE slots\nmutex + condvar"]
    fmt["Format thread\nCPU-only"]
    str["String ring\nSTR_RING_SIZE slots\nmutex + condvar"]
    io["IO thread\nI/O-only"]
    out["stdout"]

    NIC -->|raw frame| pcap
    pcap -->|memcpy + signal| raw
    raw -->|dequeue| fmt
    fmt -->|dissect + format + push| str
    str -->|dequeue| io
    io -->|fwrite / fflush| out
```

Three threads run concurrently:

| Thread | Responsibility | Calls fwrite? |
|---|---|---|
| Capture (`pcap_loop`) | Copies raw frames into the raw ring via `pcap_callback` | No |
| Format | Dequeues raw frames, dissects and formats them, pushes strings into the string ring; tracks peak fps, peak throughput and peak dissect+format latency | No |
| IO | Dequeues formatted strings and writes them to stdout; flushes when the string ring is momentarily empty | **Yes — only thread** |

**Why two output stages?**
A single thread that both formats and writes to stdout can drop frames when
stdout blocks (slow terminal, pipe backpressure): the raw ring fills with
nobody draining it.  By splitting the work:

- The **format thread** is purely CPU-bound.  It never blocks on I/O, so it
  always drains the raw ring promptly.
- The **IO thread** owns stdout exclusively.  If stdout stalls, only the IO
  thread stalls; the format thread and capture thread are unaffected.

**Flush policy** (IO thread): flush when the string ring is momentarily empty.
One condition, no percentage thresholds.

**Session summary:** when `ENABLE_SESSION_STATS` is defined (default on), the
format thread accumulates peak fps, peak throughput, and peak dissect+format
latency in per-second windows as it runs.  After Ctrl+C, once all threads
have joined, `main()` prints a single summary block to stderr.  Comment out
`#define ENABLE_SESSION_STATS` in `main.c` to build with zero stats overhead.

**Kernel pcap buffer:** `pcap_create` / `pcap_set_buffer_size` / `pcap_activate`
are used instead of `pcap_open_live` so the kernel TPACKET ring can be sized
explicitly.  `PCAP_BUFFER_SIZE` (default 16 MB) is defined in `main.c`.

---

## Dissector call tree

```
dissect_frame()
├── dissect_l3()
│   ├── dissect_ipv4()
│   │   └── dissect_l4()
│   │       ├── dissect_tcp()
│   │       ├── dissect_udp()
│   │       ├── dissect_icmp()
│   │       └── dissect_icmpv6()
│   │           └── dissect_ndp_options()
│   ├── dissect_ipv6()
│   │   └── dissect_l4()          (same as above)
│   └── dissect_arp()
├── dissect_doip()                 (called after L3/L4; port 13400 check)
└── dissect_someip_sd()            (called after L3/L4; port 30490 check)
```

`dissect_doip` and `dissect_someip_sd` are called by `dissect_frame` **after**
`dissect_l3` returns, not from inside the L4 dissectors.  They need the port
numbers that `dissect_tcp` / `dissect_udp` already wrote into `parsed_frame_t`,
so they can only run once L4 parsing is complete.  

---

## Source files

| File | Responsibility |
|---|---|
| `src/main.c` | CLI, pcap setup, thread creation, signal handler, session summary |
| `src/ring.h` | Types and API for both ring buffers (`raw_ring_t`, `str_ring_t`) |
| `src/ring.c` | All ring buffer operations: init, push, pop, occupancy, peak tracking |
| `src/dissect.c` | All protocol dissectors + `format_frame()` |
| `src/dissect.h` | Public types (`parsed_frame_t`, enums) and declarations |
| `CMakeLists.txt` | Build targets: `ethsniff`, `send_frames`;  |

---

## Key data structures

Both rings are defined in `ring.h` and implemented in `ring.c`.

```
raw_ring_t                           (stage 1: capture → format)
├── raw_slot_t[RAW_RING_SIZE] slots  (circular buffer of raw frame slots)
│   ├── uint8_t[MAX_FRAME_BYTES] data (raw frame bytes; MAX_FRAME_BYTES = max
│   │                                standard Ethernet incl. QinQ, FCS stripped by NIC)
│   ├── uint32_t       caplen        (bytes actually captured)
│   ├── uint32_t       wirelen       (bytes on the wire)
│   ├── long           ts_sec        (pcap timestamp – seconds)
│   ├── long           ts_usec       (pcap timestamp – microseconds)
│   └── uint32_t       frame_no      (monotonically increasing index)
├── uint32_t           head          (consumer read pointer  – format thread)
├── uint32_t           tail          (producer write pointer – capture thread)
├── uint32_t           dropped       (frames lost because the ring was full)
├── uint32_t           peak          (all-time max occupancy in slots)
├── pthread_mutex_t    mutex
└── pthread_cond_t     not_empty

str_ring_t                           (stage 2: format → IO)
├── str_slot_t[STR_RING_SIZE] slots  (circular buffer of pre-formatted strings)
│   ├── char[STR_SLOT_MAX_LEN] text  (null-terminated formatted frame string)
│   └── int            len           (strlen(text), cached for fwrite)
├── uint32_t           head          (consumer read pointer  – IO thread)
├── uint32_t           tail          (producer write pointer – format thread)
├── uint32_t           dropped       (strings lost because the ring was full)
├── uint32_t           peak          (all-time max occupancy in slots)
├── pthread_mutex_t    mutex
└── pthread_cond_t     not_empty

/* the following globals exist only when ENABLE_SESSION_STATS is defined */
g_total_frames   uint64_t           (total frames formatted by format thread)
g_total_bytes    uint64_t           (total wire bytes of those frames)
g_peak_fps       uint64_t           (max frames in any one-second window)
g_peak_bps       uint64_t           (max bytes  in any one-second window)
g_fmt_max_ns     uint64_t           (worst-case dissect+format time, ns)

parsed_frame_t
├── eth_info_t          eth          (L2: MACs, EtherType, VLAN tags)
├── l3_type_t           l3_type      (L3_NONE / L3_IPV4 / L3_IPV6 / L3_ARP)
├── union { ipv4_info_t / ipv6_info_t / arp_info_t }   l3
├── l4_type_t           l4_type      (L4_NONE / L4_TCP / L4_UDP / L4_ICMP / L4_ICMPv6)
├── union { tcp_info_t / udp_info_t / icmp_info_t / icmpv6_info_t }   l4
├── const uint8_t      *payload      (pointer into ring buffer slot)
├── doip_info_t         doip         (valid when has_doip != 0)
├── someip_sd_info_t    someip_sd    (valid when has_someip_sd != 0)
└── dissect_err_t       dissect_err  (DISSECT_ERR_NONE = no error)
```

---

## Protocol stack coverage

```
┌──────────────────────────────────────────────────────────────┐
│  Application    DoIP (ISO 13400-2)    SOME/IP-SD (AUTOSAR)   │
├──────────────────────────────────────────────────────────────┤
│  L4             TCP     UDP     ICMP     ICMPv6              │
│                                         └─ NDP RS/RA/NS/NA   │
├──────────────────────────────────────────────────────────────┤
│  L3             IPv4    IPv6    ARP                           │
├──────────────────────────────────────────────────────────────┤
│  L2             Ethernet II                                   │
│                 802.1Q VLAN  ·  QinQ (802.1ad / 0x9100)      │
└──────────────────────────────────────────────────────────────┘
```

**Frame size limit:** `MAX_FRAME_BYTES` — the largest standard Ethernet
frame without jumbo frame support:

| Frame type | Size (FCS stripped by NIC) |
|---|---|
| Untagged | 1514 bytes |
| 802.1Q single tag | 1518 bytes |
| QinQ double tag | **`MAX_FRAME_BYTES`** |

Frames larger than `MAX_FRAME_BYTES` bytes are clamped on capture. The pcap snaplen is
set to `MAX_FRAME_BYTES` so the kernel never captures more than the ring
slot can hold.

---

## Error handling strategy

| Failure | Behaviour |
|---|---|
| L2 truncated (< 14 bytes) | `dissect_frame` returns immediately; nothing printed |
| L3 malformed | `l3_type` reset to `L3_NONE`; `dissect_err` set; frame still formatted |
| L4 truncated | `l4_type` stays `L4_NONE`; `dissect_err` set; valid L3 fields still printed |
| Raw ring full | Frame dropped; `raw_ring_t.dropped` incremented; total reported to stderr when format thread exits |
| String ring full | String dropped; `str_ring_t.dropped` incremented; total reported to stderr when IO thread exits |
