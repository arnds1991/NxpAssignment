/**
 * dissect.h – Protocol dissector declarations for ethsniff.
 *
 * Architecture:
 *   capture thread  →  ring buffer  →  print thread
 *   pcap callback enqueues a copy of each packet into a fixed-size ring
 *   buffer (mutex-protected).  A dedicated format thread dequeues and
 *   dissects packets so pcap never blocks on I/O.
 */

#ifndef DISSECT_H
#define DISSECT_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  error "Windows is not supported. Build on Linux or macOS."
#endif
#include <netinet/in.h>

/* ------------------------------------------------------------------ */
/*  Ethernet                                                            */
/* ------------------------------------------------------------------ */
#define ETH_ALEN  6
#define ETH_HDR_LEN 14

#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_ARP    0x0806
#define ETHERTYPE_VLAN   0x8100  /* 802.1Q                            */
#define ETHERTYPE_QINQ1  0x88A8  /* 802.1ad outer                     */
#define ETHERTYPE_QINQ2  0x9100  /* older QinQ                        */
#define ETHERTYPE_IPV6   0x86DD
#define ETHERTYPE_LLDP   0x88CC
#define ETHERTYPE_PTP    0x88F7

/* ------------------------------------------------------------------ */
/*  IP protocols                                                        */
/* ------------------------------------------------------------------ */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ICMPv6 58

/* ------------------------------------------------------------------ */
/*  Application-layer well-known ports                                  */
/* ------------------------------------------------------------------ */
#define DOIP_PORT  13400  /* DoIP – UDP & TCP (ISO 13400-2)           */
#define DOIP_HDR_LEN  8   /* fixed header: version(1)+inv(1)+type(2)+len(4) */

#define SOMEIP_SD_PORT   30490  /* SOME/IP-SD – UDP (AUTOSAR)          */
#define SOMEIP_HDR_LEN   16    /* SOME/IP fixed header length          */
#define SOMEIP_SD_ENTRY_LEN 16 /* each SD entry is 16 bytes            */
#define SOMEIP_SD_MAX_ENTRIES 8

/* SOME/IP-SD entry types */
#define SOMEIP_SD_FIND_SERVICE     0x00
#define SOMEIP_SD_OFFER_SERVICE    0x01  /* TTL=0 means Stop Offer     */
#define SOMEIP_SD_SUBSCRIBE_EG     0x06  /* Subscribe Eventgroup       */
#define SOMEIP_SD_SUBSCRIBE_EG_ACK 0x07  /* Subscribe Eventgroup ACK   */

/* DoIP payload types (ISO 13400-2 Table 17) */
#define DOIP_TYPE_VEHICLE_ID_REQ          0x0001
#define DOIP_TYPE_VEHICLE_ID_REQ_EID      0x0002
#define DOIP_TYPE_VEHICLE_ID_REQ_VIN      0x0003
#define DOIP_TYPE_VEHICLE_ANNOUNCE        0x0004
#define DOIP_TYPE_ROUTING_ACTIVATION_REQ  0x0005
#define DOIP_TYPE_ROUTING_ACTIVATION_RESP 0x0006
#define DOIP_TYPE_ALIVE_CHECK_REQ         0x0007
#define DOIP_TYPE_ALIVE_CHECK_RESP        0x0008
#define DOIP_TYPE_ENTITY_STATUS_REQ       0x8001
#define DOIP_TYPE_ENTITY_STATUS_RESP      0x8002
#define DOIP_TYPE_DIAG_MSG                0x4001
#define DOIP_TYPE_DIAG_MSG_POS_ACK        0x4002
#define DOIP_TYPE_DIAG_MSG_NEG_ACK        0x4003

/* ------------------------------------------------------------------ */
/*  ICMPv6 Neighbor Discovery types                                    */
/* ------------------------------------------------------------------ */
#define ICMPV6_RS   133  /* Router Solicitation    */
#define ICMPV6_RA   134  /* Router Advertisement   */
#define ICMPV6_NS   135  /* Neighbor Solicitation  */
#define ICMPV6_NA   136  /* Neighbor Advertisement */

/* ------------------------------------------------------------------ */
/*  Generic return codes                                               */
/* ------------------------------------------------------------------ */

typedef enum rc_e {
    RC_OK  =  0,   /* success                                         */
    RC_ERR = -1    /* failure (packet too short, malformed, etc.)      */
} rc_t;

/* ------------------------------------------------------------------ */
/*  Parsed frame                                                        */
/* ------------------------------------------------------------------ */

typedef struct eth_info_s {
    uint8_t  src[ETH_ALEN];
    uint8_t  dst[ETH_ALEN];
    uint16_t ethertype;       /* outermost after stripping VLAN tags  */
    int      vlan_count;      /* 0, 1, or 2                           */
    uint16_t outer_vlan_id;   /* 12-bit VID                           */
    uint8_t  outer_pcp;       /* 3-bit PCP                            */
    uint16_t inner_vlan_id;
    uint8_t  inner_pcp;
} eth_info_t;

typedef struct ipv4_info_s {
    uint8_t  version;         /* always 4                             */
    uint8_t  ihl;             /* header length in 32-bit words        */
    uint8_t  dscp;
    uint8_t  ecn;
    uint16_t total_len;
    uint8_t  ttl;
    uint8_t  proto;
    char     src[INET_ADDRSTRLEN];
    char     dst[INET_ADDRSTRLEN];
} ipv4_info_t;

typedef struct ipv6_info_s {
    uint8_t  version;
    uint8_t  traffic_class;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    char     src[INET6_ADDRSTRLEN];
    char     dst[INET6_ADDRSTRLEN];
} ipv6_info_t;

typedef struct arp_info_s {
    uint16_t htype;           /* hardware type                        */
    uint16_t ptype;           /* protocol type                        */
    uint16_t opcode;          /* request=1, reply=2                   */
    uint8_t  sha[ETH_ALEN];   /* sender hw addr                       */
    char     spa[INET_ADDRSTRLEN];
    uint8_t  tha[ETH_ALEN];   /* target hw addr                       */
    char     tpa[INET_ADDRSTRLEN];
} arp_info_t;

typedef struct tcp_info_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;           /* SYN, ACK, FIN, RST, PSH, URG        */
    uint16_t window;
} tcp_info_t;

typedef struct udp_info_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
} udp_info_t;

typedef struct icmp_info_s {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;            /* echo id+seq or unused                */
} icmp_info_t;

typedef struct icmpv6_info_s {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;
    /* Neighbor Discovery fields – valid when has_nd != 0 */
    int      has_nd;
    char     target[INET6_ADDRSTRLEN]; /* NS / NA: target address     */
    uint8_t  na_flags;                 /* NA: R=0x80  S=0x40  O=0x20  */
    uint8_t  ra_hop_limit;             /* RA: current hop limit        */
    uint8_t  ra_flags;                 /* RA: M=0x80  O=0x40           */
    uint16_t ra_lifetime;              /* RA: router lifetime (s)      */
    uint32_t ra_reachable;             /* RA: reachable time (ms)      */
    uint32_t ra_retrans;               /* RA: retransmit timer (ms)    */
    int      has_neighbor_mac;              /* NDP link-layer addr present  */
    uint8_t  neighbor_mac[ETH_ALEN];        /* SLLA (RS/NS) or TLLA (NA)    */
} icmpv6_info_t;

typedef struct doip_info_s {
    uint8_t  proto_version;
    uint16_t payload_type;
    uint32_t payload_length;
} doip_info_t;

typedef struct someip_sd_entry_s {
    uint8_t  type;           /* SOMEIP_SD_FIND_SERVICE etc.           */
    uint16_t service_id;
    uint16_t instance_id;
    uint8_t  major_version;
    uint32_t ttl;            /* 3-byte; 0 = Stop Offer               */
    uint32_t minor_version;  /* valid for Find/Offer (type 0x00/0x01) */
    uint16_t eventgroup_id;  /* valid for Subscribe (type 0x06/0x07)  */
} someip_sd_entry_t;

typedef struct someip_sd_info_s {
    uint8_t           flags;         /* reboot(b7) + unicast(b6) bits */
    uint32_t          entry_count;
    someip_sd_entry_t entries[SOMEIP_SD_MAX_ENTRIES];
} someip_sd_info_t;

typedef enum l3_type_e {
    L3_NONE,
    L3_IPV4,
    L3_IPV6,
    L3_ARP
} l3_type_t;

typedef enum l4_type_e {
    L4_NONE,
    L4_TCP,
    L4_UDP,
    L4_ICMP,
    L4_ICMPv6
} l4_type_t;

typedef enum dissect_err_e {
    DISSECT_ERR_NONE = 0,     /* no error                          */
    DISSECT_ERR_TRUNC_TCP,    /* TCP segment shorter than 20 bytes */
    DISSECT_ERR_TRUNC_UDP,    /* UDP datagram shorter than 8 bytes */
    DISSECT_ERR_TRUNC_ICMP,   /* ICMP message shorter than 8 bytes */
    DISSECT_ERR_TRUNC_ICMPv6, /* ICMPv6 message shorter than 8 bytes */
    DISSECT_ERR_BAD_IPV4,     /* IPv4 header malformed/truncated   */
    DISSECT_ERR_BAD_IPV6,     /* IPv6 header shorter than 40 bytes */
    DISSECT_ERR_BAD_ARP       /* ARP message shorter than 28 bytes */
} dissect_err_t;

typedef struct parsed_frame_s {
    /* timing */
    long     ts_sec;
    long     ts_usec;

    /* capture stats */
    uint32_t wire_len;
    uint32_t cap_len;
    uint32_t frame_no;

    eth_info_t eth;

    l3_type_t  l3_type;
    union {
        ipv4_info_t ipv4;
        ipv6_info_t ipv6;
        arp_info_t  arp;
    } l3;

    l4_type_t  l4_type;
    union {
        tcp_info_t    tcp;
        udp_info_t    udp;
        icmp_info_t   icmp;
        icmpv6_info_t icmpv6;
    } l4;

    /* application payload (points into the original raw frame buffer) */
    const uint8_t *payload;
    uint32_t       payload_len;

    /* DoIP application layer (set when has_doip != 0) */
    int         has_doip;
    doip_info_t doip;

    /* SOME/IP-SD (set when has_someip_sd != 0; payload holds the raw SD bytes) */
    int              has_someip_sd;
    someip_sd_info_t someip_sd;

    /* dissection error (DISSECT_ERR_NONE when frame parsed cleanly) */
    dissect_err_t dissect_err;
} parsed_frame_t;

/* ------------------------------------------------------------------ */
/*  Dissect entry point                                                 */
/* ------------------------------------------------------------------ */

/**
 * Dissect a raw Ethernet frame.
 *
 * @param data     raw packet bytes
 * @param caplen   number of captured bytes
 * @param wirelen  original wire length
 * @param ts_sec   pcap timestamp seconds
 * @param ts_usec  pcap timestamp microseconds
 * @param frame_no monotonically increasing frame counter
 * @param out      caller-allocated output struct
 */
void dissect_frame(const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                   long ts_sec, long ts_usec,
                   uint32_t frame_no, parsed_frame_t *out);

/**
 * Format a parsed_frame_t as a human-readable multi-line string
 * into buf (null-terminated).
 *
 * @param f    parsed frame
 * @param buf  output buffer
 * @param sz   buffer size in bytes
 */
void format_frame(const parsed_frame_t *f, char *buf, size_t sz);

#endif /* DISSECT_H */
