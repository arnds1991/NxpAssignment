/**
 * dissect.c – Protocol dissector implementation for ethsniff.
 */

#include "dissect.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

/* Maximum payload bytes shown in the hex dump per frame.
 * Edit this value to display more or fewer bytes.
 * Set to 0 to suppress the payload dump entirely.                     */
#define PAYLOAD_DUMP_BYTES  128

/* ------------------------------------------------------------------ */
/*  Portable network-to-host helpers                                    */
/* ------------------------------------------------------------------ */

/* Read a 16-bit unsigned integer from two consecutive bytes in big-endian
 * (network) byte order; avoids alignment and endianness assumptions. */
static uint16_t read_bigEndian16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Read a 32-bit unsigned integer from four consecutive bytes in big-endian
 * (network) byte order; avoids alignment and endianness assumptions. */
static uint32_t read_bigEndian32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* ------------------------------------------------------------------ */
/*  MAC helper                                                          */
/* ------------------------------------------------------------------ */

/* Format a 6-byte Ethernet MAC address as a colon-separated hex string
 * (e.g. "aa:bb:cc:dd:ee:ff") into the caller-supplied buffer buf[sz]. */
static void mac_to_str(const uint8_t *m, char *buf, size_t sz) {
    (void)snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
                   m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* Human-readable messages indexed by dissect_err_t */
static const char * const dissect_err_str[] = {
    "",                          /* DISSECT_ERR_NONE      */
    "truncated TCP segment",     /* DISSECT_ERR_TRUNC_TCP */
    "truncated UDP datagram",    /* DISSECT_ERR_TRUNC_UDP */
    "truncated ICMP message",    /* DISSECT_ERR_TRUNC_ICMP */
    "truncated ICMPv6 message",  /* DISSECT_ERR_TRUNC_ICMPv6 */
    "malformed IPv4 header",     /* DISSECT_ERR_BAD_IPV4 */
    "malformed IPv6 header",     /* DISSECT_ERR_BAD_IPV6 */
    "malformed ARP message"      /* DISSECT_ERR_BAD_ARP */
};

/* ------------------------------------------------------------------ */
/*  L4 dissectors                                                       */
/* ------------------------------------------------------------------ */

/* Parse a TCP segment header (RFC 793, min 20 bytes).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Source Port          |       Destination Port        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Sequence Number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Acknowledgment Number                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Data Offset|Rsv|C|E|U|A|P|R|S|F|            Window            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |         Urgent Pointer        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_tcp(const uint8_t *data, uint32_t len, tcp_info_t *out)
{
    if (len < 20) return RC_ERR;
    out->src_port   = read_bigEndian16(data);
    out->dst_port   = read_bigEndian16(data + 2);
    out->seq        = read_bigEndian32(data + 4);
    out->ack        = read_bigEndian32(data + 8);
    out->data_offset = (uint8_t)((data[12] >> 4) & 0xF);
    out->flags      = data[13];
    out->window     = read_bigEndian16(data + 14);
    return RC_OK;
}

/* Parse a UDP datagram header (RFC 768, fixed 8 bytes).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Source Port          |       Destination Port        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Length            |            Checksum           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_udp(const uint8_t *data, uint32_t len, udp_info_t *out)
{
    if (len < 8) return RC_ERR;
    out->src_port = read_bigEndian16(data);
    out->dst_port = read_bigEndian16(data + 2);
    out->length   = read_bigEndian16(data + 4);
    return RC_OK;
}

/* Parse an ICMPv4 message header (RFC 792, fixed 8 bytes).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Code      |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Rest of Header (type-dependent)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_icmp(const uint8_t *data, uint32_t len, icmp_info_t *out)
{
    if (len < 8) return RC_ERR;
    out->type     = data[0];
    out->code     = data[1];
    out->checksum = read_bigEndian16(data + 2);
    out->rest     = read_bigEndian32(data + 4);
    return RC_OK;
}

/* Walk the variable-length TLV option list that follows NDP fixed headers
 * (RS/RA/NS/NA).  Each option has the layout:
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |  Length (×8)  |   Value (Length×8 - 2 bytes) |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Extracts the link-layer address from SLLA (type 1) or TLLA (type 2)
 * options if present. */
static void dissect_ndp_options(const uint8_t *data, uint32_t len,
                                icmpv6_info_t *out)
{
    uint32_t off = 0;
    while (off + 2 <= len) {
        uint8_t  opt_type  = data[off];
        uint8_t  opt_len   = data[off + 1]; /* units of 8 bytes */
        uint32_t opt_bytes;

        if (opt_len == 0) break; /* malformed – avoid infinite loop */
        opt_bytes = (uint32_t)opt_len * 8u;
        if (off + opt_bytes > len) break;

        /* Type 1 = SLLA, Type 2 = TLLA – both carry a MAC at offset 2 */
        if ((opt_type == 1 || opt_type == 2) && opt_bytes >= 8) {
            memcpy(out->neighbor_mac, data + off + 2, ETH_ALEN);
            out->has_neighbor_mac = 1;
        }
        off += opt_bytes;
    }
}

/* Parse an ICMPv6 message (RFC 4443, 8 bytes minimum) and further decode
 * NDP sub-types RS/RA/NS/NA (RFC 4861), including their option lists.
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Code      |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Message Body (type-dependent, at least 4 bytes)     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_icmpv6(const uint8_t *data, uint32_t len,
                            icmpv6_info_t *out)
{
    if (len < 8) return RC_ERR;
    out->type     = data[0];
    out->code     = data[1];
    out->checksum = read_bigEndian16(data + 2);
    out->rest     = read_bigEndian32(data + 4);
    out->has_nd          = 0;
    out->has_neighbor_mac = 0;

    switch (out->type) {
        case ICMPV6_RS: /* Router Solicitation – 8-byte fixed header */
            out->has_nd = 1;
            if (len > 8)
                dissect_ndp_options(data + 8, len - 8, out);
            break;

        case ICMPV6_RA: /* Router Advertisement – 16-byte fixed header */
            if (len < 16) break;
            out->has_nd       = 1;
            out->ra_hop_limit = data[4];
            out->ra_flags     = data[5];
            out->ra_lifetime  = read_bigEndian16(data + 6);
            out->ra_reachable = read_bigEndian32(data + 8);
            out->ra_retrans   = read_bigEndian32(data + 12);
            if (len > 16)
                dissect_ndp_options(data + 16, len - 16, out);
            break;

        case ICMPV6_NS: /* Neighbor Solicitation – 24-byte fixed header */
            if (len < 24) break;
            out->has_nd = 1;
            inet_ntop(AF_INET6, data + 8, out->target, sizeof(out->target));
            if (len > 24)
                dissect_ndp_options(data + 24, len - 24, out);
            break;

        case ICMPV6_NA: /* Neighbor Advertisement – 24-byte fixed header */
            if (len < 24) break;
            out->has_nd   = 1;
            out->na_flags = data[4]; /* R=bit7  S=bit6  O=bit5 */
            inet_ntop(AF_INET6, data + 8, out->target, sizeof(out->target));
            if (len > 24)
                dissect_ndp_options(data + 24, len - 24, out);
            break;

        default:
            break;
    }
    return RC_OK;
}

/* ------------------------------------------------------------------ */
/*  L4 dispatcher                                                       */
/* ------------------------------------------------------------------ */

/* Dispatch raw L4 bytes to the appropriate dissector based on the IP
 * protocol number.  Fills out->l4_type and out->l4 on success; writes
 * a human-readable message into out->dissect_err on truncation. */
static void dissect_l4(const uint8_t *data, uint32_t len,
                       uint8_t proto, parsed_frame_t *out)
{
    switch (proto) {
        case IP_PROTO_TCP:
            if (dissect_tcp(data, len, &out->l4.tcp) == RC_OK)
                out->l4_type = L4_TCP;
            else
                out->dissect_err = DISSECT_ERR_TRUNC_TCP;
            break;
        case IP_PROTO_UDP:
            if (dissect_udp(data, len, &out->l4.udp) == RC_OK)
                out->l4_type = L4_UDP;
            else
                out->dissect_err = DISSECT_ERR_TRUNC_UDP;
            break;
        case IP_PROTO_ICMP:
            if (dissect_icmp(data, len, &out->l4.icmp) == RC_OK)
                out->l4_type = L4_ICMP;
            else
                out->dissect_err = DISSECT_ERR_TRUNC_ICMP;
            break;
        case IP_PROTO_ICMPv6:
            if (dissect_icmpv6(data, len, &out->l4.icmpv6) == RC_OK)
                out->l4_type = L4_ICMPv6;
            else
                out->dissect_err = DISSECT_ERR_TRUNC_ICMPv6;
            break;
        default:
            break;
    }
}

/* ------------------------------------------------------------------ */
/*  L3 dissectors                                                       */
/* ------------------------------------------------------------------ */

/* Parse an IPv4 packet header (RFC 791, min 20 bytes) and dispatch the
 * L4 payload to the appropriate dissector (TCP/UDP/ICMP).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |    DSCP   |ECN|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|     Fragment Offset     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |    Protocol   |        Header Checksum        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Source Address                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Destination Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_ipv4(const uint8_t *data, uint32_t len, parsed_frame_t *out)
{
    uint32_t    ihl_bytes;
    ipv4_info_t *ip4 = &out->l3.ipv4;

    if (len < 20) return RC_ERR;
    ip4->version   = (uint8_t)((data[0] >> 4) & 0xF);
    ip4->ihl       = (uint8_t)(data[0] & 0xF);
    ihl_bytes      = (uint32_t)ip4->ihl * 4u; /* IHL is in 32-bit words */
    if (ihl_bytes < 20 || ihl_bytes > len) return RC_ERR;

    ip4->dscp      = (uint8_t)((data[1] >> 2) & 0x3F);
    ip4->ecn       = (uint8_t)(data[1] & 0x3);
    ip4->total_len = read_bigEndian16(data + 2);
    ip4->ttl       = data[8];
    ip4->proto     = data[9];

    {
        struct in_addr a;
        uint32_t s = read_bigEndian32(data + 12);
        uint32_t d = read_bigEndian32(data + 16);
        a.s_addr = htonl(s);
        inet_ntop(AF_INET, &a, ip4->src, sizeof(ip4->src));
        a.s_addr = htonl(d);
        inet_ntop(AF_INET, &a, ip4->dst, sizeof(ip4->dst));
    }

    if (len > ihl_bytes)
        dissect_l4(data + ihl_bytes, len - ihl_bytes, ip4->proto, out);

    return RC_OK;
}

/* Parse an IPv6 packet header (RFC 8200, fixed 40 bytes) and dispatch the
 * L4 payload to the appropriate dissector (TCP/UDP/ICMPv6).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version| Traffic Class |             Flow Label                |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Payload Length        |  Next Header  |   Hop Limit   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Source Address (128 bits)                   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Destination Address (128 bits)                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_ipv6(const uint8_t *data, uint32_t len, parsed_frame_t *out)
{
    uint32_t    vtcfl;
    ipv6_info_t *ip6 = &out->l3.ipv6;

    if (len < 40) return RC_ERR;

    vtcfl = read_bigEndian32(data);
    ip6->version       = (uint8_t)((vtcfl >> 28) & 0xF);
    ip6->traffic_class = (uint8_t)((vtcfl >> 20) & 0xFF);
    ip6->flow_label    = vtcfl & 0x000FFFFFu;
    ip6->payload_len   = read_bigEndian16(data + 4);
    ip6->next_hdr      = data[6];
    ip6->hop_limit     = data[7];

    inet_ntop(AF_INET6, data + 8,  ip6->src, sizeof(ip6->src));
    inet_ntop(AF_INET6, data + 24, ip6->dst, sizeof(ip6->dst));

    if (len > 40)
        dissect_l4(data + 40, len - 40, ip6->next_hdr, out);

    return RC_OK;
}

/* Parse an Ethernet/IPv4 ARP message (RFC 826, fixed 28 bytes).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Hardware Type          |        Protocol Type          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  HW Addr Len  |Proto Addr Len |           Operation           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               Sender Hardware Address (6 bytes)               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  SHA (cont.)  |        Sender Protocol Address (4 bytes)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  SPA (cont.)  |        Target Hardware Address (6 bytes)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         THA (cont.)           |  Target Protocol Addr (cont.) |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static rc_t dissect_arp(const uint8_t *data, uint32_t len, arp_info_t *out)
{
    if (len < 28) return RC_ERR;
    out->htype  = read_bigEndian16(data);
    out->ptype  = read_bigEndian16(data + 2);
    out->opcode = read_bigEndian16(data + 6);
    memcpy(out->sha, data + 8,  ETH_ALEN);
    {
        struct in_addr a;
        uint32_t s = read_bigEndian32(data + 14);
        uint32_t t = read_bigEndian32(data + 24);
        a.s_addr = htonl(s);
        inet_ntop(AF_INET, &a, out->spa, sizeof(out->spa));
        a.s_addr = htonl(t);
        inet_ntop(AF_INET, &a, out->tpa, sizeof(out->tpa));
    }
    memcpy(out->tha, data + 18, ETH_ALEN);
    return RC_OK;
}

/* ------------------------------------------------------------------ */
/*  L3 dispatcher                                                       */
/* ------------------------------------------------------------------ */

/* Dispatch the L3 payload to the appropriate dissector based on EtherType.
 * Fills out->l3_type, out->l3, out->l4_type, out->l4; writes to
 * out->dissect_err on failure.  On L3 failure, l3_type is reset to
 * L3_NONE so format_frame never prints partially-parsed L3 fields. */
static void dissect_l3(uint16_t etype,
                       const uint8_t *data, uint32_t len,
                       parsed_frame_t *out)
{
    switch (etype) {
        case ETHERTYPE_IPV4:
            out->l3_type = L3_IPV4;
            if (dissect_ipv4(data, len, out) != RC_OK) {
                out->dissect_err = DISSECT_ERR_BAD_IPV4;
                out->l3_type = L3_NONE;
            }
            break;
        case ETHERTYPE_IPV6:
            out->l3_type = L3_IPV6;
            if (dissect_ipv6(data, len, out) != RC_OK) {
                out->dissect_err = DISSECT_ERR_BAD_IPV6;
                out->l3_type = L3_NONE;
            }
            break;
        case ETHERTYPE_ARP:
            out->l3_type = L3_ARP;
            if (dissect_arp(data, len, &out->l3.arp) != RC_OK) {
                out->dissect_err = DISSECT_ERR_BAD_ARP;
                out->l3_type = L3_NONE;
            }
            break;
        default:
            out->l3_type = L3_NONE;
            break;
    }
}

/* ------------------------------------------------------------------ */
/*  DoIP dissector (ISO 13400-2)                                        */
/* ------------------------------------------------------------------ */

/* Parse the 8-byte DoIP generic header (ISO 13400-2).  The payload type
 * field identifies the specific message (routing activation, diagnostics…).
 *
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Protocol Version |Inv. Version |          Payload Type         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Payload Length                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void dissect_doip(const uint8_t *data, uint32_t len, doip_info_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < DOIP_HDR_LEN) return;

    out->proto_version  = data[0];
    out->payload_type   = read_bigEndian16(data + 2);
    out->payload_length = read_bigEndian32(data + 4);
}

/* ------------------------------------------------------------------ */
/*  SOME/IP-SD dissector (AUTOSAR PRS_SOMEIPSD)                        */
/*  data = raw UDP payload (= full SOME/IP frame incl. 16-byte header) */
/* ------------------------------------------------------------------ */

/* Parse the SOME/IP-SD service-discovery payload.  The 16-byte SOME/IP
 * header is skipped; the SD payload begins with flags + entries array.
 *
 *  SD payload (after 16-byte SOME/IP header):
 *   0               1               2               3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Flags      |              Reserved (3 bytes)               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Entries Array Length                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Entries Array (N × 16 bytes each)                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void dissect_someip_sd(const uint8_t *data, uint32_t len,
                               someip_sd_info_t *out)
{
    const uint8_t *sd;
    uint32_t sd_len, entries_len, count, i;

    memset(out, 0, sizeof(*out));

    /* Skip the 16-byte SOME/IP header to reach the SD payload */
    if (len < SOMEIP_HDR_LEN + 8) return; /* need flags(1)+rsvd(3)+entries_len(4) */
    sd     = data + SOMEIP_HDR_LEN;
    sd_len = len  - SOMEIP_HDR_LEN;

    out->flags   = sd[0];
    /* sd[1..3] = reserved */
    entries_len  = read_bigEndian32(sd + 4);

    /* sanity: entries array must fit inside the packet */
    if (entries_len + 8 > sd_len) return;

    count = entries_len / SOMEIP_SD_ENTRY_LEN;
    if (count > SOMEIP_SD_MAX_ENTRIES) count = SOMEIP_SD_MAX_ENTRIES;

    for (i = 0; i < count; i++) {
        const uint8_t     *e     = sd + 8 + i * SOMEIP_SD_ENTRY_LEN;
        someip_sd_entry_t *entry = &out->entries[out->entry_count];

        entry->type         = e[0];
        entry->service_id   = read_bigEndian16(e + 4);
        entry->instance_id  = read_bigEndian16(e + 6);
        entry->major_version = e[8];
        entry->ttl          = ((uint32_t)e[9] << 16) |
                              ((uint32_t)e[10] << 8) | e[11];

        if (entry->type == SOMEIP_SD_FIND_SERVICE ||
            entry->type == SOMEIP_SD_OFFER_SERVICE) {
            entry->minor_version = read_bigEndian32(e + 12);
            entry->eventgroup_id = 0;
        } else {
            entry->minor_version = 0;
            entry->eventgroup_id = read_bigEndian16(e + 14);
        }
        out->entry_count++;
    }
}

/* ------------------------------------------------------------------ */
/*  Public entry point                                                  */
/* ------------------------------------------------------------------ */

/* Top-level frame dissector.  Walks Ethernet → optional VLAN tag(s) →
 * L3 (IPv4/IPv6/ARP) → L4 (TCP/UDP/ICMP/ICMPv6) → application layer
 * (DoIP, SOME/IP-SD) and populates all fields of *out. */
void dissect_frame(const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                   long ts_sec, long ts_usec,
                   uint32_t frame_no, parsed_frame_t *out)
{
    uint32_t   offset = 0;
    uint16_t   etype;

    memset(out, 0, sizeof(*out));
    out->ts_sec   = ts_sec;
    out->ts_usec  = ts_usec;
    out->wire_len = wirelen;
    out->cap_len  = caplen;
    out->frame_no = frame_no;

    /* ---- Ethernet base header ---- */
    if (caplen < ETH_HDR_LEN) return;

    memcpy(out->eth.dst, data,     ETH_ALEN);
    memcpy(out->eth.src, data + 6, ETH_ALEN);
    etype = read_bigEndian16(data + 12);
    offset = ETH_HDR_LEN;

    /* ---- VLAN tags (802.1Q / QinQ) ---- */
    while ((etype == ETHERTYPE_VLAN ||
            etype == ETHERTYPE_QINQ1 ||
            etype == ETHERTYPE_QINQ2) &&
           offset + 4 <= caplen &&
           out->eth.vlan_count < 2)
    {
        uint16_t tci = read_bigEndian16(data + offset);
        uint8_t  pcp = (uint8_t)((tci >> 13) & 0x7);
        uint16_t vid = tci & 0x0FFF;
        etype = read_bigEndian16(data + offset + 2);
        offset += 4;

        if (out->eth.vlan_count == 0) {
            out->eth.outer_vlan_id = vid;
            out->eth.outer_pcp     = pcp;
        } else {
            out->eth.inner_vlan_id = vid;
            out->eth.inner_pcp     = pcp;
        }
        out->eth.vlan_count++;
    }

    out->eth.ethertype = etype;

    /* ---- L3 + L4 ---- */
    if (offset >= caplen) return;

    dissect_l3(etype, data + offset, caplen - offset, out);

    /* ---- Payload ---- */
    {
        uint32_t poff = offset;   /* start of L3 */

        /* skip L3 header */
        switch (out->l3_type) {
            case L3_IPV4: poff += (uint32_t)out->l3.ipv4.ihl * 4u; break;
            case L3_IPV6: poff += 40u;                              break;
            case L3_ARP:  poff += 28u;                              break;
            default:                                                break;
        }

        /* skip L4 header */
        switch (out->l4_type) {
            case L4_TCP:    poff += (uint32_t)out->l4.tcp.data_offset * 4u; break;
            case L4_UDP:    poff += 8u;                                      break;
            case L4_ICMP:   poff += 8u;                                      break;
            case L4_ICMPv6:
                switch (out->l4.icmpv6.type) {
                    case ICMPV6_RA: poff += 16u; break;
                    case ICMPV6_NS:
                    case ICMPV6_NA: poff += 24u; break;
                    default:        poff +=  8u; break;
                }
                break;
            default:                                                          break;
        }

        if (poff < caplen) {
            out->payload     = data + poff;
            out->payload_len = caplen - poff;
        }
    }

    /* ---- DoIP application layer ---- */
    if (out->payload && out->payload_len >= DOIP_HDR_LEN) {
        uint16_t sp = 0, dp = 0;
        if (out->l4_type == L4_UDP) {
            sp = out->l4.udp.src_port;
            dp = out->l4.udp.dst_port;
        } else if (out->l4_type == L4_TCP) {
            sp = out->l4.tcp.src_port;
            dp = out->l4.tcp.dst_port;
        }
        if (sp == DOIP_PORT || dp == DOIP_PORT) {
            dissect_doip(out->payload, out->payload_len, &out->doip);
            out->has_doip = 1;
        }
    }

    /* ---- SOME/IP-SD (UDP port 30490 only) ---- */
    if (out->l4_type == L4_UDP) {
        uint16_t sp = out->l4.udp.src_port;
        uint16_t dp = out->l4.udp.dst_port;
        if ((sp == SOMEIP_SD_PORT || dp == SOMEIP_SD_PORT) && out->payload) {
            dissect_someip_sd(out->payload, out->payload_len, &out->someip_sd);
            out->has_someip_sd = 1;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Formatting helpers                                                  */
/* ------------------------------------------------------------------ */

/* Return a human-readable name string for a given EtherType value. */
static const char *ethertype_name(uint16_t t)
{
    switch (t) {
        case ETHERTYPE_IPV4:  return "IPv4";
        case ETHERTYPE_IPV6:  return "IPv6";
        case ETHERTYPE_ARP:   return "ARP";
        case ETHERTYPE_VLAN:  return "VLAN(802.1Q)";
        case ETHERTYPE_QINQ1: return "QinQ(802.1ad)";
        case ETHERTYPE_QINQ2: return "QinQ(0x9100)";
        case ETHERTYPE_LLDP:  return "LLDP";
        case ETHERTYPE_PTP:   return "PTP";
        default:              return "Unknown";
    }
}

/* Return a human-readable name string for a given IP protocol number. */
static const char *proto_name(uint8_t p)
{
    switch (p) {
        case IP_PROTO_ICMP:   return "ICMP";
        case IP_PROTO_TCP:    return "TCP";
        case IP_PROTO_UDP:    return "UDP";
        case IP_PROTO_ICMPv6: return "ICMPv6";
        default:              return "Other";
    }
}

/* Build a '|'-separated string of the active TCP control flags
 * (e.g. "SYN|ACK") into buf[sz].  Returns buf. */
static const char *tcp_flags_str(uint8_t f, char *buf, size_t sz)
{
    buf[0] = '\0';
    if (f & 0x02) {  strncat(buf, "SYN|", sz - strlen(buf) - 1); }
    if (f & 0x10) {  strncat(buf, "ACK|", sz - strlen(buf) - 1); }
    if (f & 0x01) {  strncat(buf, "FIN|", sz - strlen(buf) - 1); }
    if (f & 0x04) {  strncat(buf, "RST|", sz - strlen(buf) - 1); }
    if (f & 0x08) {  strncat(buf, "PSH|", sz - strlen(buf) - 1); }
    if (f & 0x20) {  strncat(buf, "URG|", sz - strlen(buf) - 1); }
    if (buf[0] == '\0') strncat(buf, "none", sz - strlen(buf) - 1);
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '|') buf[len-1] = '\0';
    return buf;
}

/* Return a human-readable name for the given ICMPv4 type code. */
static const char *icmp_type_str(uint8_t t)
{
    switch (t) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        default: return "Other";
    }
}

/* Return a human-readable name for the given ICMPv6 type code. */
static const char *icmpv6_type_str(uint8_t t)
{
    switch (t) {
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        default:  return "Other";
    }
}

/* Render a parsed_frame_t to a human-readable multi-line text block in
 * buf[sz], covering Ethernet, VLAN, L3, L4, DoIP, SOME/IP-SD, and a
 * hex dump of up to PAYLOAD_DUMP_BYTES payload bytes. */
void format_frame(const parsed_frame_t *f, char *buf, size_t sz)
{
    char      mac_src[18], mac_dst[18];
    char      tmp[128];
    size_t    pos = 0;
    time_t    epoch_sec  = (time_t)f->ts_sec;
    struct tm local_time;
    char      time_str[32] = {0};

    localtime_r(&epoch_sec, &local_time);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &local_time);

#define APPEND(...)  do { \
    int _n = snprintf(buf + pos, sz - pos - 1, __VA_ARGS__); \
    if (_n > 0) pos += (size_t)_n; \
    if (pos >= sz - 1) { buf[sz-1] = '\0'; return; } \
} while (0)

    APPEND("============================== Frame #%u ─ %s.%06ld =====================================\n",
           f->frame_no, time_str, f->ts_usec);
    APPEND("  Captured %u bytes (wire: %u)\n", f->cap_len, f->wire_len);

    /* Ethernet */
    mac_to_str(f->eth.src, mac_src, sizeof(mac_src));
    mac_to_str(f->eth.dst, mac_dst, sizeof(mac_dst));
    APPEND("  [ETH]  src=%-17s  dst=%-17s  EtherType=0x%04x (%s)\n",
           mac_src, mac_dst,
           f->eth.ethertype, ethertype_name(f->eth.ethertype));

    /* VLAN */
    if (f->eth.vlan_count >= 1) {
        APPEND("  [VLAN] outer VID=%-4u  PCP=%u\n",
               f->eth.outer_vlan_id, f->eth.outer_pcp);
    }
    if (f->eth.vlan_count >= 2) {
        APPEND("  [VLAN] inner VID=%-4u  PCP=%u\n",
               f->eth.inner_vlan_id, f->eth.inner_pcp);
    }

    /* L3 */
    switch (f->l3_type) {
        case L3_IPV4: {
            const ipv4_info_t *ip = &f->l3.ipv4;
            APPEND("  [IPv4] src=%-15s  dst=%-15s  TTL=%3u  proto=%u(%s)\n",
                   ip->src, ip->dst, ip->ttl,
                   ip->proto, proto_name(ip->proto));
            APPEND("         DSCP=%u  ECN=%u  total_len=%u\n",
                   ip->dscp, ip->ecn, ip->total_len);
            break;
        }
        case L3_IPV6: {
            const ipv6_info_t *ip = &f->l3.ipv6;
            APPEND("  [IPv6] src=%-39s\n", ip->src);
            APPEND("         dst=%-39s\n", ip->dst);
            APPEND("         hop_limit=%u  next_hdr=%u(%s)  flow=0x%05x\n",
                   ip->hop_limit, ip->next_hdr,
                   proto_name(ip->next_hdr), ip->flow_label);
            break;
        }
        case L3_ARP: {
            const arp_info_t *a = &f->l3.arp;
            mac_to_str(a->sha, mac_src, sizeof(mac_src));
            mac_to_str(a->tha, mac_dst, sizeof(mac_dst));
            APPEND("  [ARP]  op=%u(%s)  sender=%s(%s)  target=%s(%s)\n",
                   a->opcode, a->opcode == 1 ? "request" : "reply",
                   mac_src, a->spa,
                   mac_dst, a->tpa);
            break;
        }
        default:
            break;
    }

    /* L4 */
    switch (f->l4_type) {
        case L4_TCP: {
            const tcp_info_t *t4 = &f->l4.tcp;
            const char *doip_tag = (t4->src_port == DOIP_PORT ||
                                    t4->dst_port == DOIP_PORT) ? " (DoIP)" : "";
            (void)tcp_flags_str(t4->flags, tmp, sizeof(tmp));
            APPEND("  [TCP]  src_port=%-5u  dst_port=%-5u%s  flags=[%s]\n",
                   t4->src_port, t4->dst_port, doip_tag, tmp);
            APPEND("         seq=%-10u  ack=%-10u  window=%u\n",
                   t4->seq, t4->ack, t4->window);
            break;
        }
        case L4_UDP: {
            const udp_info_t *u = &f->l4.udp;
            const char *doip_tag = (u->src_port == DOIP_PORT ||
                                    u->dst_port == DOIP_PORT) ? " (DoIP)" : "";
            APPEND("  [UDP]  src_port=%-5u  dst_port=%-5u%s  length=%u\n",
                   u->src_port, u->dst_port, doip_tag, u->length);
            break;
        }
        case L4_ICMP: {
            const icmp_info_t *ic = &f->l4.icmp;
            APPEND("  [ICMP] type=%u(%s)  code=%u  rest=0x%08x\n",
                   ic->type, icmp_type_str(ic->type), ic->code, ic->rest);
            break;
        }
        case L4_ICMPv6: {
            const icmpv6_info_t *ic = &f->l4.icmpv6;
            char neighbor_mac_str[18];
            APPEND("  [ICMPv6] type=%u(%s)  code=%u\n",
                   ic->type, icmpv6_type_str(ic->type), ic->code);
            if (ic->has_nd) {
                switch (ic->type) {
                    case ICMPV6_RS:
                        APPEND("  [RS]   Router Solicitation\n");
                        break;
                    case ICMPV6_RA:
                        APPEND("  [RA]   hop_limit=%u  M=%u  O=%u"
                               "  lifetime=%us\n",
                               ic->ra_hop_limit,
                               (ic->ra_flags >> 7) & 1u,
                               (ic->ra_flags >> 6) & 1u,
                               ic->ra_lifetime);
                        APPEND("         reachable=%ums  retrans=%ums\n",
                               ic->ra_reachable, ic->ra_retrans);
                        break;
                    case ICMPV6_NS:
                        APPEND("  [NS]   target=%s\n", ic->target);
                        break;
                    case ICMPV6_NA:
                        APPEND("  [NA]   target=%s\n", ic->target);
                        APPEND("         R=%u  S=%u  O=%u\n",
                               (ic->na_flags >> 7) & 1u,
                               (ic->na_flags >> 6) & 1u,
                               (ic->na_flags >> 5) & 1u);
                        break;
                    default:
                        break;
                }
                if (ic->has_neighbor_mac) {
                    mac_to_str(ic->neighbor_mac, neighbor_mac_str, sizeof(neighbor_mac_str));
                    APPEND("         LLA=%s\n", neighbor_mac_str);
                }
            }
            break;
        }
        default:
            break;
    }

    /* DoIP application layer */
    if (f->has_doip) {
        static const struct { uint16_t type; const char *name; } doip_names[] = {
            { DOIP_TYPE_VEHICLE_ID_REQ,          "Vehicle ID Request"           },
            { DOIP_TYPE_VEHICLE_ID_REQ_EID,      "Vehicle ID Request (EID)"     },
            { DOIP_TYPE_VEHICLE_ID_REQ_VIN,      "Vehicle ID Request (VIN)"     },
            { DOIP_TYPE_VEHICLE_ANNOUNCE,         "Vehicle Announcement"         },
            { DOIP_TYPE_ROUTING_ACTIVATION_REQ,  "Routing Activation Request"   },
            { DOIP_TYPE_ROUTING_ACTIVATION_RESP, "Routing Activation Response"  },
            { DOIP_TYPE_ALIVE_CHECK_REQ,         "Alive Check Request"          },
            { DOIP_TYPE_ALIVE_CHECK_RESP,        "Alive Check Response"         },
            { DOIP_TYPE_ENTITY_STATUS_REQ,       "Entity Status Request"        },
            { DOIP_TYPE_ENTITY_STATUS_RESP,      "Entity Status Response"       },
            { DOIP_TYPE_DIAG_MSG,                "Diagnostic Message"           },
            { DOIP_TYPE_DIAG_MSG_POS_ACK,        "Diagnostic Message Pos-ACK"   },
            { DOIP_TYPE_DIAG_MSG_NEG_ACK,        "Diagnostic Message Neg-ACK"   },
            { 0, NULL }
        };
        const doip_info_t *d = &f->doip;
        const char *type_name = "Unknown";
        int i;
        for (i = 0; doip_names[i].name; i++) {
            if (doip_names[i].type == d->payload_type) {
                type_name = doip_names[i].name;
                break;
            }
        }
        APPEND("  [DoIP] ver=0x%02x  type=0x%04x (%s)  payload_len=%u\n",
               d->proto_version, d->payload_type, type_name, d->payload_length);
    }

    /* SOME/IP-SD */
    if (f->has_someip_sd) {
        const someip_sd_info_t *sd = &f->someip_sd;
        uint32_t i;
        APPEND("  [SOME/IP-SD] Service Discovery  reboot=%u  unicast=%u"
               "  entries=%u\n",
               (sd->flags >> 7) & 1u, (sd->flags >> 6) & 1u,
               sd->entry_count);
        for (i = 0; i < sd->entry_count; i++) {
            const someip_sd_entry_t *e = &sd->entries[i];
            const char *type_str;
            switch (e->type) {
                case SOMEIP_SD_FIND_SERVICE:
                    type_str = "Find Service";     break;
                case SOMEIP_SD_OFFER_SERVICE:
                    type_str = (e->ttl == 0) ? "Stop Offer Service"
                                              : "Offer Service";
                    break;
                case SOMEIP_SD_SUBSCRIBE_EG:
                    type_str = (e->ttl == 0) ? "Stop Subscribe Eventgroup"
                                              : "Subscribe Eventgroup";
                    break;
                case SOMEIP_SD_SUBSCRIBE_EG_ACK:
                    type_str = "Subscribe Eventgroup ACK"; break;
                default:
                    type_str = "Unknown";           break;
            }
            if (e->type == SOMEIP_SD_FIND_SERVICE ||
                e->type == SOMEIP_SD_OFFER_SERVICE) {
                APPEND("    [%u] %-26s  svc=0x%04x  inst=0x%04x"
                       "  v%u.%u  TTL=%u\n",
                       i, type_str,
                       e->service_id, e->instance_id,
                       e->major_version, e->minor_version,
                       e->ttl);
            } else {
                APPEND("    [%u] %-26s  svc=0x%04x  inst=0x%04x"
                       "  eg=0x%04x  TTL=%u\n",
                       i, type_str,
                       e->service_id, e->instance_id,
                       e->eventgroup_id, e->ttl);
            }
        }
    }

    /* Payload hex dump (capped at PAYLOAD_DUMP_BYTES) */
    if (f->payload_len > 0 && PAYLOAD_DUMP_BYTES > 0) {
        uint32_t dump_len = f->payload_len > PAYLOAD_DUMP_BYTES ? PAYLOAD_DUMP_BYTES : f->payload_len;
        uint32_t i;
        if (f->payload_len > PAYLOAD_DUMP_BYTES)
            APPEND("  [PAYLOAD] %u bytes (showing first %u)\n",
                   f->payload_len, (uint32_t)PAYLOAD_DUMP_BYTES);
        else
            APPEND("  [PAYLOAD] %u bytes\n", f->payload_len);
        for (i = 0; i < dump_len; i += 16) {
            uint32_t j, row = dump_len - i > 16 ? 16 : dump_len - i;
            APPEND("  %04x  ", i);
            for (j = 0; j < row; j++) {
                if (j == 8) APPEND(" ");
                APPEND("%02x ", f->payload[i + j]);
            }
            /* pad short last row */
            for (j = row; j < 16; j++) {
                if (j == 8) APPEND(" ");
                APPEND("   ");
            }
            APPEND(" ");
            for (j = 0; j < row; j++) {
                uint8_t c = f->payload[i + j];
                APPEND("%c", (c >= 0x20 && c < 0x7f) ? (char)c : '.');
            }
            APPEND("\n");
        }
    }

    if (f->dissect_err != DISSECT_ERR_NONE)
        APPEND("  [ERROR] %s\n", dissect_err_str[f->dissect_err]);

    APPEND("===================================================================\n");

#undef APPEND
    buf[pos] = '\0';
}
