/**
 * send_frames.c – Inject one frame of every supported type onto an interface.
 *
 * Usage:  sudo ./build/send_frames <interface>
 * Example: sudo ./build/send_frames eth0
 *
 * Requires CAP_NET_RAW (run as root or: sudo setcap cap_net_raw+ep ./build/send_frames)
 */

#define _GNU_SOURCE   /* sendmmsg(2) – batched sends for maximum throughput */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* ------------------------------------------------------------------ */
/*  Frame builder helpers (same as in test_dissect.c)                   */
/* ------------------------------------------------------------------ */

static void put16(uint8_t *b, int off, uint16_t v)
{
    b[off]     = (uint8_t)(v >> 8);
    b[off + 1] = (uint8_t)(v);
}

static void put32(uint8_t *b, int off, uint32_t v)
{
    b[off]     = (uint8_t)(v >> 24);
    b[off + 1] = (uint8_t)(v >> 16);
    b[off + 2] = (uint8_t)(v >>  8);
    b[off + 3] = (uint8_t)(v);
}

static void put_mac(uint8_t *b, int off,
                    uint8_t a, uint8_t b2, uint8_t c,
                    uint8_t d, uint8_t e,  uint8_t f)
{
    b[off+0]=a; b[off+1]=b2; b[off+2]=c;
    b[off+3]=d; b[off+4]=e;  b[off+5]=f;
}

static void put_ipv4(uint8_t *b, int off,
                     uint8_t a, uint8_t bv, uint8_t c, uint8_t d)
{
    b[off+0]=a; b[off+1]=bv; b[off+2]=c; b[off+3]=d;
}

static void put_ipv6(uint8_t *b, int off, const uint8_t addr[16])
{
    memcpy(b + off, addr, 16);
}

/* 14-byte Ethernet header */
static int eth_hdr(uint8_t *b, uint16_t ethertype)
{
    put_mac(b,  0, 0xff,0xff,0xff,0xff,0xff,0xff); /* dst: broadcast */
    put_mac(b,  6, 0xaa,0xbb,0xcc,0x11,0x22,0x33); /* src: fake      */
    put16(b, 12, ethertype);
    return 14;
}

/* 20-byte IPv4 header */
static int ipv4_hdr(uint8_t *b, uint8_t proto, uint8_t ttl, uint16_t total_len)
{
    b[0]  = 0x45;
    b[1]  = 0x00;
    put16(b, 2, total_len);
    put16(b, 4, 0x0001);
    put16(b, 6, 0x4000);  /* DF */
    b[8]  = ttl;
    b[9]  = proto;
    put16(b, 10, 0x0000); /* checksum (not verified by receiver in this demo) */
    put_ipv4(b, 12, 10, 0, 0, 1);
    put_ipv4(b, 16, 10, 0, 0, 2);
    return 20;
}

/* 40-byte IPv6 header */
static int ipv6_hdr(uint8_t *b, uint8_t next_hdr,
                    uint8_t hop_limit, uint16_t payload_len)
{
    static const uint8_t src6[16] = {
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01
    };
    static const uint8_t dst6[16] = {
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x02
    };
    put32(b, 0, 0x60000000u);
    put16(b, 4, payload_len);
    b[6] = next_hdr;
    b[7] = hop_limit;
    put_ipv6(b,  8, src6);
    put_ipv6(b, 24, dst6);
    return 40;
}

/* 20-byte TCP header */
static int tcp_hdr(uint8_t *b, uint16_t sp, uint16_t dp,
                   uint32_t seq, uint32_t ack_seq, uint8_t flags)
{
    put16(b, 0, sp);
    put16(b, 2, dp);
    put32(b, 4, seq);
    put32(b, 8, ack_seq);
    b[12] = 0x50;   /* data offset = 5 */
    b[13] = flags;
    put16(b, 14, 0xFFFF);
    put16(b, 16, 0x0000);
    put16(b, 18, 0x0000);
    return 20;
}

/* 8-byte UDP header */
static int udp_hdr(uint8_t *b, uint16_t sp, uint16_t dp, uint16_t length)
{
    put16(b, 0, sp);
    put16(b, 2, dp);
    put16(b, 4, length);
    put16(b, 6, 0x0000);
    return 8;
}

/* 8-byte ICMPv4 header */
static int icmp_hdr(uint8_t *b, uint8_t type, uint8_t code)
{
    b[0] = type; b[1] = code;
    put16(b, 2, 0x0000);
    put16(b, 4, 0x0001);  /* id  */
    put16(b, 6, 0x0001);  /* seq */
    return 8;
}

/* ------------------------------------------------------------------ */
/*  Raw socket sender                                                   */
/* ------------------------------------------------------------------ */

static int g_fd = -1;
static struct sockaddr_ll g_addr;

/* ------------------------------------------------------------------ */
/*  Send statistics (accumulated across all frames)                    */
/* ------------------------------------------------------------------ */

static uint64_t g_stat_frames = 0; /* frames successfully sent */
static uint64_t g_stat_bytes  = 0; /* bytes  successfully sent */
static uint64_t g_stat_errors = 0; /* send() call failures     */

static int g_perf_test = 0;        /* 1 activates 3-phase performance test */

static int open_raw_socket(const char *iface)
{
    struct ifreq ifr;

    g_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    /* Enlarge the kernel send buffer to 4 MB to avoid ENOBUFS drops
     * under sustained high-rate sends.  The kernel doubles the value
     * internally, so effective buffer = 8 MB.                        */
    {
        int sndbuf = 4 * 1024 * 1024;
        if (setsockopt(g_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
            perror("setsockopt(SO_SNDBUF) [non-fatal]");
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(g_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(g_fd);
        return -1;
    }

    memset(&g_addr, 0, sizeof(g_addr));
    g_addr.sll_family   = AF_PACKET;
    g_addr.sll_protocol = htons(ETH_P_ALL);
    g_addr.sll_ifindex  = ifr.ifr_ifindex;

    printf("Opened interface %s (ifindex=%d)\n\n", iface, ifr.ifr_ifindex);
    return 0;
}

static void send_frame(const uint8_t *buf, int len, const char *desc)
{
    ssize_t sent;
    sent = sendto(g_fd, buf, (size_t)len, 0,
                  (struct sockaddr *)&g_addr, sizeof(g_addr));
    if (sent < 0) {
        fprintf(stderr, "  [ERR] send failed for %s: %s\n",
                desc, strerror(errno));
        g_stat_errors++;
    } else {
        printf("  Sent %-40s  %d bytes\n", desc, (int)sent);
        g_stat_frames++;
        g_stat_bytes += (uint64_t)sent;
    }

    usleep(10000); /* 10 ms inter-frame gap in typed-frame mode */
}

/* ------------------------------------------------------------------ */
/*  One function per frame type                                         */
/* ------------------------------------------------------------------ */

static void send_ipv4_tcp_syn(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 6 /*TCP*/, 64, 40);
    off += tcp_hdr(f + off, 12345, 80, 0x01020304, 0, 0x02 /*SYN*/);
    send_frame(f, off, "IPv4 / TCP SYN");
}

static void send_ipv4_tcp_synack(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 6, 64, 40);
    off += tcp_hdr(f + off, 80, 12345, 0xDEADBEEF, 0x01020305,
                   0x12 /*SYN+ACK*/);
    send_frame(f, off, "IPv4 / TCP SYN+ACK");
}

static void send_ipv4_tcp_fin(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 6, 64, 40);
    off += tcp_hdr(f + off, 12345, 80, 0xABABABAB, 0xDEADBEF0,
                   0x11 /*FIN+ACK*/);
    send_frame(f, off, "IPv4 / TCP FIN+ACK");
}

static void send_ipv4_udp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 17 /*UDP*/, 128, 28);
    off += udp_hdr(f + off, 5000, 5001, 8);
    send_frame(f, off, "IPv4 / UDP");
}

static void send_ipv4_icmp_echo_req(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 1 /*ICMP*/, 64, 28);
    off += icmp_hdr(f + off, 8 /*Echo Request*/, 0);
    send_frame(f, off, "IPv4 / ICMP Echo Request");
}

static void send_ipv4_icmp_echo_reply(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 1, 64, 28);
    off += icmp_hdr(f + off, 0 /*Echo Reply*/, 0);
    send_frame(f, off, "IPv4 / ICMP Echo Reply");
}

static void send_arp_request(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0806);
    put16(f + off,  0, 0x0001);
    put16(f + off,  2, 0x0800);
    f[off + 4] = 6; f[off + 5] = 4;
    put16(f + off,  6, 0x0001); /* request */
    put_mac (f + off,  8, 0xaa,0xbb,0xcc,0x11,0x22,0x33);
    put_ipv4(f + off, 14, 192,168,1,10);
    put_mac (f + off, 18, 0,0,0,0,0,0);
    put_ipv4(f + off, 24, 192,168,1,20);
    off += 28;
    send_frame(f, off, "ARP Request");
}

static void send_arp_reply(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0806);
    put16(f + off,  0, 0x0001);
    put16(f + off,  2, 0x0800);
    f[off + 4] = 6; f[off + 5] = 4;
    put16(f + off,  6, 0x0002); /* reply */
    put_mac (f + off,  8, 0xdd,0xee,0xff,0x44,0x55,0x66);
    put_ipv4(f + off, 14, 192,168,1,20);
    put_mac (f + off, 18, 0xaa,0xbb,0xcc,0x11,0x22,0x33);
    put_ipv4(f + off, 24, 192,168,1,10);
    off += 28;
    send_frame(f, off, "ARP Reply");
}

static void send_vlan_ipv4_tcp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    put_mac(f,  0, 0xff,0xff,0xff,0xff,0xff,0xff);
    put_mac(f,  6, 0xaa,0xbb,0xcc,0x11,0x22,0x33);
    put16(f, 12, 0x8100); /* 802.1Q */
    off = 14;
    put16(f + off, 0, (uint16_t)((3u << 13) | 100u)); /* PCP=3, VID=100 */
    put16(f + off, 2, 0x0800);
    off += 4;
    off += ipv4_hdr(f + off, 6, 64, 40);
    off += tcp_hdr(f + off, 8080, 443, 1, 0, 0x02 /*SYN*/);
    send_frame(f, off, "802.1Q VLAN(100) / IPv4 / TCP");
}

static void send_qinq_ipv4_udp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    put_mac(f,  0, 0xff,0xff,0xff,0xff,0xff,0xff);
    put_mac(f,  6, 0xaa,0xbb,0xcc,0x11,0x22,0x33);
    put16(f, 12, 0x88A8); /* 802.1ad outer */
    off = 14;
    put16(f + off, 0, (uint16_t)((1u << 13) | 200u)); /* outer VID=200 */
    put16(f + off, 2, 0x8100);
    off += 4;
    put16(f + off, 0, (uint16_t)((0u << 13) | 10u));  /* inner VID=10  */
    put16(f + off, 2, 0x0800);
    off += 4;
    off += ipv4_hdr(f + off, 17, 64, 28);
    off += udp_hdr(f + off, 1000, 2000, 8);
    send_frame(f, off, "QinQ outer=200/inner=10 / IPv4 / UDP");
}

static void send_ipv6_tcp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 6 /*TCP*/, 64, 20);
    off += tcp_hdr(f + off, 443, 54321, 0xDEADBEEF, 0xCAFEBABE,
                   0x02 /*SYN*/);
    send_frame(f, off, "IPv6 / TCP SYN");
}

static void send_ipv6_udp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 17 /*UDP*/, 64, 8);
    off += udp_hdr(f + off, 9000, 9001, 8);
    send_frame(f, off, "IPv6 / UDP");
}

static void send_ipv6_icmpv6_ns(void)
{
    static const uint8_t target[16] = {
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x99
    };
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 58 /*ICMPv6*/, 255, 24);
    f[off + 0] = 135; /* NS */
    f[off + 1] = 0;
    put16(f + off, 2, 0x0000);
    put32(f + off, 4, 0x00000000);
    memcpy(f + off + 8, target, 16);
    off += 24;
    send_frame(f, off, "IPv6 / ICMPv6 Neighbor Solicitation");
}

static void send_ipv6_icmpv6_na(void)
{
    static const uint8_t target[16] = {
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x99
    };
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 58, 255, 24);
    f[off + 0] = 136;  /* NA   */
    f[off + 1] = 0;
    put16(f + off, 2, 0x0000);
    f[off + 4] = 0x60; /* S+O flags */
    memcpy(f + off + 8, target, 16);
    off += 24;
    send_frame(f, off, "IPv6 / ICMPv6 Neighbor Advertisement");
}

static void send_ipv6_icmpv6_rs(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 58, 255, 8);
    f[off + 0] = 133; /* RS */
    f[off + 1] = 0;
    put16(f + off, 2, 0x0000);
    put32(f + off, 4, 0x00000000);
    off += 8;
    send_frame(f, off, "IPv6 / ICMPv6 Router Solicitation");
}

static void send_ipv6_icmpv6_ra(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x86DD);
    off += ipv6_hdr(f + off, 58, 255, 16);
    f[off + 0] = 134;  /* RA            */
    f[off + 1] = 0;
    put16(f + off, 2, 0x0000);
    f[off + 4] = 64;   /* hop limit     */
    f[off + 5] = 0x80; /* M flag        */
    put16(f + off, 6, 1800);  /* router lifetime */
    put32(f + off, 8, 3600);  /* reachable time  */
    put32(f + off, 12, 1000); /* retrans timer   */
    off += 16;
    send_frame(f, off, "IPv6 / ICMPv6 Router Advertisement");
}

static void send_doip_udp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 17, 64, 36);
    off += udp_hdr(f + off, 13400, 13400, 16);
    /* DoIP generic header */
    f[off + 0] = 0xFD; /* protocol version        */
    f[off + 1] = 0x02; /* inverse (complement)     */
    put16(f + off, 2, 0x0001); /* Vehicle ID Request */
    put32(f + off, 4, 0);      /* payload length = 0 */
    off += 8;
    send_frame(f, off, "IPv4 / UDP / DoIP Vehicle ID Request");
}

static void send_doip_tcp(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 6, 64, 40 + 8);
    off += tcp_hdr(f + off, 13400, 13400, 0xABCD1234, 0, 0x02 /*SYN*/);
    /* DoIP routing activation request */
    f[off + 0] = 0x02;
    f[off + 1] = 0xFD;
    put16(f + off, 2, 0x0005); /* Routing Activation Request */
    put32(f + off, 4, 0);
    off += 8;
    send_frame(f, off, "IPv4 / TCP / DoIP Routing Activation Request");
}

static void send_someip_sd_offer(void)
{
    /* SOME/IP header(16) + SD flags+rsvd+entries_len(8) + 1 entry(16) = 40 */
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 17, 64, (uint16_t)(20 + 8 + 40));
    off += udp_hdr(f + off, 30490, 30490, (uint16_t)(8 + 40));

    /* SOME/IP header */
    put16(f + off,  0, 0xFFFF);
    put16(f + off,  2, 0x8100);
    put32(f + off,  4, 32); /* length = rest after first 8 bytes of SOME/IP hdr */
    put16(f + off,  8, 0x0000);
    put16(f + off, 10, 0x0000);
    f[off + 12] = 0x01; f[off + 13] = 0x01;
    f[off + 14] = 0x02; f[off + 15] = 0x00;
    off += 16;

    /* SD payload */
    f[off + 0] = 0xC0;        /* reboot + unicast flags */
    put32(f + off, 4, 16);    /* entries array length = 1 entry */
    off += 8;

    /* Offer Service entry */
    f[off + 0] = 0x01;         /* OFFER_SERVICE */
    put16(f + off, 4, 0x1234); /* service ID    */
    put16(f + off, 6, 0x0001); /* instance ID   */
    f[off + 8]  = 1;            /* major version */
    f[off + 9]  = 0x00; f[off + 10] = 0x00; f[off + 11] = 0x05; /* TTL=5 */
    put32(f + off, 12, 0x00000000); /* minor version */
    off += 16;

    send_frame(f, off, "IPv4 / UDP / SOME/IP-SD Offer Service");
}

static void send_someip_sd_find(void)
{
    uint8_t f[256] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    off += ipv4_hdr(f + off, 17, 64, (uint16_t)(20 + 8 + 40));
    off += udp_hdr(f + off, 30490, 30490, (uint16_t)(8 + 40));

    put16(f + off,  0, 0xFFFF); put16(f + off,  2, 0x8100);
    put32(f + off,  4, 32);
    put16(f + off,  8, 0x0000); put16(f + off, 10, 0x0000);
    f[off+12]=0x01; f[off+13]=0x01; f[off+14]=0x02; f[off+15]=0x00;
    off += 16;

    f[off + 0] = 0x80;
    put32(f + off, 4, 16);
    off += 8;

    f[off + 0] = 0x00;          /* FIND_SERVICE  */
    put16(f + off, 4, 0x5678);  /* service ID    */
    put16(f + off, 6, 0xFFFF);  /* any instance  */
    f[off + 8]  = 0xFF;          /* any major ver */
    f[off + 9]  = 0xFF; f[off+10]=0xFF; f[off+11]=0xFF; /* TTL=forever */
    put32(f + off, 12, 0xFFFFFFFFu);
    off += 16;

    send_frame(f, off, "IPv4 / UDP / SOME/IP-SD Find Service");
}

/* ------------------------------------------------------------------ */
/*  Error demonstration frames                                          */
/*                                                                      */
/*  These frames contain deliberate malformations to exercise the       */
/*  [ERROR] paths in dissect.c.  Each frame produces an error tag in   */
/*  ethsniff output instead of (or alongside) parsed L4 fields.        */
/*                                                                      */
/*  Technique for truncation errors: set IPv4 IHL=15 (60-byte header,  */
/*  40 bytes of padding) so only 4 bytes remain for the L4 header.     */
/*  The frame is 14+60+4 = 78 bytes – above the 64-byte NIC minimum –  */
/*  so no hardware padding occurs and the truncation reaches pcap.      */
/* ------------------------------------------------------------------ */

/* Triggers DISSECT_ERR_BAD_IPV4: IHL=1 → ihl_bytes=4 < 20 minimum.   */
static void send_error_bad_ipv4_ihl(void)
{
    uint8_t f[128] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    f[off + 0] = 0x41;   /* version=4, IHL=1 → ihl_bytes=4 < 20       */
    off += 20;
    send_frame(f, off, "ERROR: IPv4 bad IHL=1 (DISSECT_ERR_BAD_IPV4)");
}

/* Triggers DISSECT_ERR_TRUNC_TCP: only 4 bytes after the IP header    */
/* where TCP requires ≥ 20.                                             */
static void send_error_trunc_tcp(void)
{
    uint8_t f[128] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    f[off + 0] = 0x4F;              /* version=4, IHL=15 (60-byte hdr) */
    f[off + 8] = 64;                /* TTL                              */
    f[off + 9] = 6;                 /* proto=TCP                        */
    off += 60;                      /* skip oversized IP header         */
    put16(f + off, 0, 9999);        /* src port (partial TCP stub)      */
    put16(f + off, 2, 80);          /* dst port                         */
    off += 4;                       /* only 4 bytes – TCP needs ≥ 20    */
    send_frame(f, off, "ERROR: truncated TCP header (DISSECT_ERR_TRUNC_TCP)");
}

/* Triggers DISSECT_ERR_TRUNC_UDP: only 4 bytes where UDP requires 8.  */
static void send_error_trunc_udp(void)
{
    uint8_t f[128] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    f[off + 0] = 0x4F;              /* version=4, IHL=15               */
    f[off + 8] = 64;
    f[off + 9] = 17;                /* proto=UDP                        */
    off += 60;
    put16(f + off, 0, 9999);        /* src port (partial UDP stub)      */
    put16(f + off, 2, 9998);        /* dst port                         */
    off += 4;                       /* only 4 bytes – UDP needs 8       */
    send_frame(f, off, "ERROR: truncated UDP header (DISSECT_ERR_TRUNC_UDP)");
}

/* Triggers DISSECT_ERR_TRUNC_ICMP: only 4 bytes where ICMP requires 8.*/
static void send_error_trunc_icmp(void)
{
    uint8_t f[128] = {0}; int off = 0;
    off += eth_hdr(f + off, 0x0800);
    f[off + 0] = 0x4F;              /* version=4, IHL=15               */
    f[off + 8] = 64;
    f[off + 9] = 1;                 /* proto=ICMP                       */
    off += 60;
    f[off + 0] = 8;                 /* type=Echo Request                */
    f[off + 1] = 0;                 /* code=0                           */
    off += 4;                       /* only 4 bytes – ICMP needs 8      */
    send_frame(f, off, "ERROR: truncated ICMP header (DISSECT_ERR_TRUNC_ICMP)");
}

static void send_error_frames(void)
{
    send_error_bad_ipv4_ihl();
    send_error_trunc_tcp();
    send_error_trunc_udp();
    send_error_trunc_icmp();
}

/* ------------------------------------------------------------------ */
/*  One full cycle: send every supported frame type + error demos      */
/* ------------------------------------------------------------------ */

static void send_all_frames(void)
{
    /* IPv4 */
    send_ipv4_tcp_syn();
    send_ipv4_tcp_synack();
    send_ipv4_tcp_fin();
    send_ipv4_udp();
    send_ipv4_icmp_echo_req();
    send_ipv4_icmp_echo_reply();

    /* ARP */
    send_arp_request();
    send_arp_reply();

    /* VLAN / QinQ */
    send_vlan_ipv4_tcp();
    send_qinq_ipv4_udp();

    /* IPv6 */
    send_ipv6_tcp();
    send_ipv6_udp();
    send_ipv6_icmpv6_rs();
    send_ipv6_icmpv6_ra();
    send_ipv6_icmpv6_ns();
    send_ipv6_icmpv6_na();

    /* Application layer */
    send_doip_udp();
    send_doip_tcp();
    send_someip_sd_offer();
    send_someip_sd_find();

    /* Malformed frames – exercise [ERROR] paths in dissect.c */
    send_error_frames();
}

/* ------------------------------------------------------------------ */
/*  Flood mode – frame builder and high-throughput send loop           */
/* ------------------------------------------------------------------ */

/* Maximum flood frame size (jumbo Ethernet).                          */
#define FLOOD_MAX_SIZE  9000
/* Minimum: Eth(14) + IPv4(20) + UDP(8) = 42 bytes.                   */
#define FLOOD_MIN_SIZE  42

/* Number of frames batched into a single sendmmsg() syscall on Linux.
 * 64 is a good balance: large enough to amortise syscall overhead,   */
/* small enough to stay in cache.                                      */
#define MMSG_BATCH  512

/* Pre-built flood frame buffer (filled once by build_flood_frame).    */
static uint8_t g_flood_buf[FLOOD_MAX_SIZE];
static int     g_flood_buf_len = 0;

#define PERF_FRAME_SIZE  1514u   /* fixed frame size for perf/flood tests */

/*
 * build_flood_frame – construct a valid Ethernet/IPv4/UDP frame of
 * PERF_FRAME_SIZE bytes.  The UDP payload is padded with 0xAB so
 * the frame is easy to identify in a packet capture.
 */
static void build_flood_frame(void)
{
    unsigned int frame_size = PERF_FRAME_SIZE;
    uint16_t payload_len, udp_len, ip_total;
    int off = 0;

    memset(g_flood_buf, 0, frame_size);

    /* Ethernet header (14 bytes) */
    off += eth_hdr(g_flood_buf + off, 0x0800);

    /* Derive sizes so IP total length and UDP length are consistent */
    payload_len = (uint16_t)(frame_size - 14u - 20u - 8u);
    udp_len     = (uint16_t)(8u + payload_len);
    ip_total    = (uint16_t)(20u + udp_len);

    /* IPv4 header (20 bytes) */
    off += ipv4_hdr(g_flood_buf + off, 17 /*UDP*/, 64, ip_total);

    /* UDP header (8 bytes) */
    off += udp_hdr(g_flood_buf + off, 9999, 9999, udp_len);

    /* Fill the payload with a recognisable pattern */
    memset(g_flood_buf + off, 0xAB, payload_len);

    g_flood_buf_len = (int)frame_size;

    printf("Perf frame: %d bytes  (Eth/IPv4/UDP + %u-byte 0xAB payload)\n\n",
           g_flood_buf_len, payload_len);
}

/*
 * send_frames_raw – send 'count' copies of the pre-built g_flood_buf.
 *
 * delay_us == 0: Linux uses sendmmsg() batching for maximum throughput.
 * delay_us  > 0: one sendto()/write() per frame followed by usleep().
 */
static void send_frames_raw(uint64_t count, unsigned int delay_us)
{
    uint64_t remaining = count;

#ifdef __linux__
    if (delay_us == 0) {
        /* ---- Maximum-throughput path: sendmmsg batch ---- */
        struct mmsghdr msgs[MMSG_BATCH];
        struct iovec   iovs[MMSG_BATCH];
        int k;

        /* All entries point at the same pre-built frame buffer */
        for (k = 0; k < MMSG_BATCH; k++) {
            iovs[k].iov_base                = g_flood_buf;
            iovs[k].iov_len                 = (size_t)g_flood_buf_len;
            memset(&msgs[k], 0, sizeof(msgs[k]));
            msgs[k].msg_hdr.msg_name    = &g_addr;
            msgs[k].msg_hdr.msg_namelen = sizeof(g_addr);
            msgs[k].msg_hdr.msg_iov     = &iovs[k];
            msgs[k].msg_hdr.msg_iovlen  = 1;
        }

        while (remaining > 0) {
            unsigned int batch = (remaining < MMSG_BATCH)
                                 ? (unsigned int)remaining : MMSG_BATCH;
            int r = sendmmsg(g_fd, msgs, batch, 0);
            if (r < 0) {
                g_stat_errors++;
                continue; /* retry on signal interruption */
            }
            g_stat_frames += (uint64_t)r;
            g_stat_bytes  += (uint64_t)r * (uint64_t)g_flood_buf_len;
            remaining     -= (uint64_t)r;
        }
        return;
    }
#endif  /* __linux__ */

    /* ---- Rate-limited path ---- */
    /*
     * Each individual sendto() costs ~1-3 ms of kernel/hypervisor
     * overhead inside VMs.  Batch RATE_BATCH frames into one
     * sendmmsg() call and busy-wait once per batch to keep the rate
     * accurate without compounding syscall latency.
     */
    {
#define RATE_BATCH  32u
        struct mmsghdr msgs[RATE_BATCH];
        struct iovec   iovs[RATE_BATCH];
        unsigned int k;

        for (k = 0; k < RATE_BATCH; k++) {
            iovs[k].iov_base                = g_flood_buf;
            iovs[k].iov_len                 = (size_t)g_flood_buf_len;
            memset(&msgs[k], 0, sizeof(msgs[k]));
            msgs[k].msg_hdr.msg_name    = &g_addr;
            msgs[k].msg_hdr.msg_namelen = sizeof(g_addr);
            msgs[k].msg_hdr.msg_iov     = &iovs[k];
            msgs[k].msg_hdr.msg_iovlen  = 1;
        }

        while (remaining > 0) {
            unsigned int   batch = (remaining < RATE_BATCH)
                                   ? (unsigned int)remaining : RATE_BATCH;
            struct timespec _deadline, _now;
            int             r;

            /* Set deadline = now + batch * delay_us before the send */
            clock_gettime(CLOCK_MONOTONIC, &_deadline);
            {
                long ns = (long)batch * (long)delay_us * 1000L;
                _deadline.tv_nsec += ns;
                while (_deadline.tv_nsec >= 1000000000L) {
                    _deadline.tv_sec++;
                    _deadline.tv_nsec -= 1000000000L;
                }
            }

            r = sendmmsg(g_fd, msgs, batch, 0);
            if (r < 0) {
                g_stat_errors++;
                /* don't advance remaining – retry the same batch */
            } else {
                g_stat_frames += (uint64_t)r;
                g_stat_bytes  += (uint64_t)r * (uint64_t)g_flood_buf_len;
                remaining     -= (uint64_t)r;
            }

            /* Busy-wait for the remainder of this batch's time window */
            do { clock_gettime(CLOCK_MONOTONIC, &_now); }
            while (_now.tv_sec < _deadline.tv_sec ||
                   (_now.tv_sec == _deadline.tv_sec &&
                    _now.tv_nsec < _deadline.tv_nsec));
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Print timing and throughput summary after the burst                */
/* ------------------------------------------------------------------ */

static void print_send_stats(const struct timespec *t0, const struct timespec *t1)
{
    double elapsed = (double)(t1->tv_sec  - t0->tv_sec) +
                     (double)(t1->tv_nsec - t0->tv_nsec) * 1e-9;
    double fps     = (elapsed > 0.0) ? (double)g_stat_frames / elapsed : 0.0;
    double kbps    = (elapsed > 0.0) ? (double)g_stat_bytes  / elapsed / 1024.0 : 0.0;

    printf("\n========== Send Summary ==========\n");
    printf("  Frames sent:  %" PRIu64 "\n", g_stat_frames);
    printf("  Bytes sent:   %" PRIu64 "\n", g_stat_bytes);
    printf("  Errors:       %" PRIu64 "\n", g_stat_errors);
    printf("  Elapsed:      %.3f s\n",       elapsed);
    printf("  Frame rate:   %.1f frames/s\n", fps);
    printf("  Throughput:   %.2f KB/s\n",    kbps);
    printf("==================================\n");
}

/* ------------------------------------------------------------------ */
/*  Performance test – exercise the three operating zones              */
/*                                                                      */
/*  Sends three bursts of Ethernet/IPv4/UDP frames at increasing rates */
/*  to demonstrate the behaviour described in README.md#performance.   */
/*  Run ethsniff on the same interface; watch the 1-second stats line  */
/*  for ring occupancy and drop counts after each phase.               */
/* ------------------------------------------------------------------ */

/* Phase 1: safe zone  – frame rate well below the ~5 000 fps threshold */
#define PERF_PHASE1_FPS     3000u
#define PERF_PHASE1_FRAMES 15000u   /* ≈ 5 s at 3 000 fps */

/* Phase 2: stress zone – inside the 5 000–15 000 fps band */
#define PERF_PHASE2_FPS    10000u
#define PERF_PHASE2_FRAMES 50000u   /* ≈ 5 s at 10 000 fps */

/* Phase 3: flood zone  – max rate; run long enough to see steady drops */
#define PERF_PHASE3_FRAMES 300000u

static void run_perf_test(void)
{
    struct timespec ph_t0, ph_t1;

    /* Use default 1514-byte frames unless the user passed -s */
    build_flood_frame();

    printf("=== Performance test: 3 phases, %u-byte frames ===\n\n",
           PERF_FRAME_SIZE);
    printf("Ensure ethsniff is already running on this interface.\n");
    printf("Watch the 1-second stats line for ring occupancy and drop counts.\n\n");

    /* ---- Phase 1: safe zone ---- */
    printf("Phase 1: safe zone  (%u fps, %u µs gap)  –  %u frames\n",
           PERF_PHASE1_FPS, 1000000u / PERF_PHASE1_FPS, PERF_PHASE1_FRAMES);
    printf("  Expected: 0 drops; IO thread keeps up with fwrite.\n\n");
    clock_gettime(CLOCK_MONOTONIC, &ph_t0);
    send_frames_raw(PERF_PHASE1_FRAMES, 1000000u / PERF_PHASE1_FPS);
    clock_gettime(CLOCK_MONOTONIC, &ph_t1);
    print_send_stats(&ph_t0, &ph_t1);

    sleep(3);   /* pause so ethsniff stats clearly separate the phases */

    /* ---- Phase 2: stress zone ---- */
    printf("\nPhase 2: stress zone  (%u fps, %u µs gap)  –  %u frames\n",
           PERF_PHASE2_FPS, 1000000u / PERF_PHASE2_FPS, PERF_PHASE2_FRAMES);
    printf("  Expected: str_ring occupancy rises; output may be delayed.\n\n");
    clock_gettime(CLOCK_MONOTONIC, &ph_t0);
    send_frames_raw(PERF_PHASE2_FRAMES, 1000000u / PERF_PHASE2_FPS);
    clock_gettime(CLOCK_MONOTONIC, &ph_t1);
    print_send_stats(&ph_t0, &ph_t1);

    sleep(3);

    /* ---- Phase 3: flood zone ---- */
    printf("\nPhase 3: flood zone  (max rate, sendmmsg)  –  %u frames\n",
           PERF_PHASE3_FRAMES);
    printf("  Expected: str_ring saturates; ethsniff drop counter > 0\n");
    printf("  (only visible when ethsniff stdout is a terminal).\n\n");
    clock_gettime(CLOCK_MONOTONIC, &ph_t0);
    send_frames_raw(PERF_PHASE3_FRAMES, 0u);
    clock_gettime(CLOCK_MONOTONIC, &ph_t1);
    print_send_stats(&ph_t0, &ph_t1);
}

/* ------------------------------------------------------------------ */
/*  Usage                                                               */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s <interface> [--perf-test] [-h]\n\n"
        "Modes:\n"
        "  (default)      Typed-frame mode: sends one frame of every supported\n"
        "                 protocol type (24 frames total, 10 ms gap).\n"
        "  --perf-test    Performance test: three successive bursts at 3 000 fps,\n"
        "                 10 000 fps, and max rate. Run ethsniff on the same\n"
        "                 interface first.\n\n"
        "Options:\n"
        "  -h, --help     Show this help\n\n"
        "Examples:\n"
        "  sudo %s eth0\n"
        "  sudo %s eth0 --perf-test\n",
        prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char     *iface = NULL;
    struct timespec t0, t1;
    int             i;

    if (argc < 2) { print_usage(argv[0]); return EXIT_FAILURE; }

    iface = argv[1];

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--perf-test") == 0) {
            g_perf_test = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]); return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Unknown option: %s\n\n", argv[i]);
            print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (open_raw_socket(iface) != 0)
        return EXIT_FAILURE;

    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (g_perf_test) {
        /* ---- Performance test: 3 phases at increasing frame rates ---- */
        run_perf_test();
    } else {
        /* ---- Typed-frame mode: one frame of every supported protocol ---- */
        printf("Typed-frame mode: 24 frames on %s  (10 ms inter-frame gap)\n", iface);
        printf("Run ethsniff in another terminal to capture.\n\n");
        send_all_frames();
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    print_send_stats(&t0, &t1);

    close(g_fd);
    return EXIT_SUCCESS;
}
