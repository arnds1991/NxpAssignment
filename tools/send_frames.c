/**
 * send_frames.c – Inject one frame of every supported type onto an interface.
 *
 * Usage:  sudo ./build/send_frames <interface>
 * Example: sudo ./build/send_frames eth0
 *
 * Requires CAP_NET_RAW (run as root or: sudo setcap cap_net_raw+ep ./build/send_frames)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

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

static int g_sock = -1;
static struct sockaddr_ll g_addr;

static int open_raw_socket(const char *iface)
{
    struct ifreq ifr;

    g_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_sock < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(g_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(g_sock);
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
    ssize_t sent = sendto(g_sock, buf, (size_t)len, 0,
                          (struct sockaddr *)&g_addr, sizeof(g_addr));
    if (sent < 0)
        fprintf(stderr, "  [ERR] sendto failed for %s: %s\n",
                desc, strerror(errno));
    else
        printf("  Sent %-40s  %d bytes\n", desc, (int)sent);

    usleep(10000); /* 10 ms gap so ethsniff can print them in order */
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
/*  main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (open_raw_socket(argv[1]) != 0)
        return EXIT_FAILURE;

    printf("Sending frames on %s — run ethsniff in another terminal to capture.\n\n",
           argv[1]);

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

    /* VLAN */
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

    printf("\nDone. 20 frames sent.\n");
    close(g_sock);
    return EXIT_SUCCESS;
}
