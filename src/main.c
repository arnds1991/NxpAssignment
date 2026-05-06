/**
 * main.c – ethsniff: Ethernet packet sniffer
 *
 * Architecture:
 *   ┌──────────────────┐        ┌──────────────────────┐        ┌──────────────┐
 *   │  capture thread  │──────▶ │      ring buffer     │──────▶ │ print thread │
 *   │  (pcap_loop)     │  copy  │  (RING_SIZE slots)   │  deq   │              │
 *   └──────────────────┘        └──────────────────────┘        └──────────────┘
 *
 *   The pcap callback copies each raw frame into the next free ring slot and
 *   marks it READY.  A dedicated printing thread dequeues READY slots,
 *   dissects and formats each packet, then writes to stdout.
 *   This decouples I/O latency from capture so no kernel buffer overruns
 *   due to slow printing.
 *
 *   Synchronisation: pthread mutex + condition variables.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <pcap.h>
#include "dissect.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define RING_SIZE        512
#define MAX_FRAME_BYTES  65535
#define DEFAULT_SNAPLEN  65535
#define DEFAULT_TIMEOUT  1000
#define FORMAT_BUF_SIZE  2048

/* ------------------------------------------------------------------ */
/*  Ring buffer                                                         */
/* ------------------------------------------------------------------ */

typedef struct ring_slot_s {
    int      ready;
    uint8_t  data[MAX_FRAME_BYTES];
    uint32_t caplen;
    uint32_t wirelen;
    long     ts_sec;
    long     ts_usec;
    uint32_t frame_no;
} ring_slot_t;

typedef struct ring_buf_s {
    ring_slot_t  slots[RING_SIZE];
    uint32_t     tail;   /* write pointer – producer appends here  */
    uint32_t     head;   /* read  pointer – consumer removes here */
    uint32_t     dropped;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
} ring_buf_t;

/* ------------------------------------------------------------------ */
/*  Global state                                                        */
/* ------------------------------------------------------------------ */

static ring_buf_t   g_ring;
static volatile int g_stop     = 0;
static pcap_t      *g_handle   = NULL;
static uint32_t     g_frame_no = 0;

/* ------------------------------------------------------------------ */
/*  Ring buffer helpers                                                 */
/* ------------------------------------------------------------------ */

static void ring_init(ring_buf_t *r)
{
    memset(r, 0, sizeof(*r));
    pthread_mutex_init(&r->mutex,     NULL);
    pthread_cond_init (&r->not_empty, NULL);
}

static uint32_t ring_next(uint32_t i) { return (i + 1) % RING_SIZE; }

static rc_t ring_push(ring_buf_t *r,
                      const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                      long ts_sec, long ts_usec, uint32_t frame_no)
{
    uint32_t next;
    ring_slot_t *s;

    pthread_mutex_lock(&r->mutex);

    next = ring_next(r->tail);
    if (next == r->head) {
        r->dropped++;
        pthread_mutex_unlock(&r->mutex);
        return RC_ERR;
    }

    s = &r->slots[r->tail];
    {
        uint32_t n = caplen < MAX_FRAME_BYTES ? caplen : MAX_FRAME_BYTES;
        memcpy(s->data, data, n);
        s->caplen   = n;
    }
    s->wirelen  = wirelen;
    s->ts_sec   = ts_sec;
    s->ts_usec  = ts_usec;
    s->frame_no = frame_no;
    s->ready    = 1;
    r->tail     = next;

    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

static rc_t ring_pop(ring_buf_t *r, ring_slot_t *out)
{
    pthread_mutex_lock(&r->mutex);
    while (r->head == r->tail && !g_stop) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 10000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&r->not_empty, &r->mutex, &ts);
    }
    if (r->head == r->tail) { pthread_mutex_unlock(&r->mutex); return RC_ERR; }

    *out = r->slots[r->head];
    r->slots[r->head].ready = 0;
    r->head = ring_next(r->head);

    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

/* ------------------------------------------------------------------ */
/*  pcap callback – runs on capture thread                             */
/* ------------------------------------------------------------------ */

static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *hdr,
                          const u_char *packet)
{
    ring_buf_t *r = (ring_buf_t *)user;
    g_frame_no++;
    ring_push(r,
              (const uint8_t *)packet,
              (uint32_t)hdr->caplen,
              (uint32_t)hdr->len,
              (long)hdr->ts.tv_sec,
              (long)hdr->ts.tv_usec,
              g_frame_no);
}

/* ------------------------------------------------------------------ */
/*  Print thread                                                        */
/* ------------------------------------------------------------------ */

static void *print_thread_func(void *arg)
{
    ring_buf_t    *r = (ring_buf_t *)arg;
    ring_slot_t    slot;
    parsed_frame_t frame;
    char           buf[FORMAT_BUF_SIZE];

    while (!g_stop || r->head != r->tail) {
        if (ring_pop(r, &slot) != 0) continue;
        dissect_frame(slot.data, slot.caplen, slot.wirelen,
                      slot.ts_sec, slot.ts_usec,
                      slot.frame_no, &frame);
        format_frame(&frame, buf, sizeof(buf));
        fputs(buf, stdout);
        fflush(stdout);
    }

    if (r->dropped > 0)
        fprintf(stdout, "WARNING: %u frame(s) dropped (ring buffer full).\n",
                r->dropped);

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Signal handler                                                      */
/* ------------------------------------------------------------------ */

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

/* ------------------------------------------------------------------ */
/*  Interface listing                                                   */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  CLI argument parsing                                                */
/* ------------------------------------------------------------------ */

static void print_usage(const char *p)
{
    fprintf(stderr,
        "ethsniff – Ethernet frame sniffer\n\n"
        "Usage:\n"
        "  %s -i <iface> [options]\n\n"
        "Options:\n"
        "  -i, --interface <name>   Interface to capture on\n"
        "  -h, --help               Show this help\n\n"
        "Example:\n"
        "  %s -i eth0\n",
        p, p);
}

static const char *parse_args(int argc, char **argv)
{
    const char *interface = NULL;
    int i;

    for (i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) && i+1 < argc)
            interface = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]); exit(0);
        } else {
            fprintf(stderr, "Unknown option: %s\n\n", argv[i]);
            print_usage(argv[0]); exit(1);
        }
    }
    return interface;
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *interface;
    char        errbuf[PCAP_ERRBUF_SIZE] = {0};
    int         ret;
    pthread_t   pt;

    if (argc < 2) { print_usage(argv[0]); return 1; }

    interface = parse_args(argc, argv);

    if (!interface) {
        fputs("Error: no interface specified. Use -i <iface>.\n", stderr);
        return 1;
    }

    g_handle = pcap_open_live(interface, DEFAULT_SNAPLEN,
                              1, DEFAULT_TIMEOUT, errbuf);
    if (!g_handle) {
        fprintf(stderr, "pcap_open_live('%s'): %s\n", interface, errbuf);
        return 1;
    }

    if (pcap_datalink(g_handle) != DLT_EN10MB)
        fprintf(stderr, "Warning: link type is not Ethernet (DLT=%d).\n",
                pcap_datalink(g_handle));

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    ring_init(&g_ring);

    printf("ethsniff – capturing on '%s'\n", interface);
    printf("Press Ctrl+C to stop.\n\n");

    if (pthread_create(&pt, NULL, print_thread_func, &g_ring) != 0) {
        fputs("pthread_create failed\n", stderr); pcap_close(g_handle); return 1;
    }

    ret = pcap_loop(g_handle, -1, pcap_callback, (u_char *)&g_ring);
    if (ret == -1) {
        const char *e = pcap_geterr(g_handle);
        if (e && *e) fprintf(stderr, "pcap_loop: %s\n", e);
    }

    g_stop = 1;
    pthread_cond_signal(&g_ring.not_empty);

    pthread_join(pt, NULL);

    {
        struct pcap_stat ps;
        if (pcap_stats(g_handle, &ps) == 0)
            printf("\nCapture stats: received=%u  dropped(kernel)=%u  dropped(iface)=%u\n",
                   ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    }

    pcap_close(g_handle);
    return 0;
}
