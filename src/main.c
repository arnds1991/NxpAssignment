/**
 * main.c – ethsniff: Ethernet packet sniffer
 *
 * Two-stage output pipeline:
 *
 *   ┌───────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
 *   │    capture    │────▶│   raw_ring   │────▶│    format     │────▶│  str_ring    │
 *   │  (pcap_loop)  │copy │  512 slots   │deq  │    thread     │push │  512 slots   │
 *   └───────────────┘     └──────────────┘     └───────────────┘     └──────┬───────┘
 *                                                                            │
 *                                                                     ┌──────▼───────┐
 *                                                                     │   IO thread  │
 *                                                                     │  fwrite/flush│
 *                                                                     └──────┬───────┘
 *                                                                            │
 *                                                                          stdout
 *
 * Thread responsibilities:
 *
 *   Capture   – pcap_loop() calls pcap_callback() which pushes raw frame
 *               bytes into raw_ring via raw_ring_push().  Never touches I/O.
 *
 *   Format    – Pops raw frames from raw_ring, dissects bytes into protocol
 *               fields, renders a string, and pushes it into str_ring via
 *               str_ring_push().  CPU-bound only; never calls fwrite/fflush.
 *
 *   IO        – Pops formatted strings from str_ring and writes them to
 *               stdout.  The only thread that calls fwrite or fflush.
 *               Flushes when str_ring is momentarily empty – one simple rule.
 *
 *   Stats     – Samples both rings every 10 ms; prints a 1-second summary.
 *
 * Ring buffer and dissector code live in ring.c / dissect.c respectively.
 * main.c is responsible only for wiring the threads together.
 *
 * Synchronisation: pthread mutex + condition variables (see ring.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>

#include <pcap.h>
#include "dissect.h"
#include "ring.h"

/* ------------------------------------------------------------------ */
/*  Constants local to main.c                                          */
/* ------------------------------------------------------------------ */

#define DEFAULT_SNAPLEN    MAX_FRAME_BYTES   /* match ring slot size          */
#define DEFAULT_TIMEOUT    1000              /* pcap read timeout (ms)        */
#define PCAP_BUFFER_SIZE   (16 * 1024 * 1024) /* kernel pcap ring buffer: 16 MB */

/* ------------------------------------------------------------------ */
/*  Session statistics                                                  */
/*                                                                      */
/*  Define ENABLE_SESSION_STATS to compile in peak tracking and the    */
/*  summary printed to stderr after Ctrl+C.  Comment it out to build   */
/*  with zero stats overhead.                                           */
/* ------------------------------------------------------------------ */
#define ENABLE_SESSION_STATS

/* ------------------------------------------------------------------ */
/*  Global state                                                        */
/* ------------------------------------------------------------------ */

static raw_ring_t   g_raw_ring;   /* stage 1: capture  -> format          */
static str_ring_t   g_str_ring;   /* stage 2: format   -> IO              */

static volatile int g_stop        = 0; /* set to 1 on SIGINT/SIGTERM       */
static volatile int g_format_done = 0; /* set to 1 when format thread exits */

static pcap_t      *g_handle   = NULL;
static uint32_t     g_frame_no = 0;

#ifdef ENABLE_SESSION_STATS
/* Written by the format thread only; read by main() after pthread_join.
 * No mutex needed: the join provides the happens-before guarantee.    */
static uint64_t g_total_frames = 0;   /* total frames processed            */
static uint64_t g_total_bytes  = 0;   /* total wire bytes processed        */
static uint64_t g_peak_fps     = 0;   /* max frames   in any 1-second slot */
static uint64_t g_peak_bps     = 0;   /* max bytes    in any 1-second slot */
static uint64_t g_fmt_max_ns   = 0;   /* worst-case dissect+format time    */
#endif /* ENABLE_SESSION_STATS */

/* ------------------------------------------------------------------ */
/*  pcap callback – runs on the capture thread                         */
/* ------------------------------------------------------------------ */

static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *hdr,
                          const u_char *packet)
{
    raw_ring_t *r = (raw_ring_t *)user;
    g_frame_no++;
    raw_ring_push(r,
                  (const uint8_t *)packet,
                  (uint32_t)hdr->caplen,
                  (uint32_t)hdr->len,
                  (long)hdr->ts.tv_sec,
                  (long)hdr->ts.tv_usec,
                  g_frame_no);
}

/* ------------------------------------------------------------------ */
/*  Format thread                                                       */
/*                                                                      */
/*  Single responsibility: drain raw_ring, dissect each frame,         */
/*  format it to a string, push that string into str_ring.             */
/*  This thread never calls fwrite or fflush.                          */
/* ------------------------------------------------------------------ */

static void *format_thread_func(void *arg)
{
    raw_ring_t     *r = (raw_ring_t *)arg;
    raw_slot_t      slot;
    parsed_frame_t  frame;
    char            text[STR_SLOT_MAX_LEN];
    int             len;
#ifdef ENABLE_SESSION_STATS
    struct timespec _win_start;
    uint64_t        _win_frames = 0;
    uint64_t        _win_bytes  = 0;
    clock_gettime(CLOCK_MONOTONIC, &_win_start);
#endif

    while (!g_stop || raw_ring_occupancy(r) > 0) {

        if (raw_ring_pop(r, &slot, &g_stop) != RC_OK)
            continue;   /* g_stop set and ring empty – exit the loop */

#ifdef ENABLE_SESSION_STATS
        struct timespec _t0, _t1;
        clock_gettime(CLOCK_MONOTONIC, &_t0);
#endif
        dissect_frame(slot.data, slot.caplen, slot.wirelen,
                      slot.ts_sec, slot.ts_usec, slot.frame_no, &frame);
        format_frame(&frame, text, sizeof(text));
        len = (int)strlen(text);

        /* Hand the string to the IO thread via str_ring. */
        str_ring_push(&g_str_ring, text, len);
#ifdef ENABLE_SESSION_STATS
        clock_gettime(CLOCK_MONOTONIC, &_t1);
        {
            uint64_t ns = (uint64_t)(_t1.tv_sec  - _t0.tv_sec)  * 1000000000ULL +
                          (uint64_t)(_t1.tv_nsec - _t0.tv_nsec);
            if (ns > g_fmt_max_ns) g_fmt_max_ns = ns;
        }
        g_total_frames++;
        g_total_bytes += slot.wirelen;
        _win_frames++;
        _win_bytes += slot.wirelen;
        {
            double _elapsed = (_t1.tv_sec  - _win_start.tv_sec) +
                              (_t1.tv_nsec - _win_start.tv_nsec) / 1e9;
            if (_elapsed >= 1.0) {
                if (_win_frames > g_peak_fps) g_peak_fps = _win_frames;
                if (_win_bytes  > g_peak_bps) g_peak_bps = _win_bytes;
                _win_frames = 0;
                _win_bytes  = 0;
                _win_start  = _t1;
            }
        }
#endif
    }

    /*
     * Tell the IO thread no more strings will arrive.
     * The signal wakes it if it is sleeping on the condvar.
     */
    g_format_done = 1;
    pthread_cond_signal(&g_str_ring.not_empty);

    if (r->dropped > 0)
        fprintf(stderr,
                "WARNING: %u raw frame(s) dropped (raw ring was full).\n",
                r->dropped);

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  IO thread                                                           */
/*                                                                      */
/*  Single responsibility: drain str_ring and write strings to stdout. */
/*  This is the only thread that calls fwrite or fflush.               */
/*                                                                      */
/*  Flush policy: flush when str_ring is momentarily empty.            */
/*  One condition – no percentage thresholds.                          */
/* ------------------------------------------------------------------ */

static void *io_thread_func(void *arg)
{
    str_ring_t *r = (str_ring_t *)arg;
    str_slot_t  slot;

    for (;;) {
        /*
         * str_ring_pop blocks until a string is available or g_format_done
         * is set and the ring is empty (nothing more will ever arrive).
         */
        if (str_ring_pop(r, &slot, &g_format_done) != RC_OK)
            break;

        fwrite(slot.text, 1, (size_t)slot.len, stdout);

        /*
         * Flush when str_ring is momentarily empty: if there is more to
         * write we batch naturally by deferring the flush.
         */
        if (r->head == r->tail)
            fflush(stdout);
    }

    /* Final flush for anything written since the last idle point. */
    fflush(stdout);

    if (r->dropped > 0)
        fprintf(stderr,
                "WARNING: %u formatted string(s) dropped (string ring was full).\n",
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
/*  CLI argument parsing                                                */
/* ------------------------------------------------------------------ */

static void print_usage(const char *p)
{
    fprintf(stderr,
        "ethsniff - Ethernet frame sniffer\n\n"
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
    pthread_t   format_pt;
    pthread_t   io_pt;

    if (argc < 2) { print_usage(argv[0]); return 1; }

    interface = parse_args(argc, argv);
    if (!interface) {
        fputs("Error: no interface specified. Use -i <iface>.\n", stderr);
        return 1;
    }

    {
        g_handle = pcap_create(interface, errbuf);
        if (!g_handle) {
            fprintf(stderr, "pcap_create('%s'): %s\n", interface, errbuf);
            return 1;
        }
        pcap_set_snaplen(g_handle, DEFAULT_SNAPLEN);
        pcap_set_promisc(g_handle, 1);
        pcap_set_timeout(g_handle, DEFAULT_TIMEOUT);
        pcap_set_buffer_size(g_handle, PCAP_BUFFER_SIZE);
        if (pcap_activate(g_handle) != 0) {
            fprintf(stderr, "pcap_activate('%s'): %s\n", interface,
                    pcap_geterr(g_handle));
            pcap_close(g_handle);
            return 1;
        }
    }

    if (pcap_datalink(g_handle) != DLT_EN10MB)
        fprintf(stderr, "Warning: link type is not Ethernet (DLT=%d).\n",
                pcap_datalink(g_handle));

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /*
     * Switch stdout to fully-buffered mode so the C library does not
     * insert per-newline flushes.  The IO thread controls all flushing.
     */
    setvbuf(stdout, NULL, _IOFBF, STR_SLOT_MAX_LEN);

    /* Initialise both rings. */
    raw_ring_init(&g_raw_ring);
    str_ring_init(&g_str_ring);

    fprintf(stderr, "ethsniff - capturing on '%s'\n", interface);
    fprintf(stderr, "Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    /*
     * Start threads in pipeline order:
     *   1. format thread  - reads raw ring, writes string ring
     *   2. IO thread      - reads string ring, writes stdout
     */
    if (pthread_create(&format_pt, NULL, format_thread_func, &g_raw_ring) != 0) {
        fputs("pthread_create (format) failed\n", stderr);
        pcap_close(g_handle); return 1;
    }
    if (pthread_create(&io_pt, NULL, io_thread_func, &g_str_ring) != 0) {
        fputs("pthread_create (io) failed\n", stderr);
        pcap_close(g_handle); return 1;
    }

    /* Run the capture loop – blocks until SIGINT or pcap_breakloop(). */
    ret = pcap_loop(g_handle, -1, pcap_callback, (u_char *)&g_raw_ring);
    if (ret == -1) {
        const char *e = pcap_geterr(g_handle);
        if (e && *e) fprintf(stderr, "pcap_loop: %s\n", e);
    }

    /*
     * Shutdown sequence (pipeline order, back to front):
     *   1. Set g_stop and wake the format thread.
     *   2. Join format thread – it drains raw_ring, sets g_format_done,
     *      and signals str_ring.not_empty so the IO thread wakes.
     *   3. Join IO thread    – it drains str_ring and exits.
     */
    g_stop = 1;
    pthread_cond_signal(&g_raw_ring.not_empty);  /* wake format thread */

    pthread_join(format_pt, NULL);
    pthread_join(io_pt,     NULL);

#ifdef ENABLE_SESSION_STATS
    fprintf(stderr,
        "\n========== Session summary ==========\n"
        "  Frames processed:  %" PRIu64 "\n"
        "  Bytes  processed:  %" PRIu64 "  (%.2f MB)\n"
        "  Raw ring  peak:    %u / %u slots\n"
        "  Str ring  peak:    %u / %u slots\n"
        "  Peak frame rate:   %" PRIu64 " frames/s\n"
        "  Peak throughput:   %.2f MB/s  (%.2f Mbps)\n"
        "  Peak dissect+fmt:  %" PRIu64 " ns/frame\n",
        g_total_frames,
        g_total_bytes, (double)g_total_bytes / (1024.0 * 1024.0),
        g_raw_ring.peak, RAW_RING_SIZE,
        g_str_ring.peak, STR_RING_SIZE,
        g_peak_fps,
        (double)g_peak_bps / (1024.0 * 1024.0),
        (double)g_peak_bps / (1024.0 * 1024.0) * 8.0,
        g_fmt_max_ns);
    {
        struct pcap_stat ps;
        if (pcap_stats(g_handle, &ps) == 0)
            fprintf(stderr,
                "  Kernel buf size:   %d MB\n"
                "  Kernel received:   %u\n"
                "  Kernel dropped:    %u\n"
                "  Iface  dropped:    %u\n",
                PCAP_BUFFER_SIZE / (1024 * 1024),
                ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    }
    fprintf(stderr, "=====================================\n");
#endif

    pcap_close(g_handle);
    return 0;
}
