/**
 * ring.h – Ring buffer types and operations for ethsniff.
 *
 * Two ring buffers form the two-stage output pipeline:
 *
 *   capture thread
 *        │  raw_ring_push()
 *        ▼
 *   raw_ring_t         ← holds raw pcap frame bytes
 *        │  raw_ring_pop()
 *        ▼
 *   format thread
 *        │  str_ring_push()
 *        ▼
 *   str_ring_t         ← holds pre-formatted, human-readable strings
 *        │  str_ring_pop()
 *        ▼
 *   IO thread  →  stdout
 *
 * Both rings follow the same producer/consumer contract:
 *   - One mutex guards the head/tail pointers.
 *   - One condition variable wakes the consumer when a slot is ready.
 *   - If the ring is full the producer drops the item and increments
 *     the dropped counter rather than blocking – so the fast path
 *     (capture or format) is never stalled by a slow consumer.
 *
 * The pop functions each accept a volatile int *stop_flag so that this
 * module does not depend on any global variables from main.c.
 */

#ifndef RING_H
#define RING_H

#include <stdint.h>
#include <pthread.h>
#include "dissect.h"   /* rc_t, RC_OK, RC_ERR */

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

#define RAW_RING_SIZE     512    /* number of raw-frame slots           */
#define MAX_FRAME_BYTES   1522   /* standard Ethernet max: 14 (hdr) +   */
                                 /*   4 (802.1Q tag) + 1500 (payload) + */
                                 /*   4 (FCS). No jumbo frame support.  */

/*
 * STR_RING_SIZE is intentionally much larger than RAW_RING_SIZE.
 *
 * The format thread (producer) is CPU-bound and drains the raw ring in
 * microseconds per frame.  The IO thread (consumer) calls fwrite/fflush
 * which can stall for tens of milliseconds on a slow terminal or pipe.
 *
 * Worst-case sizing: at 10 000 frames/s a 100 ms fwrite stall produces
 * ~1 000 queued strings.  STR_RING_SIZE slots gives a comfortable safety
 * margin (STR_RING_SIZE x STR_SLOT_MAX_LEN bytes).
 */
#define STR_RING_SIZE     10000   /* number of string slots              */
#define STR_SLOT_MAX_LEN  2048   /* max bytes in one formatted string   */

/* ------------------------------------------------------------------ */
/*  Raw ring  (capture thread  ->  format thread)                      */
/*                                                                      */
/*  Each slot holds one captured Ethernet frame, its lengths, the      */
/*  pcap timestamp, and the frame sequence number.                     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  data[MAX_FRAME_BYTES];  /* raw frame bytes                */
    uint32_t caplen;                 /* bytes actually captured        */
    uint32_t wirelen;                /* bytes on the wire              */
    long     ts_sec;                 /* pcap timestamp (seconds)       */
    long     ts_usec;                /* pcap timestamp (microseconds)  */
    uint32_t frame_no;               /* monotonically increasing index */
} raw_slot_t;

typedef struct {
    raw_slot_t      slots[RAW_RING_SIZE];
    uint32_t        head;      /* read  pointer – format thread removes here  */
    uint32_t        tail;      /* write pointer – capture thread appends here */
    uint32_t        dropped;   /* frames lost because the ring was full       */
    uint32_t        peak;      /* all-time max occupancy (slots used)         */
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
} raw_ring_t;

/* ------------------------------------------------------------------ */
/*  String ring  (format thread  ->  IO thread)                        */
/*                                                                      */
/*  Each slot holds one fully-formatted, null-terminated frame string. */
/*  len caches strlen(text) so the IO thread can call fwrite without   */
/*  rescanning the string.                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    char text[STR_SLOT_MAX_LEN];  /* null-terminated formatted string */
    int  len;                     /* strlen(text), cached for fwrite  */
} str_slot_t;

typedef struct {
    str_slot_t      slots[STR_RING_SIZE];
    uint32_t        head;      /* read  pointer – IO thread removes here     */
    uint32_t        tail;      /* write pointer – format thread appends here */
    uint32_t        dropped;   /* strings lost because the ring was full     */
    uint32_t        peak;      /* all-time max occupancy (slots used)        */
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
} str_ring_t;

/* ------------------------------------------------------------------ */
/*  Raw ring operations                                                 */
/* ------------------------------------------------------------------ */

/* Initialise a raw ring. Must be called before any push or pop. */
void raw_ring_init(raw_ring_t *r);

/*
 * raw_ring_push – append a captured frame to the ring.
 *
 * Called by the capture thread (pcap callback).
 * Returns RC_OK on success.
 * Returns RC_ERR (and increments r->dropped) if the ring is full;
 * the caller should not block – dropping is intentional.
 */
rc_t raw_ring_push(raw_ring_t *r,
                   const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                   long ts_sec, long ts_usec, uint32_t frame_no);

/*
 * raw_ring_pop – dequeue one frame into *out.
 *
 * Blocks (with a 10 ms timeout) until a frame is available or
 * *stop_flag becomes non-zero.
 * Returns RC_OK when a frame was dequeued.
 * Returns RC_ERR when the ring is empty AND *stop_flag is non-zero.
 */
rc_t raw_ring_pop(raw_ring_t *r, raw_slot_t *out, volatile int *stop_flag);

/* Return the current number of occupied slots. */
uint32_t raw_ring_occupancy(raw_ring_t *r);

/* ------------------------------------------------------------------ */
/*  String ring operations                                              */
/* ------------------------------------------------------------------ */

/* Initialise a string ring. Must be called before any push or pop. */
void str_ring_init(str_ring_t *r);

/*
 * str_ring_push – append a pre-formatted string to the ring.
 *
 * Called by the format thread.
 * Returns RC_OK on success.
 * Returns RC_ERR (and increments r->dropped) if the ring is full;
 * the format thread continues without blocking.
 */
rc_t str_ring_push(str_ring_t *r, const char *text, int len);

/*
 * str_ring_pop – dequeue one string slot into *out.
 *
 * Blocks (with a 10 ms timeout) until a string is available or
 * *done_flag becomes non-zero (meaning the format thread has exited
 * and no more strings will ever be pushed).
 * Returns RC_OK when a slot was dequeued.
 * Returns RC_ERR when the ring is empty AND *done_flag is non-zero.
 */
rc_t str_ring_pop(str_ring_t *r, str_slot_t *out, volatile int *done_flag);

/* Return the current number of occupied slots. */
uint32_t str_ring_occupancy(str_ring_t *r);

#endif /* RING_H */
