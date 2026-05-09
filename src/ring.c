/**
 * ring.c – Ring buffer operations for ethsniff.
 *
 * Implements the raw_ring_t and str_ring_t operations declared in ring.h.
 * See ring.h for a description of the two-stage pipeline and the
 * producer/consumer contract.
 */

#include <string.h>
#include <time.h>
#include "ring.h"

/* ------------------------------------------------------------------ */
/*  Internal helpers shared by both ring types                         */
/* ------------------------------------------------------------------ */

/* Advance a ring index by one, wrapping at capacity. */
static uint32_t raw_next(uint32_t i) { return (i + 1) % RAW_RING_SIZE; }
static uint32_t str_next(uint32_t i) { return (i + 1) % STR_RING_SIZE; }

/* Build an absolute timespec for "now + 10 ms", used as the condvar
 * timeout so that pop functions wake up periodically to re-check the
 * stop/done flag even when no new items arrive.                       */
static struct timespec timeout_10ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 10000000L;   /* +10 ms */
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return ts;
}

/* ------------------------------------------------------------------ */
/*  Raw ring operations                                                 */
/* ------------------------------------------------------------------ */

void raw_ring_init(raw_ring_t *r)
{
    memset(r, 0, sizeof(*r));
    pthread_mutex_init(&r->mutex,     NULL);
    pthread_cond_init (&r->not_empty, NULL);
}

rc_t raw_ring_push(raw_ring_t *r,
                   const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                   long ts_sec, long ts_usec, uint32_t frame_no)
{
    uint32_t   next;
    raw_slot_t *s;

    pthread_mutex_lock(&r->mutex);

    next = raw_next(r->tail);
    if (next == r->head) {
        /* Ring full – drop rather than block the capture thread */
        r->dropped++;
        pthread_mutex_unlock(&r->mutex);
        return RC_ERR;
    }

    s = &r->slots[r->tail];
    {
        uint32_t n = (caplen < MAX_FRAME_BYTES) ? caplen : MAX_FRAME_BYTES;
        memcpy(s->data, data, n);
        s->caplen = n;
    }
    s->wirelen  = wirelen;
    s->ts_sec   = ts_sec;
    s->ts_usec  = ts_usec;
    s->frame_no = frame_no;
    r->tail     = next;

    /* Track peak occupancy for session stats */
    {
        uint32_t occ = (r->tail - r->head + RAW_RING_SIZE) % RAW_RING_SIZE;
        if (occ > r->peak) r->peak = occ;
    }

    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

rc_t raw_ring_pop(raw_ring_t *r, raw_slot_t *out, volatile int *stop_flag)
{
    struct timespec ts;

    pthread_mutex_lock(&r->mutex);

    while (r->head == r->tail && !*stop_flag) {
        ts = timeout_10ms();
        pthread_cond_timedwait(&r->not_empty, &r->mutex, &ts);
    }

    if (r->head == r->tail) {
        /* Ring empty and stop was requested – nothing more will arrive */
        pthread_mutex_unlock(&r->mutex);
        return RC_ERR;
    }

    *out    = r->slots[r->head];
    r->head = raw_next(r->head);

    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

uint32_t raw_ring_occupancy(raw_ring_t *r)
{
    uint32_t occ;
    pthread_mutex_lock(&r->mutex);
    occ = (r->tail - r->head + RAW_RING_SIZE) % RAW_RING_SIZE;
    pthread_mutex_unlock(&r->mutex);
    return occ;
}

/* ------------------------------------------------------------------ */
/*  String ring operations                                              */
/* ------------------------------------------------------------------ */

void str_ring_init(str_ring_t *r)
{
    memset(r, 0, sizeof(*r));
    pthread_mutex_init(&r->mutex,     NULL);
    pthread_cond_init (&r->not_empty, NULL);
}

rc_t str_ring_push(str_ring_t *r, const char *text, int len)
{
    uint32_t next;

    pthread_mutex_lock(&r->mutex);

    next = str_next(r->tail);
    if (next == r->head) {
        /* Ring full – drop rather than block the format thread */
        r->dropped++;
        pthread_mutex_unlock(&r->mutex);
        return RC_ERR;
    }

    /* Clamp to slot size and copy */
    if (len > STR_SLOT_MAX_LEN - 1)
        len = STR_SLOT_MAX_LEN - 1;

    memcpy(r->slots[r->tail].text, text, (size_t)len);
    r->slots[r->tail].text[len] = '\0';
    r->slots[r->tail].len       = len;
    r->tail = next;

    /* Track peak occupancy for session stats */
    {
        uint32_t occ = (r->tail - r->head + STR_RING_SIZE) % STR_RING_SIZE;
        if (occ > r->peak) r->peak = occ;
    }

    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

rc_t str_ring_pop(str_ring_t *r, str_slot_t *out, volatile int *done_flag)
{
    struct timespec ts;

    pthread_mutex_lock(&r->mutex);

    while (r->head == r->tail && !*done_flag) {
        ts = timeout_10ms();
        pthread_cond_timedwait(&r->not_empty, &r->mutex, &ts);
    }

    if (r->head == r->tail) {
        /* Ring empty and format thread is done – nothing more will arrive */
        pthread_mutex_unlock(&r->mutex);
        return RC_ERR;
    }

    *out    = r->slots[r->head];
    r->head = str_next(r->head);

    pthread_mutex_unlock(&r->mutex);
    return RC_OK;
}

uint32_t str_ring_occupancy(str_ring_t *r)
{
    uint32_t occ;
    pthread_mutex_lock(&r->mutex);
    occ = (r->tail - r->head + STR_RING_SIZE) % STR_RING_SIZE;
    pthread_mutex_unlock(&r->mutex);
    return occ;
}
