#ifndef _TCM_TIME_H_
#define _TCM_TIME_H_

#include <stdbool.h>

typedef enum {
    TCM_MODE_CLOCK      = 0,
    TCM_MODE_DELTA      = 1,
    TCM_MODE_DEFAULT    = 2,
    TCM_MODE_MAX
} tcm_time_mode;

typedef struct {
    struct timespec ts;         // Timespec, 0sec/0nsec = one-shot
    int64_t         interval;   // Polling interval, <0 = blocking operation (tbd)
    bool            delta;      // 0: Real time (monotonic), 1: Delta
} tcm_time;

static inline int tcm_check_deadline(struct timespec * ts)
{
    struct timespec now;
    int ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret == -1)
        return -errno;
    
    return ((now.tv_sec > ts->tv_sec && now.tv_nsec > ts->tv_nsec)
            || (now.tv_sec == ts->tv_sec && now.tv_nsec > ts->tv_nsec));
}

static inline void tcm_get_delay(struct timespec * ts, struct timespec * ts_out, 
    uint64_t delay_ms)
{
    ts_out->tv_sec = ts->tv_sec + (delay_ms / 1000);
    ts_out->tv_nsec = ts->tv_nsec + ((delay_ms % 1000) * 1000000);
    if (ts_out->tv_nsec > 1000000000)
    {
        ts_out->tv_sec++;
        ts_out->tv_nsec -= 1000000000;
    }
}

static inline int tcm_get_deadline(struct timespec * out, int delay_ms)
{
    // this is unnecessary but GCC won't shut up if I don't include it
    out->tv_sec = 0;
    out->tv_nsec = 0;

    struct timespec now;
    int ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret != 0)
        return -errno;

    tcm_get_delay(&now, out, delay_ms);
    return ret;
}

static inline int tcm_sleep(uint64_t ms)
{
    if (!ms)
        return 0;

#ifdef _WIN32
    Sleep(ms);
    return 0;
#else
    struct timespec t;
    t.tv_sec    = ms / 1000;
    t.tv_nsec   = (ms % 1000) * 1000000;
    int ret = nanosleep(&t, NULL);
    if (ret < 0)
        return -errno;
        
    return 0;
#endif
}

static inline int tcm_conv_time(tcm_time * tt, struct timespec * ts)
{
    if (tt->delta)
    {
        struct timespec cur;
        int ret = clock_gettime(CLOCK_MONOTONIC, &cur);
        if (ret < 0)
        {
            return -errno;
        }
        ts->tv_sec  = cur.tv_sec + tt->ts.tv_sec;
        ts->tv_nsec = cur.tv_nsec + tt->ts.tv_nsec;
        if (ts->tv_nsec > 1000000000)
        {
            ts->tv_sec++;
            ts->tv_nsec -= 1000000000;
        }
    }
    else
    {
        ts->tv_sec  = tt->ts.tv_sec;
        ts->tv_nsec = tt->ts.tv_nsec;
    }
    return 0;
}

#endif