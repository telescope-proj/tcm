// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_TIME_H_
#define TCM_TIME_H_

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

enum tcm_time_mode : uint8_t {
    TCM_TIME_MODE_INVALID = 0,
    TCM_TIME_MODE_SINGLE,
    TCM_TIME_MODE_ABSOLUTE,
    TCM_TIME_MODE_RELATIVE,
    TCM_TIME_MODE_MAX
};

struct tcm_timeout {
    int64_t timeout;
    int64_t interval;
};

struct tcm_time {
    struct timespec ts;
    int64_t         interval;
    int64_t         timeout;
    tcm_time_mode   mode;

    /* Single-shot mode */
    tcm_time() {
        this->mode       = TCM_TIME_MODE_SINGLE;
        this->timeout    = 0;
        this->interval   = 0;
        this->ts.tv_sec  = 0;
        this->ts.tv_nsec = 0;
        return;
    }

    /* Relative timeout */
    tcm_time(int64_t timeout_ms, int64_t interval_us) {
        if (timeout_ms == 0)
            this->mode = TCM_TIME_MODE_SINGLE;
        else
            this->mode = TCM_TIME_MODE_RELATIVE;

        this->timeout  = timeout_ms;
        this->interval = interval_us;
    }

    /* Absolute deadline */
    tcm_time(struct timespec * deadline) {
        this->mode = TCM_TIME_MODE_ABSOLUTE;
        this->ts   = *deadline;
    }
};

int64_t tcm_time_sleep(tcm_time * t, bool interruptable);
void    tcm_get_abs_time(tcm_time * tt, struct timespec * ts);

static inline tcm_time tcm_time_select(tcm_time * param, tcm_time * default_) {
    tcm_time out;
    if (!param) {
        out = *default_;
    } else {
        out = *param;
    }
    return out;
}

static inline float tcm_timespec_diff(const timespec * start,
                                      const timespec * end) {
    assert(start);
    assert(end);
    return (end->tv_sec - start->tv_sec) +
           (end->tv_nsec - start->tv_nsec) / 1e9;
}

/*  Return the number of seconds remaining until a specific deadline in
    the future. */
static inline float tcm_get_sec_left(const timespec * end) {
    assert(end);
    timespec now;
    int      ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret == -1)
        return -errno;

    return tcm_timespec_diff(&now, end);
}

/* Check whether an absolute deadline has passed. */
static inline int tcm_check_deadline(const timespec * ts) {
    /* Special value for single poll */
    if (ts->tv_sec == 0 && ts->tv_nsec == 0)
        return 1;

    struct timespec now;
    int             ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret == -1)
        return -errno;

    return ((now.tv_sec > ts->tv_sec && now.tv_nsec > ts->tv_nsec) ||
            (now.tv_sec == ts->tv_sec && now.tv_nsec > ts->tv_nsec));
}

static inline void tcm_get_delay(struct timespec * ts, struct timespec * ts_out,
                                 uint64_t delay_ms) {
    ts_out->tv_sec  = ts->tv_sec + (delay_ms / 1000);
    ts_out->tv_nsec = ts->tv_nsec + ((delay_ms % 1000) * 1000000);
    if (ts_out->tv_nsec > 1000000000) {
        ts_out->tv_sec++;
        ts_out->tv_nsec -= 1000000000;
    }
}

static inline int tcm_get_deadline(struct timespec * out, int delay_ms) {
    // this is unnecessary but GCC won't shut up if I don't include it
    out->tv_sec  = 0;
    out->tv_nsec = 0;

    struct timespec now;
    int             ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret != 0)
        return -errno;

    tcm_get_delay(&now, out, delay_ms);
    return ret;
}

static inline int tcm_sleep(uint64_t ms) {
    if (!ms)
        return 0;

#ifdef _WIN32
    Sleep(ms);
    return 0;
#else
    struct timespec t;
    t.tv_sec  = ms / 1000;
    t.tv_nsec = (ms % 1000) * 1000000;
    int ret   = nanosleep(&t, NULL);
    if (ret < 0)
        return -errno;

    return 0;
#endif
}

static inline int tcm_usleep(uint64_t us) {
    if (!us)
        return 0;

#ifdef _WIN32
    LARGE_INTEGER i;
    i.QuadPart = -(dwMilliseconds * 10);
    NtDelayExecution(false, i);
    return 0;
#else
    struct timespec t;
    t.tv_sec  = us / 1000000;
    t.tv_nsec = (us % 1000000) * 1000;
    int ret   = nanosleep(&t, NULL);
    if (ret < 0)
        return -errno;

    return 0;
#endif
}

static inline int tcm_fsleep(float sec) {
    if (!sec)
        return 0;

#ifdef _WIN32
    return -ENOSYS;
#else
    struct timespec t;
    t.tv_sec  = (time_t) sec;
    t.tv_nsec = (time_t) ((sec - (float) t.tv_sec) * 1e9);
    int ret   = nanosleep(&t, NULL);
    if (ret < 0)
        return -errno;

    return 0;
#endif
}

#endif