// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_time.h"
#include "tcm_exception.h"

int64_t tcm_time_sleep(const tcm_time * t, bool interruptable) {
    assert(t);
    if (t->mode == TCM_TIME_MODE_SINGLE)
        return 0;

    struct timespec dl;
    int             ret;

    if (t->mode == TCM_TIME_MODE_RELATIVE) {
        ret = clock_gettime(CLOCK_MONOTONIC, &dl);
        if (ret < 0)
            throw tcm_exception(errno, __FILE__, __LINE__,
                                "System clock failure");
        dl.tv_sec += t->interval / 1000000;
        dl.tv_nsec += (t->interval % 1000000) * 1000;
    } else {
        dl.tv_sec  = t->ts.tv_sec;
        dl.tv_nsec = t->ts.tv_nsec;
    }

    struct timespec req, rem;
    ret = clock_gettime(CLOCK_MONOTONIC, &req);
    if (ret < 0)
        throw tcm_exception(errno, __FILE__, __LINE__, "System clock failure");
    req.tv_sec += t->interval / 1000000;
    req.tv_nsec += (t->interval % 1000000) * 1000;
    while (1) {
        ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, &rem);
        switch (ret) {
            case 0:
                return 0;
            case EINTR:
                if (interruptable) {
                    return -EINTR;
                } else {
                    /* If < 500 usec left don't bother sleeping again */
                    if (rem.tv_sec > 0 ||
                        (rem.tv_sec == 0 && rem.tv_nsec > 500000)) {
                        continue;
                    } else {
                        return rem.tv_sec * 1000000 + rem.tv_nsec / 1000;
                    }
                }
            default:
                throw tcm_exception(ret, __FILE__, __LINE__,
                                    "Unexpected sleep completion result");
        }
    }
}

void tcm_get_abs_time(const tcm_time * tt, timespec * ts) {
    assert(tt);
    assert(ts);
    switch (tt->mode) {
        case TCM_TIME_MODE_ABSOLUTE: {
            *ts = tt->ts;
            return;
        }
        case TCM_TIME_MODE_RELATIVE: {
            struct timespec cur;
            if (tt->timeout < 0) {
                ts->tv_sec  = -1;
                ts->tv_nsec = -1;
                return;
            } else {
                int ret = clock_gettime(CLOCK_MONOTONIC, &cur);
                if (ret < 0) {
                    throw tcm_exception(errno, __FILE__, __LINE__,
                                        "System clock failure");
                }
                ts->tv_sec  = cur.tv_sec + tt->timeout / 1000;
                ts->tv_nsec = cur.tv_nsec + (tt->timeout % 1000) * 1000000;
                if (ts->tv_nsec > 1000000000) {
                    ts->tv_sec++;
                    ts->tv_nsec -= 1000000000;
                }
                return;
            }
        }
        case TCM_TIME_MODE_SINGLE: {
            ts->tv_sec  = 0;
            ts->tv_nsec = 0;
            return;
        }
        default:
            assert(false && "Invalid program state");
    }
    return;
};
