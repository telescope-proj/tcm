/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "tcm_log.h"
#include "compat/tcmc_tl.h"

#define MAX_CALLBACKS 32

static tcm_thrlocal struct tm tm_r;
static int                    use_color = 0;

typedef struct {
    tcm__log_LogFn fn;
    void *         udata;
    int            level;
} tcm__log_Callback;

static struct {
    void *            udata;
    tcm__log_LockFn   lock;
    int               level;
    bool              quiet;
    tcm__log_Callback callbacks[MAX_CALLBACKS];
} L;

void tcm__log_set_color_mode(int mode) { use_color = mode; }

static const char * level_strings[] = {"TRACE", "DEBUG", "INFO",
                                       "WARN",  "ERROR", "FATAL"};

static const char * level_colors[] = {"\x1b[94m", "\x1b[36m", "\x1b[32m",
                                      "\x1b[33m", "\x1b[31m", "\x1b[35m"};

static void stdout_callback(tcm__log_Event * ev) {
    char buf[16];
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", ev->time)] = '\0';
    if (use_color)
        fprintf(ev->udata, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf,
                level_colors[ev->level], level_strings[ev->level], ev->file,
                ev->line);
    else
        fprintf(ev->udata, "%s %-5s %s:%d: ", buf, level_strings[ev->level],
                ev->file, ev->line);
    vfprintf(ev->udata, ev->fmt, ev->ap);
    fprintf(ev->udata, "\n");
    fflush(ev->udata);
}

static void file_callback(tcm__log_Event * ev) {
    char buf[64];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ev->time)] = '\0';
    fprintf(ev->udata, "%s %-5s %s:%d: ", buf, level_strings[ev->level],
            ev->file, ev->line);
    vfprintf(ev->udata, ev->fmt, ev->ap);
    fprintf(ev->udata, "\n");
    fflush(ev->udata);
}

static void lock(void) {
    if (L.lock) {
        L.lock(true, L.udata);
    }
}

static void unlock(void) {
    if (L.lock) {
        L.lock(false, L.udata);
    }
}

const char * tcm__log_level_string(int level) { return level_strings[level]; }

void tcm__log_set_lock(tcm__log_LockFn fn, void * udata) {
    L.lock  = fn;
    L.udata = udata;
}

void tcm__log_set_level(int level) { L.level = level; }

void tcm__log_set_quiet(bool enable) { L.quiet = enable; }

int tcm__log_add_callback(tcm__log_LogFn fn, void * udata, int level) {
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (!L.callbacks[i].fn) {
            L.callbacks[i] = (tcm__log_Callback){fn, udata, level};
            return 0;
        }
    }
    return -1;
}

int tcm__log_add_fp(FILE * fp, int level) {
    return tcm__log_add_callback(file_callback, fp, level);
}

static void init_event(tcm__log_Event * ev, void * udata) {
    if (!ev->time) {
        time_t t = time(NULL);
        ev->time = localtime_r(&t, &tm_r);
    }
    ev->udata = udata;
}

void tcm__log_log(int level, const char * file, int line, const char * fmt,
                  ...) {
    tcm__log_Event ev = {
        .fmt   = fmt,
        .file  = file,
        .line  = line,
        .level = level,
    };

    lock();

    if (!L.quiet && level >= L.level) {
        init_event(&ev, stderr);
        va_start(ev.ap, fmt);
        stdout_callback(&ev);
        va_end(ev.ap);
    }

    for (int i = 0; i < MAX_CALLBACKS && L.callbacks[i].fn; i++) {
        tcm__log_Callback * cb = &L.callbacks[i];
        if (level >= cb->level) {
            init_event(&ev, cb->udata);
            va_start(ev.ap, fmt);
            cb->fn(&ev);
            va_end(ev.ap);
        }
    }

    unlock();
}
