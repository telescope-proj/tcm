/**
 * Copyright (c) 2020 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

/*  
    -------------------- Internal TCM Logging Functions -------------------- 

    Do not use these functions outside of library code; please load your own
    log.c file from https://github.com/rxi/log.c

    ------------------------------------------------------------------------
*/

#ifndef _TCM_LOG_H_
#define _TCM_LOG_H_

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#define tcm_fi_error(msg, code) \
    tcm__log_error("[fabric] %s: %s (%d)", msg, fi_strerror(tcm_abs(code)), code)

#define tcm_fi_warn(msg, code) \
    tcm__log_warn("[fabric] %s: %s (%d)", msg, fi_strerror(tcm_abs(code)), code)

#define TCM_LOG_VERSION "0.1.0"

#define _TCM_FNAME_ (strrchr("/" __FILE__, '/') + 1)

typedef struct {
  va_list ap;
  const char *fmt;
  const char *file;
  struct tm *time;
  void *udata;
  int line;
  int level;
} tcm__log_Event;

typedef void (*tcm__log_LogFn)(tcm__log_Event *ev);
typedef void (*tcm__log_LockFn)(bool lock, void *udata);

enum { TCM__LOG_TRACE, TCM__LOG_DEBUG, TCM__LOG_INFO, TCM__LOG_WARN, TCM__LOG_ERROR, TCM__LOG_FATAL };

#define tcm__log_trace(...) tcm__log_log(TCM__LOG_TRACE, _TCM_FNAME_, __LINE__, __VA_ARGS__)
#define tcm__log_debug(...) tcm__log_log(TCM__LOG_DEBUG, _TCM_FNAME_, __LINE__, __VA_ARGS__)
#define tcm__log_info(...)  tcm__log_log(TCM__LOG_INFO,  _TCM_FNAME_, __LINE__, __VA_ARGS__)
#define tcm__log_warn(...)  tcm__log_log(TCM__LOG_WARN,  _TCM_FNAME_, __LINE__, __VA_ARGS__)
#define tcm__log_error(...) tcm__log_log(TCM__LOG_ERROR, _TCM_FNAME_, __LINE__, __VA_ARGS__)
#define tcm__log_fatal(...) tcm__log_log(TCM__LOG_FATAL, _TCM_FNAME_, __LINE__, __VA_ARGS__)

const char* tcm__log_level_string(int level);
void tcm__log_set_lock(tcm__log_LockFn fn, void *udata);
void tcm__log_set_level(int level);
void tcm__log_set_quiet(bool enable);
int tcm__log_add_callback(tcm__log_LogFn fn, void *udata, int level);
int tcm__log_add_fp(FILE *fp, int level);

void tcm__log_log(int level, const char *file, int line, const char *fmt, ...);

#endif
