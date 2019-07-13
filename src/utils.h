/*
 * utils.h - Misc utilities
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define new(type)   ss_calloc(1, sizeof(type))
#define elvis(a, b) (a) ? (a) : (b)
#define nelem(x)    (sizeof(x) / sizeof((x)[0]))
#define ntlforeach(type, var, list) \
                    for (type curr = (list); curr != NULL; curr++)

#define PORTSTRLEN 16
#define SS_ADDRSTRLEN (INET6_ADDRSTRLEN + PORTSTRLEN + 1)

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define PACKED __attribute__((packed, aligned(1)))

extern int use_tty;
extern int use_syslog;
extern FILE *logfile;

#ifdef __ANDROID__
#include <android/log.h>

#define LOGI(...)                                                \
    ((void)__android_log_print(ANDROID_LOG_DEBUG, "shadowsocks", \
                               __VA_ARGS__))
#define LOGE(...)                                                \
    ((void)__android_log_print(ANDROID_LOG_ERROR, "shadowsocks", \
                               __VA_ARGS__))

#else // not __ANDROID__

#define STR(x) # x
#define TOSTR(x) STR(x)

#ifdef __MINGW32__
#define red    FOREGROUND_RED | FOREGROUND_BLUE
#define green  FOREGROUND_GREEN
#define reset  0

#define fprintc(f, color, format, ...) {    \
    set_concolor(color, FALSE);             \
    fprintf(f, format, ## __VA_ARGS__);     \
    set_concolor(reset, FALSE);             \
}

#else // not __MINGW32__
#include <errno.h>
#include <syslog.h>

#define ansi_code(code, format) \
        "\e[" STR(code) "m" format "\e[0m"
#define red    1;31
#define green  1;32

#define fprintc(f, color, format, ...)   \
    fprintf(f, use_tty ? ansi_code(color, format) : format, ## __VA_ARGS__)

#define HAS_SYSLOG
#define USE_TTY()                        \
    use_tty = isatty(STDERR_FILENO)

#define USE_SYSLOG(_ident, _cond)                           \
    if (use_syslog || (_cond)) {                            \
        openlog((_ident), LOG_CONS | LOG_PID, LOG_DAEMON);  \
    }

#endif // if __MINGW32__

#define USE_LOGFILE(ident)            \
    if (ident != NULL) {              \
        logfile = fopen(ident, "w+"); \
    }

#define CLOSE_LOGFILE()               \
    if (logfile != NULL) {            \
        fclose(logfile);              \
    }

#ifndef HAS_SYSLOG
#define	LOG_ERR		3	/* error conditions */
#define	LOG_INFO	6	/* informational */
#define syslog(priority, format, ...) {                     \
    use_syslog = 0;                                         \
    switch (priority) {                                     \
        case LOG_ERROR:                                     \
            LOGE(format, ## __VA_ARGS__);                   \
            break;                                          \
        default:                                            \
        case LOG_INFO:                                      \
            LOGI(format, ## __VA_ARGS__);                   \
            break;                                          \
    }                                                       \
}
#endif // if syslog

#define LOGI(format, ...) {                                             \
    FILE *f = logfile ? logfile : stdout;                               \
    if (use_syslog) {                                                   \
        syslog(LOG_INFO, format, ## __VA_ARGS__);                       \
    } else {                                                            \
        fprintc(f, green, " %s INFO: ", currtime_readable());           \
        fprintf(f, format "\n", ## __VA_ARGS__);                        \
        fflush(f);                                                      \
    }                                                                   \
}

#define LOGE(format, ...) {                                             \
    FILE *f = logfile ? logfile : stderr;                               \
    if (use_syslog) {                                                   \
        syslog(LOG_ERR, format, ## __VA_ARGS__);                        \
    } else {                                                            \
        fprintc(f, red, " %s ERROR: ", currtime_readable());            \
        fprintf(f, format "\n", ## __VA_ARGS__);                        \
        fflush(f);                                                      \
    }                                                                   \
}

#endif // if __ANDROID__

// Workaround for "%z" in Windows printf
#ifdef __MINGW32__
#define SSIZE_FMT "%Id"
#define SIZE_FMT "%Iu"
#else
#define SSIZE_FMT "%zd"
#define SIZE_FMT "%zu"
#endif

#ifdef __MINGW32__
// Override Windows built-in functions
#ifdef ERROR
#undef ERROR
#endif
#define ERROR(s) ss_error(s)

// Implemented in winsock.c
void ss_error(const char *s);
void ss_color_info(void);
void ss_color_error(void);
void ss_color_reset(void);
#else
#define ERROR(format, ...)          \
    LOGE(format ": %s", ## __VA_ARGS__, strerror(errno));
#endif

#define FATAL(format, ...) {        \
    LOGE(format, ## __VA_ARGS__);   \
    exit(-1);                       \
}

int run_as(const char *user);
void usage(void);
void daemonize(const char *path);

char *ss_itoa(int i);
int ss_isnumeric(const char *s);
char *ss_strndup(const char *s, size_t n);
#ifdef HAVE_SETRLIMIT
int set_nofile(int nofile);
#endif

#define ss_free(ptr) { \
    free(ptr); \
    ptr = NULL; \
}

#ifdef __MINGW32__
#define ss_aligned_free(ptr) { \
    _aligned_free(ptr); \
    ptr = NULL; \
}
#else
#define ss_aligned_free(ptr) ss_free(ptr)
#endif

inline void *
ss_malloc(size_t size)
{
    void *tmp = malloc(size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

inline void *
ss_aligned_malloc(size_t size)
{
    int err;
    void *tmp = NULL;
#ifdef HAVE_POSIX_MEMALIGN
    /* ensure 16 byte alignment */
    err = posix_memalign(&tmp, 16, size);
#elif __MINGW32__
    tmp = _aligned_malloc(size, 16);
    err = tmp == NULL;
#else
    err = -1;
#endif
    return err ? ss_malloc(size) : tmp;
}

inline void *
ss_realloc(void *ptr, size_t new_size)
{
    void *new = realloc(ptr, new_size);
    if (new == NULL)
    {
        free(ptr);
        ptr = NULL;
        exit(EXIT_FAILURE);
    }
    return new;
}

inline void *
ss_calloc(size_t num, size_t size)
{
    void *tmp = calloc(num, size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

int ss_is_ipv6addr(const char *addr);
char *trim_whitespace(char *str);

// file operations
#define current_dir(path) \
    realpath(dirname(strdup(path)), NULL)
#define setcwd(path)    \
    if (chdir(path) != 0)   \
        ERROR("setcwd");

size_t readoff_from(char **content, const char *file);
char *get_default_conf(void);

// time functions
time_t strtotime(char *str);
static inline char *
currtime_readable()
{
    time_t now = time(NULL);
    static char timestr[20] = {};
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));
    return timestr;
}

// libcork extension functions
#include <libcork/ds.h>

#define cork_array_merge(dst, src) \
    for (int i = 0; i < cork_array_size(src); i++) {    \
        cork_array_append(dst, cork_array_at(src, i));  \
    }

inline void
cork_dllist_merge(struct cork_dllist *dst, struct cork_dllist *src)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(src, curr, next)
        cork_dllist_add(dst, curr);
}

#endif // _UTILS_H
