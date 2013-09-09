#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <time.h>

#ifdef ANDROID

#include <android/log.h>

#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "shadowsocks", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "shadowsocks", __VA_ARGS__))

#else

#define STR(x) #x
#define TOSTR(x) STR(x)

#ifdef _WIN32

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define LOGD(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, " %s INFO: " format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#define LOGE(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, " %s ERROR: " format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#else

#define TIME_FORMAT "%F %T"

#define LOGD(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#define LOGE(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#endif 
/* _WIN32 */

#endif

#ifdef __MINGW32__

#ifdef ERROR
#undef ERROR
#endif
#define ERROR(s) ss_error(s)

char *ss_itoa(int i);

#else

void ERROR(const char *s);
char *itoa(int i);

#endif

void FATAL(const char *msg);
void usage(void);
void demonize(const char* path);
char *ss_strndup(const char *s, size_t n);

#endif // _UTILS_H
