#ifndef _WIN32_H
#define _WIN32_H

#define _WIN32_WINNT 0x0501

#include <winsock2.h>
#include <ws2tcpip.h>
#include "utils.h"

#ifdef EWOULDBLOCK
#undef EWOULDBLOCK
#endif

#ifdef errno
#undef errno
#endif

#ifdef ERROR
#undef ERROR
#endif

#define EWOULDBLOCK WSAEWOULDBLOCK
#define errno WSAGetLastError()
#define close(fd) closesocket(fd)
#define ERROR(s) ss_error(s)
#define setsockopt(a, b, c, d, e) setsockopt(a, b, c, (char *) (d), e)

void winsock_init(void);
void winsock_cleanup(void);
void ss_error(const char *s);
size_t strnlen(const char *s, size_t maxlen);

#endif