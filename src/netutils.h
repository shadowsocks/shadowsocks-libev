/*
 * netutils.h - Network utilities
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

#ifndef _NETUTILS_H
#define _NETUTILS_H

#ifdef __MINGW32__
#include "winsock.h"
#else
#include <sys/socket.h>
#endif
#include <netinet/in.h>

#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#elif HAVE_NETDB_H
#include <netdb.h>
#endif

/* Hard coded defines for TCP fast open on Android */
#ifdef __ANDROID__
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif
#ifdef TCP_FASTOPEN_CONNECT
#undef TCP_FASTOPEN_CONNECT
#endif
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IP_RECVORIGDSTADDR
#ifdef  IP_ORIGDSTADDR
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR
#else
#define IP_RECVORIGDSTADDR   20
#endif
#endif

#ifndef IPV6_RECVORIGDSTADDR
#ifdef  IPV6_ORIGDSTADDR
#define IPV6_RECVORIGDSTADDR   IPV6_ORIGDSTADDR
#else
#define IPV6_RECVORIGDSTADDR   74
#endif
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001UL
#endif

#define MAX_CONNECT_TIMEOUT 10
#define MAX_REQUEST_TIMEOUT 30
#define MIN_UDP_TIMEOUT     10

#ifdef MODULE_REMOTE
#define MAX_UDP_SOCKET_NUM 512
#else
#define MAX_UDP_SOCKET_NUM 256
#endif

#define DSCP_EF      0x2E
#define DSCP_MIN     0x0
#define DSCP_MAX     0x3F
#define DSCP_DEFAULT 0x0
#define DSCP_MIN_LEN 2
#define DSCP_MAX_LEN 4
#define DSCP_CS_LEN  3
#define DSCP_AF_LEN  4

#define MAX_HOSTNAME_LEN 256 // FQCN <= 255 characters
#define MAX_PORT_STR_LEN 6   // PORT < 65536

#ifndef BUF_SIZE
#define BUF_SIZE 65535
#endif

#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
#define STREAM_BUF_SIZE SOCKET_BUF_SIZE

#define DGRAM_PKT_SIZE      1397        // 1492 - DGRAM_PKT_HDR_SIZE = 1397, the default MTU for UDP relay
#define DGRAM_BUF_SIZE      (DGRAM_PKT_SIZE * 2)
#define DGRAM_PKT_HDR_SIZE  (1 + 28 + 2 + 64)
#define MAX_DGRAM_PKT_SIZE  65507

typedef struct {
    uint8_t ss_family;
    union {
        struct in_addr addr;
        struct in6_addr addr6;
    } sin;
} ss_inaddr_t;

typedef enum {
    PORT_SERVICE_UNKNOWN = -1,
    PORT_DOMAIN_SERVICE,
    PORT_HTTP_SERVICE,
    PORT_HTTPS_SERVICE
} ss_service;

typedef struct {
    ss_service service;
    char **ports;
} ss_service_t;

struct cache *port_cache;

static const ss_service_t service_ports[] = {
    { .service = PORT_DOMAIN_SERVICE,
      .ports = (char *[]) { "domain", NULL }            },
    { .service = PORT_HTTP_SERVICE,
      .ports = (char *[]) { "http", "http-alt", NULL }  },
    { .service = PORT_HTTPS_SERVICE,
      .ports = (char *[]) { "https", NULL }             },
    { }
};

/**
 * MPTCP_ENABLED
 * ---------------------
 * Enable multipath TCP for kernel version 3 and 4.
 * The best way to maintain compatibility is to
 * test from newest to the latest version and see if
 * mptcp is enabled.
 */
#ifndef MPTCP_ENABLED
static const char mptcp_enabled_values[] = { 42, 26, 0 };
#else
static const char mptcp_enabled_values[] = { MPTCP_ENABLED, 0 };
#endif

#ifndef UPDATE_INTERVAL
#define UPDATE_INTERVAL 5
#endif

/** byte size of ipv4 address */
#define INET_SIZE 4
/** byte size of ipv6 address */
#define INET6_SIZE 16

#define inetaddr_selector(storage, addr, len)                   \
    switch (storage->ss_family) {                               \
        case AF_INET: {                                         \
            struct sockaddr_in *s = (sockaddr_in *)storage;     \
            len  = sizeof(s->sin_addr);                         \
            addr = &s->sin_addr;                                \
        } break;                                                \
        case AF_INET6: {                                        \
            struct sockaddr_in6 *s = (sockaddr_in6 *)storage;   \
            len  = sizeof(s->sin6_addr);                        \
            addr = &s->sin6_addr;                               \
        } break;                                                \
    }

#define inaddr_inc(addr, n)                                     \
        addr.s_addr = htonl(ntohl(addr.s_addr) + n);
#define in6addr_inc(addr, n)                                    \
        for (int i = 15; i >= 0; i--) {                         \
            addr.s6_addr[i] += n;                               \
            if (addr.s6_addr[i]) break;                         \
        }


#define get_sockaddr(node, service, storage, resolv, ipv6first) \
        get_sockaddr_r(node, service, 0, storage, resolv, ipv6first)

#define get_sockaddr_len(addr) \
    (addr)->sa_family == AF_INET  ? sizeof(struct sockaddr_in)  :    \
    (addr)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : 0

int get_sockaddr_r(const char *, const char *,
                   uint16_t, struct sockaddr_storage *, int, int);
int get_sockaddr_str(struct sockaddr_storage *storage,
                     char *host, char *port);
char *sockaddr_readable(char *format, struct sockaddr_storage *addr);

int tproxy_socket(int socket, int family);
int getdestaddr(int fd, struct sockaddr_storage *destaddr);
int getdestaddr_dgram(struct msghdr *msg, struct sockaddr_storage *destaddr);

int set_reuseport(int socket);
int set_mptcp(int socket);
int set_fastopen_passive(int socket);

#ifdef SET_INTERFACE
int setinterface(int socket_fd, const char *interface_name);
#endif

#ifndef __MINGW32__
int setnonblocking(int fd);
#endif

typedef struct listen_ctx listen_ctx_t;
int create_and_bind(struct sockaddr_storage *storage,
                    int protocol, listen_ctx_t *listen_ctx);
int bind_and_listen(struct sockaddr_storage *storage,
                    int protocol, listen_ctx_t *listen_ctx);
#ifdef HAVE_LAUNCHD
int launch_or_create(struct sockaddr_storage *storage,
                     int protocol, listen_ctx_t *listen_ctx);
#endif

ssize_t
sendto_idempotent(int fd, const void *buf, size_t len,
                  struct sockaddr *addr
#ifdef TCP_FASTOPEN_WINSOCK
                  , OVERLAPPED *olap, int *connect_ex_done
#endif
);

/**
 * Compare two sockaddrs. Imposes an ordering on the addresses.
 * Compares address and port.
 * @param addr1: address 1.
 * @param addr2: address 2.
 * @param len: lengths of addr.
 * @return: 0 if addr1 == addr2. -1 if addr1 is smaller, +1 if larger.
 */
int sockaddr_cmp(struct sockaddr_storage *addr1,
                 struct sockaddr_storage *addr2, socklen_t len);

/**
 * Compare two sockaddrs. Compares address, not the port.
 * @param addr1: address 1.
 * @param addr2: address 2.
 * @param len: lengths of addr.
 * @return: 0 if addr1 == addr2. -1 if addr1 is smaller, +1 if larger.
 */
int sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                      struct sockaddr_storage *addr2, socklen_t len);

char *hostname_readable(const char *dname, const int dname_len, uint16_t port);

int is_addr_loopback(const struct sockaddr *addr);

void parse_addr_cidr(const char *str, char *host, int *cidr);

int port_service(uint16_t port);
int port_service_init(void);

#endif
