/*
 * netutils.c - Network utilities
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

#include <math.h>
#include <fcntl.h>
#include <errno.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __MINGW32__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#ifdef __linux__
#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#else
#include <linux/if.h>
#endif
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#endif

#include "netutils.h"
#include "utils.h"
#include "cache.h"
#include "common.h"

extern int verbose;
static const char valid_label_bytes[] =
    "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

int
set_reuseport(int socket)
{
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

int
set_mptcp(int socket)
{
    int mptcp = 1, opt = 1;
    const char *enabled_values = mptcp_enabled_values;
    while (((mptcp = *(enabled_values++)) > 0) &&
           setsockopt(socket, IPPROTO_TCP, mptcp, &opt, sizeof(opt)) != -1);
    if (!mptcp) {
        ERROR("failed to enable multipath TCP");
        return -1;
    }
    return 0;
}

int
set_fastopen_passive(int socket)
{
    int s = 0;
#ifdef TCP_FASTOPEN
#if defined(__APPLE__) || defined(__MINGW32__)
    int opt = 1;
#else
    int opt = 5;
#endif
    s = setsockopt(socket, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

    if (s == -1) {
        if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
            LOGE("fast open is not supported on this platform");
        } else {
            ERROR("setsockopt");
        }
    }
#endif
    return s;
}

socklen_t
get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

int
getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
#if defined(SO_ORIGINAL_DST) && \
    defined(IP6T_SO_ORIGINAL_DST)

    if (destaddr == NULL)
        return -1;
    socklen_t socklen = sizeof(*destaddr);

    // Didn't find a proper way to detect IP version.
    if (!getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &socklen)) {
        return 0;
    }
    if (!getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen)) {
        return 0;
    }
#else
    FATAL("transparent proxy not supported in this build");
#endif
    return -1;
}

int
getdestaddr_dgram(struct msghdr *msg, struct sockaddr_storage *destaddr)
{
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP &&
            cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            destaddr->ss_family = AF_INET;
            return 0;
        } else if (cmsg->cmsg_level == SOL_IPV6 &&
                   cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            destaddr->ss_family = AF_INET6;
            return 0;
        }
    }

    return -1;
}

#ifdef SET_INTERFACE
int
setinterface(int socket_fd, const char *interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(struct ifreq));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ - 1);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                         sizeof(struct ifreq));
    return res;
}

#endif

#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(struct sockaddr_storage *storage,
                int protocol, listen_ctx_t *listen_ctx)
{
    int fd = socket(storage->ss_family,
                    protocol == IPPROTO_TCP ?
                        SOCK_STREAM : SOCK_DGRAM,
                    protocol);
    if (fd == -1) {
        return fd;
    }

    int ipv6only = storage->ss_family == AF_INET6;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (listen_ctx != NULL) {
        if (listen_ctx->reuse_port) {
            int err = set_reuseport(fd);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

#ifdef MODULE_REMOTE
        if (protocol == IPPROTO_TCP
            && listen_ctx->mptcp) {
            set_mptcp(fd);
        }
#endif
    }

    int s = bind(fd, (struct sockaddr *)storage, get_sockaddr_len((struct sockaddr *)storage));
    if (s == 0) {
        return fd;
    } else {
        ERROR("bind");
        FATAL("failed to bind address %s", sockaddr_readable("%a:%p", storage));
        close(fd);
    }
    return -1;
}

int
bind_and_listen(struct sockaddr_storage *storage,
                int protocol, listen_ctx_t *listen_ctx)
{
    int listenfd = create_and_bind(storage, protocol, listen_ctx);

    if (listenfd != -1) {
        setnonblocking(listenfd);
        listen_ctx->fd = listenfd;
        if (protocol == IPPROTO_TCP
            && listen(listenfd, SOMAXCONN) == -1)
        {
            ERROR("listen");
            FATAL("failed to listen on address %s", sockaddr_readable("%a:%p", storage));
            close(listenfd);
            return -1;
        }
    }

    return listenfd;
}


#ifdef HAVE_LAUNCHD
int
launch_or_create(struct sockaddr_storage *storage,
                 int protocol, listen_ctx_t *listen_ctx)
{
    int *listenfd;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &listenfd, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            if (*listenfd == -1) {
                FATAL("[launchd] bind() error");
            }
            if (listen(*listenfd, SOMAXCONN) == -1) {
                FATAL("[launchd] listen() error");
            }
            setnonblocking(*listenfd);
            listen_ctx->fd = listenfd;
            return listenfd;
        } else {
            FATAL("[launchd] please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /**
         * ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *         in the caller's launchd.plist(5).
         */
        return bind_and_listen(storage, protocol, listen_ctx);
    } else {
        FATAL("[launchd] launch_activate_socket() error");
    }
    return -1;
}

#endif

ssize_t
sendto_idempotent(int fd, const void *buf, size_t len,
                  struct sockaddr *addr
#ifdef TCP_FASTOPEN_WINSOCK
                  , OVERLAPPED *olap, int *connect_ex_done
#endif
)
{
    ssize_t s = -1;
#ifdef TCP_FASTOPEN_WINSOCK
    DWORD err = 0;
    do {
        int optval = 1;
        // Set fast open option
        if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN,
                        &optval, sizeof(optval)) != 0) {
            ERROR("setsockopt");
            break;
        }
        // Load ConnectEx function
        LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
        if (ConnectEx == NULL) {
            LOGE("Cannot load ConnectEx() function");
            err = WSAENOPROTOOPT;
            break;
        }
        // ConnectEx requires a bound socket
        if (winsock_dummybind(fd, addr) != 0) {
            ERROR("bind");
            break;
        }
        // Call ConnectEx to send data
        *connect_ex_done = 0;
        memset(olap, 0, sizeof(*olap));
        if (ConnectEx(fd, addr, get_sockaddr_len(addr),
                      buf, len, &s, &olap)) {
            *connect_ex_done = 1;
            break;
        }
        // XXX: ConnectEx pending, check later in remote_send
        if (WSAGetLastError() == ERROR_IO_PENDING) {
            err = CONNECT_IN_PROGRESS;
            break;
        }
        ERROR("ConnectEx");
    } while (0);
    if (err)
        SetLastError(err); // Set error number
#elif CONNECT_DATA_IDEMPOTENT
    ((struct sockaddr_in *)addr)->sin_len = sizeof(struct sockaddr_in);
    sa_endpoints_t endpoints;
    memset((char *)&endpoints, 0, sizeof(endpoints));
    endpoints.sae_dstaddr    = addr;
    endpoints.sae_dstaddrlen = get_sockaddr_len(addr);
    s                        = connectx(fd, &endpoints, SAE_ASSOCID_ANY,
                                        CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                                        NULL, 0, NULL, NULL);
    if (s == 0)
        s = send(fd, buf, len, 0);
#elif TCP_FASTOPEN_CONNECT
    int optval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                    (void *)&optval, sizeof(optval)) < 0)
        FATAL("failed to set TCP_FASTOPEN_CONNECT");
    s = connect(fd, addr, get_sockaddr_len(addr));
    if (s == 0)
        s = send(fd, buf, len, 0);
#elif MSG_FASTOPEN
    s = sendto(fd, buf, len, MSG_FASTOPEN, addr, get_sockaddr_len(addr));
#else
    FATAL("tcp fast open is not supported on this platform");
#endif
    return s;
}

int
get_sockaddr_r(const char *node,
               const char *service, uint16_t port,
               struct sockaddr_storage *storage,
               int resolv, int ipv6first)
{
    if (storage == NULL)
        return -1;

#ifdef __ANDROID__
    extern int vpn;
    assert(!vpn);   // DNS packet protection isn't supported yet
#endif
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,                 /* Return IPv4 and IPv6 choices */
        .ai_flags  = AI_PASSIVE | AI_ADDRCONFIG /* For wildcard IP address */
    };

    if (!resolv)
        hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;

    struct addrinfo *result, *rp;

    int err = getaddrinfo(node, service, &hints, &result);

    if (err != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(err));
        return -1;
    }

    int prefer_af = ipv6first ? AF_INET6 : AF_INET;
again:
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (prefer_af ? rp->ai_family == prefer_af : true) {
            storage->ss_family = rp->ai_family;
            switch (rp->ai_family) {
                case AF_INET: {
                    struct sockaddr_in *dst = (struct sockaddr_in *)storage;
                    struct sockaddr_in *src = (struct sockaddr_in *)rp->ai_addr;
                    dst->sin_addr = src->sin_addr;
                    dst->sin_port = elvis(src->sin_port, port);
                } break;
                case AF_INET6: {
                    struct sockaddr_in6 *dst = (struct sockaddr_in6 *)storage;
                    struct sockaddr_in6 *src = (struct sockaddr_in6 *)rp->ai_addr;
                    dst->sin6_addr = src->sin6_addr;
                    dst->sin6_port = elvis(src->sin6_port, port);
                } break;
            }
            break;
        }
    }

    if (prefer_af && rp == NULL) {
        prefer_af = 0;
        goto again;
    }

    if (rp == NULL) {
        LOGE("failed to resolve remote addr");
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

int
get_sockaddr_str(struct sockaddr_storage *storage,
                 char *host, char *port)
{
    if (storage != NULL) {
        uint8_t family = storage->ss_family;

        switch (family) {
            case AF_INET: {
                struct sockaddr_in *addr = (struct sockaddr_in *)storage;

                if (!inet_ntop(family, &addr->sin_addr, host, INET_ADDRSTRLEN)) {
                    LOGI("inet_ntop: %s", strerror(errno));
                    return -1;
                }
                sprintf(port, "%d", ntohs(addr->sin_port));
            } break;
            case AF_INET6: {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;

                if (!inet_ntop(family, &addr->sin6_addr, host, INET6_ADDRSTRLEN)) {
                    LOGI("inet_ntop: %s", strerror(errno));
                    return -1;
                }
                sprintf(port, "%d", ntohs(addr->sin6_port));
            } break;
            default:
                return -1;
        }
        return 0;
    }
    return -1;
}

char *
sockaddr_readable(char *format, struct sockaddr_storage *addr)
{
    int i, len = strlen(format);
    char *ret = ss_calloc(1, sizeof(char));
    char host[INET6_ADDRSTRLEN] = { 0 }, port[16] = { 0 };
    if (get_sockaddr_str(addr, host, port) != 0)
        return NULL;

    for (i = 0; i < len; i++) {
        char *substr = NULL;
        switch (format[i]) {
            case '%':
            if (i + 1 < len) {
                switch (format[++i]) {
                    case 'a': {
                        // IPv4/IPv6 address
                        if (addr->ss_family == AF_INET6
                            && i + 1 < len && format[i + 1] == ':')
                        {
                            substr = malloc(strlen(host) + 2);
                            sprintf(substr, "[%s]", host);
                        } else {
                            substr = host;
                        }
                    } break;
                    case 'p': {
                        //LOGI("sockaddr_readable >>> idx %d %s", i, port);
                        substr = port;  // port
                    } break;
                    default:
                        continue;
                }
            } break;
            default: {
                substr = (char[]){ format[i], 0 };
            } break;
        }

        size_t substrlen = strlen(substr);
        ret = realloc(ret, strlen(ret) + substrlen);
        strcat(ret, substr);
    }
    return ret;
}

int
sockaddr_cmp(struct sockaddr_storage *addr1,
             struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        /* just order it, ntohs not required */
        if (p1_in->sin_port < p2_in->sin_port)
            return -1;
        if (p1_in->sin_port > p2_in->sin_port)
            return 1;
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        /* just order it, ntohs not required */
        if (p1_in6->sin6_port < p2_in6->sin6_port)
            return -1;
        if (p1_in6->sin6_port > p2_in6->sin6_port)
            return 1;
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                  struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    if (verbose) {
        LOGI("sockaddr_cmp_addr: sin_family equal? %d", p1_in->sin_family == p2_in->sin_family);
    }
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
validate_hostname(const char *hostname, const int hostname_len)
{
    if (hostname == NULL)
        return 0;

    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *label = hostname;
    while (label < hostname + hostname_len) {
        size_t label_len = hostname_len - (label - hostname);
        char *next_dot   = strchr(label, '.');
        if (next_dot != NULL)
            label_len = next_dot - label;

        if (label + label_len > hostname + hostname_len)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, valid_label_bytes) < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}

char *
hostname_readable(char *dname, uint16_t port)
{
    static char ret[] = { 0 };
    sprintf(ret, "%s:%d", dname, ntohs(port));
    return ret;
}

int
is_addr_loopback(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
        case AF_INET:
            return ((struct sockaddr_in *)addr)->sin_addr.s_addr
                        == htonl(INADDR_LOOPBACK);
        case AF_INET6:
            return IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    return 0;
}

void
parse_addr_cidr(const char *str, char *host, int *cidr)
{
    int ret = -1;
    char *pch;

    pch = strchr(str, '/');
    while (pch != NULL) {
        ret = pch - str;
        pch = strchr(pch + 1, '/');
    }
    if (ret == -1) {
        strcpy(host, str);
        *cidr = -1;
    } else {
        memcpy(host, str, ret);
        host[ret] = '\0';
        *cidr     = atoi(str + ret + 1);
    }
}

int
port_service(uint16_t port)
{
    int *service = NULL;
    if (cache_lookup(port_cache,
                     &port, sizeof(port), &service) == 0) {
        return *service;
    }
    return PORT_SERVICE_UNKNOWN;
}

int
port_service_init(void)
{
    struct addrinfo *result, *rp;
    cache_create(&port_cache, -1, NULL);

    const ss_service_t *service_port = service_ports;
    do {
        char **svport = service_port->ports;
        do {
            int err = getaddrinfo(NULL, *svport, NULL, &result);

            if (err != 0) {
                LOGE("[%s] getaddrinfo: %s",
                     *svport, gai_strerror(err));
                return -1;
            }

            uint16_t port = 0;
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                switch (rp->ai_family) {
                    case AF_INET: {
                        port = ((struct sockaddr_in *)rp->ai_addr)->sin_port;
                    } break;
                    case AF_INET6: {
                        port = ((struct sockaddr_in6 *)rp->ai_addr)->sin6_port;
                    } break;
                }
                if (!cache_key_exist(port_cache, &port, sizeof(port))) {
                    int *service_type = ss_malloc(sizeof(*service_type));
                    *service_type = service_port->service;
                    cache_insert(port_cache, &port, sizeof(port), service_type);
                }
            }
            freeaddrinfo(result);
        } while (*++svport != NULL);
    } while ((++service_port)->ports != NULL);

    return 0;
}
