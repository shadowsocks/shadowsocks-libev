/*
 * udprelay.c - Setup UDP relay for both client and server
 *
 * Copyright (C) 2013 - 2014, Max Lv <max.c.lv@gmail.com>
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
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifndef __MINGW32__
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "utils.h"
#include "udprelay.h"
#include "cache.h"

#ifdef UDPRELAY_REMOTE
#define MAX_UDP_CONN_NUM 1024
#else
#define MAX_UDP_CONN_NUM 256
#endif

#ifdef UDPRELAY_REMOTE
#ifdef UDPRELAY_LOCAL
#error "UDPRELAY_REMOTE and UDPRELAY_LOCAL should not be both defined"
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define BUF_SIZE MAX_UDP_PACKET_SIZE

extern int verbose;

static struct server_ctx *server_ctx = NULL;
struct resolve_ctx *resolve_ctx = NULL;

#ifndef __MINGW32__
static int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

#ifdef SET_INTERFACE
static int setinterface(int socket_fd, const char * interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                         sizeof(struct ifreq));
    return res;
}
#endif

#if defined(UDPRELAY_REMOTE) && defined(SO_BROADCAST)
static int set_broadcast(int socket_fd)
{
    int opt = 1;
    return setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
}
#endif

#ifdef SO_NOSIGPIPE
static int set_nosigpipe(int socket_fd)
{
    int opt = 1;
    return setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
}
#endif

static char *hash_key(const char *header, const int header_len,
                      const struct sockaddr_storage *addr)
{
    char key[384];

    // calculate hash key
    // assert header_len < 256
    memset(key, 0, 384);
    memcpy(key, addr, sizeof(struct sockaddr_storage));
    memcpy(key + sizeof(struct sockaddr_storage), header, header_len);

    return (char *)enc_md5((const uint8_t *)key,
                           sizeof(struct sockaddr_storage) + header_len, NULL);
}

static int parse_udprealy_header(const char * buf, const int buf_len,
                                 char *host, char *port)
{

    const uint8_t atyp = *(uint8_t *)buf;
    int offset = 1;
    // get remote addr and port
    if (atyp == 1) {
        // IP V4
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf_len > in_addr_len) {
            if (host != NULL) {
                inet_ntop(AF_INET, (const void *)(buf + offset),
                          host, INET_ADDRSTRLEN);
            }
            offset += in_addr_len;
        }
    } else if (atyp == 3) {
        // Domain name
        uint8_t name_len = *(uint8_t *)(buf + offset);
        if (name_len < buf_len && name_len < 255 && name_len > 0) {
            if (host != NULL) {
                memcpy(host, buf + offset + 1, name_len);
            }
            offset += name_len + 1;
        }
    } else if (atyp == 4) {
        // IP V6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf_len > in6_addr_len) {
            if (host != NULL) {
                inet_ntop(AF_INET6, (const void *)(buf + offset),
                          host, INET6_ADDRSTRLEN);
            }
            offset += in6_addr_len;
        }
    }

    if (offset == 1) {
        LOGE("[udp] invalid header with addr type %d", atyp);
        return 0;
    }

    if (port != NULL) {
        sprintf(port, "%d", ntohs(*(uint16_t *)(buf + offset)));
    }
    offset += 2;

    return offset;
}

static char *get_addr_str(const struct sockaddr *sa)
{
    static char s[SS_ADDRSTRLEN];
    memset(s, 0, SS_ADDRSTRLEN);
    char addr[INET6_ADDRSTRLEN] = { 0 };
    char port[PORTSTRLEN] = { 0 };
    uint16_t p;

    switch (sa->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                  addr, INET_ADDRSTRLEN);
        p = ntohs(((struct sockaddr_in *)sa)->sin_port);
        sprintf(port, "%d", p);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                  addr, INET6_ADDRSTRLEN);
        p = ntohs(((struct sockaddr_in *)sa)->sin_port);
        sprintf(port, "%d", p);
        break;

    default:
        strncpy(s, "Unknown AF", SS_ADDRSTRLEN);
    }

    int addr_len = strlen(addr);
    int port_len = strlen(port);
    memcpy(s, addr, addr_len);
    memcpy(s + addr_len + 1, port, port_len);
    s[addr_len] = ':';

    return s;
}


int create_remote_socket(int ipv6)
{
    int remote_sock;

    if (ipv6) {
        // Try to bind IPv6 first
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = 0;
        remote_sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (remote_sock == -1) {
            ERROR("[udp] cannot create socket.");
            return -1;
        }
        if (bind(remote_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            FATAL("[udp] cannot bind remote.");
            return -1;
        }
    } else {
        // Or else bind to IPv4
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0;
        remote_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (remote_sock == -1) {
            ERROR("[udp] cannot create socket.");
            return -1;
        }

        if (bind(remote_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            FATAL("[udp] cannot bind remote.");
            return -1;
        }
    }
    return remote_sock;
}

int create_server_socket(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, server_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("[udp] getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        server_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        set_nosigpipe(remotefd);
#endif

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("[udp] bind");
        }

        close(server_sock);
    }

    if (rp == NULL) {
        LOGE("[udp] cannot bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

struct remote_ctx *new_remote(int fd, struct server_ctx *server_ctx)
{
    struct remote_ctx *ctx = malloc(sizeof(struct remote_ctx));
    memset(ctx, 0, sizeof(struct remote_ctx));
    ctx->fd = fd;
    ctx->server_ctx = server_ctx;
    ev_io_init(&ctx->io, remote_recv_cb, fd, EV_READ);
    ev_timer_init(&ctx->watcher, remote_timeout_cb, server_ctx->timeout,
                  server_ctx->timeout);
    return ctx;
}

struct server_ctx * new_server_ctx(int fd)
{
    struct server_ctx *ctx = malloc(sizeof(struct server_ctx));
    memset(ctx, 0, sizeof(struct server_ctx));
    ctx->fd = fd;
    ev_io_init(&ctx->io, server_recv_cb, fd, EV_READ);
    return ctx;
}

#ifdef UDPRELAY_REMOTE
struct query_ctx *new_query_ctx(asyncns_query_t *query,
                                const char *buf, const int buf_len)
{
    struct query_ctx *ctx = malloc(sizeof(struct query_ctx));
    memset(ctx, 0, sizeof(struct query_ctx));
    ctx->buf = malloc(buf_len);
    ctx->buf_len = buf_len;
    memcpy(ctx->buf, buf, buf_len);
    ctx->query = query;
    return ctx;
}

void close_and_free_query(EV_P_ struct query_ctx *ctx)
{
    if (ctx != NULL) {
        if (ctx->buf != NULL) {
            free(ctx->buf);
        }
        free(ctx);
    }
}

#endif

void close_and_free_remote(EV_P_ struct remote_ctx *ctx)
{
    if (ctx != NULL) {
        ev_timer_stop(EV_A_ & ctx->watcher);
        ev_io_stop(EV_A_ & ctx->io);
        close(ctx->fd);
        free(ctx);
    }
}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)(((void *)watcher)
                                                          - sizeof(ev_io));

    if (verbose) {
        LOGD("[udp] connection timeout");
    }

    char *key = hash_key(remote_ctx->addr_header,
                         remote_ctx->addr_header_len, &remote_ctx->src_addr);
    cache_remove(remote_ctx->server_ctx->conn_cache, key);
}

#ifdef UDPRELAY_REMOTE
static void query_resolve_cb(EV_P_ ev_io *w, int revents)
{
    int err;
    struct addrinfo *result, *rp;
    struct resolve_ctx *resolve_ctx = (struct resolve_ctx *)w;
    asyncns_t *asyncns = resolve_ctx->asyncns;

    err = asyncns_handle(asyncns);
    if (err == ASYNCNS_HANDLE_AGAIN) {
        // try again
        return;
    } else if (err == ASYNCNS_HANDLE_ERROR) {
        // asyncns error
        FATAL("[udp] asyncns exit unexpectedly.");
    }

    asyncns_query_t *query = asyncns_getnext(asyncns);
    struct query_ctx *query_ctx = (struct query_ctx *)asyncns_getuserdata(
        asyncns, query);

    if (!asyncns_isdone(asyncns, query)) {
        // wait reolver
        return;
    }

    if (verbose) {
        LOGD("[udp] asyncns resolved.");
    }

    query_ctx->query = NULL;

    err = asyncns_getaddrinfo_done(asyncns, query, &result);

    if (err) {
        ERROR("[udp] getaddrinfo");
    } else {
        // Use IPV4 address if possible
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) {
                break;
            }
        }

        if (rp == NULL) {
            rp = result;
        }

        int remotefd = create_remote_socket(rp->ai_family == AF_INET6);
        if (remotefd != -1) {
            setnonblocking(remotefd);
#ifdef SO_BROADCAST
            set_broadcast(remotefd);
#endif
#ifdef SO_NOSIGPIPE
            set_nosigpipe(remotefd);
#endif
#ifdef SET_INTERFACE
            if (query_ctx->server_ctx->iface) {
                setinterface(remotefd, query_ctx->server_ctx->iface);
            }
#endif

            struct remote_ctx *remote_ctx = new_remote(remotefd,
                                                       query_ctx->server_ctx);
            remote_ctx->src_addr = query_ctx->src_addr;
            remote_ctx->dst_addr = *((struct sockaddr_storage *)rp->ai_addr);
            remote_ctx->server_ctx = query_ctx->server_ctx;
            remote_ctx->addr_header_len = query_ctx->addr_header_len;
            memcpy(remote_ctx->addr_header, query_ctx->addr_header,
                   query_ctx->addr_header_len);

            size_t addr_len = sizeof(struct sockaddr_in);
            if (remote_ctx->dst_addr.ss_family == AF_INET6) {
                addr_len = sizeof(struct sockaddr_in6);
            }
            int s = sendto(remote_ctx->fd, query_ctx->buf, query_ctx->buf_len,
                           0, (struct sockaddr *)&remote_ctx->dst_addr,
                           addr_len);

            if (s == -1) {
                ERROR("[udp] sendto_remote");
                close_and_free_remote(EV_A_ remote_ctx);
            } else {
                // Add to conn cache
                char *key = hash_key(remote_ctx->addr_header,
                                     remote_ctx->addr_header_len,
                                     &remote_ctx->src_addr);
                cache_insert(query_ctx->server_ctx->conn_cache, key,
                             (void *)remote_ctx);

                ev_io_start(EV_A_ & remote_ctx->io);
            }

        } else {
            ERROR("[udp] bind() error..");
        }
    }

    // clean up
    asyncns_freeaddrinfo(result);
    close_and_free_query(EV_A_ query_ctx);
}
#endif

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)w;
    struct server_ctx *server_ctx = remote_ctx->server_ctx;

    // server has been closed
    if (server_ctx == NULL) {
        LOGE("[udp] invalid server.");
        close_and_free_remote(EV_A_ remote_ctx);
        return;
    }

    if (verbose) {
        LOGD("[udp] remote receive a packet");
    }

    // triger the timer
    ev_timer_again(EV_A_ & remote_ctx->watcher);

    struct sockaddr src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    char *buf = malloc(BUF_SIZE);

    // recv
    ssize_t buf_len = recvfrom(remote_ctx->fd, buf, BUF_SIZE, 0, &src_addr,
                               &src_addr_len);

    if (buf_len == -1) {
        // error on recv
        // simply drop that packet
        if (verbose) {
            ERROR("[udp] server_recvfrom");
        }
        goto CLEAN_UP;
    }

#ifdef UDPRELAY_LOCAL
    buf = ss_decrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);
    if (buf == NULL) {
        if (verbose) {
            ERROR("[udp] server_ss_decrypt_all");
        }
        goto CLEAN_UP;
    }

    int len = parse_udprealy_header(buf, buf_len, NULL, NULL);
    if (len == 0) {
        LOGD("[udp] error in parse header");
        // error in parse header
        goto CLEAN_UP;
    }
    // server may return using a different address type other than the type we
    // have used during sending

#ifdef UDPRELAY_TUNNEL
    // Construct packet
    buf_len -= len;
    memmove(buf, buf + len, buf_len);
#else
    // Construct packet
    char *tmpbuf = malloc(buf_len + 3);
    memset(tmpbuf, 0, 3);
    memcpy(tmpbuf + 3, buf, buf_len);
    free(buf);
    buf = tmpbuf;
    buf_len += 3;
#endif
#endif

#ifdef UDPRELAY_REMOTE

    unsigned int addr_header_len = remote_ctx->addr_header_len;

    // Construct packet
    char *tmpbuf = malloc(buf_len + addr_header_len);
    memcpy(tmpbuf, remote_ctx->addr_header, addr_header_len);
    memcpy(tmpbuf + addr_header_len, buf, buf_len);
    free(buf);
    buf = tmpbuf;
    buf_len += addr_header_len;

    buf = ss_encrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);
#endif

    size_t addr_len = sizeof(struct sockaddr_in);
    if (remote_ctx->src_addr.ss_family == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
    }
    int s = sendto(server_ctx->fd, buf, buf_len, 0,
                   (struct sockaddr *)&remote_ctx->src_addr, addr_len);

    if (s == -1) {
        ERROR("[udp] sendto_local");
    }

 CLEAN_UP:
    free(buf);

}

static void server_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_ctx = (struct server_ctx *)w;
    struct sockaddr_storage src_addr;
    char *buf = malloc(BUF_SIZE);

    socklen_t src_addr_len = sizeof(struct sockaddr_storage);
    unsigned int offset = 0;

    ssize_t buf_len =
        recvfrom(server_ctx->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&src_addr,
                 &src_addr_len);

    if (buf_len == -1) {
        // error on recv
        // simply drop that packet
        if (verbose) {
            ERROR("[udp] server_recvfrom");
        }
        goto CLEAN_UP;
    }

    if (verbose) {
        LOGD("[udp] server receive a packet.");
    }

#ifdef UDPRELAY_REMOTE
    buf = ss_decrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);
    if (buf == NULL) {
        if (verbose) {
            ERROR("[udp] server_ss_decrypt_all");
        }
        goto CLEAN_UP;
    }
#endif

#ifdef UDPRELAY_LOCAL
#ifndef UDPRELAY_TUNNEL
    uint8_t frag = *(uint8_t *)(buf + 2);
    offset += 3;
#endif
#endif

    /*
     *
     * SOCKS5 UDP Request
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * SOCKS5 UDP Response
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * shadowsocks UDP Request (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Response (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Request and Response (after encrypted)
     * +-------+--------------+
     * |   IV  |    PAYLOAD   |
     * +-------+--------------+
     * | Fixed |   Variable   |
     * +-------+--------------+
     *
     */

#ifdef UDPRELAY_TUNNEL
    char addr_header[256] = { 0 };
    char * host = server_ctx->tunnel_addr.host;
    char * port = server_ctx->tunnel_addr.port;
    int host_len = strlen(host);
    uint16_t port_num = (uint16_t)atoi(port);
    uint16_t port_net_num = htons(port_num);
    int addr_header_len = 2 + host_len + 2;

    // initialize the addr header
    addr_header[0] = 3;
    addr_header[1] = host_len;
    memcpy(addr_header + 2, host, host_len);
    memcpy(addr_header + 2 + host_len, &port_net_num, 2);

    // reconstruct the buffer
    char *tmp = malloc(buf_len + addr_header_len);
    memcpy(tmp, addr_header, addr_header_len);
    memcpy(tmp + addr_header_len, buf, buf_len);
    free(buf);
    buf = tmp;
    buf_len += addr_header_len;

#else
    char host[256] = { 0 };
    char port[64] = { 0 };

    int addr_header_len = parse_udprealy_header(buf + offset,
                                                buf_len - offset, host, port);
    if (addr_header_len == 0) {
        // error in parse header
        goto CLEAN_UP;
    }
    char *addr_header = buf + offset;
#endif

    char *key = hash_key(addr_header, addr_header_len, &src_addr);
    struct cache *conn_cache = server_ctx->conn_cache;

    struct remote_ctx *remote_ctx = NULL;
    cache_lookup(conn_cache, key, (void *)&remote_ctx);

    if (remote_ctx != NULL) {
        if (memcmp(&src_addr, &remote_ctx->src_addr, sizeof(src_addr))
            || strcmp(addr_header, remote_ctx->addr_header) != 0) {
            remote_ctx = NULL;
        }
    }

    if (remote_ctx == NULL) {
        if (verbose) {
            LOGD("[udp] cache missed: %s:%s <-> %s", host, port,
                 get_addr_str((struct sockaddr *)&src_addr));
        }
    } else {
        if (verbose) {
            LOGD("[udp] cache hit: %s:%s <-> %s", host, port,
                 get_addr_str((struct sockaddr *)&src_addr));
        }
    }

#ifdef UDPRELAY_LOCAL

#ifndef UDPRELAY_TUNNEL
    if (frag) {
        LOGE("[udp] drop a message since frag is not 0, but %d", frag);
        goto CLEAN_UP;
    }
#endif

    if (remote_ctx == NULL) {
        struct addrinfo hints;
        struct addrinfo *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;    /* Return IPv4 and IPv6 choices */
        hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

        int s = getaddrinfo(server_ctx->remote_host, server_ctx->remote_port,
                            &hints, &result);
        if (s != 0 || result == NULL) {
            LOGE("[udp] getaddrinfo: %s", gai_strerror(s));
            goto CLEAN_UP;
        }

        // Bind to any port
        int remotefd = create_remote_socket(result->ai_family == AF_INET6);
        if (remotefd < 0) {
            ERROR("[udp] udprelay bind() error..");
            // remember to free addrinfo
            freeaddrinfo(result);
            goto CLEAN_UP;
        }
        setnonblocking(remotefd);

#ifdef SO_NOSIGPIPE
        set_nosigpipe(remotefd);
#endif
#ifdef SET_INTERFACE
        if (server_ctx->iface) {
            setinterface(remotefd, server_ctx->iface);
        }
#endif

        // Init remote_ctx
        remote_ctx = new_remote(remotefd, server_ctx);
        remote_ctx->src_addr = src_addr;
        remote_ctx->dst_addr = *((struct sockaddr_storage *)result->ai_addr);
        remote_ctx->addr_header_len = addr_header_len;
        memcpy(remote_ctx->addr_header, addr_header, addr_header_len);

        // Add to conn cache
        cache_insert(conn_cache, key, (void *)remote_ctx);

        // Start remote io
        ev_io_start(EV_A_ & remote_ctx->io);

        // clean up
        freeaddrinfo(result);
    }

    if (offset > 0) {
        buf_len -= offset;
        memmove(buf, buf + offset, buf_len);
    }

    buf = ss_encrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);

    size_t addr_len = sizeof(struct sockaddr_in);
    if (remote_ctx->dst_addr.ss_family == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
    }
    int s = sendto(remote_ctx->fd, buf, buf_len, 0,
                   (struct sockaddr *)&remote_ctx->dst_addr, addr_len);

    if (s == -1) {
        ERROR("[udp] sendto_remote");
    }

#else

    if (remote_ctx == NULL) {
        struct addrinfo hints;
        asyncns_query_t *query;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        query = asyncns_getaddrinfo(server_ctx->asyncns,
                                    host, port, &hints);

        if (query == NULL) {
            ERROR("[udp] asyncns_getaddrinfo");
            goto CLEAN_UP;
        }

        struct query_ctx *query_ctx = new_query_ctx(query,
                                                    buf + addr_header_len,
                                                    buf_len - addr_header_len);
        query_ctx->server_ctx = server_ctx;
        query_ctx->addr_header_len = addr_header_len;
        query_ctx->src_addr = src_addr;
        memcpy(query_ctx->addr_header, addr_header, addr_header_len);
        asyncns_setuserdata(server_ctx->asyncns, query, query_ctx);
    } else {
        size_t addr_len = sizeof(struct sockaddr_in);
        if (remote_ctx->dst_addr.ss_family == AF_INET6) {
            addr_len = sizeof(struct sockaddr_in6);
        }
        int s = sendto(remote_ctx->fd, buf + addr_header_len,
                       buf_len - addr_header_len, 0,
                       (struct sockaddr *)&remote_ctx->dst_addr, addr_len);

        if (s == -1) {
            ERROR("[udp] sendto_remote");
        }
    }
#endif

 CLEAN_UP:
    free(buf);

}

void free_cb(void *element)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)element;

    if (verbose) {
        LOGD("[udp] free a remote context");
    }

    close_and_free_remote(EV_DEFAULT, remote_ctx);
}

int init_udprelay(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
                  const char *remote_host, const char *remote_port,
#ifdef UDPRELAY_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
#ifdef UDPRELAY_REMOTE
                  int dns_thread_num,
#endif
                  int method, int timeout, const char *iface)
{
    // Inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // Inilitialize cache
    struct cache *conn_cache;
    cache_create(&conn_cache, MAX_UDP_CONN_NUM, free_cb);

    //////////////////////////////////////////////////
    // Setup server context

#ifdef UDPRELAY_REMOTE
    // setup asyncns
    asyncns_t *asyncns;
    if (!(asyncns = asyncns_new(dns_thread_num))) {
        FATAL("[udp] asyncns failed");
    }
    resolve_ctx = malloc(sizeof(struct resolve_ctx));

    int asyncnsfd = asyncns_fd(asyncns);
    ev_io_init(&resolve_ctx->io, query_resolve_cb, asyncnsfd, EV_READ);
    ev_io_start(loop, &resolve_ctx->io);

    resolve_ctx->asyncns = asyncns;
    resolve_ctx->asyncnsfd = asyncnsfd;
#endif

    // Bind to port
    int serverfd = create_server_socket(server_host, server_port);
    if (serverfd < 0) {
        FATAL("[udp] bind() error..");
    }
    setnonblocking(serverfd);

    server_ctx = new_server_ctx(serverfd);
    server_ctx->timeout = timeout;
    server_ctx->method = method;
    server_ctx->iface = iface;
    server_ctx->conn_cache = conn_cache;
#ifdef UDPRELAY_LOCAL
    server_ctx->remote_host = remote_host;
    server_ctx->remote_port = remote_port;
#ifdef UDPRELAY_TUNNEL
    server_ctx->tunnel_addr = tunnel_addr;
#endif
#endif
#ifdef UDPRELAY_REMOTE
    server_ctx->asyncns = asyncns;
#endif

    ev_io_start(loop, &server_ctx->io);

    return 0;
}

void free_udprelay()
{
    struct ev_loop *loop = EV_DEFAULT;
#ifdef UDPRELAY_REMOTE
    if (resolve_ctx != NULL) {
        ev_io_stop(loop, &resolve_ctx->io);
        asyncns_free(resolve_ctx->asyncns);

        close(resolve_ctx->asyncnsfd);
        free(resolve_ctx);
        resolve_ctx = NULL;
    }
#endif
    if (server_ctx != NULL) {
        ev_io_stop(loop, &server_ctx->io);
        close(server_ctx->fd);
        cache_delete(server_ctx->conn_cache, 0);
        free(server_ctx);
        server_ctx = NULL;
    }
}
