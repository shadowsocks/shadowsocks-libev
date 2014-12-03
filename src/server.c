/*
 * server.c - Provide shadowsocks service
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "utils.h"
#include "server.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void server_resolve_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static struct remote * new_remote(int fd);
static struct server * new_server(int fd, struct listen_ctx *listener);
static struct remote *connect_to_remote(struct addrinfo *res,
                                        struct server *server);

static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);
static void free_server(struct server *server);
static void close_and_free_server(EV_P_ struct server *server);

int verbose = 0;
int udprelay = 0;
#ifdef TCP_FASTOPEN
static int fast_open = 0;
#endif
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
static int remote_conn = 0;
static int server_conn = 0;

static struct cork_dllist connections;

static void free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr;
    for (curr = cork_dllist_start(&connections);
         !cork_dllist_is_end(&connections, curr);
         curr = curr->next) {
        struct server *server = cork_container_of(curr, struct server, entries);
        struct remote *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#ifdef SET_INTERFACE
int setinterface(int socket_fd, const char * interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                         sizeof(struct ifreq));
    return res;
}
#endif

int create_and_bind(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#ifdef TCP_FASTOPEN
        if (fast_open) {
            opt = 5;
            int r = setsockopt(listen_sock, IPPROTO_TCP, TCP_FASTOPEN, &opt,
                               sizeof(opt));
            if (r == -1) {
                if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
                    LOGE("fast open is not supported on this platform");
                } else {
                    ERROR("setsockopt");
                }
            }
        }
#endif

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static struct remote *connect_to_remote(struct addrinfo *res,
                                        struct server *server)
{
    int sockfd;
#ifdef SET_INTERFACE
    const char *iface = server->listen_ctx->iface;
#endif

    // initilize remote socks
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

#ifdef SO_NOSIGPIPE
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct remote *remote = new_remote(sockfd);

    // setup remote socks
    setnonblocking(sockfd);
#ifdef SET_INTERFACE
    if (iface) {
        setinterface(sockfd, iface);
    }
#endif

#ifdef TCP_FASTOPEN
    if (fast_open) {
        ssize_t s = sendto(sockfd, server->buf + server->buf_idx,
                           server->buf_len, MSG_FASTOPEN, res->ai_addr,
                           res->ai_addrlen);
        if (s == -1) {
            if (errno == EINPROGRESS || errno == EAGAIN
                    || errno == EWOULDBLOCK) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                       errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = false;
                LOGE("fast open is not supported on this platform");
                connect(sockfd, res->ai_addr, res->ai_addrlen);
            } else {
                ERROR("sendto");
            }
        } else if (s < server->buf_len) {
            server->buf_idx += s;
            server->buf_len -= s;
        } else {
            server->buf_idx = 0;
            server->buf_len = 0;
        }
    } else
#endif
    connect(sockfd, res->ai_addr, res->ai_addrlen);

    return remote;
}

static void server_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
    struct server *server = server_recv_ctx->server;
    struct remote *remote = NULL;

    int len = server->buf_len;
    char **buf = &server->buf;

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    if (server->stage != 0) {
        remote = server->remote;
        buf = &remote->buf;
        len = 0;
    }

    ssize_t r = recv(server->fd, *buf + len, BUF_SIZE - len, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGD("server_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // handle incomplete header
    if (server->stage == 0) {
        r += server->buf_len;
        if (r <= enc_get_iv_len()) {
            // wait for more
            if (verbose) {
                LOGD("imcomplete header: %zu", r);
            }
            server->buf_len = r;
            return;
        } else {
            server->buf_len = 0;
        }
    }

    *buf = ss_decrypt(BUF_SIZE, *buf, &r, server->d_ctx);

    if (*buf == NULL) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    // handshake and transmit data
    if (server->stage == 5) {
        int s = send(remote->fd, remote->buf, r, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf_len = r;
                remote->buf_idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            } else {
                ERROR("server_recv_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < r) {
            remote->buf_len = r - s;
            remote->buf_idx = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
        return;

    } else if (server->stage == 0) {

        /*
         * Shadowsocks Protocol:
         *
         *    +------+----------+----------+
         *    | ATYP | DST.ADDR | DST.PORT |
         *    +------+----------+----------+
         *    |  1   | Variable |    2     |
         *    +------+----------+----------+
         */

        int offset = 0;
        char atyp = server->buf[offset++];
        char host[256] = { 0 };
        char port[64] = { 0 };

        // get remote addr and port
        if (atyp == 1) {
            // IP V4
            size_t in_addr_len = sizeof(struct in_addr);
            if (r > in_addr_len) {
                inet_ntop(AF_INET, (const void *)(server->buf + offset),
                          host, INET_ADDRSTRLEN);
                offset += in_addr_len;
            }
        } else if (atyp == 3) {
            // Domain name
            uint8_t name_len = *(uint8_t *)(server->buf + offset);
            if (name_len < r && name_len < 255 && name_len > 0) {
                memcpy(host, server->buf + offset + 1, name_len);
                offset += name_len + 1;
            }
        } else if (atyp == 4) {
            // IP V6
            size_t in6_addr_len = sizeof(struct in6_addr);
            if (r > in6_addr_len) {
                inet_ntop(AF_INET6, (const void *)(server->buf + offset),
                          host, INET6_ADDRSTRLEN);
                offset += in6_addr_len;
            }
        }

        if (offset == 1) {
            LOGE("invalid header with addr type %d", atyp);
            close_and_free_server(EV_A_ server);
            return;
        }

        sprintf(port, "%d",
                ntohs(*(uint16_t *)(server->buf + offset)));

        offset += 2;

        if (verbose) {
            LOGD("connect to: %s:%s", host, port);
        }

        struct addrinfo hints;
        asyncns_query_t *query;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        query = asyncns_getaddrinfo(server->listen_ctx->asyncns,
                                    host, port, &hints);

        if (query == NULL) {
            ERROR("asyncns_getaddrinfo");
            close_and_free_server(EV_A_ server);
            return;
        }

        asyncns_setuserdata(server->listen_ctx->asyncns, query, server);

        // XXX: should handle buffer carefully
        if (r > offset) {
            server->buf_len = r - offset;
            server->buf_idx = offset;
        }

        server->stage = 4;
        server->query = query;

        ev_io_stop(EV_A_ & server_recv_ctx->io);

        return;
    }
    // should not reach here
    FATAL("server context error.");
}

static void server_send_cb(EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;

    if (remote == NULL) {
        LOGE("invalid server.");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf_len == 0) {
        // close and free
        if (verbose) {
            LOGD("server_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                         server->buf_len, 0);
        if (s < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf_len) {
            // partly sent, move memory, wait for the next time to send
            server->buf_len -= s;
            server->buf_idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf_len = 0;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct server_ctx *server_ctx = (struct server_ctx *)(((void *)watcher)
                                                          - sizeof(ev_io));
    struct server *server = server_ctx->server;
    struct remote *remote = server->remote;

    LOGE("TCP connection timeout");

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void server_resolve_cb(EV_P_ ev_io *w, int revents)
{
    int err;
    struct addrinfo *result, *rp;
    struct listen_ctx *listen_ctx = (struct listen_ctx *)w;
    asyncns_t *asyncns = listen_ctx->asyncns;

    err = asyncns_handle(asyncns);
    if (err == ASYNCNS_HANDLE_AGAIN) {
        // try again
        return;
    } else if (err == ASYNCNS_HANDLE_ERROR) {
        // asyncns error
        FATAL("asyncns exit unexpectedly.");
    }

    asyncns_query_t *query = asyncns_getnext(asyncns);
    struct server *server =
        (struct server *)asyncns_getuserdata(asyncns, query);

    if (!asyncns_isdone(asyncns, query)) {
        // wait for reolver
        return;
    }

    server->query = NULL;

    if (verbose) {
        LOGD("asyncns resolved.");
    }

    err = asyncns_getaddrinfo_done(asyncns, query, &result);

    if (err) {
        ERROR("getaddrinfo");
        close_and_free_server(EV_A_ server);
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

        struct remote *remote = connect_to_remote(rp, server);

        if (remote == NULL) {
            LOGE("connect error.");
            close_and_free_server(EV_A_ server);
        } else {
            server->remote = remote;
            remote->server = server;

            // XXX: should handel buffer carefully
            if (server->buf_len > 0) {
                memcpy(remote->buf, server->buf + server->buf_idx,
                       server->buf_len);
                remote->buf_len = server->buf_len;
                remote->buf_idx = 0;
                server->buf_len = 0;
                server->buf_idx = 0;
            }

            // listen to remote connected event
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    }

    // release addrinfo
    asyncns_freeaddrinfo(result);
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server.");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGD("remote_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf = ss_encrypt(BUF_SIZE, server->buf, &r, server->e_ctx);

    if (server->buf == NULL) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(server->fd, server->buf, r, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
        return;
    } else if (s < r) {
        server->buf_len = r - s;
        server->buf_idx = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
        return;
    }
}

static void remote_send_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;
    struct server *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server.");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {

        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            if (verbose) {
                LOGD("remote connected.");
            }
            remote_send_ctx->connected = 1;

            if (remote->buf_len == 0) {
                server->stage = 5;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }

        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf_len == 0) {
        // close and free
        if (verbose) {
            LOGD("remote_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                         remote->buf_len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf_len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf_len -= s;
            remote->buf_idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf_len = 0;
            remote->buf_idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage == 4) {
                    server->stage = 5;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

static struct remote * new_remote(int fd)
{
    if (verbose) {
        remote_conn++;
    }

    struct remote *remote;
    remote = malloc(sizeof(struct remote));
    remote->buf = malloc(BUF_SIZE);
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->buf_len = 0;
    remote->buf_idx = 0;
    remote->server = NULL;
    return remote;
}

static void free_remote(struct remote *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        free(remote->buf);
    }
    free(remote->recv_ctx);
    free(remote->send_ctx);
    free(remote);
}

static void close_and_free_remote(EV_P_ struct remote *remote)
{
    if (remote != NULL) {
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
        if (verbose) {
            remote_conn--;
            LOGD("current remote connection: %d", remote_conn);
        }
    }
}

static struct server * new_server(int fd, struct listen_ctx *listener)
{
    if (verbose) {
        server_conn++;
    }

    struct server *server;
    server = malloc(sizeof(struct server));
    server->buf = malloc(BUF_SIZE);
    server->recv_ctx = malloc(sizeof(struct server_ctx));
    server->send_ctx = malloc(sizeof(struct server_ctx));
    server->fd = fd;
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  listener->timeout, listener->timeout * 5);
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    server->stage = 0;
    server->query = NULL;
    server->listen_ctx = listener;
    if (listener->method) {
        server->e_ctx = malloc(sizeof(struct enc_ctx));
        server->d_ctx = malloc(sizeof(struct enc_ctx));
        enc_ctx_init(listener->method, server->e_ctx, 1);
        enc_ctx_init(listener->method, server->d_ctx, 0);
    } else {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }
    server->buf_len = 0;
    server->buf_idx = 0;
    server->remote = NULL;

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void free_server(struct server *server)
{
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        cipher_context_release(&server->e_ctx->evp);
        free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        cipher_context_release(&server->d_ctx->evp);
        free(server->d_ctx);
    }
    if (server->buf != NULL) {
        free(server->buf);
    }
    free(server->recv_ctx);
    free(server->send_ctx);
    free(server);
}

static void close_and_free_server(EV_P_ struct server *server)
{
    if (server != NULL) {
        if (server->query != NULL) {
            asyncns_cancel(server->listen_ctx->asyncns, server->query);
            server->query = NULL;
        }
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        close(server->fd);
        free_server(server);
        if (verbose) {
            server_conn--;
            LOGD("current server connection: %d", server_conn);
        }
    }
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *)w;
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);

#ifdef SO_NOSIGPIPE
    int opt = 1;
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (verbose) {
        LOGD("accept a connection.");
    }

    struct server *server = new_server(serverfd, listener);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int main(int argc, char **argv)
{

    int i, c;
    int pid_flags = 0;
    char *user = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;

    int server_num = 0;
    const char *server_host[MAX_REMOTE_NUM];
    const char *server_port = NULL;

    int dns_thread_num = DNS_THREAD_NUM;

    int option_index = 0;
    static struct option long_options[] =
    {
        { "fast-open", no_argument, 0,           0 },
        { 0,           0,           0,           0 }
    };

    opterr = 0;

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:i:d:a:uv",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
#ifdef TCP_FASTOPEN
                fast_open = 1;
                LOGD("using tcp fast open");
#else
                LOGE("tcp fast open is not supported by this environment");
#endif
            }
            break;
        case 's':
            server_host[server_num++] = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            dns_thread_num = atoi(optarg);
            if (!dns_thread_num) {
                FATAL("Invalid DNS thread number");
            }
            break;
        case 'a':
            user = optarg;
            break;
        case 'u':
            udprelay = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++) {
                server_host[i] = conf->remote_addr[i].host;
            }
        }
        if (server_port == NULL) {
            server_port = conf->remote_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
#ifdef TCP_FASTOPEN
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#endif
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
        /*
         * no need to check the return value here since we will show
         * the user an error message if setrlimit(2) fails
         */
        if (nofile) {
            if (verbose) {
                LOGD("setting NOFILE to %d", nofile);
            }
            set_nofile(nofile);
        }
#endif
    }

    if (server_num == 0 || server_port == NULL || password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (timeout == NULL) {
        timeout = "60";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    // setup asyncns
    asyncns_t *asyncns;
    if (!(asyncns = asyncns_new(dns_thread_num))) {
        FATAL("asyncns failed");
    }

    // setup keys
    LOGD("initialize ciphers... %s", method);
    int m = enc_init(password, method);

    // inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // inilitialize listen context
    struct listen_ctx listen_ctx_list[server_num + 1];

    // bind to each interface
    while (server_num > 0) {
        int index = --server_num;
        const char * host = server_host[index];

        // Bind to port
        int listenfd;
        listenfd = create_and_bind(host, server_port);
        if (listenfd < 0) {
            FATAL("bind() error..");
        }
        if (listen(listenfd, SSMAXCONN) == -1) {
            FATAL("listen() error.");
        }
        setnonblocking(listenfd);
        LOGD("server listening at port %s.", server_port);

        struct listen_ctx *listen_ctx = &listen_ctx_list[index + 1];

        // Setup proxy context
        listen_ctx->timeout = atoi(timeout);
        listen_ctx->asyncns = asyncns;
        listen_ctx->fd = listenfd;
        listen_ctx->method = m;
        listen_ctx->iface = iface;

        ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx->io);
    }

    // initialize the DNS
    struct listen_ctx *listen_ctx = &listen_ctx_list[0];
    int asyncnsfd = asyncns_fd(asyncns);
    listen_ctx->timeout = atoi(timeout);
    listen_ctx->asyncns = asyncns;
    listen_ctx->fd = asyncnsfd;
    listen_ctx->method = m;
    listen_ctx->iface = iface;
    ev_io_init(&listen_ctx->io, server_resolve_cb, asyncnsfd, EV_READ);
    ev_io_start(loop, &listen_ctx->io);

    // Setup UDP
    if (udprelay) {
        LOGD("udprelay enabled.");
        init_udprelay(server_host[0], server_port, dns_thread_num, m,
                      listen_ctx->timeout, iface);
    }

    // setuid
    if (user != NULL) {
        run_as(user);
    }

    // Init connections
    cork_dllist_init(&connections);

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGD("closed nicely.");
    }

    // Clean up
    listen_ctx = &listen_ctx_list[0];
    ev_io_stop(loop, &listen_ctx->io);
    asyncns_free(listen_ctx->asyncns);
    close(listen_ctx->fd);

    for (int i = 1; i <= server_num; i++) {
        listen_ctx = &listen_ctx_list[i];
        ev_io_stop(loop, &listen_ctx->io);
        close(listen_ctx->fd);
    }

    free_connections(loop);

    if (udprelay) {
        free_udprelay();
    }

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}

