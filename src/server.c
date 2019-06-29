/*
 * server.c - Provide shadowsocks service
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#endif
#include <libcork/core.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "acl.h"
#include "plugin.h"
#include "winsock.h"
#include "relay.h"

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

#ifndef MAX_FRAG
#define MAX_FRAG 1
#endif

#ifdef USE_NFCONNTRACK_TOS

#ifndef MARK_MAX_PACKET
#define MARK_MAX_PACKET 10
#endif

#ifndef MARK_MASK_PREFIX
#define MARK_MASK_PREFIX 0xDC00
#endif

#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);

static remote_t *
connect_to_remote(EV_P_ server_t *server, struct sockaddr_storage *addr);

static void resolv_cb(struct sockaddr *addr, void *data);
static void resolv_free_cb(void *data);

int verbose = 0;
int acl = 0;
int no_delay = 0;
int fast_open = 0;
int ipv6first = 0;

static int ret_val   = 0;

static char *manager_addr = NULL;
uint64_t tx = 0, rx = 0;

#ifndef __MINGW32__
ev_timer stat_watcher;
#endif

struct ev_signal sigint_watcher;
struct ev_signal sigterm_watcher;
#ifndef __MINGW32__
struct ev_signal sigchld_watcher;
#endif

static struct cork_dllist listeners;

#ifndef __MINGW32__
static void
stat_update_cb(EV_P_ ev_timer *watcher, int revents)
{
    listen_ctx_t *listen_ctx
        = cork_container_of(watcher, listen_ctx_t, stat_watcher);
    struct sockaddr_storage addr;

    if (getsockname(listen_ctx->fd,
                    (struct sockaddr *)&addr, NULL) != 0) {
        return;
    }

    struct sockaddr_un svaddr, claddr;
    int sfd = -1;
    size_t msgLen;
    char resp[SOCKET_BUF_SIZE];

    if (verbose) {
        LOGI("update traffic stat: tx: %" PRIu64 " rx: %" PRIu64 "", tx, rx);
    }

    snprintf(resp, SOCKET_BUF_SIZE, "stat: {\"%s\":%" PRIu64 "}", sockaddr_readable("%p", &addr), tx + rx);
    msgLen = strlen(resp) + 1;

    ss_addr_t ip_addr = { .host = NULL, .port = NULL };
    parse_addr(manager_addr, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sfd == -1) {
            ERROR("stat_socket");
            return;
        }

        memset(&claddr, 0, sizeof(struct sockaddr_un));
        claddr.sun_family = AF_UNIX;
        snprintf(claddr.sun_path, sizeof(claddr.sun_path), "/tmp/shadowsocks.%s", sockaddr_readable("%p", &addr));

        unlink(claddr.sun_path);

        if (bind(sfd, (struct sockaddr *)&claddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("stat_bind");
            close(sfd);
            return;
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        strncpy(svaddr.sun_path, manager_addr, sizeof(svaddr.sun_path) - 1);

        if (sendto(sfd, resp, strlen(resp) + 1, 0, (struct sockaddr *)&svaddr,
                   sizeof(struct sockaddr_un)) != msgLen) {
            ERROR("stat_sendto");
            close(sfd);
            return;
        }

        unlink(claddr.sun_path);
    } else {
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(ip_addr.host, ip_addr.port, &storage, 1, ipv6first) == -1) {
            ERROR("failed to parse the manager addr");
            return;
        }

        sfd = socket(storage.ss_family, SOCK_DGRAM, 0);

        if (sfd == -1) {
            ERROR("stat_socket");
            return;
        }

        size_t addr_len = get_sockaddr_len((struct sockaddr *)&storage);
        if (sendto(sfd, resp, strlen(resp) + 1, 0, (struct sockaddr *)&storage,
                   addr_len) != msgLen) {
            ERROR("stat_sendto");
            close(sfd);
            return;
        }
    }

    close(sfd);
}

#endif

static void
free_listeners(struct ev_loop *loop)
{
    listen_ctx_t *listener = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&listeners, curr, next,
                        listen_ctx_t, listener, entries) {
        if (listener != NULL) {
#ifndef __MINGW32__
            if (manager_addr != NULL)
                ev_timer_stop(loop, &stat_watcher);
#endif
            ev_io_stop(loop, &listener->io);
            close(listener->fd);
        }
    }
}

static void
report_addr(EV_P_ server_t *server, const char *info)
{
    server->stage = STAGE_STOP;

    if (verbose) {
        struct sockaddr_storage addr = { 0 };
        socklen_t len = sizeof(struct sockaddr_storage);
        if (getpeername(server->fd, (struct sockaddr *)&addr, &len) == 0) {
            LOGE("failed to handshake with %s: %s", sockaddr_readable("%a", &addr), info);
        }
    }
}

static remote_t *
connect_to_remote(EV_P_ server_t *server,
                  struct sockaddr_storage *addr)
{
    listen_ctx_t *listen_ctx = server->listen_ctx;
    socklen_t addr_len = get_sockaddr_len((struct sockaddr *)addr);

    // initialize remote socks
    int sockfd = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (setnonblocking(sockfd) == -1)
        ERROR("setnonblocking");

    /*if (listen_ctx->addr) {
        socklen_t addrlen = 0;
        struct sockaddr_storage *storage = NULL;
        switch (listen_ctx->addr->ss_family) {
            case AF_INET:
                addrlen = sizeof(struct sockaddr_in);
                storage = (struct sockaddr_storage *)&(struct sockaddr_in) {
                    .sin_family = AF_INET,
                    .sin_addr = ((struct sockaddr_in *)listen_ctx->addr)->sin_addr
                };
                break;
            case AF_INET6:
                addrlen = sizeof(struct sockaddr_in6);
                storage = (struct sockaddr_storage *)&(struct sockaddr_in6) {
                    .sin6_family = AF_INET6,
                    .sin6_addr = ((struct sockaddr_in6 *)listen_ctx->addr)->sin6_addr,
                };
                break;
            default:
                return NULL;
        }

        if (bind(sockfd, (struct sockaddr *)storage, addrlen) != 0) {
            ERROR("bind");
            close(sockfd);
            return NULL;
        }
    } */

#ifdef SET_INTERFACE
    if (listen_ctx->iface) {
        if (setinterface(sockfd, listen_ctx->iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            return NULL;
        }
    }
#endif

    remote_t *remote = new_remote(sockfd);

    if (fast_open) {
        ssize_t s = sendto_idempotent(remote->fd,
                                      remote->buf->data + remote->buf->idx,
                                      remote->buf->len, (struct sockaddr *)remote->addr
#ifdef TCP_FASTOPEN_WINSOCK
                                      , &remote->olap, &remote->connect_ex_done
#endif
        );

        if (s == -1) {
            if (errno == CONNECT_IN_PROGRESS) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                       errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("fast_open_connect");
            }
        } else {
            server->buf->idx += s;
            server->buf->len -= s;
        }
    }

    if (!fast_open) {
        int r = connect(sockfd, (struct sockaddr *)addr, addr_len);

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            return NULL;
        }
    }

    return remote;
}

#ifdef USE_NFCONNTRACK_TOS
int
setMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    server_t *server            = (server_t *)data;
    struct dscptracker *tracker = server->tracker;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (setsockopt(server->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

void
conntrackQuery(server_t *server)
{
    struct dscptracker *tracker = server->tracker;
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, setMarkDscpCallback, (void *)server);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(errno));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

void
setTosFromConnmark(remote_t *remote, server_t *server)
{
    if (server->tracker && server->tracker->ct) {
        if (server->tracker->mark == 0 && server->tracker->packet_count < MARK_MAX_PACKET) {
            server->tracker->packet_count++;
            conntrackQuery(server);
        }
    } else {
        socklen_t len;
        struct sockaddr_storage sin;
        len = sizeof(sin);
        if (getsockname(remote->fd, (struct sockaddr *)&sin, &len) == 0) {
            struct sockaddr_storage from_addr;
            len = sizeof from_addr;
            if (getpeername(remote->fd, (struct sockaddr *)&from_addr, &len) == 0) {
                if ((server->tracker = (struct dscptracker *)ss_malloc(sizeof(struct dscptracker)))) {
                    if ((server->tracker->ct = nfct_new())) {
                        // Build conntrack query SELECT
                        if (from_addr.ss_family == AF_INET) {
                            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
                            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin_port);
                        } else if (from_addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
                            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET6);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin6_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin6_port);
                        }
                        nfct_set_attr_u8(server->tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
                        conntrackQuery(server);
                    } else {
                        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
                        server->tracker->ct = NULL;
                    }
                }
            }
        }
    }
}

#endif

void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    crypto_t *crypto              = server->crypto;
    remote_t *remote              = NULL;

    buffer_t *buf = server->buf;

    switch (server->stage) {
        case STAGE_STOP:
            return;
        case STAGE_STREAM: {
            remote = server->remote;
            buf    = remote->buf;

            // Only timer the watcher if a valid connection is established
            ev_timer_again(EV_A_ & server->recv_ctx->watcher);
        } break;
    }

    ssize_t r = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("server_recv close the connection");
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

    tx      += r;
    buf->len = r;

    int err = crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);

    switch (err) {
        case CRYPTO_ERROR:
            report_addr(EV_A_ server, "authentication error");
            return;
        case CRYPTO_NEED_MORE: {
            if (server->stage != STAGE_STREAM
                && server->frag > MAX_FRAG)
            {
                report_addr(EV_A_ server, "malicious fragmentation");
                return;
            }
            server->frag++;
        } return;
    }

    // handshake and transmit data
    switch (server->stage) {
        case STAGE_INIT: {
            ssocks_addr_t destaddr = { 0 };
            int offset = parse_ssocks_header(server->buf, &destaddr, 0);

            if (offset < 0) {
                report_addr(EV_A_ server, "invalid destination address");
                return;
            }

            if (server->buf->len < offset) {
                report_addr(EV_A_ server, "invalid request length");
                return;
            } else {
                server->buf->len -= offset;
                memmove(server->buf->data, server->buf->data + offset, server->buf->len);
            }

            if (destaddr.dname != NULL) {
                if (acl && search_acl(ACL_ATYP_DOMAIN, destaddr.dname, ACL_BLOCKLIST)) {
                    if (verbose)
                        LOGI("blocking access to %s", destaddr.dname);
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (verbose) {
                    LOGI("connecting to %s:%d", destaddr.dname, ntohs(destaddr.port));
                }

                ev_io_stop(EV_A_ & server_recv_ctx->io);

                query_t *query  = ss_calloc(1, sizeof(query_t));
                query->server   = server;
                query->hostname = destaddr.dname;

                server->stage = STAGE_RESOLVE;

                resolv_start(destaddr.dname, destaddr.port,
                             resolv_cb, resolv_free_cb, query);
            } else {
                if (acl && search_acl(ACL_ATYP_IP, destaddr.addr, ACL_BLOCKLIST)) {
                    if (verbose)
                        LOGI("blocking access to %s",
                             sockaddr_readable("%a:%p", destaddr.addr));
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (verbose) {
                    LOGI("connecting to %s",
                         sockaddr_readable("%a:%p", destaddr.addr));
                }
                remote_t *remote = connect_to_remote(EV_A_ server, destaddr.addr);

                if (remote == NULL) {
                    LOGE("connect error");
                    close_and_free_server(EV_A_ server);
                    return;
                } else {
                    server->remote = remote;
                    remote->server = server;

                    // XXX: should handle buffer carefully
                    if (server->buf->len > 0) {
                        brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
                        memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                               server->buf->len);
                        remote->buf->len = server->buf->len;
                        remote->buf->idx = 0;
                        server->buf->len = 0;
                        server->buf->idx = 0;
                    }

                    // waiting on remote connected event
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                }
            }
        } return;
        case STAGE_STREAM: {
            int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
            if (s == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // no data, wait for send
                    remote->buf->idx = 0;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                } else {
                    ERROR("server_recv_send");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
            } else if (s < remote->buf->len) {
                remote->buf->len -= s;
                remote->buf->idx  = s;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
        } return;
    }
    // should not reach here
    FATAL("server context error");
}

void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid server");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("server_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

static void
resolv_free_cb(void *data)
{
    query_t *query = (query_t *)data;

    if (query != NULL) {
        ss_free(query);
    }
}

static void
resolv_cb(struct sockaddr *addr, void *data)
{
    query_t *query   = (query_t *)data;
    server_t *server = query->server;

    if (server == NULL)
        return;

    struct ev_loop *loop = server->listen_ctx->loop;

    if (addr == NULL) {
        LOGE("unable to resolve %s", query->hostname);
        close_and_free_server(EV_A_ server);
    } else {
        if (verbose) {
            LOGI("successfully resolved %s", query->hostname);
        }

        remote_t *remote = connect_to_remote(EV_A_ server, (struct sockaddr_storage *)addr);

        if (remote == NULL) {
            close_and_free_server(EV_A_ server);
        } else {
            server->remote = remote;
            remote->server = server;

            // XXX: should handle buffer carefully
            if (server->buf->len > 0) {
                brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
                memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                       server->buf->len);
                remote->buf->len = server->buf->len;
                remote->buf->idx = 0;
                server->buf->len = 0;
                server->buf->idx = 0;
            }

            // listen to remote connected event
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    }
}

void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;
    crypto_t *crypto              = server->crypto;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("remote_recv close the connection");
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
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    rx += r;

    server->buf->len = r;
    int err = crypto->encrypt(server->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

#ifdef USE_NFCONNTRACK_TOS
    setTosFromConnmark(remote, server);
#endif
    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len       -= numBytes;
                    remote->buf->idx        = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);
        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            if (verbose) {
                LOGI("remote connected");
            }
            remote_send_ctx->connected = 1;

            if (remote->buf->len == 0) {
                server->stage = STAGE_STREAM;
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

    if (remote->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("remote_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
#endif
        case SIGINT:
        case SIGTERM:
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
#endif
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    struct sockaddr_storage addr;
    socklen_t len = sizeof(struct sockaddr_storage);
    memset(&addr, 0, len);
    int r = getpeername(serverfd, (struct sockaddr *)&addr, &len);

    if (r == 0) {
        if (acl && search_acl(ACL_ATYP_IP, &addr, ACL_UNSPCLIST))
        {
            if (verbose) {
                LOGE("blocking all requests from %s",
                     sockaddr_readable("%a", &addr));
            }
            return;
        }
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setnonblocking(serverfd);

    if (verbose) {
        LOGI("accepted a connection");
    }

    server_t *server = new_server(serverfd, listener);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int
main(int argc, char **argv)
{
    USE_TTY();
    srand(time(NULL));

    int i;
    int plugin_enabled = 0;
    int pid_flags = 0;
    jconf_t conf  = jconf_default;

    if (parse_argopts(&conf, argc, argv) != 0 ||
        !(conf.remotes != NULL && conf.remote_num > 0))
    {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf.log) {
        USE_LOGFILE(conf.log);
        LOGI("enabled %slogging %s", conf.verbose ? "verbose " : "", conf.log);
    }

    if (conf.mtu > 0) {
        LOGI("setting MTU to %d", conf.mtu);
    }

    if (conf.mptcp) {
        LOGI("enabled multipath TCP");
    }

    if (conf.no_delay) {
        LOGI("enabled TCP no-delay");
    }

    if (conf.mode != TCP_ONLY) {
        LOGI("UDP relay enabled");
    }

    if (conf.mode == UDP_ONLY) {
        LOGI("TCP relay disabled");
    }

    if (conf.ipv6_first) {
        LOGI("prioritized IPv6 addresses in domain resolution");
    }

    if (conf.acl != NULL) {
        LOGI("initializing acl...");
        acl = !init_acl(&conf);
    }

#ifdef HAVE_SETRLIMIT
    /*
     * No need to check the return value here.
     * We will show users an error message if setrlimit(2) fails.
     */
    if (conf.nofile > 1024) {
        if (conf.verbose) {
            LOGI("setting NOFILE to %d", conf.nofile);
        }
        set_nofile(conf.nofile);
    }
#endif

    if (conf.fast_open) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        conf.fast_open = 0;
#endif
    }

    pid_flags = conf.pid_path != NULL;
    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(conf.pid_path);
    }

    no_delay   = conf.no_delay;
    fast_open  = conf.fast_open;
    verbose    = conf.verbose;
    ipv6first  = conf.ipv6_first;
    manager_addr = conf.manager_addr;

#ifdef __MINGW32__
    winsock_init();
#endif

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);
#endif

    struct ev_loop *loop = EV_DEFAULT;
    resolv_init(loop, conf.nameserver, conf.ipv6_first);
    if (conf.nameserver != NULL)
        LOGI("using nameserver: %s", conf.nameserver);
    port_service_init();

    cork_dllist_init(&listeners);

    for (i = 0; i < conf.remote_num; i++) {
        ss_remote_t *r = conf.remotes[i];
        char *host     = r->addr,
             *port     = elvis(r->port, conf.remote_port),
             *password = elvis(r->password, conf.password),
             *key      = elvis(r->key, conf.key),
             *method   = elvis(r->method, conf.method),
             *iface    = elvis(r->iface, conf.iface),
             *plugin   = elvis(r->plugin, conf.plugin),
             *plugin_opts
                       = elvis(r->plugin_opts, conf.plugin_opts);

        if (port == NULL || method == NULL ||
            (password == NULL && key == NULL))
        {
            usage();
            exit(EXIT_FAILURE);
        }

        LOGI("[%d/%d] listening on %s:%s", i + 1, conf.remote_num, host, port);

        LOGI("initializing ciphers... %s", method);
        crypto_t *crypto = crypto_init(password, key, method);
        if (crypto == NULL)
            FATAL("failed to initialize ciphers");

        /**
         * "If node(host) is NULL, then the network address
         * will be set to the loopback interface address," meaning that
         * by default the server will bind to `lo' instead of 0.0.0.0.
         *
         * On Linux, when net.ipv6.bindv6only = 0 (the default),
         * getaddrinfo(NULL) with AI_PASSIVE returns 0.0.0.0 and :: (in this order).
         * AI_PASSIVE was meant to return a list of addresses to listen on,
         * but it is impossible to listen on 0.0.0.0 and :: at the same time,
         * unless `bindv6only' is enabled.
         */
        struct sockaddr_storage *storage =
                ss_calloc(1, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, conf.ipv6_first) == -1) {
            FATAL("failed to resolve %s", host);
        }

        if (plugin != NULL) {
            if (!plugin_enabled) {
                init_plugin(MODE_SERVER);
                plugin_enabled = 1;
            }

            uint16_t plugin_port = get_local_port();
            switch (storage->ss_family) {
                case AF_INET: {
                    *(struct sockaddr_in *)storage = (struct sockaddr_in) {
                        .sin_addr =
                            (struct in_addr) { htonl(INADDR_LOOPBACK) },
                        .sin_port = plugin_port
                    };
                } break;
                case AF_INET6: {
                    *(struct sockaddr_in6 *)storage = (struct sockaddr_in6) {
                        .sin6_addr = in6addr_loopback,
                        .sin6_port = plugin_port
                    };
                } break;
            }

            if (plugin_port == 0)
                FATAL("failed to find a free port");

            LOGI("plugin \"%s\" enabled", plugin);

            int err = start_plugin(plugin, plugin_opts,                 // user-defined plugin options
                                   sockaddr_readable("%a", storage),
                                   sockaddr_readable("%p", storage),    // plugin destination override
                                   host, port);
            if (err)
                FATAL("failed to start the plugin");
        }

        listen_ctx_t listen_ctx = {
            .iface   = iface,
            .addr    = storage,
            .crypto  = crypto,
            .timeout = atoi(conf.timeout),
            .loop    = loop
        };

#ifndef __MINGW32__
        if (conf.manager_addr != NULL) {
            ev_timer_init(&listen_ctx.stat_watcher, stat_update_cb,
                          UPDATE_INTERVAL, UPDATE_INTERVAL);
            ev_timer_start(EV_DEFAULT, &listen_ctx.stat_watcher);
        }
#endif

        if (conf.mode != UDP_ONLY) {
            int listenfd = bind_and_listen(storage, IPPROTO_TCP, &listen_ctx);
            if (listenfd != -1) {
                if (fast_open)
                    set_fastopen_passive(listenfd);
                ev_io_init(&listen_ctx.io, accept_cb, listen_ctx.fd, EV_READ);
                ev_io_start(loop, &listen_ctx.io);
                cork_dllist_add(&listeners, &listen_ctx.entries);
            }
        }

        // Setup UDP
        if (conf.mode != TCP_ONLY) {
            listen_ctx_t listen_ctx_dgram = listen_ctx;
            int listenfd = bind_and_listen(storage, IPPROTO_UDP, &listen_ctx_dgram);
            if ((listen_ctx_dgram.fd = listenfd) != -1) {
                init_udprelay(&listen_ctx_dgram);
            }
        }
    }

#ifndef __MINGW32__
    // setuid
    if (conf.user && !run_as(conf.user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // Init connections
    cork_dllist_init(&connections);

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

#ifndef __MINGW32__
    if (conf.manager_addr != NULL) {
        ev_timer_stop(loop, &stat_watcher);
    }
#endif

    if (plugin_enabled) {
        stop_plugin();
    }

    resolv_shutdown(loop);

    if (conf.mode != UDP_ONLY) {
        free_listeners(loop);
        free_connections(loop);
    }

    if (conf.mode != TCP_ONLY) {
        free_udprelay(loop);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return ret_val;
}
