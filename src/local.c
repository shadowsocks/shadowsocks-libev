/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
 *
 * Copyright (C) 2013 - 2017, Max Lv <max.c.lv@gmail.com>
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
#include <unistd.h>
#include <getopt.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>

#ifdef LIB_ONLY
#include <pthread.h>
#include "shadowsocks.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>
#include <udns.h>

#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "http.h"
#include "tls.h"
#include "plugin.h"
#include "local.h"

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

int verbose        = 0;
int reuse_port     = 0;
int keep_resolving = 1;

#ifdef __ANDROID__
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;
#endif

static crypto_t *crypto;

static int acl       = 0;
static int mode      = TCP_ONLY;
static int ipv6first = 0;
static int fast_open = 0;
static int udp_fd    = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;
static struct ev_signal sigusr1_watcher;

#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void signal_cb(EV_P_ ev_signal *w, int revents);

static int create_and_bind(const char *addr, const char *port);
#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr);
static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static struct cork_dllist connections;

int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    result = NULL;

    s = getaddrinfo(addr, port, &hints, &result);

    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
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
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}
#endif

static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server = cork_container_of(watcher, server_t,
                                         delayed_connect_watcher);

    server->stage = STAGE_WAIT;
    server_recv_cb(EV_A_ & server->recv_ctx->io, revents);
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf;
    ssize_t r;

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    if (server->stage != STAGE_WAIT) {
        r = recv(server->fd, buf->data + buf->len, BUF_SIZE - buf->len, 0);

        if (r == 0) {
            // connection closed
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                if (verbose)
                    ERROR("server_recv_cb_recv");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
        buf->len += r;
    } else {
        server->stage = STAGE_STREAM;
    }

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            if (remote == NULL) {
                LOGE("invalid remote");
                close_and_free_server(EV_A_ server);
                return;
            }

            ev_timer_stop(EV_A_ & server->delayed_connect_watcher);

            // insert shadowsocks header
            if (!remote->direct) {
#ifdef __ANDROID__
                tx += remote->buf->len;
#endif
                int err = crypto->encrypt(remote->buf, server->e_ctx, BUF_SIZE);

                if (err) {
                    LOGE("invalid password or cipher");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }

                if (server->abuf) {
                    bprepend(remote->buf, server->abuf, BUF_SIZE);
                    bfree(server->abuf);
                    ss_free(server->abuf);
                    server->abuf = NULL;
                }
            }

            if (!remote->send_ctx->connected) {
#ifdef __ANDROID__
                if (vpn) {
                    int not_protect = 0;
                    if (remote->addr.ss_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
                        if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                            not_protect = 1;
                    }
                    if (!not_protect) {
                        if (protect_socket(remote->fd) == -1) {
                            ERROR("protect_socket");
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    }
                }
#endif

                remote->buf->idx = 0;

                if (!fast_open || remote->direct) {
                    // connecting, wait until connected
                    int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

                    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                        ERROR("connect");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }

                    // wait on remote connected event
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                } else {
#ifdef TCP_FASTOPEN
#ifdef __APPLE__
                    ((struct sockaddr_in *)&(remote->addr))->sin_len = sizeof(struct sockaddr_in);
                    sa_endpoints_t endpoints;
                    memset((char *)&endpoints, 0, sizeof(endpoints));
                    endpoints.sae_dstaddr    = (struct sockaddr *)&(remote->addr);
                    endpoints.sae_dstaddrlen = remote->addr_len;

                    int s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                                     CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                                     NULL, 0, NULL, NULL);
                    if (s == 0) {
                        s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                    }
#else
                    int s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN,
                                   (struct sockaddr *)&(remote->addr), remote->addr_len);
#endif
                    if (s == -1) {
                        if (errno == CONNECT_IN_PROGRESS) {
                            // in progress, wait until connected
                            remote->buf->idx = 0;
                            ev_io_stop(EV_A_ & server_recv_ctx->io);
                            ev_io_start(EV_A_ & remote->send_ctx->io);
                            return;
                        } else {
                            ERROR("sendto");
                            if (errno == ENOTCONN) {
                                LOGE("fast open is not supported on this platform");
                                // just turn it off
                                fast_open = 0;
                            }
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    } else if (s < (int)(remote->buf->len)) {
                        remote->buf->len -= s;
                        remote->buf->idx  = s;

                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                        return;
                    } else {
                        // Just connected
                        remote->buf->idx = 0;
                        remote->buf->len = 0;
#ifdef __APPLE__
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
#else
                        remote->send_ctx->connected = 1;
                        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
                        ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
                        ev_io_start(EV_A_ & remote->recv_ctx->io);
                        return;
#endif
                    }
#else
                    // if TCP_FASTOPEN is not defined, fast_open will always be 0
                    LOGE("can't come here");
                    exit(1);
#endif
                }
            } else {
                int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                if (s == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // no data, wait for send
                        remote->buf->idx = 0;
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        return;
                    } else {
                        ERROR("server_recv_cb_send");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }
                } else if (s < (int)(remote->buf->len)) {
                    remote->buf->len -= s;
                    remote->buf->idx  = s;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                } else {
                    remote->buf->idx = 0;
                    remote->buf->len = 0;
                }
            }

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            if (buf->len < sizeof(struct method_select_request) + 1) {
                return;
            }
            struct method_select_request *method = (struct method_select_request *)buf->data;
            int method_len = method->nmethods + sizeof(struct method_select_request);
            if (buf->len < method_len) {
                return;
            }
            struct method_select_response response;
            response.ver    = SVERSION;
            response.method = 0;
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, sizeof(response), 0);
            server->stage = STAGE_HANDSHAKE;

            if (method->ver == SVERSION && method_len < (int)(buf->len)) {
                memmove(buf->data, buf->data + method_len , buf->len - method_len);
                buf->len -= method_len;
                continue;
            }

            buf->len = 0;
            return;
        } else if (server->stage == STAGE_HANDSHAKE || server->stage == STAGE_PARSE) {
            struct socks5_request *request = (struct socks5_request *)buf->data;
            size_t request_len = sizeof(struct socks5_request);
            struct sockaddr_in sock_addr;
            memset(&sock_addr, 0, sizeof(sock_addr));

            if (buf->len < request_len) {
                return;
            }

            int udp_assc = 0;

            if (request->cmd == 3) {
                udp_assc = 1;
                socklen_t addr_len = sizeof(sock_addr);
                getsockname(udp_fd, (struct sockaddr *)&sock_addr,
                            &addr_len);
                if (verbose) {
                    LOGI("udp assc request accepted");
                }
            } else if (request->cmd != 1) {
                LOGE("unsupported cmd: %d", request->cmd);
                struct socks5_response response;
                response.ver  = SVERSION;
                response.rep  = CMD_NOT_SUPPORTED;
                response.rsv  = 0;
                response.atyp = 1;
                char *send_buf = (char *)&response;
                send(server->fd, send_buf, 4, 0);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            // Fake reply
            if (server->stage == STAGE_HANDSHAKE) {
                struct socks5_response response;
                response.ver  = SVERSION;
                response.rep  = 0;
                response.rsv  = 0;
                response.atyp = 1;

                buffer_t resp_to_send;
                buffer_t *resp_buf = &resp_to_send;
                balloc(resp_buf, BUF_SIZE);

                memcpy(resp_buf->data, &response, sizeof(struct socks5_response));
                memcpy(resp_buf->data + sizeof(struct socks5_response),
                       &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
                memcpy(resp_buf->data + sizeof(struct socks5_response) +
                       sizeof(sock_addr.sin_addr),
                       &sock_addr.sin_port, sizeof(sock_addr.sin_port));

                int reply_size = sizeof(struct socks5_response) +
                                 sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

                int s = send(server->fd, resp_buf->data, reply_size, 0);

                bfree(resp_buf);

                if (s < reply_size) {
                    LOGE("failed to send fake reply");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (udp_assc) {
                    // Wait until client closes the connection
                    return;
                }
            }

            char host[257], ip[INET6_ADDRSTRLEN], port[16];

            buffer_t *abuf = server->abuf;
            abuf->idx = 0;
            abuf->len = 0;

            abuf->data[abuf->len++] = request->atyp;
            int atyp = request->atyp;

            // get remote addr and port
            if (atyp == 1) {
                // IP V4
                size_t in_addr_len = sizeof(struct in_addr);
                if (buf->len < request_len + in_addr_len + 2) {
                    return;
                }
                memcpy(abuf->data + abuf->len, buf->data + request_len, in_addr_len + 2);
                abuf->len += in_addr_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(buf->data + request_len + in_addr_len));
                    dns_ntop(AF_INET, (const void *)(buf->data + request_len),
                             ip, INET_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
            } else if (atyp == 3) {
                // Domain name
                uint8_t name_len = *(uint8_t *)(buf->data + request_len);
                if (buf->len < request_len + 1 + name_len + 2) {
                    return;
                }
                abuf->data[abuf->len++] = name_len;
                memcpy(abuf->data + abuf->len, buf->data + request_len + 1, name_len + 2);
                abuf->len += name_len + 2;

                if (acl || verbose) {
                    uint16_t p =
                        ntohs(*(uint16_t *)(buf->data + request_len + 1 + name_len));
                    memcpy(host, buf->data + request_len + 1, name_len);
                    host[name_len] = '\0';
                    sprintf(port, "%d", p);

                }
            } else if (atyp == 4) {
                // IP V6
                size_t in6_addr_len = sizeof(struct in6_addr);
                if (buf->len < request_len + in6_addr_len + 2) {
                    return;
                }
                memcpy(abuf->data + abuf->len, buf->data + request_len, in6_addr_len + 2);
                abuf->len += in6_addr_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(buf->data + request_len + in6_addr_len));
                    dns_ntop(AF_INET6, (const void *)(buf->data + request_len),
                             ip, INET6_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
            } else {
                LOGE("unsupported addrtype: %d", request->atyp);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            size_t abuf_len  = abuf->len;
            int sni_detected = 0;

            if (atyp == 1 || atyp == 4) {
                char *hostname;
                uint16_t p = ntohs(*(uint16_t *)(abuf->data + abuf->len - 2));
                int ret    = 0;
                if (p == http_protocol->default_port)
                    ret = http_protocol->parse_packet(buf->data + 3 + abuf->len,
                                                      buf->len - 3 - abuf->len, &hostname);
                else if (p == tls_protocol->default_port)
                    ret = tls_protocol->parse_packet(buf->data + 3 + abuf->len,
                                                     buf->len - 3 - abuf->len, &hostname);
                if (ret == -1 && buf->len < BUF_SIZE) {
                    server->stage = STAGE_PARSE;
                    return;
                } else if (ret > 0) {
                    sni_detected = 1;

                    // Reconstruct address buffer
                    abuf->len               = 0;
                    abuf->data[abuf->len++] = 3;
                    abuf->data[abuf->len++] = ret;
                    memcpy(abuf->data + abuf->len, hostname, ret);
                    abuf->len += ret;
                    p          = htons(p);
                    memcpy(abuf->data + abuf->len, &p, 2);
                    abuf->len += 2;

                    if (acl || verbose) {
                        memcpy(host, hostname, ret);
                        host[ret] = '\0';
                    }

                    ss_free(hostname);
                }
            }

            server->stage = STAGE_STREAM;

            buf->len -= (3 + abuf_len);
            if (buf->len > 0) {
                memmove(buf->data, buf->data + 3 + abuf_len, buf->len);
            }

            if (verbose) {
                if (sni_detected || atyp == 3)
                    LOGI("connect to %s:%s", host, port);
                else if (atyp == 1)
                    LOGI("connect to %s:%s", ip, port);
                else if (atyp == 4)
                    LOGI("connect to [%s]:%s", ip, port);
            }

            if (acl
#ifdef __ANDROID__
                    && !(vpn && strcmp(port, "53") == 0)
#endif
                    ) {
                int host_match = acl_match_host(host);
                int bypass = 0;
                int resolved = 0;
                struct sockaddr_storage storage;
                memset(&storage, 0, sizeof(struct sockaddr_storage));
                int err;

                if (host_match > 0)
                    bypass = 1;                 // bypass hostnames in black list
                else if (host_match < 0)
                    bypass = 0;                 // proxy hostnames in white list
                else {
#ifndef __ANDROID__
                    if (atyp == 3) {            // resolve domain so we can bypass domain with geoip
                        err = get_sockaddr(host, port, &storage, 0, ipv6first);
                        if (err != -1) {
                            resolved = 1;
                            switch(((struct sockaddr*)&storage)->sa_family) {
                                case AF_INET: {
                                    struct sockaddr_in *addr_in = (struct sockaddr_in *)&storage;
                                    dns_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
                                    break;
                                }
                                case AF_INET6: {
                                    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&storage;
                                    dns_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
                                    break;
                                }
                                default:
                                    break;
                            }
                        }
                    }
#endif
                    int ip_match = acl_match_host(ip);
                    switch (get_acl_mode()) {
                        case BLACK_LIST:
                            if (ip_match > 0)
                                bypass = 1;               // bypass IPs in black list
                            break;
                        case WHITE_LIST:
                            bypass = 1;
                            if (ip_match < 0)
                                bypass = 0;               // proxy IPs in white list
                            break;
                    }
                }

                if (bypass) {
                    if (verbose) {
                        if (sni_detected || atyp == 3)
                            LOGI("bypass %s:%s", host, port);
                        else if (atyp == 1)
                            LOGI("bypass %s:%s", ip, port);
                        else if (atyp == 4)
                            LOGI("bypass [%s]:%s", ip, port);
                    }
#ifndef __ANDROID__
                    if (atyp == 3 && resolved != 1)
                        err = get_sockaddr(host, port, &storage, 0, ipv6first);
                    else
#endif
                        err = get_sockaddr(ip, port, &storage, 0, ipv6first);
                    if (err != -1) {
                        remote = create_remote(server->listener, (struct sockaddr *)&storage);
                        if (remote != NULL)
                            remote->direct = 1;
                    }
                }
            }

            // Not match ACL
            if (remote == NULL) {
                remote = create_remote(server->listener, NULL);
            }

            if (remote == NULL) {
                LOGE("invalid remote addr");
                close_and_free_server(EV_A_ server);
                return;
            }

            if (!remote->direct) {
                int err = crypto->encrypt(abuf, server->e_ctx, BUF_SIZE);
                if (err) {
                    LOGE("invalid password or cipher");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            if (buf->len > 0) {
                memcpy(remote->buf->data, buf->data, buf->len);
                remote->buf->len = buf->len;
            }

            server->remote = remote;
            remote->server = server;

            ev_timer_start(EV_A_ & server->delayed_connect_watcher);

            return;
        }
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

#ifdef __ANDROID__
void
stat_update_cb()
{
    ev_tstamp now = ev_time();
    if (now - last > 0.5) {
        send_traffic_stat(tx, rx);
        last = now;
    }
}

#endif

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
#ifdef __ANDROID__
        rx += server->buf->len;
        stat_update_cb();
#endif
        int err = crypto->decrypt(server->buf, server->d_ctx, BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (err == CRYPTO_NEED_MORE) {
            return; // Wait for more
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < (int)(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        remote->recv_ctx->connected = 1;
    }
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (!remote_send_ctx->connected) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0) {
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
        } else {
            // not connected
            ERROR("getpeername");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote;
    remote = ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                  timeout, timeout);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd)
{
    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    server->abuf     = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, BUF_SIZE);
    balloc(server->abuf, BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->stage               = STAGE_INIT;
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->send_ctx->server    = server;

    server->e_ctx = ss_align(sizeof(cipher_ctx_t));
    server->d_ctx = ss_align(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher,
            delayed_connect_cb, 0.05, 0);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->abuf != NULL) {
        bfree(server->abuf);
        ss_free(server->abuf);
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->delayed_connect_watcher);
        close(server->fd);
        free_server(server);
    }
}

static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr)
{
    struct sockaddr *remote_addr;

    int index = rand() % listener->remote_num;
    if (addr == NULL) {
        remote_addr = listener->remote_addr[index];
    } else {
        remote_addr = addr;
    }

    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (listener->mptcp > 1) {
        int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable multipath TCP");
        }
    }

    // Setup
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    if (listener->iface) {
        if (setinterface(remotefd, listener->iface) == -1)
            ERROR("setinterface");
    }
#endif

    remote_t *remote = new_remote(remotefd, listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);

    return remote;
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGCHLD:
            if (!is_plugin_running())
                LOGE("plugin service exit unexpectedly");
            else
                return;
        case SIGUSR1:
        case SIGINT:
        case SIGTERM:
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
            ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
            keep_resolving = 0;
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    server_t *server = new_server(serverfd);
    server->listener = listener;

    ev_io_start(EV_A_ & server->recv_ctx->io);
}

#ifndef LIB_ONLY
int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mtu          = 0;
    int mptcp        = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password   = NULL;
    char *key        = NULL;
    char *timeout    = NULL;
    char *method     = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;
    char *iface      = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    srand(time(NULL));

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    static struct option long_options[] = {
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT },
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN },
        { "acl",         required_argument, NULL, GETOPT_VAL_ACL },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP },
        { NULL,          0,                 NULL, 0 }
    };

    opterr = 0;

    USE_TTY();

#ifdef __ANDROID__
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUvV6A",
                            long_options, NULL)) != -1) {
#else
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUv6A",
                            long_options, NULL)) != -1) {
#endif
        switch (c) {
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_ACL:
            LOGI("initializing acl...");
            acl = !init_acl(optarg);
            break;
        case GETOPT_VAL_MTU:
            mtu = atoi(optarg);
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = 1;
            LOGI("enable multipath TCP");
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host   = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
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
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
        case GETOPT_VAL_HELP:
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
#ifdef __ANDROID__
        case 'V':
            vpn = 1;
            break;
#endif
        case 'A':
            FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = DEFAULT_CONF_PATH;
        }
    }
    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
    }

    if (remote_num == 0 || remote_port == NULL ||
#ifndef HAVE_LAUNCHD
        local_port == NULL ||
#endif
        (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        plugin_host = "127.0.0.1";
        plugin_port = tmp_port;

        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (method == NULL) {
        method = "rc4-md5";
    }

    if (timeout == NULL) {
        timeout = "60";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (plugin != NULL) {
        int len = 0;
        size_t buf_size = 256 * remote_num;
        char *remote_str = ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", remote_addr[0].host);
        len = strlen(remote_str);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", remote_addr[i].host);
            len = strlen(remote_str);
        }
        int err = start_plugin(plugin, plugin_opts, remote_str,
                remote_port, plugin_host, plugin_port, MODE_CLIENT);
        if (err) {
            FATAL("failed to start the plugin");
        }
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, key, method);
    if (crypto == NULL)
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;

        if (plugin != NULL) break;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.iface   = iface;
    listen_ctx.mptcp   = mptcp;

    // Setup signal handler
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    struct ev_loop *loop = EV_DEFAULT;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
#ifdef HAVE_LAUNCHD
        listenfd = launch_or_create(local_addr, local_port);
#else
        listenfd = create_and_bind(local_addr, local_port);
#endif
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        setnonblocking(listenfd);

        listen_ctx.fd = listenfd;

        ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx.io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        char *host = remote_addr[0].host;
        char *port = remote_addr[0].port == NULL ? remote_port : remote_addr[0].port;
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        struct sockaddr *addr = (struct sockaddr *)storage;
        udp_fd = init_udprelay(local_addr, local_port, addr,
                      get_sockaddr_len(addr), mtu, crypto, listen_ctx.timeout, iface);
    }

#ifdef HAVE_LAUNCHD
    if (local_port == NULL)
        LOGI("listening through launchd");
    else
#endif

    if (strcmp(local_addr, ":") > 0)
        LOGI("listening at [%s]:%s", local_addr, local_port);
    else
        LOGI("listening at %s:%s", local_addr, local_port);

    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }

    // Init connections
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (plugin != NULL) {
        stop_plugin();
    }

    if (mode != UDP_ONLY) {
        ev_io_stop(loop, &listen_ctx.io);
        free_connections(loop);

        for (i = 0; i < remote_num; i++)
            ss_free(listen_ctx.remote_addr[i]);
        ss_free(listen_ctx.remote_addr);
    }

    if (mode != TCP_ONLY) {
        free_udprelay();
    }

    return 0;
}

#else

int
start_ss_local_server(profile_t profile)
{
    srand(time(NULL));

    char *remote_host = profile.remote_host;
    char *local_addr  = profile.local_addr;
    char *method      = profile.method;
    char *password    = profile.password;
    char *log         = profile.log;
    int remote_port   = profile.remote_port;
    int local_port    = profile.local_port;
    int timeout       = profile.timeout;
    int mtu           = 0;
    int mptcp         = 0;

    mode      = profile.mode;
    fast_open = profile.fast_open;
    verbose   = profile.verbose;
    mtu       = profile.mtu;
    mptcp     = profile.mptcp;

    char local_port_str[16];
    char remote_port_str[16];
    sprintf(local_port_str, "%d", local_port);
    sprintf(remote_port_str, "%d", remote_port);

    USE_LOGFILE(log);

    if (profile.acl != NULL) {
        acl = !init_acl(profile.acl);
    }

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, NULL, method);
    if (crypto == NULL)
        FATAL("failed to init ciphers");

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(struct sockaddr_storage));
    if (get_sockaddr(remote_host, remote_port_str, &storage, 0, ipv6first) == -1) {
        return -1;
    }

    // Setup proxy context
    struct ev_loop *loop = EV_DEFAULT;

    struct sockaddr *remote_addr_tmp[MAX_REMOTE_NUM];
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num     = 1;
    listen_ctx.remote_addr    = remote_addr_tmp;
    listen_ctx.remote_addr[0] = (struct sockaddr *)(&storage);
    listen_ctx.timeout        = timeout;
    listen_ctx.iface          = NULL;
    listen_ctx.mptcp          = mptcp;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port_str);
        if (listenfd == -1) {
            ERROR("bind()");
            return -1;
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            ERROR("listen()");
            return -1;
        }
        setnonblocking(listenfd);

        listen_ctx.fd = listenfd;

        ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx.io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        struct sockaddr *addr = (struct sockaddr *)(&storage);
        udp_fd = init_udprelay(local_addr, local_port_str, addr,
                      get_sockaddr_len(addr), mtu, crypto, timeout, NULL);
    }

    if (strcmp(local_addr, ":") > 0)
        LOGI("listening at [%s]:%s", local_addr, local_port_str);
    else
        LOGI("listening at %s:%s", local_addr, local_port_str);

    // Init connections
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (mode != UDP_ONLY) {
        ev_io_stop(loop, &listen_ctx.io);
        free_connections(loop);
        close(listen_ctx.fd);
    }

    if (mode != TCP_ONLY) {
        free_udprelay();
    }

    return 0;
}

#endif
