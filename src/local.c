/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
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

#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#endif

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

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "local.h"
#include "bitcoin.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

int acl = 0;
int verbose = 0;
int udprelay = 0;
char *bitcoin_address = NULL;
char *bitcoin_privkey = NULL;
static int fast_open = 0;
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
static struct remote * connect_to_remote(struct listen_ctx *listener, struct sockaddr *addr);
static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);
static void free_server(struct server *server);
static void close_and_free_server(EV_P_ struct server *server);

static struct remote * new_remote(int fd, int timeout);
static struct server * new_server(int fd, int method);

static struct cork_dllist connections;

#ifndef __MINGW32__
int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

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

int create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
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

static void server_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
    struct server *server = server_recv_ctx->server;
    struct remote *remote = server->remote;
    char *buf;

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    ssize_t r = recv(server->fd, buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    while (1) {
        // local socks5 server
        if (server->stage == 5) {
            if (remote == NULL) {
                LOGE("invalid remote");
                close_and_free_server(EV_A_ server);
                return;
            }

            // insert shadowsocks header
            if (!remote->direct) {
                remote->buf = ss_encrypt(BUF_SIZE, remote->buf, &r,
                                         server->e_ctx);

                if (remote->buf == NULL) {
                    LOGE("invalid password or cipher");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            if (!remote->send_ctx->connected) {
                remote->buf_idx = 0;
                remote->buf_len = r;

                if (!fast_open || remote->direct) {
                    // connecting, wait until connected
                    connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

                    // wait on remote connected event
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                } else {
#ifdef TCP_FASTOPEN
                    int s = sendto(remote->fd, remote->buf, r, MSG_FASTOPEN,
                                   (struct sockaddr *)&(remote->addr), remote->addr_len);
                    if (s == -1) {
                        if (errno == EINPROGRESS) {
                            // in progress, wait until connected
                            remote->buf_idx = 0;
                            remote->buf_len = r;
                            ev_io_stop(EV_A_ & server_recv_ctx->io);
                            ev_io_start(EV_A_ & remote->send_ctx->io);
                            return;
                        } else {
                            ERROR("sendto");
                            if (errno == ENOTCONN) {
                                LOGE(
                                    "fast open is not supported on this platform");
                                // just turn it off
                                fast_open = 0;
                            }
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    } else if (s < r) {
                        remote->buf_len = r - s;
                        remote->buf_idx = s;
                    }

                    // Just connected
                    remote->send_ctx->connected = 1;
                    ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
#else
                    // if TCP_FASTOPEN is not defined, fast_open will always be 0
                    LOGE("can't come here");
                    exit(1);
#endif
                }
            } else {
                int s = send(remote->fd, remote->buf, r, 0);
                if (s == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // no data, wait for send
                        remote->buf_idx = 0;
                        remote->buf_len = r;
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        return;
                    } else {
                        ERROR("server_recv_cb_send");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }
                } else if (s < r) {
                    remote->buf_len = r - s;
                    remote->buf_idx = s;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                }
            }

            // all processed
            return;
        } else if (server->stage == 0) {
            struct method_select_response response;
            response.ver = SVERSION;
            response.method = 0;
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, sizeof(response), 0);
            server->stage = 1;
            return;
        } else if (server->stage == 1) {
            struct socks5_request *request = (struct socks5_request *)buf;

            struct sockaddr_in sock_addr;
            memset(&sock_addr, 0, sizeof(sock_addr));

            int udp_assc = 0;

            if (udprelay && request->cmd == 3) {
                udp_assc = 1;
                socklen_t addr_len = sizeof(sock_addr);
                getsockname(server->fd, (struct sockaddr *)&sock_addr,
                            &addr_len);
                if (verbose) {
                    LOGI("udp assc request accepted");
                }
            } else if (request->cmd != 1) {
                LOGE("unsupported cmd: %d", request->cmd);
                struct socks5_response response;
                response.ver = SVERSION;
                response.rep = CMD_NOT_SUPPORTED;
                response.rsv = 0;
                response.atyp = 1;
                char *send_buf = (char *)&response;
                send(server->fd, send_buf, 4, 0);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            } else {
                char host[256], port[16];
                char ss_addr_to_send[450];

                ssize_t addr_len = 0;
                ss_addr_to_send[addr_len++] = request->atyp;

                // get remote addr and port
                if (request->atyp == 1) {
                    // IP V4
                    size_t in_addr_len = sizeof(struct in_addr);
                    memcpy(ss_addr_to_send + addr_len, buf + 4, in_addr_len +
                           2);
                    addr_len += in_addr_len + 2;

                    if (acl || verbose) {
                        uint16_t p =
                            ntohs(*(uint16_t *)(buf + 4 + in_addr_len));
                        dns_ntop(AF_INET, (const void *)(buf + 4),
                                 host, INET_ADDRSTRLEN);
                        sprintf(port, "%d", p);
                    }
                } else if (request->atyp == 3) {
                    // Domain name
                    uint8_t name_len = *(uint8_t *)(buf + 4);
                    ss_addr_to_send[addr_len++] = name_len;
                    memcpy(ss_addr_to_send + addr_len, buf + 4 + 1, name_len +
                           2);
                    addr_len += name_len + 2;

                    if (acl || verbose) {
                        uint16_t p =
                            ntohs(*(uint16_t *)(buf + 4 + 1 + name_len));
                        memcpy(host, buf + 4 + 1, name_len);
                        host[name_len] = '\0';
                        sprintf(port, "%d", p);
                    }
                } else if (request->atyp == 4) {
                    // IP V6
                    size_t in6_addr_len = sizeof(struct in6_addr);
                    memcpy(ss_addr_to_send + addr_len, buf + 4, in6_addr_len +
                           2);
                    addr_len += in6_addr_len + 2;

                    if (acl || verbose) {
                        uint16_t p =
                            ntohs(*(uint16_t *)(buf + 4 + in6_addr_len));
                        dns_ntop(AF_INET6, (const void *)(buf + 4),
                                 host, INET6_ADDRSTRLEN);
                        sprintf(port, "%d", p);
                    }
                } else {
                    LOGE("unsupported addrtype: %d", request->atyp);
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }

                // add bitcoin infomation to `ss_addr_to_send`
                size_t bitcoin_len = 0;
                if (bitcoin_address != NULL && bitcoin_privkey != NULL) {
                    /*
                     * bitcoin information:
                     *    +-----------+-----------+----------+
                     *    | Signature | Timestamp |  Address |
                     *    +-----------+-----------+----------+
                     *    |    65     |     4     |  String  |
                     *    +-----------+-----------+----------+
                     */
                    uint32_t now = (uint32_t)time(NULL);
                    uint8_t msg[4] = {(uint8_t)(now >> 24), (uint8_t)(now >> 16),
                                      (uint8_t)(now >>  8), (uint8_t)(now >>  0)};
                    uint8_t sig[65] = {0};  // signature buf size always 65 bytes
                    if (!bitcoin_sign_message(sig, msg, sizeof(msg), bitcoin_privkey, bitcoin_address)) {
                        FATAL("bitcoin sign message fail");
                    }
                    size_t addr_len_ori = addr_len;
                    memcpy(ss_addr_to_send + addr_len, sig, 65);
                    addr_len += 65;
                    memcpy(ss_addr_to_send + addr_len, msg, sizeof(msg));
                    addr_len += 4;
                    memcpy(ss_addr_to_send + addr_len, bitcoin_address, strlen(bitcoin_address));
                    addr_len += strlen(bitcoin_address);
                    ss_addr_to_send[addr_len++] = '\0';

                    bitcoin_len = addr_len - addr_len_ori;
                    ss_addr_to_send[0] |= 0x10;  // set bitcoin flag
                }

                server->stage = 5;

                // bitcoin information is extra, so minus it's length
                r   -= (3 + addr_len - bitcoin_len);
                buf += (3 + addr_len - bitcoin_len);

                if (verbose) {
                    LOGI("connect to %s:%s", host, port);
                }

                if ((acl && (request->atyp == 1 || request->atyp == 3) && acl_contains_ip(host))) {
                    if (verbose) {
                        LOGI("bypass %s:%s", host, port);
                    }
                    struct sockaddr_storage storage;
                    memset(&storage, 0, sizeof(struct sockaddr_storage));
                    if (get_sockaddr(host, port, &storage, 0) != -1) {
                        remote = connect_to_remote(server->listener, (struct sockaddr *)&storage);
                        remote->direct = 1;
                    }
                } else {
                    remote = connect_to_remote(server->listener, NULL);
                }

                if (remote == NULL) {
                    LOGE("invalid remote addr");
                    close_and_free_server(EV_A_ server);
                    return;
                }

                if (!remote->direct) {
                    memcpy(remote->buf, ss_addr_to_send, addr_len);
                    if (r > 0) {
                        memcpy(remote->buf + addr_len, buf, r);
                    }
                    r += addr_len;
                } else {
                    if (r > 0) {
                        memcpy(remote->buf, buf, r);
                    }
                }

                server->remote = remote;
                remote->server = server;
            }

            // Fake reply
            struct socks5_response response;
            response.ver = SVERSION;
            response.rep = 0;
            response.rsv = 0;
            response.atyp = 1;

            memcpy(server->buf, &response, sizeof(struct socks5_response));
            memcpy(server->buf + sizeof(struct socks5_response),
                   &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
            memcpy(server->buf + sizeof(struct socks5_response) +
                   sizeof(sock_addr.sin_addr),
                   &sock_addr.sin_port, sizeof(sock_addr.sin_port));

            int reply_size = sizeof(struct socks5_response) +
                             sizeof(sock_addr.sin_addr) +
                             sizeof(sock_addr.sin_port);
            int s = send(server->fd, server->buf, reply_size, 0);
            if (s < reply_size) {
                LOGE("failed to send fake reply");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            if (udp_assc) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

static void server_send_cb(EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;
    if (server->buf_len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                         server->buf_len, 0);
        if (s < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
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
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
    }

}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)(((void *)watcher)
                                                          - sizeof(ev_io));
    struct remote *remote = remote_ctx->remote;
    struct server *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;

    ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r < 0) {
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

    if (!remote->direct) {
        server->buf = ss_decrypt(BUF_SIZE, server->buf, &r, server->d_ctx);
        if (server->buf == NULL) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    int s = send(server->fd, server->buf, r, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
            return;
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
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

    if (!remote_send_ctx->connected) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf_len == 0) {
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

    if (remote->buf_len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                         remote->buf_len, 0);
        if (s < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
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
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static struct remote * new_remote(int fd, int timeout)
{
    struct remote *remote;
    remote = malloc(sizeof(struct remote));

    memset(remote, 0, sizeof(struct remote));

    remote->buf = malloc(BUF_SIZE);
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT,
                      timeout),
                  0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT,
                      timeout),
                  timeout);
    remote->recv_ctx->remote = remote;
    remote->send_ctx->remote = remote;
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
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static struct server * new_server(int fd, int method)
{
    struct server *server;
    server = malloc(sizeof(struct server));

    memset(server, 0, sizeof(struct server));

    server->buf = malloc(BUF_SIZE);
    server->recv_ctx = malloc(sizeof(struct server_ctx));
    server->send_ctx = malloc(sizeof(struct server_ctx));
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd = fd;
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    server->recv_ctx->server = server;
    server->send_ctx->server = server;
    if (method) {
        server->e_ctx = malloc(sizeof(struct enc_ctx));
        server->d_ctx = malloc(sizeof(struct enc_ctx));
        enc_ctx_init(method, server->e_ctx, 1);
        enc_ctx_init(method, server->d_ctx, 0);
    } else {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }

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
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        close(server->fd);
        free_server(server);
    }
}

static struct remote * connect_to_remote(struct listen_ctx *listener,
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

    if (remotefd < 0) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Setup
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    if (listener->iface) {
        setinterface(remotefd, listener->iface);
    }
#endif

    struct remote *remote = new_remote(remotefd, listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);

    return remote;
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

void accept_cb(EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *)w;
    int serverfd = accept(listener->fd, NULL, NULL);
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

    struct server *server = new_server(serverfd, listener->method);
    server->listener = listener;

    ev_io_start(EV_A_ & server->recv_ctx->io);
}

#ifndef LIB_ONLY
int main(int argc, char **argv)
{

    int i, c;
    int pid_flags = 0;
    char *user = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;

    srand(time(NULL));

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    int option_index = 0;
    static struct option long_options[] =
    {
        { "fast-open",       no_argument,       0, 0 },
        { "acl",             required_argument, 0, 0 },
        { "bitcoin-address", required_argument, 0, 0 },
        { "bitcoin-privkey", required_argument, 0, 0 },
        { 0,                 0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:uv",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
                fast_open = 1;
            } else if (option_index == 1) {
                LOGI("initialize acl...");
                acl = !init_acl(optarg);
            } else if (strcmp(long_options[option_index].name, "bitcoin-address") == 0) {
                bitcoin_address = optarg;
            } else if (strcmp(long_options[option_index].name, "bitcoin-privkey") == 0) {
                bitcoin_privkey = optarg;
            }
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
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
        case 'b':
            local_addr = optarg;
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

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = DEFAULT_CONF_PATH;
        }
    }
    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++) {
                remote_addr[i] = conf->remote_addr[i];
            }
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
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (bitcoin_address == NULL) {
            bitcoin_address = conf->bitcoin_address;
        }
        if (bitcoin_privkey == NULL) {
            bitcoin_privkey = conf->bitcoin_privkey;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
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
                LOGI("setting NOFILE to %d", nofile);
            }
            set_nofile(nofile);
        }
#endif
    }

    if (remote_num == 0 || remote_port == NULL ||
        local_port == NULL || password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (timeout == NULL) {
        timeout = "10";
    }

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
#endif
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    // Setup keys
    LOGI("initialize ciphers... %s", method);
    int m = enc_init(password, method);

    // Setup socket
    int listenfd;
    listenfd = create_and_bind(local_addr, local_port);
    if (listenfd < 0) {
        FATAL("bind() error");
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        FATAL("listen() error");
    }
    setnonblocking(listenfd);
    LOGI("listening at %s:%s", local_addr, local_port);

    // Setup proxy context
    struct listen_ctx listen_ctx;
    listen_ctx.remote_num = remote_num;
    listen_ctx.remote_addr = malloc(sizeof(struct sockaddr *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        struct sockaddr_storage *storage = malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.fd = listenfd;
    listen_ctx.iface = iface;
    listen_ctx.method = m;

    struct ev_loop *loop = EV_DEFAULT;
    ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start(loop, &listen_ctx.io);

    // Setup UDP
    if (udprelay) {
        LOGI("udprelay enabled");
        init_udprelay(local_addr, local_port, listen_ctx.remote_addr[0],
                      get_sockaddr_len(listen_ctx.remote_addr[0]), m, listen_ctx.timeout, iface);
    }

    // setuid
    if (user != NULL) {
        run_as(user);
    }

    // Init connections
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    free_connections(loop);
    free_udprelay();

    ev_io_stop(loop, &listen_ctx.io);
    for (i = 0; i < remote_num; i++) {
        free(listen_ctx.remote_addr[i]);
    }
    free(listen_ctx.remote_addr);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}

#else

int start_ss_local_server(profile_t profile)
{
    srand(time(NULL));

    char *remote_host = profile.remote_host;
    char *local_addr = profile.local_addr;
    char *method = profile.method;
    char *password = profile.password;
    char *log = profile.log;
    int remote_port = profile.remote_port;
    int local_port = profile.local_port;
    int timeout = profile.timeout;

    udprelay = profile.udp_relay;
    fast_open = profile.fast_open;
    verbose = profile.verbose;

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

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    // Setup keys
    LOGI("initialize ciphers... %s", method);
    int m = enc_init(password, method);

    // Setup socket
    int listenfd;
    listenfd = create_and_bind(local_addr, local_port_str);
    if (listenfd < 0) {
        ERROR("bind()");
        return -1;
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        ERROR("listen()");
        return -1;
    }
    setnonblocking(listenfd);
    LOGI("listening at %s:%s", local_addr, local_port_str);

    // Setup proxy context
    struct listen_ctx listen_ctx;

    listen_ctx.remote_num = 1;
    listen_ctx.remote_addr = malloc(sizeof(struct sockaddr *));
    struct sockaddr_storage *storage = malloc(sizeof(struct sockaddr_storage));
    memset(storage, 0, sizeof(struct sockaddr_storage));
    if (get_sockaddr(remote_host, remote_port_str, storage, 1) == -1) {
        return -1;
    }
    listen_ctx.remote_addr[0] = (struct sockaddr *)storage;
    listen_ctx.timeout = timeout;
    listen_ctx.fd = listenfd;
    listen_ctx.method = m;
    listen_ctx.iface = NULL;

    struct ev_loop *loop = EV_DEFAULT;
    ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start(loop, &listen_ctx.io);

    // Setup UDP
    if (udprelay) {
        LOGI("udprelay enabled");
        init_udprelay(local_addr, local_port_str, listen_ctx.remote_addr[0],
                      get_sockaddr_len(listen_ctx.remote_addr[0]), m,
                      listen_ctx.timeout, NULL);
    }

    // Init connections
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    free_connections(loop);
    if (udprelay) {
        free_udprelay();
    }

    ev_io_stop(loop, &listen_ctx.io);
    free(listen_ctx.remote_addr);
    close(listen_ctx.fd);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    // cannot reach here
    return 0;
}

#endif

