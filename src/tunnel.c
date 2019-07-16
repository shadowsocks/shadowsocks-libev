/*
 * tunnel.c - Setup a local port forwarding through remote shadowsocks server
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

#include <libcork/core.h>

#include "common.h"
#include "shadowsocks.h"
#include "netutils.h"
#include "utils.h"
#include "plugin.h"
#include "winsock.h"
#include "tcprelay.h"

int verbose = 0;
int acl = 0;
int ipv6first = 0;
int fast_open = 0;
#ifdef __ANDROID__
int vpn = 0;
#endif
int remote_dns = 1; // resolve hostname remotely

static int no_delay  = 0;

void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    crypto_t *crypto              = remote->crypto;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r = recv(server->fd, remote->buf->data, SOCKET_BUF_SIZE, 0);

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
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf->len = r;

    int err = crypto->encrypt(remote->buf, remote->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx  = s;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    }
}

void
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
                ERROR("send");
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
            } else {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;
    crypto_t *crypto              = remote->crypto;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

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
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    int err = crypto->decrypt(server->buf, remote->d_ctx, SOCKET_BUF_SIZE);
    if (err == CRYPTO_ERROR) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        return; // Wait for more
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("send");
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
    crypto_t *crypto              = remote->crypto;

    ev_timer_stop(EV_A_ & remote_send_ctx->watcher);

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
        int r = 0;

        if (remote->addr == NULL) {
            struct sockaddr_storage addr;
            socklen_t len = sizeof(struct sockaddr_storage);
            r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        }

        if (r == 0) {
            remote_send_ctx->connected = 1;

            assert(remote->buf->len == 0);
            create_ssocks_header(remote->buf, &server->listen_ctx->destaddr);

            int err = crypto->encrypt(remote->buf, remote->e_ctx, SOCKET_BUF_SIZE);

            if (err) {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            ev_io_start(EV_A_ & remote->recv_ctx->io);
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
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = -1;
        if (fast_open && remote->addr != NULL) {
            ssize_t s = sendto_idempotent(remote->fd,
                                          remote->buf->data + remote->buf->idx,
                                          remote->buf->len, (struct sockaddr *)remote->addr
#ifdef TCP_FASTOPEN_WINSOCK
                                          , &remote->olap, &remote->connect_ex_done
#endif
            );
            remote->addr = NULL;

            if (s == -1) {
                if (errno == CONNECT_IN_PROGRESS) {
                    ev_io_start(EV_A_ & remote_send_ctx->io);
                    ev_timer_start(EV_A_ & remote_send_ctx->watcher);
                } else {
                    fast_open = 0;
                    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                        errno == ENOPROTOOPT) {
                        LOGE("fast open is not supported on this platform");
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
                return;
            }
        } else {
            s = send(remote->fd, remote->buf->data + remote->buf->idx,
                     remote->buf->len, 0);
        }

        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
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
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *)w;
    int serverfd                = accept(listener->fd, NULL, NULL);
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
    remote_t *remote = new_remote(server);

    server->listen_ctx = listener;
    if (create_remote(EV_A_ remote, NULL, &listener->destaddr, 0) == -1) {
        ERROR("create_remote");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
    } else {
        int r = connect(remote->fd, (struct sockaddr *)remote->addr, sizeof(*remote->addr));

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        // listen to remote connected event
        ev_io_start(EV_A_ & remote->send_ctx->io);
        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
    }
}

int
main(int argc, char **argv)
{
    USE_TTY();
    srand(time(NULL));

    int pid_flags = 0;
    jconf_t conf  = jconf_default;

    if (parse_argopts(&conf, argc, argv) != 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    pid_flags = conf.pid_path != NULL;
    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(conf.pid_path);
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

    no_delay   = conf.no_delay;
    ipv6first  = conf.ipv6_first;
    fast_open  = conf.fast_open;
    verbose    = conf.verbose;
#ifdef __ANDROID__
    vpn        = conf.vpn;
#endif
    return start_relay(&conf, NULL, NULL);
}
