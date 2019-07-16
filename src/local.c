/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
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
#include <unistd.h>
#include <getopt.h>
#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>

#include "common.h"
#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "shadowsocks.h"
#include "http.h"
#include "tls.h"
#include "plugin.h"
#include "winsock.h"
#include "tcprelay.h"
#include "acl.h"

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

int verbose    = 0;
int ipv6first  = 0;
int remote_dns = 1; // resolve hostname remotely
int acl        = 0;
int fast_open  = 0;

#ifdef __ANDROID__
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;
char *stat_path = NULL;
#endif

static int no_delay  = 0;

static int
server_handshake_reply(EV_P_ ev_io *w, int udp_assc, struct socks5_response *response)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    if (server->stage != STAGE_HANDSHAKE)
        return 0;

    struct sockaddr_in sock_addr;
    if (udp_assc) {
        socklen_t addr_len = sizeof(sock_addr);
        if (getsockname(server->fd, (struct sockaddr *)&sock_addr, &addr_len) < 0) {
            LOGE("getsockname: %s", strerror(errno));
            response->rep = SOCKS5_REP_CONN_REFUSED;
            send(server->fd, (char *)response, sizeof(struct socks5_response), 0);
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    } else
        memset(&sock_addr, 0, sizeof(sock_addr));

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
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
        return -1;
    }
    if (udp_assc) {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

static int
server_handshake(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    struct socks5_request *request = (struct socks5_request *)buf->data;
    size_t request_len             = sizeof(struct socks5_request);

    if (buf->len < request_len) {
        return -1;
    }

    struct socks5_response response = {
        .ver  = SVERSION,
        .rep  = SOCKS5_REP_SUCCEEDED,
        .rsv  = 0,
        .atyp = SOCKS5_ATYP_IPV4
    };

    // TODO fixme BUGS ALERT
    if (request->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        if (verbose) {
            LOGI("udp assc request accepted");
        }
        return server_handshake_reply(EV_A_ w, 1, &response);
    } else if (request->cmd != SOCKS5_CMD_CONNECT) {
        LOGE("unsupported cmd: %d", request->cmd);
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }

    ssocks_addr_t destaddr = { 0 };
    int offset = parse_ssocks_header(buf, &destaddr, 3);
    if (offset < 0) {
        LOGE("unsupported addrtype: %d", request->atyp);
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        send(server->fd, &response, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    } else {
        buf->len -= offset;
        if (buf->len > 0) {
            memmove(buf->data, buf->data + offset, buf->len);
        }
    }

    int acl_eligible = (acl
#ifdef __ANDROID__
        && !(vpn && port_service(destaddr.port) == PORT_DOMAIN_SERVICE)
#endif
        );

    if (create_remote(EV_A_ remote, buf, &destaddr, acl_eligible) != -1) {
        if (server_handshake_reply(EV_A_ w, 0, &response) < 0)
            return -1;
        server->stage = STAGE_STREAM;
    } else {
        if (server->stage != STAGE_SNI
            && buf->len < SOCKET_BUF_SIZE) {
            if (server_handshake_reply(EV_A_ w, 0, &response) == 0) {
                server->stage = STAGE_SNI;
                ev_io_start(EV_A_ & server_recv_ctx->io);
            }
        } else {
            ERROR("create_remote");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
        return -1;
    }

    if (!remote->direct) {
        crypto_t *crypto = remote->crypto;
        int err = crypto->encrypt(server->abuf, remote->e_ctx, SOCKET_BUF_SIZE);
        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    }

    if (buf->len > 0) {
        remote->buf->len = buf->len;
        memcpy(remote->buf->data, buf->data, buf->len);
        return 0;
    } else {
        ev_io_start(EV_A_ & server_recv_ctx->io);
    }

    return -1;
}

static void
server_stream(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    crypto_t *crypto              = remote->crypto;

    if (remote == NULL) {
        LOGE("invalid remote");
        close_and_free_server(EV_A_ server);
        return;
    }

    // insert shadowsocks header
    if (!remote->direct) {
#ifdef __ANDROID__
        tx += remote->buf->len;
#endif
        int err = crypto->encrypt(remote->buf, remote->e_ctx, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        if (server->abuf) {
            bprepend(remote->buf, server->abuf, SOCKET_BUF_SIZE);
            bfree(server->abuf);
            ss_free(server->abuf);
            server->abuf = NULL;
        }
    }

    if (!remote->send_ctx->connected) {

        remote->buf->idx = 0;

        if (!fast_open) {
            // connecting, wait until connected
            int r = connect(remote->fd, (struct sockaddr *)remote->addr, sizeof(*remote->addr));

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
            ssize_t s = sendto_idempotent(remote->fd,
                                          remote->buf->data + remote->buf->idx,
                                          remote->buf->len, (struct sockaddr *)remote->addr
#ifdef TCP_FASTOPEN_WINSOCK
                                          , &remote->olap, &remote->connect_ex_done
#endif
            );

            if (s == -1) {
                if (errno == CONNECT_IN_PROGRESS) {
                    // in progress, wait until connected
                    remote->buf->idx = 0;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                } else {
                    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                        errno == ENOPROTOOPT) {
                        LOGE("fast open is not supported on this platform");
                        // just turn it off
                        fast_open = 0;
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else {
                remote->buf->len -= s;
                remote->buf->idx  = s;

                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
                ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                return;
            }
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
}

void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf                 = remote ? remote->buf : server->buf;

    ssize_t r = recv(server->fd, buf->data + buf->len, SOCKET_BUF_SIZE - buf->len, 0);

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

    while (1) {
        // local socks5 server
        switch (server->stage) {
            case STAGE_INIT: {
                if (buf->len < 1)
                    return;
                if (buf->data[0] != SVERSION) {
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (buf->len < sizeof(struct method_select_request)) {
                    return;
                }
                struct method_select_request *method = (struct method_select_request *)buf->data;
                int method_len                       = method->nmethods + sizeof(struct method_select_request);
                if (buf->len < method_len) {
                    return;
                }

                struct method_select_response response = {
                    .ver    = SVERSION,
                    .method = METHOD_UNACCEPTABLE
                };

                for (int i = 0; i < method->nmethods; i++)
                    if (method->methods[i] == METHOD_NOAUTH) {
                        response.method = METHOD_NOAUTH;
                        break;
                    }
                char *send_buf = (char *)&response;
                send(server->fd, send_buf, sizeof(response), 0);
                if (response.method == METHOD_UNACCEPTABLE) {
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }

                server->stage = STAGE_HANDSHAKE;

                if (method_len < (int)(buf->len)) {
                    memmove(buf->data, buf->data + method_len, buf->len - method_len);
                    buf->len -= method_len;
                    continue;
                }

                buf->len = 0;
            } return;
            case STAGE_HANDSHAKE:
            case STAGE_SNI:
                if (server_handshake(EV_A_ w, buf)) {
                    return;
                } break;
            case STAGE_STREAM: {
                server_stream(EV_A_ w, buf);
            } return;
        }
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
        int err = crypto->decrypt(server->buf, remote->d_ctx, SOCKET_BUF_SIZE);
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
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
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
    server->listen_ctx = listener;

    new_remote(server);
    ev_io_start(EV_A_ & server->recv_ctx->io);
}

int
new_shadowsocks_(ssocks_module_t module,
                 jconf_t *conf, ss_callback_t callback, void *data)
{
#ifdef __ANDROID__
    stat_path = conf->stat_path;
#endif
    return start_relay(conf, NULL, NULL);
}

#ifndef LIB_ONLY
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
    fast_open  = conf.fast_open;
    verbose    = conf.verbose;
    ipv6first  = conf.ipv6_first;
    remote_dns = conf.remote_dns;
#ifdef __ANDROID__
    stat_path  = conf.stat_path;
#endif
    return new_shadowsocks(module_local, &conf);
}

#endif
