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
#include "relay.h"

static void accept_cb(EV_P_ ev_io *w, int revents);

int verbose = 0;
int acl = 0;
int ipv6first = 0;
int fast_open = 0;
#ifdef __ANDROID__
int vpn = 0;
#endif
int remote_dns = 1; // resolve hostname remotely

static int no_delay  = 0;
static int ret_val   = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
#ifndef __MINGW32__
static struct ev_signal sigchld_watcher;
#endif

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

static void
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

int
main(int argc, char **argv)
{
    USE_TTY();
    srand(time(NULL));

    int i;
    int plugin_enabled = 0;
    int pid_flags = 0;
    jconf_t conf  = jconf_default;

    if (parse_argopts(&conf, argc, argv) != 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (!(conf.remotes != NULL &&
        conf.remote_num > 0)) {
        FATAL("at least one server should be specified");
    }

    if (conf.local_port == NULL) {
        conf.local_port = "0";
        LOGE("warning: random local port will be assigned");
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

    if (conf.ipv6_first) {
        LOGI("prioritized IPv6 addresses in domain resolution");
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
    ipv6first  = conf.ipv6_first;
    fast_open  = conf.fast_open;
    verbose    = conf.verbose;
#ifdef __ANDROID__
    vpn        = conf.vpn;
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

    // Setup proxy context
    struct ev_loop *loop = EV_DEFAULT;
    struct listen_ctx listen_ctx = {
        .mtu        = conf.mtu,
        .mptcp      = conf.mptcp,
        .reuse_port = conf.reuse_port,
        .remote_num = conf.remote_num,
        .remotes    = ss_calloc(conf.remote_num, sizeof(struct remote_cnf *)),
        .timeout    = atoi(conf.timeout),
        .loop       = loop
    };

    ss_addr_t *tunnel_addr = &conf.tunnel_addr;
    if (tunnel_addr->host == NULL ||
        tunnel_addr->port == NULL) {
        FATAL("tunnel address either undefined or invalid");
    }

    ssocks_addr_t *destaddr = &listen_ctx.destaddr;
    destaddr->addr = ss_calloc(1, sizeof(struct sockaddr_storage));
    if (get_sockaddr(tunnel_addr->host, tunnel_addr->port,
                     destaddr->addr, !remote_dns, conf.ipv6_first) == -1)
    {
        destaddr->dname = tunnel_addr->host;
        destaddr->dname_len = strlen(tunnel_addr->host);
        destaddr->port  = htons(atoi(tunnel_addr->port));
    }

    // else LOGI("%s", sockaddr_readable("%a:%p", destaddr->addr));

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

        if (host == NULL || port == NULL ||
            (password == NULL && key == NULL))
        {
            usage();
            exit(EXIT_FAILURE);
        }

        // Setup keys
        LOGI("[%d/%d] server %s:%s", i + 1, conf.remote_num, host, port);
        LOGI("initializing ciphers... %s", method);
        crypto_t *crypto = crypto_init(password, key, method);
        if (crypto == NULL)
            FATAL("failed to initialize ciphers");

        struct sockaddr_storage *storage
            = ss_calloc(1, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, conf.ipv6_first) == -1) {
            FATAL("failed to resolve %s", host);
        }

        if (plugin != NULL) {
            if (!plugin_enabled) {
                init_plugin(MODE_CLIENT);
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
                                   host, port,                          // user-defined destination address
                                   sockaddr_readable("%a", storage),
                                   sockaddr_readable("%p", storage));
            if (err)
                FATAL("failed to start plugin %s", plugin);
        }

        listen_ctx.remotes[i] = &(remote_cnf_t) {
            .iface  = iface,
            .addr   = storage,
            .crypto = crypto
        };
    }

    ss_dscp_t **dscp = conf.dscp;
    char *local_addr = conf.local_addr,
         *local_port = conf.local_port;

    listen_ctx_t listen_ctx_current = listen_ctx;
    do {
        if (listen_ctx_current.tos) {
            LOGI("listening on %s:%s (TOS 0x%x)",
                 local_addr, local_port, listen_ctx_current.tos);
        } else {
            LOGI("listening on %s:%s", local_addr, local_port);
        }

        struct sockaddr_storage *storage = &(struct sockaddr_storage) {};
        if (get_sockaddr(local_addr, local_port,
                         storage, 1, conf.ipv6_first) == -1)
        {
            FATAL("failed to resolve %s", local_addr);
        }

        if (conf.mode != UDP_ONLY) {
            // Setup socket
            int listenfd = bind_and_listen(storage, IPPROTO_TCP, &listen_ctx_current);
            if (listenfd != -1) {
                if (fast_open)
                    set_fastopen_passive(listenfd);
                ev_io_init(&listen_ctx_current.io, accept_cb, listen_ctx_current.fd, EV_READ);
                ev_io_start(loop, &listen_ctx_current.io);
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

        if (conf.mode == UDP_ONLY) {
            LOGI("TCP relay disabled");
        }

        // Handle additional TOS/DSCP listening ports
        if (*dscp != NULL) {
            listen_ctx_current      = listen_ctx;
            local_port              = (*dscp)->port;
            listen_ctx_current.tos  = (*dscp)->dscp << 2;
        }
    } while (*(dscp++) != NULL);

    // setuid
    if (conf.user && !run_as(conf.user))
        FATAL("failed to switch user");

    if (geteuid() == 0)
        LOGI("running from root user");

    // Init connections
    cork_dllist_init(&connections);

    ev_run(loop, 0);

    if (plugin_enabled)
        stop_plugin();

    if (conf.mode != TCP_ONLY) {
        free_udprelay(loop);
    }

    return ret_val;
}
