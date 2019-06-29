/*
 * relay.c - Define TCP relay's buffers and callbacks
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
#include <time.h>
#include <unistd.h>
#ifndef __MINGW32__
#include <arpa/inet.h>
#include <errno.h>
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

#include "utils.h"
#include "netutils.h"
#include "winsock.h"
#include "http.h"
#include "tls.h"
#include "acl.h"

#include "relay.h"

extern int verbose;
extern int fast_open;
extern int remote_dns;
extern int ipv6first;

#ifdef __ANDROID__
extern int vpn;
#endif

#ifdef MODULE_REMOTE
static int remote_conn = 0;
static int server_conn = 0;
#endif

#ifdef MODULE_LOCAL
remote_t *
new_remote(server_t *server)
{
    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;

    server->remote = remote;
    remote->server = server;

    return remote;
}

server_t *
new_server(int fd)
{
    server_t *server = ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    server->abuf     = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    balloc(server->abuf, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->stage               = STAGE_INIT;
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timed out");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

int
create_remote(EV_P_ remote_t *remote, buffer_t *buf,
              ssocks_addr_t *destaddr, int acl_enabled)
{
    server_t *server         = remote->server;
    listen_ctx_t *listen_ctx = server->listen_ctx;

    if (buf != NULL && remote_dns && !destaddr->dname) {
        switch (port_service(destaddr->port)) {
            case PORT_HTTP_SERVICE: {
                destaddr->dname_len =
                    http_protocol->parse_packet(buf->data, buf->len, &destaddr->dname);
            } break;
            case PORT_HTTPS_SERVICE: {
                destaddr->dname_len =
                    tls_protocol->parse_packet(buf->data, buf->len, &destaddr->dname);
            } break;
            default:
                break;
        }
    }

    if (destaddr->dname_len == -1) {
        return -1;
    } else if (destaddr->dname_len <= 0 ||
               !validate_hostname(destaddr->dname, destaddr->dname_len))
    {
        destaddr->dname = NULL;
    }

    dname_t dname = { destaddr->dname_len, destaddr->dname };

    int direct = acl_enabled     ?
                 destaddr->dname ? search_acl(ACL_ATYP_DOMAIN, &dname, ACL_UNSPCLIST):
                 destaddr->addr  ? search_acl(ACL_ATYP_IP, destaddr->addr, ACL_UNSPCLIST):
                 0 : 0;

    if (verbose) {
        LOGI("%s %s", direct ? "bypassing" : "connecting to",
             destaddr->dname ? hostname_readable(destaddr->dname, destaddr->port)
                             : sockaddr_readable("%a:%p", destaddr->addr));
    }

    remote->direct = direct;

    if (!remote->direct)
bailed: {
        int remote_idx = acl_enabled     ?
                         destaddr->dname ? search_acl(ACL_ATYP_DOMAIN, &dname, ACL_DELEGATION):
                         destaddr->addr  ? search_acl(ACL_ATYP_IP, destaddr->addr, ACL_DELEGATION):
                         -1 : -1;
        if (remote_idx < 0)
            remote_idx = rand() % listen_ctx->remote_num;
        create_ssocks_header(server->abuf, destaddr);
        return init_remote(EV_A_ remote, listen_ctx->remotes[remote_idx]);
    } else {
        struct sockaddr_storage *addr
                = elvis(destaddr->addr, ss_calloc(1, sizeof(*addr)));
        if (destaddr->dname &&
            get_sockaddr_r(destaddr->dname, NULL,
                           destaddr->port, addr, 1, ipv6first) == -1)
        {
            remote->direct = 0;
            LOGE("failed to resolve %s", destaddr->dname);
            goto bailed;
        }

        return init_remote(EV_A_ remote, &(remote_cnf_t) { .addr = addr, .iface = listen_ctx->iface });
    }
    return 0;
}

int
init_remote(EV_P_ remote_t *remote, remote_cnf_t *conf)
{
    server_t *server             = remote->server;
    listen_ctx_t *listen_ctx     = server->listen_ctx;
    struct sockaddr_storage *remote_addr = conf->addr;
    //cara rm
    LOGI("destaddr %s", sockaddr_readable("%a:%p", remote_addr));

    int remotefd = socket(remote_addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (remotefd == -1) {
        ERROR("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Enable TCP keepalive
    setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(opt));

    // Set non blocking
    setnonblocking(remotefd);

    if (listen_ctx->tos >= 0) {
        if (setsockopt(remotefd, IPPROTO_IP, IP_TOS,
                       &listen_ctx->tos, sizeof(listen_ctx->tos)) != 0) {
            ERROR("setsockopt IP_TOS");
        }
    }

    // Enable MPTCP
    if (listen_ctx->mptcp) {
        set_mptcp(remotefd);
    }

#ifdef __ANDROID__
    if (vpn
        && !is_addr_loopback((struct sockaddr *)remote_addr)
        && protect_socket(remotefd) == -1)
    {
        ERROR("protect_socket");
        close(remotefd);
        return -1;
    }
#endif

    if (conf->crypto) {
        crypto_t *crypto = conf->crypto;
        remote->crypto   = crypto;
        remote->e_ctx    = ss_malloc(sizeof(cipher_ctx_t));
        remote->d_ctx    = ss_malloc(sizeof(cipher_ctx_t));

        crypto->ctx_init(crypto->cipher, remote->e_ctx, 1);
        crypto->ctx_init(crypto->cipher, remote->d_ctx, 0);
    }

    remote->fd   = remotefd;
    remote->addr = remote_addr;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, remotefd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, remotefd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, listen_ctx->timeout), 0);

    return 0;
}

#elif defined MODULE_REMOTE
remote_t *
new_remote(int fd)
{
    if (verbose)
        remote_conn++;

    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;
    remote->server              = NULL;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

    return remote;
}

server_t *
new_server(int fd, listen_ctx_t *listener)
{
    if (verbose)
        server_conn++;

    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;
    server->stage               = STAGE_INIT;
    server->frag                = 0;
    server->listen_ctx          = listener;
    server->remote              = NULL;

    crypto_t *crypto = listener->crypto;
    server->crypto   = crypto;
    server->e_ctx    = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx    = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
                          + rand() % MAX_REQUEST_TIMEOUT;

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  request_timeout, listener->timeout);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

void
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);

    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    if (verbose) {
        LOGI("TCP connection timed out");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}
#endif

void
free_remote(remote_t *remote)
{
#ifdef MODULE_REMOTE
    if (verbose)
        remote_conn--;
#elif defined MODULE_LOCAL
    if (remote->e_ctx != NULL) {
        remote->crypto->ctx_release(remote->e_ctx);
        ss_free(remote->e_ctx);
    }
    if (remote->d_ctx != NULL) {
        remote->crypto->ctx_release(remote->d_ctx);
        ss_free(remote->d_ctx);
    }
#endif
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

void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
#ifdef MODULE_LOCAL
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
#endif
        close(remote->fd);
        free_remote(remote);
    }
}

void
free_server(server_t *server)
{
#ifdef MODULE_REMOTE
    if (verbose) {
        server_conn--;
        LOGI("current server connection: %d", server_conn);
    }
    if (server->e_ctx != NULL) {
        server->crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        server->crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
#ifdef USE_NFCONNTRACK_TOS
    if (server->tracker) {
        struct dscptracker *tracker = server->tracker;
        struct nf_conntrack *ct     = server->tracker->ct;
        server->tracker = NULL;
        if (ct) {
            nfct_destroy(ct);
        }
        free(tracker);
    }
#endif
#endif
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
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

void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
#ifdef MODULE_REMOTE
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
#endif
        close(server->fd);
        free_server(server);
    }
}

void
free_connections(struct ev_loop *loop)
{
    server_t *server = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&connections, curr, next,
                        server_t, server, entries) {
        if (server != NULL) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, server->remote);
        }
    }
}
