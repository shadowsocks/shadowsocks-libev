/*
 * relay.h - Define TCP relay's buffers and callbacks
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

#ifndef _TCP_RELAY_H
#define _TCP_RELAY_H

#include <time.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "common.h"
#include "shadowsocks.h"
#include "crypto.h"
#include "jconf.h"

#ifdef MODULE_REMOTE
#include "resolv.h"
#ifdef USE_NFCONNTRACK_TOS
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

struct dscptracker {
    struct nf_conntrack *ct;
    long unsigned int mark;
    unsigned int dscp;
    unsigned int packet_count;
};
#endif

typedef struct server server_t;
typedef struct query {
    server_t *server;
    char *hostname;
} query_t;
#endif

typedef struct server_ctx {
    ev_io io;
#ifdef MODULE_REMOTE
    ev_timer watcher;
#endif
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    int stage;

    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    struct remote *remote;

    buffer_t *buf;
    buffer_t *abuf;

#ifdef MODULE_REMOTE
    int frag;

    crypto_t *crypto;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;

#ifdef USE_NFCONNTRACK_TOS
    struct dscptracker *tracker;
#endif
#elif defined MODULE_REDIR
    struct ssocks_addr *destaddr;
#endif

    struct cork_dllist_item entries;
} server_t;

typedef struct remote_ctx {
    ev_io io;
#ifdef MODULE_LOCAL
    ev_timer watcher;
#endif
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    int direct;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    buffer_t *buf;

#ifdef MODULE_LOCAL
    crypto_t *crypto;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
#endif

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage *addr;
} remote_t;

enum {
    STAGE_ERROR = -1,   /* Error detected                   */
    STAGE_INIT,         /* Initial stage                    */
    STAGE_HANDSHAKE,    /* Handshake with client            */
    STAGE_SNI,          /* Parse HTTP/SNI header            */
    STAGE_RESOLVE,      /* Resolve the hostname             */
    STAGE_STREAM,       /* Stream between client and server */
    STAGE_STOP          /* Server stop to respond           */
};

void accept_cb(EV_P_ ev_io *, int);
void server_recv_cb(EV_P_ ev_io *, int);
void server_send_cb(EV_P_ ev_io *, int);
void remote_recv_cb(EV_P_ ev_io *, int);
void remote_send_cb(EV_P_ ev_io *, int);

void free_remote(remote_t *remote);
void close_and_free_remote(EV_P_ remote_t *remote);
void free_server(server_t *server);
void close_and_free_server(EV_P_ server_t *server);

#ifdef MODULE_REMOTE
remote_t *new_remote(int fd);
server_t *new_server(int fd, listen_ctx_t *listener);
void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);
#elif defined MODULE_LOCAL
remote_t *new_remote(server_t *server);
server_t *new_server(int fd);
void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents);
int init_remote(EV_P_ remote_t *remote, remote_cnf_t *conf);
int create_remote(EV_P_ remote_t *remote, buffer_t *buf,
                  ssocks_addr_t *destaddr, int acl_enabled);
#endif

int start_relay(jconf_t *conf,
                ss_callback_t callback, void *data);

#endif // _RELAY_H
