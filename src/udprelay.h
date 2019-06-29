/*
 * udprelay.h - Define UDP relay's buffers and callbacks
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

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <time.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "crypto.h"
#include "jconf.h"

#ifdef MODULE_REMOTE
#include "resolv.h"
#endif

#include "common.h"

#ifdef MODULE_REMOTE
typedef struct query {
    buffer_t *buf;
    struct server *server;
    struct sockaddr_storage *src_addr;
} query_t;
#endif

typedef struct server {
    ev_io io;
    int fd;

    struct remote *remote;
    struct listen_ctx *listen_ctx;

    // socket pool/cache
    struct cork_dllist remotes;
} server_t;

typedef struct remote {
    ev_io io;
    ev_timer watcher;
    int fd;
    int direct;

#ifdef MODULE_LOCAL
    crypto_t *crypto;
#ifdef MODULE_SOCKS
    buffer_t *abuf;
#endif
#endif

    struct server *server;
    struct cork_dllist_item entries;

    struct sockaddr_storage *src_addr;
#ifdef MODULE_REDIR
    struct sockaddr_storage *destaddr;
#endif
} remote_t;

#endif // _UDPRELAY_H
