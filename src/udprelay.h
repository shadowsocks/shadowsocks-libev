 /*
 * udprelay.h - Define UDP relay's buffers and callbacks
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

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"

#ifdef UDPRELAY_REMOTE
#include "resolv.h"
#endif

#include "cache.h"

#include "common.h"

#define MAX_UDP_PACKET_SIZE (65507)

#define MTU 1397 // 1492 - 1 - 28 - 2 - 64 = 1397, the default MTU for UDP relay

struct server_ctx {
    ev_io io;
    int fd;
    int method;
    int timeout;
    const char *iface;
    struct cache *conn_cache;
#ifdef UDPRELAY_LOCAL
    const struct sockaddr *remote_addr;
    int remote_addr_len;
#ifdef UDPRELAY_TUNNEL
    ss_addr_t tunnel_addr;
#endif
#endif
#ifdef UDPRELAY_REMOTE
    struct ev_loop *loop;
#endif
};

#ifdef UDPRELAY_REMOTE
struct query_ctx {
    struct ResolvQuery *query;
    struct sockaddr_storage src_addr;
    int buf_len;
    char *buf; // server send from, remote recv into
    int addr_header_len;
    char addr_header[384];
    struct server_ctx *server_ctx;
    struct remote_ctx *remote_ctx;
};
#endif

struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int af;
    int fd;
    int addr_header_len;
    char addr_header[384];
    struct sockaddr_storage src_addr;
#ifdef UDPRELAY_REMOTE
    struct sockaddr_storage dst_addr;
#endif
    struct server_ctx *server_ctx;
};

#ifdef ANDROID
struct protect_ctx {
    int buf_len;
    char *buf;
    struct sockaddr_storage addr;
    int addr_len;
    struct remote_ctx *remote_ctx;
};
#endif

#endif // _UDPRELAY_H
