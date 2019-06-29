/*
 * server.h - Define shadowsocks server's buffers and callbacks
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

#ifndef _MANAGER_H
#define _MANAGER_H

#include <time.h>
#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "jconf.h"

#include "common.h"

typedef struct manager_ctx {
    ev_io io;
    int fd;
    jconf_t *conf;
} manager_ctx_t;

typedef struct server {
    char *port;
    char *password;
    char *fast_open;
    char *no_delay;
    char *mode;
    char *method;
    char *plugin;
    char *plugin_opts;
    uint64_t traffic;
} server_t;

#endif // _MANAGER_H
