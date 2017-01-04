/*
 * acl.h - Define the ACL interface
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
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

#ifndef _PLUGIN_H
#define _PLUGIN_H

#define PLUGIN_EXIT_ERROR  -2
#define PLUGIN_EXIT_NORMAL -1
#define PLUGIN_RUNNING      0

int start_plugin(const char *plugin,
                 const char *remote_host,
                 const char *remote_port,
                 const char *local_host,
                 const char *local_port);
uint16_t get_local_port();
void stop_plugin();

#endif // _PLUGIN_H
