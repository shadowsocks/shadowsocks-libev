/*
 * acl.h - Define the ACL interface
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

#ifndef _ACL_H
#define _ACL_H

#ifdef USE_SYSTEM_SHARED_LIB
#include <libcorkipset/ipset.h>
#else
#include <ipset/ipset.h>
#endif

#include "jconf.h"

enum {
    ACL_UNSPCLIST  = -1,
    ACL_ALLISTS    = 0,
    ACL_BLACKLIST  = 1,
    ACL_WHITELIST  = 2,
    ACL_BLOCKLIST  = 4,
    ACL_DELEGATION = 5
} acl_lists;

enum {
    ACL_ATYP_ANY = -1,
    ACL_ATYP_IP,
    ACL_ATYP_IPV4,
    ACL_ATYP_IPV6,
    ACL_ATYP_DOMAIN
} acl_types;

typedef struct {
    struct ip_set ipv4, ipv6;
    struct cork_dllist domain;
} addrlist;

typedef struct {
    int remote_num;     // number of remote servers
    int *remote_idxs;   // a list of indexes of remote servers
    addrlist _;         // the delegation list for load-balancing
} delglist;

typedef struct acl {
    int mode;
    addrlist blocklist;
    addrlist blacklist, whitelist;
    delglist **deleglist;
    //addrlist **deleglist;
} acl_t;

int init_acl(jconf_t *conf);
void free_acl(void);
void update_addrlist(addrlist *list, int atyp, const void *host);
bool search_addrlist(addrlist *list, int atyp, const void *host);
int search_acl(int atyp, const void *host, int type);

#endif // _ACL_H
