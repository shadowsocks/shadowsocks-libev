/*
 * acl.c - Manage the ACL (Access Control List)
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

#include <ipset/ipset.h>

#include "rule.h"
#include "utils.h"
#include "acl.h"

static struct ip_set white_list_ipv4;
static struct ip_set white_list_ipv6;

static struct ip_set black_list_ipv4;
static struct ip_set black_list_ipv6;

rule_head_t black_list_rules;
rule_head_t white_list_rules;

static int acl_mode = BLACK_LIST;

static void parse_addr_cidr(const char *str, char *host, int *cidr)
{
    int ret = -1, n = 0;
    char *pch;

    pch = strchr(str, '/');
    while (pch != NULL) {
        n++;
        ret = pch - str;
        pch = strchr(pch + 1, '/');
    }
    if (ret == -1) {
        strcpy(host, str);
        *cidr = -1;
    } else {
        memcpy(host, str, ret);
        host[ret] = '\0';
        *cidr     = atoi(str + ret + 1);
    }
}

int init_acl(const char *path, int mode)
{
    acl_mode = mode;

    // initialize ipset
    ipset_init_library();

    ipset_init(&white_list_ipv4);
    ipset_init(&white_list_ipv6);
    ipset_init(&black_list_ipv4);
    ipset_init(&black_list_ipv6);

    STAILQ_INIT(&black_list_rules);
    STAILQ_INIT(&white_list_rules);

    struct ip_set *list_ipv4 = &black_list_ipv4;
    struct ip_set *list_ipv6 = &black_list_ipv6;
    rule_head_t *rules       = &black_list_rules;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        LOGE("Invalid acl path.");
        return -1;
    }

    char line[257];
    while (!feof(f))
        if (fgets(line, 256, f)) {
            // Trim the newline
            int len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            if (strcmp(line, "[black_list]") == 0
                    || strcmp(line, "[bypass_list]") == 0) {
                list_ipv4 = &black_list_ipv4;
                list_ipv6 = &black_list_ipv6;
                rules     = &black_list_rules;
                continue;
            } else if (strcmp(line, "[white_list]") == 0
                    || strcmp(line, "[proxy_list]") == 0) {
                list_ipv4 = &white_list_ipv4;
                list_ipv6 = &white_list_ipv6;
                rules     = &white_list_rules;
                continue;
            }

            char host[257];
            int cidr;
            parse_addr_cidr(line, host, &cidr);

            struct cork_ip addr;
            int err = cork_ip_init(&addr, host);
            if (!err) {
                if (addr.version == 4) {
                    if (cidr >= 0) {
                        ipset_ipv4_add_network(list_ipv4, &(addr.ip.v4), cidr);
                    } else {
                        ipset_ipv4_add(list_ipv4, &(addr.ip.v4));
                    }
                } else if (addr.version == 6) {
                    if (cidr >= 0) {
                        ipset_ipv6_add_network(list_ipv6, &(addr.ip.v6), cidr);
                    } else {
                        ipset_ipv6_add(list_ipv6, &(addr.ip.v6));
                    }
                }
            } else {
                rule_t *rule = new_rule();
                accept_rule_arg(rule, line);
                init_rule(rule);
                add_rule(rules, rule);
            }
        }

    fclose(f);

    return 0;
}

void free_rules(rule_head_t *rules)
{
    rule_t *iter;
    while ((iter = STAILQ_FIRST(rules)) != NULL)
        remove_rule(rules, iter);
}

void free_acl(void)
{
    ipset_done(&black_list_ipv4);
    ipset_done(&black_list_ipv6);
    ipset_done(&white_list_ipv4);
    ipset_done(&white_list_ipv6);

    free_rules(&black_list_rules);
    free_rules(&white_list_rules);
}

int get_acl_mode(void)
{
    return acl_mode;
}

void set_acl_mode(int mode)
{
    LOGI("white");
    acl_mode = mode;
}

/*
 * Return 0,  if not match.
 * Return 1,  if match black list.
 * Return -1, if match white list.
 */
int acl_match_host(const char *host)
{
    struct cork_ip addr;
    int ret = 0;
    int err = cork_ip_init(&addr, host);

    if (err) {
        int host_len = strlen(host);
        if (lookup_rule(&black_list_rules, host, host_len) != NULL)
            ret = 1;
        else if (lookup_rule(&white_list_rules, host, host_len) != NULL)
            ret = -1;
        return ret;
    }

    if (addr.version == 4) {
        if (ipset_contains_ipv4(&black_list_ipv4, &(addr.ip.v4)))
            ret = 1;
        else if (ipset_contains_ipv4(&white_list_ipv4, &(addr.ip.v4)))
            ret = -1;
    } else if (addr.version == 6) {
        if (ipset_contains_ipv6(&black_list_ipv6, &(addr.ip.v6)))
            ret = 1;
        else if (ipset_contains_ipv6(&white_list_ipv6, &(addr.ip.v6)))
            ret = -1;
    }

    return ret;
}

int acl_add_ip(const char *ip)
{
    struct cork_ip addr;
    int err = cork_ip_init(&addr, ip);
    if (err) {
        return -1;
    }

    if (addr.version == 4) {
        ipset_ipv4_add(&black_list_ipv4, &(addr.ip.v4));
    } else if (addr.version == 6) {
        ipset_ipv6_add(&black_list_ipv6, &(addr.ip.v6));
    }

    return 0;
}

int acl_remove_ip(const char *ip)
{
    struct cork_ip addr;
    int err = cork_ip_init(&addr, ip);
    if (err) {
        return -1;
    }

    if (addr.version == 4) {
        ipset_ipv4_remove(&black_list_ipv4, &(addr.ip.v4));
    } else if (addr.version == 6) {
        ipset_ipv6_remove(&black_list_ipv6, &(addr.ip.v6));
    }

    return 0;
}
