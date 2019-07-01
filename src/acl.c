/*
 * acl.c - Manage the ACL (Access Control List)
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

#include <ctype.h>

#include "rule.h"
#include "netutils.h"
#include "utils.h"
#include "cache.h"
#include "acl.h"
#include "shadowsocks.h"

static acl_t acl;

void free_rules(struct cork_dllist *rules);
void update_addrlist(addrlist *list, int atyp, const void *host);

void
init_addrlist(addrlist *addrlist) {
    ipset_init(&addrlist->ipv4);
    ipset_init(&addrlist->ipv6);
    cork_dllist_init(&addrlist->domain);
}

void
free_addrlist(addrlist *addrlist) {
    ipset_done(&addrlist->ipv4);
    ipset_done(&addrlist->ipv6);
    free_rules(&addrlist->domain);
}

void
free_rules(struct cork_dllist *rules)
{
    rule_t *rule;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(rules, curr, next,
                        rule_t, rule, entries) {
        remove_rule(rule);
    }
}

int
init_acl(jconf_t *conf)
{
    const char *path = conf->acl;
    if (path == NULL) {
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        LOGE("Invalid acl path.");
        return -1;
    }

    acl.mode = ACL_BLACKLIST;

    init_addrlist(&acl.blocklist);
    init_addrlist(&acl.blacklist);
    init_addrlist(&acl.whitelist);

    addrlist *list = &acl.blacklist;

    char buf[MAX_HOSTNAME_LEN];

    while (!feof(f))
        if (fgets(buf, 256, f)) {
            // Discards the whole line if longer than 255 characters
            int long_line = 0;  // 1: Long  2: Error
            while ((strlen(buf) == 255) && (buf[254] != '\n')) {
                long_line = 1;
                LOGE("Discarding long ACL content: %s", buf);
                if (fgets(buf, 256, f) == NULL) {
                    long_line = 2;
                    break;
                }
            }
            if (long_line) {
                if (long_line == 1) {
                    LOGE("Discarding long ACL content: %s", buf);
                }
                continue;
            }

            // Trim the newline
            int len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }

            char *comment = strchr(buf, '#');
            if (comment) {
                *comment = '\0';
            }

            char *line = trim_whitespace(buf);
            if (strlen(line) == 0) {
                continue;
            }

            if (strcmp(line, "[outbound_block_list]") == 0) {
                list = &acl.blocklist;
                continue;
            } else if (strcmp(line, "[black_list]") == 0
                       || strcmp(line, "[bypass_list]") == 0) {
                list = &acl.blacklist;
                continue;
            } else if (strcmp(line, "[white_list]") == 0
                       || strcmp(line, "[proxy_list]") == 0) {
                list = &acl.whitelist;
                continue;
            } else if (strcmp(line, "[reject_all]") == 0
                       || strcmp(line, "[bypass_all]") == 0) {
                acl.mode = ACL_WHITELIST;
                continue;
            } else if (strcmp(line, "[accept_all]") == 0
                       || strcmp(line, "[proxy_all]") == 0) {
                acl.mode = ACL_BLACKLIST;
                continue;
            } else {
                const char *delim = "[]", *sep = ":";
                char *keyword = strtok(strdup(line), delim);

                if (strcmp(line, keyword) == 0) {
                    update_addrlist(list, ACL_ATYP_ANY, line);
                    continue;
                }

                int j = 0;
                do {
                    char *cmd = trim_whitespace(strtok(keyword, sep));
                    if (cmd != NULL) {
                        if (strcmp(cmd, "proxy_list") == 0) {
                            int remote_num = 0;
                            int *remote_idxs = NULL;

                            char *tag = NULL;
                            while ((tag = strtok(NULL, sep))) {
                                for (int i = 0; i < conf->remote_num; i++) {
                                    char *tag_ = trim_whitespace(tag);
                                    char *rtag = trim_whitespace(conf->remotes[i]->tag);
                                    if (rtag != NULL && strcmp(tag_, rtag) == 0) {
                                        remote_idxs = ss_realloc(remote_idxs,
                                                      (remote_num + 1) * sizeof(*remote_idxs));
                                        remote_idxs[remote_num++] = i;
                                    }
                                }
                            }

                            acl.deleglist = ss_realloc(acl.deleglist,
                                                (j + 1) * sizeof(acl.deleglist));
                            delglist *deleglist = acl.deleglist[j++]
                                                = ss_calloc(1, sizeof(*acl.deleglist));

                            deleglist->remote_num  = remote_num;
                            deleglist->remote_idxs = remote_idxs;
                            init_addrlist(list = &deleglist->_);
                        }
                    }
                } while ((keyword = strtok(NULL, delim)));
                acl.deleglist[j] = NULL;
            }
        }

    fclose(f);

    return 0;
}

void
free_acl(void)
{
    free_addrlist(&acl.blocklist);
    free_addrlist(&acl.blacklist);
    free_addrlist(&acl.whitelist);
}

void
update_addrlist(addrlist *list,
                int atyp, const void *host)
{
    switch (atyp) {
        case ACL_ATYP_ANY: {
            struct cork_ip addr;
            int cidr;
            char hostaddr[MAX_HOSTNAME_LEN] = { 0 };

            parse_addr_cidr((const char *)host, hostaddr, &cidr);
            int err = cork_ip_init(&addr, hostaddr);
            if (!err) {
                switch (addr.version) {
                    case 4:
                        if (cidr >= 0) {
                            ipset_ipv4_add_network(&list->ipv4, &addr.ip.v4, cidr);
                        } else {
                            ipset_ipv4_add(&list->ipv4, &addr.ip.v4);
                        } break;
                    case 6:
                        if (cidr >= 0) {
                            ipset_ipv6_add_network(&list->ipv6, &addr.ip.v6, cidr);
                        } else {
                            ipset_ipv6_add(&list->ipv6, &addr.ip.v6);
                        } break;
                }
            } else {
                rule_t *rule = new_rule();
                if (accept_rule_arg(rule, (const char *)host) != -1 && init_rule(rule)) {
                    add_rule(&list->domain, rule);
                }
            }
        }
        case ACL_ATYP_IP: {
            switch(((struct sockaddr_storage *)host)->ss_family) {
                case AF_INET: {
                    struct cork_ipv4 addr;
                    cork_ipv4_copy(&addr,
                        &((struct sockaddr_in *)host)->sin_addr);
                    ipset_ipv4_add(&list->ipv4, &addr);
                } break;
                case AF_INET6: {
                    struct cork_ipv6 addr;
                    cork_ipv6_copy(&addr,
                        &((struct sockaddr_in6 *)host)->sin6_addr);
                    ipset_ipv6_add(&list->ipv6, &addr);
                } break;
            }
        } break;
        case ACL_ATYP_IPV4: {
            struct cork_ipv4 addr;
            cork_ipv4_copy(&addr, (struct in_addr *)host);
            ipset_ipv4_add(&list->ipv4, &addr);
        } break;
        case ACL_ATYP_IPV6: {
            struct cork_ipv6 addr;
            cork_ipv6_copy(&addr, (struct in6_addr *)host);
            ipset_ipv6_add(&list->ipv6, &addr);
        } break;
        case ACL_ATYP_DOMAIN: {
            const char *dname = (const char *)host;
            rule_t *rule = new_rule();
            accept_rule_arg(rule, dname);
            init_rule(rule);
            add_rule(&list->domain, rule);
        } break;
    }
}

bool
search_addrlist(addrlist *list,
                int atyp, const void *host)
{
    if (host == NULL)
        return false;
    switch (atyp) {
        case ACL_ATYP_IP: {
            switch(((struct sockaddr_storage *)host)->ss_family) {
                case AF_INET: {
                    struct cork_ipv4 addr;
                    cork_ipv4_copy(&addr,
                        &((struct sockaddr_in *)host)->sin_addr);
                    return ipset_contains_ipv4(&list->ipv4, &addr);
                }
                case AF_INET6: {
                    struct cork_ipv6 addr;
                    cork_ipv6_copy(&addr,
                        &((struct sockaddr_in6 *)host)->sin6_addr);
                    return ipset_contains_ipv6(&list->ipv6, &addr);
                }
            }
        } break;
        case ACL_ATYP_IPV4: {
            struct cork_ipv4 addr;
            cork_ipv4_copy(&addr, (struct in_addr *)host);
            return ipset_contains_ipv4(&list->ipv4, &addr);
        }
        case ACL_ATYP_IPV6: {
            struct cork_ipv6 addr;
            cork_ipv6_copy(&addr, (struct in6_addr *)host);
            return ipset_contains_ipv6(&list->ipv6, &addr);
        }
        case ACL_ATYP_DOMAIN: {
            dname_t *dname = (dname_t *)host;
            return lookup_rule(&list->domain, dname->dname,
                               elvis(dname->len, strlen(dname->dname))) != NULL;
        }
    }
    return false;
}

/**
 * search_acl
 * ----------------------
 * Iterate through the ipset/dnamelist to see if
 * a certain entry is present given the address/domain
 *
 * @param atype
 *        the type of address
 *        ACL_ATYP_IPV4, ACL_ATYP_IPV6, or ACL_ATYP_DOMAIN
 * @param host
 *        target address/domain
 * @param type
 *        the type of list
 *
 * @return
 *        the index if delegation list is enabled,
 *        otherwise the boolean vaule to represent
 *        the searching result in context.
 */
int
search_acl(int atyp, const void *host, int type)
{
    if (type == ACL_DELEGATION) {
        delglist **deleglist = acl.deleglist;
        do {
            if (search_addrlist(&(*deleglist)->_, atyp, host)
                && (*deleglist)->remote_idxs != NULL)
                return (*deleglist)->remote_idxs[rand() % (*deleglist)->remote_num];
        } while (*(++deleglist));
    } else {
        bool ret = false;
        bool smart = (type == ACL_UNSPCLIST);
        addrlist *list = &acl.blacklist;
        for (int i = ACL_BLACKLIST; i <= ACL_BLOCKLIST; i *= 2) {
            if (smart || type == ACL_ALLISTS || i & type) {
                switch (smart ? acl.mode : i) {
                    case ACL_BLACKLIST:
                        list = &acl.blacklist;
                        break;
                    case ACL_WHITELIST:
                        list = &acl.whitelist;
                        break;
                    case ACL_BLOCKLIST:
                        list = &acl.blocklist;
                        break;
                    default:
                        return ret;
                }

                if (list == NULL)
                    return ret;

                // ACL smart mode: false for whitelist
                if ((ret = search_addrlist(list, atyp, host)) || smart)
                    return smart ? ret ^ (acl.mode == ACL_WHITELIST) : ret;
            }
        }
    }
    return -1;
}
