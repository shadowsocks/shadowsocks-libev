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
#include <unistd.h>
#include <libgen.h>

#include "rule.h"
#include "netutils.h"
#include "utils.h"
#include "cache.h"
#include "acl.h"
#include "shadowsocks.h"

static acl_t acl;

typedef cork_array(char *) labels_t;
typedef struct {
    char *ltag;   // list tag
    labels_t *tags;  // delegation label
} label_t;

typedef struct ctrlist {
    label_t label;
    cork_array(addrlist *) *list;
} ctrlist_t;

void
init_addrlist(addrlist *addrlist)
{
    ipset_init(&addrlist->ip);
    cork_dllist_init(&addrlist->domain);
}

void
merge_addrlist(addrlist *dst, addrlist *src)
{
    struct ipset_iterator
        *sit = ipset_iterate(&src->ip, true),
        *sit_ntwks = ipset_iterate_networks(&src->ip, true);

    while (!sit->finished) {
        ipset_ip_add(&dst->ip, &sit->addr);
        ipset_iterator_advance(sit);
    }

    while (!sit_ntwks->finished) {
        ipset_ip_add_network(&dst->ip, &sit->addr, sit->cidr_prefix);
        ipset_iterator_advance(sit_ntwks);
    }

    cork_dllist_merge(&dst->domain, &src->domain);
    ipset_iterator_free(sit);
    ipset_iterator_free(sit_ntwks);
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
                if (cidr < 0) {
                    ipset_ip_add(&list->ip, &addr);
                } else {
                    ipset_ip_add_network(&list->ip, &addr, cidr);
                }
            } else {
                rule_t *rule = new_rule();
                if (accept_rule_arg(rule, (const char *)host) != -1
                    && init_rule(rule))
                {
                    add_rule(&list->domain, rule);
                }
            }
        }
        case ACL_ATYP_IP: {
            switch(((struct sockaddr_storage *)host)->ss_family) {
                case AF_INET: {
                    ipset_ipv4_add(&list->ip,
                        (struct cork_ipv4 *)&((struct sockaddr_in *)host)->sin_addr);
                } break;
                case AF_INET6: {
                    ipset_ipv6_add(&list->ip,
                        (struct cork_ipv6 *)&((struct sockaddr_in6 *)host)->sin6_addr);
                } break;
            }
        } break;
        case ACL_ATYP_IPV4: {
            ipset_ipv4_add(&list->ip,
                (struct cork_ipv4 *)&((struct sockaddr_in *)host)->sin_addr);
        } break;
        case ACL_ATYP_IPV6: {
            ipset_ipv6_add(&list->ip,
                (struct cork_ipv6 *)&((struct sockaddr_in6 *)host)->sin6_addr);
        } break;
        case ACL_ATYP_DOMAIN: {
            rule_t *rule = new_rule();
            if (accept_rule_arg(rule, (const char *)host) != -1
                && init_rule(rule))
            {
                add_rule(&list->domain, rule);
            }
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
                case AF_INET:
                    return ipset_contains_ipv4(&list->ip,
                           (struct cork_ipv4 *)&((struct sockaddr_in *)host)->sin_addr);
                case AF_INET6:
                    return ipset_contains_ipv6(&list->ip,
                           (struct cork_ipv6 *)&((struct sockaddr_in6 *)host)->sin6_addr);
            }
        } break;
        case ACL_ATYP_IPV4: {
            return ipset_contains_ipv4(&list->ip,
                   (struct cork_ipv4 *)&((struct sockaddr_in *)host)->sin_addr);
        }
        case ACL_ATYP_IPV6: {
            return ipset_contains_ipv6(&list->ip,
                   (struct cork_ipv6 *)&((struct sockaddr_in6 *)host)->sin6_addr);
        }
        case ACL_ATYP_DOMAIN: {
            dname_t *dname = (dname_t *)host;
            return lookup_rule(&list->domain, dname->dname,
                               elvis(dname->len, strlen(dname->dname))) != NULL;
        }
    }
    return false;
}

void
free_addrlist(addrlist *addrlist)
{
    rule_t *rule = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&addrlist->domain, curr, next,
                        rule_t, rule, entries) {
        remove_rule(rule);
    }
    ipset_done(&addrlist->ip);
}

ctrlist_t *
fetch_ctrlist(struct cache *ctrlists, label_t *label)
{
    ctrlist_t *ctrlist = NULL;
    size_t ltaglen = strlen(label->ltag);
    if (cache_lookup(ctrlists,
                     label->ltag, ltaglen + 1, &ctrlist) != 0) {
        ctrlist = ss_calloc(1, sizeof(ctrlist_t));
        ctrlist->label = *label;
        ctrlist->list  = ss_malloc(sizeof(*ctrlist->list));
        cork_array_init(ctrlist->list);
        addrlist *addrlist = ss_malloc(sizeof(*addrlist));
        init_addrlist(addrlist);
        cork_array_append(ctrlist->list, addrlist);
        cache_insert(ctrlists, label->ltag, ltaglen + 1, ctrlist);
    }
    return ctrlist;
}

void
ctrlist_free_cb(void *key, void *element)
{
    ctrlist_t *ctrlist = element;
    if (ctrlist->label.ltag)
        ss_free(ctrlist->label.ltag);
    if (ctrlist->list) {
        for (int i = 0; i < ctrlist->list->size; i++)
            free_addrlist(ctrlist->list->items[i]);
        cork_array_done(ctrlist->list);
        ss_free(ctrlist->list);
    }
    if (ctrlist->label.tags)
        cork_array_done(ctrlist->label.tags);
}

int
merge_ctrlists(struct cache *dst, struct cache *src)
{
    if (!(dst && src))
        return -1;

    struct cache_entry *entry, *tmp;
    cache_foreach(src, entry, tmp) {
        ctrlist_t *dstlist = NULL, *srclist = entry->data;
        size_t ltaglen = strlen(srclist->label.ltag);
        if (cache_lookup(dst, srclist->label.ltag, ltaglen + 1, &dstlist) == 0) {
            // TODO merge OR replace?
            if (!srclist->list)
                continue;
            if (dstlist->list)
                cork_array_merge(dstlist->list, srclist->list);
            if (!srclist->label.tags)
                continue;
            if (!dstlist->label.tags) {
                dstlist->label.tags = ss_malloc(sizeof(*dstlist->label.tags));
                cork_array_init(dstlist->label.tags);
            }
            cork_array_merge(dstlist->label.tags, srclist->label.tags);
        } else {
            cache_insert(dst, srclist->label.ltag, ltaglen + 1, srclist);
        }
    }
    return 0;
}

void
parse_aclconf(FILE *f, aclconf_t *aclconf, ctrlist_t *ctrlist_n)
{
    char buf[MAX_HOSTNAME_LEN];
    char dlscript[] = "$$", dlvarnme[] = "[]",
         dltagsep[] = ":",  dfaultag[] = "default",
         dlempty[]  = "", whitespace[] = " \t\n";

    struct cache *ctrlists = new_cache(-1, ctrlist_free_cb);
    if (ctrlists == NULL)
        return;

    ctrlist_t *ctrlist = fetch_ctrlist(ctrlists,
                    &(label_t) { .ltag = strdup(dfaultag) });

    while (fgets(buf, sizeof(buf), f) != NULL) {
        // Discards the whole line if longer than 255 characters
        while (strlen(buf) >= sizeof(buf) &&
               buf[sizeof(buf) - 2] != '\n') {
            LOGE("Discarding long ACL content: %s", buf);
            if (fgets(buf, sizeof(buf), f) == NULL)
                break;
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

        char *keywd_n = strdup(line);
        char *keyword = strtok(keywd_n, whitespace);

        if (strcmp(keyword, "@mode") == 0) {
            char *mode = strtok(NULL, whitespace);
            if (mode != NULL) {
                if (strcmp(mode, "reject") == 0 ||
                    strcmp(mode, "bypass") == 0 ||
                    strcmp(mode, "reject_all") == 0 ||
                    strcmp(mode, "bypass_all") == 0)
                {
                    aclconf->mode = ACL_BLACKLIST;
                } else
                if (strcmp(mode, "accept") == 0 ||
                    strcmp(mode, "proxy") == 0  ||
                    strcmp(mode, "accept_all") == 0 ||
                    strcmp(mode, "proxy_all") == 0)
                {
                    aclconf->mode = ACL_WHITELIST;
                }
            }
        } else if (strcmp(keyword, "@interval") == 0) {
            aclconf->interval = strtotime(strtok(NULL, whitespace));
        } else if (strcmp(keyword, "@algorithm") == 0) {
            continue;
        } else if (strcmp(keyword, "@import") == 0) {
            char *import = NULL;
            while ((import = strtok(NULL, whitespace))) {
                // scripting identifier
                if (strcmp(import, dlscript) == 0) {
                    char *script = strtok(NULL, dlempty);
                    size_t script_len = 0;
                    if (script != NULL) {
                        script = strdup(script);
                    }

                    do {
                        script_len = script ? strlen(script) : 0;
                        script = ss_realloc(script, script_len + BUF_SIZE + 1);

                        char *n;
                        if ((n = strstr(script, dlscript))) {
                            *n = 0;
                            break;
                        }
                    } while (fgets(script + script_len, BUF_SIZE, f));

                    FILE *f = popen(script, "r");
                    parse_aclconf(f, aclconf, ctrlist);
                    pclose(f);

                    ss_free(script);
                    break;
                } else {
                    char *varname = strtok(strdup(import), dlvarnme);
                    if (strcmp(varname, import)) {
                        // variable name
                        do {
                            char *ltag = trim_whitespace(varname);
                            ctrlist_t *ctrlistv = NULL;
                            // only valid inside the list
                            if (ltag != NULL && strcmp(ctrlist->label.ltag, dfaultag) != 0 &&
                                cache_lookup(ctrlists, ltag, strlen(ltag) + 1, &ctrlistv) == 0)
                            {
                                cork_array_merge(ctrlist->list, ctrlistv->list);
                            }
                        } while ((varname = strtok(NULL, dlvarnme)));
                    } else {
                        // file path
                        FILE *f = fopen(import, "r");
                        setcwd(current_dir(import));
                        parse_aclconf(f, aclconf, ctrlist);
                        fclose(f);
                    }
                }
            }
        } else {
            char *varname = strtok(line, dlvarnme);

            /**
             * acl entry: addrlist element
             * -------------------------------
             * format:  valid CIDR notation (IP addresses)
             *          or perl-compatible regex (domain name)
             * example: 127.0.0.1, 192.168.0.1/32, (^|\.)(edu|mil|gov|us)$
             */

            if (strcmp(line, varname) == 0) {
                update_addrlist(*ctrlist->list->items, ACL_ATYP_ANY, line);
                continue;
            }

            /**
             * acl definition: addrlist tag
             * -------------------------------
             * format:  [{ addrlist_type }: { tag }:{ tag }:...]
             * example: [proxy_list: La Jolla, CA]
             *
             * NOTE: delegation tags are not inheritable
             */

            do {
                char *ltag = trim_whitespace(strtok(varname, dltagsep));
                if (ltag != NULL) {
                    char *tag = NULL;
                    labels_t *tags = ss_malloc(sizeof(*tags));
                    cork_array_init(tags);
                    while ((tag = strtok(NULL, dltagsep))) {
                        cork_array_append(tags, trim_whitespace(tag));
                    }

                    ctrlist = fetch_ctrlist(ctrlists, &(label_t) { strdup(ltag), tags });
                }
            } while ((varname = strtok(NULL, dlvarnme)));
        }
        ss_free(keywd_n);
    }

    ctrlist_t *ctrlistv = NULL;
    if (ctrlist_n != NULL &&
        strcmp(ctrlist_n->label.ltag, dfaultag) != 0 &&
        (cache_lookup(ctrlists, ctrlist_n->label.ltag,
                     strlen(ctrlist_n->label.ltag) + 1, &ctrlistv) == 0 ||
        cache_lookup(ctrlists, dfaultag, sizeof(dfaultag), &ctrlistv) == 0))
    {
        // inside the list being declared
        cork_array_merge(ctrlist_n->list, ctrlistv->list);
    } else {
        // global scope
        merge_ctrlists(aclconf->lists, ctrlists);
    }

    cache_delete(ctrlists, true);
}

int
parse_acl(acl_t *acl, aclconf_t *aclconf)
{
    const char *path = aclconf->path;
    if (path == NULL) {
        return -1;
    }

    char *prevwd = getcwd(NULL, 0);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        LOGE("[acl] invalid acl path %s", path);
        return -1;
    }

    if (!aclconf->lists)
        return -1;

    setcwd(current_dir(path));
    parse_aclconf(f, aclconf, NULL);
    fclose(f);

    if (prevwd != NULL)
        setcwd(prevwd);
    ss_free(prevwd);

    if (aclconf->interval > 0) {
        ev_timer_set(&acl->watcher, aclconf->interval, aclconf->interval);
    }

    acl->mode = aclconf->mode;

    int j = 0;
    struct cache_entry *entry, *tmp;
    cache_foreach(aclconf->lists, entry, tmp) {
        ctrlist_t *list = entry->data;
        addrlist *rlist = &acl->blacklist;
        char *ltag = list->label.ltag;

        if (strcmp(ltag, "outbound_block_list") == 0) {
            rlist = &acl->blocklist;
        } else if (strcmp(ltag, "black_list") == 0 ||
                   strcmp(ltag, "bypass_list") == 0) {
            rlist = &acl->blacklist;
        } else if (strcmp(ltag, "white_list") == 0) {
            rlist = &acl->whitelist;
        } else if (strcmp(ltag, "proxy_list") == 0) {
            rlist = &acl->whitelist;
            if (list->label.tags != NULL) {
                acl->deleglist = ss_realloc(acl->deleglist,
                                    (j + 2) * sizeof(acl->deleglist));
                delglist *deleglist = acl->deleglist[j++]
                                    = ss_calloc(1, sizeof(*deleglist));

                cork_array_init(&deleglist->idxs);
                for (int n = 0; n < list->label.tags->size; n++) {
                    for (int i = 0; i < aclconf->conf->remote_num; i++) {
                        char *rtag = trim_whitespace(aclconf->conf->remotes[i]->tag);
                        if (rtag && strcmp(list->label.tags->items[n], rtag) == 0)
                            cork_array_append(&deleglist->idxs, i);
                    }
                }

                init_addrlist(rlist = &deleglist->_);
                acl->deleglist[j] = NULL;
            }
        } else {
            if (strcmp(ltag, "default") != 0)
                LOGE("[acl] invalid list type %s", ltag);
            continue;
        }

        // merge address lists
        for (int i = 0; i < list->list->size; i++)
            merge_addrlist(rlist, list->list->items[i]);
    }

    cache_clear(aclconf->lists, 0);

    return 0;
}

int
init_acl(jconf_t *conf)
{
    acl.conf = (aclconf_t) {
        .mode  = ACL_BLACKLIST,
        .lists = new_cache(-1, NULL),
        .path  = conf->acl,
        .conf  = conf
    };

    init_addrlist(&acl.blocklist);
    init_addrlist(&acl.blacklist);
    init_addrlist(&acl.whitelist);

    if (parse_acl(&acl, &acl.conf) != 0)
        return -1;

    return 0;
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
                && (*deleglist)->idxs.items != NULL)
                return (*deleglist)->idxs.items[rand() % (*deleglist)->idxs.size];
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
