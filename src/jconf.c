/*
 * jconf.c - Parse the JSON format config file
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "jconf.h"
#include "json.h"
#include "string.h"

#include <libcork/core.h>

static char *to_string(const json_value *value)
{
    if (value->type == json_string) {
        return ss_strndup(value->u.string.ptr, value->u.string.length);
    } else if (value->type == json_integer) {
        return strdup(ss_itoa(value->u.integer));
    } else if (value->type == json_null) {
        return "null";
    } else {
        LOGE("%d", value->type);
        FATAL("Invalid config format.");
    }
    return 0;
}

void free_addr(ss_addr_t *addr)
{
    free(addr->host);
    free(addr->port);
    addr->host = NULL;
    addr->port = NULL;
}

void parse_addr(const char *str, ss_addr_t *addr)
{
    int ipv6 = 0, ret = -1, n = 0;
    char *pch;

    struct cork_ip ip;
    if (cork_ip_init(&ip, str) != -1) {
        addr->host = strdup(str);
        addr->port = NULL;
        return;
    }

    pch = strchr(str, ':');
    while (pch != NULL) {
        n++;
        ret = pch - str;
        pch = strchr(pch + 1, ':');
    }
    if (n > 1) {
        ipv6 = 1;
        if (str[ret - 1] != ']') {
            ret = -1;
        }
    }

    if (ret == -1) {
        if (ipv6) {
            addr->host = ss_strndup(str + 1, strlen(str) - 2);
        } else {
            addr->host = strdup(str);
        }
        addr->port = NULL;
    } else {
        if (ipv6) {
            addr->host = ss_strndup(str + 1, ret - 2);
        } else {
            addr->host = ss_strndup(str, ret);
        }
        addr->port = strdup(str + ret + 1);
    }
}

jconf_t *read_jconf(const char * file)
{

    static jconf_t conf;
    memset(&conf, 0, sizeof(conf));

    char *buf;
    json_value *obj;

    FILE *f = fopen(file, "rb");
    if (f == NULL) {
        FATAL("Invalid config path.");
    }

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (pos >= MAX_CONF_SIZE) {
        FATAL("Too large config file.");
    }

    buf = malloc(pos + 1);
    if (buf == NULL) {
        FATAL("No enough memory.");
    }

    int nread = fread(buf, pos, 1, f);
    if (!nread) {
        FATAL("Failed to read the config file.");
    }
    fclose(f);

    buf[pos] = '\0'; // end of string

    json_settings settings = { 0 };
    char error_buf[512];
    obj = json_parse_ex(&settings, buf, pos, error_buf);

    if (obj == NULL) {
        FATAL(error_buf);
    }

    if (obj->type == json_object) {
        int i, j;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server") == 0) {
                if (value->type == json_array) {
                    for (j = 0; j < value->u.array.length; j++) {
                        if (j >= MAX_REMOTE_NUM) {
                            break;
                        }
                        json_value *v = value->u.array.values[j];
                        parse_addr(to_string(v), conf.remote_addr + j);
                        conf.remote_num = j + 1;
                    }
                } else if (value->type == json_string) {
                    conf.remote_addr[0].host = to_string(value);
                    conf.remote_addr[0].port = NULL;
                    conf.remote_num = 1;
                }
            } else if (strcmp(name, "server_port") == 0) {
                conf.remote_port = to_string(value);
            } else if (strcmp(name, "local_address") == 0) {
                conf.local_addr = to_string(value);
            } else if (strcmp(name, "local_port") == 0) {
                conf.local_port = to_string(value);
            } else if (strcmp(name, "password") == 0) {
                conf.password = to_string(value);
            } else if (strcmp(name, "method") == 0) {
                conf.method = to_string(value);
            } else if (strcmp(name, "timeout") == 0) {
                conf.timeout = to_string(value);
            } else if (strcmp(name, "fast_open") == 0) {
                conf.fast_open = value->u.boolean;
            } else if (strcmp(name, "nofile") == 0) {
                conf.nofile = value->u.integer;
            } else if (strcmp(name, "nameserver") == 0) {
                conf.nameserver = to_string(value);
            } else if (strcmp(name, "bitcoin_address") == 0) {
                conf.bitcoin_address = to_string(value);
            } else if (strcmp(name, "bitcoin_privkey") == 0) {
                conf.bitcoin_privkey = to_string(value);
            }
        }
    } else {
        FATAL("Invalid config file");
    }

    free(buf);
    json_value_free(obj);
    return &conf;

}
