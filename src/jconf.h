/*
 * jconf.h - Define the config data structure
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
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

#ifndef _JCONF_H
#define _JCONF_H

#define MAX_PORT_NUM    1024
#define MAX_REMOTE_NUM  20
#define MAX_DSCP_NUM    64
#define MAX_CONF_SIZE   128 * 1024

enum {
    TCP_ONLY = 0,
    TCP_AND_UDP = 1,
    UDP_ONLY = 3
};

typedef enum jconf_type {
    jconf_type_any,
    jconf_type_unknown,
    jconf_type_help,
    jconf_type_boolean,
    jconf_type_int,
    jconf_type_string,
    jconf_type_proto,
    jconf_type_address,
    jconf_type_dscp,
    jconf_type_portpasswd,
    jconf_type_server,
    jconf_type_config
} jconf_types_t;

typedef struct jconf_options {
    char *name;
    jconf_types_t type;
    void *targ;
    struct jconf_options *options;
} jconf_options_t;

typedef struct jconf_args {
    char name;
    jconf_types_t type;
    int has_arg;
    void *targ;
} jconf_args_t;

typedef struct {
    char *host;
    char *port;
} ss_addr_t;

typedef struct {
    char *tag;
    char *addr;
    char *port;
    char *password;
    char *key;
    char *method;
    char *iface;
    char *plugin;
    char *plugin_opts;
} ss_remote_t;

typedef struct {
    char *port;
    char *password;
} ss_port_password_t;

typedef struct {
    char *port;
    int dscp;
} ss_dscp_t;

typedef struct {
    int remote_num;
    ss_remote_t *remotes[MAX_REMOTE_NUM + 1];
    ss_port_password_t *port_password[MAX_PORT_NUM + 1];

    char *remote_port;
    char *local_addr;
    char *local_port;
    char *iface;

    char *password;
    char *key;
    char *method;

    char *timeout;
    char *user;
    char *plugin;
    char *plugin_opts;
    int fast_open;
    int reuse_port;
    int remote_dns;
    int nofile;

    char *nameserver;

    ss_dscp_t *dscp[MAX_DSCP_NUM + 1];

    ss_addr_t tunnel_addr;

    int mode;
    int mtu;
    int mptcp;
    int ipv6_first;
    int no_delay;
    int verbose;
    char *workdir;
    char *executable;
    char *pid_path;
    char *manager_addr;
    char *log;

#ifdef __ANDROID__
    char *stat_path;
    int vpn;
#endif

    char *acl;
} jconf_t;

static
const jconf_t jconf_default = {
    .local_addr   = "localhost",
    .method       = "chacha20-ietf-poly1305",
#ifdef MODULE_MANAGER
    .manager_addr = "127.0.0.1:8839",
#endif
    .mode         = TCP_ONLY,
    .remote_dns   = 1,
    .timeout      = "60"
};

/* Values for long options */
enum {
    GETOPT_VAL_NULL,
    GETOPT_VAL_REUSE_PORT,
    GETOPT_VAL_FAST_OPEN,
    GETOPT_VAL_NODELAY,
    GETOPT_VAL_ACL,
    GETOPT_VAL_MTU,
    GETOPT_VAL_MPTCP,
    GETOPT_VAL_PLUGIN,
    GETOPT_VAL_PLUGIN_OPTS,
    GETOPT_VAL_KEY,
    GETOPT_VAL_MANAGER_ADDRESS,
    GETOPT_VAL_EXECUTABLE,
    GETOPT_VAL_WORKDIR,
    GETOPT_VAL_LOG,
    GETOPT_VAL_HELP = 'h',
    GETOPT_VAL_PASSWORD = 'k'
};

int parse_argopts(jconf_t *conf, int argc, char **argv);
void parse_jconf(jconf_t *conf, const char *file);
int validate_jconf(jconf_t *conf, void **required_options);
void parse_addr(const char *str, ss_addr_t *addr);
void free_addr(ss_addr_t *addr);

#endif // _JCONF_H
