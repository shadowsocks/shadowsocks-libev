/*
 * jconf.c - Parse the JSON format config file
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include "netutils.h"
#include "utils.h"
#include "jconf.h"
#include "json.h"
#include "string.h"

#include <libcork/core.h>

#define check_json_value_type(value, expected_type, message, ...) \
    do { \
        if ((value)->type != (expected_type)) \
            FATAL(message, ## __VA_ARGS__); \
    } while (0)

static char *
to_string(const json_value *value)
{
    switch (value->type) {
        case json_string:
            return ss_strndup(value->u.string.ptr,
                              value->u.string.length);
        case json_integer:
            return strdup(ss_itoa(value->u.integer));
        case json_null:
            return NULL;
        default:
            LOGE("unknown value type %d", value->type);
            FATAL("invalid config format.");
    }
    return "";
}

void
free_addr(ss_addr_t *addr)
{
    ss_free(addr->host);
    ss_free(addr->port);
}

void
parse_addr(const char *str_in, ss_addr_t *addr)
{
    if (str_in == NULL)
        return;

    int ipv6 = 0, ret = -1, n = 0, len;
    char *pch;
    char *str = strdup(str_in);
    len = strlen(str_in);

    struct cork_ip ip;
    if (cork_ip_init(&ip, str) != -1) {
        addr->host = str;
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
        if (ret < len - 1)
        {
            addr->port = strdup(str + ret + 1);
        } else {
            addr->port = NULL;
        }
    }

    free(str);
}

static int
parse_dscp(char *str)
{
    size_t str_len = strlen(str);

    // Pre-defined values (EF, CSx, AFxy)
    if (str_len == 2 && strcasecmp(str, "EF") == 0) {
        return DSCP_EF;
    }

    if (str_len == DSCP_CS_LEN && strncasecmp(str, "CS", 2) == 0) {
        if (str[2] >= '0' && str[2] <= '7') {
            // CSx = 8x
            return (str[2] - '0') << 3;
        }
    }

    if (str_len == DSCP_AF_LEN && strncasecmp(str, "AF", 2) == 0) {
        if (str[2] >= '1' && str[2] <= '4' && str[3] >= '1' && str[3] <= '3') {
            // AFxy = 8x + 2y
            return ((str[2] - '0') << 3) | ((str[3] - '0') << 1);
        }
    }

    // Manual hexadecimal mode (0xYZ)
    char *endptr;
    int dscp = (int)strtol(str, &endptr, 0);
    if (*endptr == '\0' && dscp >= DSCP_MIN && dscp <= DSCP_MAX) {
        return dscp;
    }

    LOGE("Invalid DSCP value (%s)", str);
    return DSCP_DEFAULT;
}

static int
parse_mode(char *str)
{
    int mode = TCP_ONLY;
    if (str != NULL) {
        if (strcmp(str, "tcp_only") == 0)
            return TCP_ONLY;
        else if (strcmp(str, "tcp_and_udp") == 0)
            return TCP_AND_UDP;
        else if (strcmp(str, "udp_only") == 0)
            return UDP_ONLY;
        else
            LOGI("ignore unknown mode: %s, use tcp_only as fallback", str);
    }
    return mode;
}

void
translate_jconf(jconf_options_t *option, json_value *value)
{
    unsigned int j;
    void *entry = option->targ;

    switch (option->type) {
        case jconf_type_boolean: {
            check_json_value_type(value, json_boolean,
                                  "invalid config file: option %s must be a boolean",
                                  option->name);
            *(int *)entry = value->u.boolean;
        } break;
        case jconf_type_int: {
            check_json_value_type(value, json_integer,
                                  "invalid config file: option %s must be an integer",
                                  option->name);
            *(int *)entry = value->u.integer;
        } break;
        case jconf_type_string: {
            *(char **)entry = to_string(value);
        } break;
        case jconf_type_proto: {
            char *mode_str = to_string(value);
            *(int *)entry = parse_mode(mode_str);
            ss_free(mode_str);
        } break;
        case jconf_type_address: {
            char *addr_str = to_string(value);
            parse_addr(addr_str, (ss_addr_t *)entry);
            ss_free(addr_str);
        } break;
        case jconf_type_dscp: {
            if (value->type == json_object) {
                for (j = 0; j < value->u.object.length; j++) {
                    if (j >= MAX_DSCP_NUM) {
                        break;
                    }
                    json_value *v = value->u.object.values[j].value;
                    if (v->type == json_string) {
                        ((ss_dscp_t **)entry)[j] = &(ss_dscp_t) {
                            .port = ss_strndup(value->u.object.values[j].name,
                                               value->u.object.values[j].name_length),
                            .dscp = parse_dscp(to_string(v))
                        };
                    }
                }
            }
        } break;
        case jconf_type_portpasswd: {
            if (value->type == json_object) {
                for (j = 0; j < value->u.object.length; j++) {
                    if (j >= MAX_PORT_NUM) {
                        break;
                    }
                    json_value *v = value->u.object.values[j].value;
                    if (v->type == json_string) {
                        ((ss_port_password_t **)entry)[j] = &(ss_port_password_t) {
                            .port     = ss_strndup(value->u.object.values[j].name,
                                                   value->u.object.values[j].name_length),
                            .password = to_string(v)
                        };
                    }
                }
            }
        } break;
        case jconf_type_server: {
            ss_remote_t **remotes = (ss_remote_t **)entry;
            jconf_t *conf =
                cork_container_of(remotes, jconf_t, remotes);
            ss_remote_t *remote = ss_calloc(1, sizeof(ss_remote_t));

            struct jconf_options server_options[] = {
                { "tag",         jconf_type_string,  &remote->tag           },
                { "address",     jconf_type_string,  &remote->addr          },
                { "port",        jconf_type_string,  &remote->port          },
                { "password",    jconf_type_string,  &remote->password      },
                { "key",         jconf_type_string,  &remote->key           },
                { "method",      jconf_type_string,  &remote->method        },
                { "iface",       jconf_type_string,  &remote->iface         },
                { "plugin",      jconf_type_string,  &remote->plugin        },
                { "plugin-opts", jconf_type_string,  &remote->plugin_opts   },
                { NULL,                          0,                   NULL  }
            };

            switch (value->type) {
                case json_array: {
                    for (j = 0; j < value->u.array.length; j++) {
                        if (j >= MAX_REMOTE_NUM) {
                            LOGE("The rest of %d/%d servers ignored because of size limit",
                                 value->u.array.length, MAX_REMOTE_NUM);
                            break;
                        }
                        json_value *v = value->u.array.values[j];

                        switch (v->type) {
                            case json_object: {
                                translate_jconf(&(jconf_options_t) {
                                                    .type = jconf_type_config,
                                                    .targ = &remote, .options = server_options
                                                }, v);
                            } break;
                            default:
                            case json_string: {
                                translate_jconf(&(jconf_options_t) {
                                                    .type = jconf_type_string,
                                                    .targ = &remote->addr
                                                }, v);
                            } break;
                        }
                        remotes[conf->remote_num++] = remote;
                    }
                } break;
                case json_object: {
                    translate_jconf(&(jconf_options_t) {
                                        .type = jconf_type_config,
                                        .targ = &remote, .options = server_options
                                    }, value);
                    remotes[conf->remote_num++] = remote;
                } break;
                case json_string: {
                    translate_jconf(&(jconf_options_t) {
                                        .type = jconf_type_string,
                                        .targ = &remote->addr
                                    }, value);
                    remotes[conf->remote_num++] = remote;
                } break;
                default: {
                    LOGE("unknown value type %d", value->type);
                    FATAL("invalid multi-server config format");
                } return;
            }
        } break;
        case jconf_type_config: {
            if (value->type == json_object) {
                for (unsigned int i = 0; i < value->u.object.length; i++) {
                    char *name    = value->u.object.values[i].name;
                    json_value *v = value->u.object.values[i].value;

                    for (jconf_options_t *opt = option->options; opt->name != NULL; opt++) {
                        if (strcmp(opt->name, name) == 0)
                            translate_jconf(opt, v);
                    }
                }
            }
        } break;
        default:
            break;
    }
}

void
parse_jconf(jconf_t *conf, const char *file)
{
    char *buf = NULL;
    size_t pos = readoff_from(&buf, file);

    if (pos >= MAX_CONF_SIZE) {
        FATAL("Too large a config file.");
    }

    json_settings settings = { 0UL, 0, NULL, NULL, NULL };
    char error_buf[512];
    json_value *obj = json_parse_ex(&settings, buf, pos, error_buf);

    if (obj == NULL) {
        FATAL("%s", error_buf);
    }

    struct jconf_options options[] = {
        { "server",         jconf_type_server,      &conf->remotes          },
        { "port_password",  jconf_type_portpasswd,  &conf->port_password    },
        { "server_port",    jconf_type_string,      &conf->remote_port      },
        { "local_address",  jconf_type_string,      &conf->local_addr       },
        { "local_port",     jconf_type_string,      &conf->local_port       },
        { "tunnel_address", jconf_type_address,     &conf->tunnel_addr      },
        { "password",       jconf_type_string,      &conf->password         },
        { "key",            jconf_type_string,      &conf->key              },
        { "method",         jconf_type_string,      &conf->method           },
        { "timeout",        jconf_type_string,      &conf->timeout          },
        { "user",           jconf_type_string,      &conf->user             },
        { "plugin",         jconf_type_string,      &conf->plugin           },
        { "plugin_opts",    jconf_type_string,      &conf->plugin_opts      },
        { "fast_open",      jconf_type_boolean,     &conf->fast_open        },
        { "reuse_port",     jconf_type_boolean,     &conf->reuse_port       },
        { "remote_dns",     jconf_type_boolean,     &conf->remote_dns       },
        { "nofile",         jconf_type_int,         &conf->nofile           },
        { "nameserver",     jconf_type_string,      &conf->nameserver       },
        { "dscp",           jconf_type_dscp,        &conf->dscp             },
        { "mode",           jconf_type_proto,       &conf->mode             },
        { "mtu",            jconf_type_int,         &conf->mtu              },
        { "mptcp",          jconf_type_boolean,     &conf->mptcp            },
        { "ipv6_first",     jconf_type_boolean,     &conf->ipv6_first       },
        { "no_delay",       jconf_type_boolean,     &conf->no_delay         },
        { "workdir",        jconf_type_string,      &conf->workdir          },
        { "acl",            jconf_type_string,      &conf->acl              },
#ifdef HAS_SYSLOG
        { "use_syslog",     jconf_type_boolean,     &use_syslog             },
#endif
        { NULL,                              0,                     NULL    }
    };

    if (obj->type == json_object) {
        translate_jconf(&(jconf_options_t) {
                            .type = jconf_type_config,
                            .targ = &conf, .options = options
                        }, obj);
    } else {
        FATAL("Invalid config file");
    }

    ss_free(buf);
    json_value_free(obj);
}

int
parse_argopts(jconf_t *conf, int argc, char **argv)
{
    if (argc == 1) {
        parse_jconf(conf, get_default_conf());
        return 0;
    }

    char *short_options = ss_calloc(1, sizeof(char));
    struct option long_options[] = {
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
#ifndef MODULE_TUNNEL
        { "acl",         required_argument, NULL, GETOPT_VAL_ACL         },
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
        { "manager-address", required_argument, NULL, GETOPT_VAL_MANAGER_ADDRESS },
#ifdef MODULE_MANAGER
        { "executable",      required_argument, NULL, GETOPT_VAL_EXECUTABLE  },
        { "workdir",         required_argument, NULL, GETOPT_VAL_WORKDIR     },
#endif
#endif
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "log",         required_argument, NULL, GETOPT_VAL_LOG         },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,                          0, NULL,                      0 }
    };
    struct jconf_args options[] = {
        { 'c',  jconf_type_config,        required_argument,      NULL                },
        { 's',  jconf_type_server,        required_argument,      &conf->remotes      },
        { 'p',  jconf_type_string,        required_argument,      &conf->remote_port  },
        { 'b',  jconf_type_string,        required_argument,      &conf->local_addr   },
        { 's',  jconf_type_string,        required_argument,      &conf->local_port   },
        { 'f',  jconf_type_string,        required_argument,      &conf->pid_path     },
        { 't',  jconf_type_string,        required_argument,      &conf->timeout      },
        { 'm',  jconf_type_string,        required_argument,      &conf->method       },
        { 'a',  jconf_type_string,        required_argument,      &conf->user         },
        { 'n',  jconf_type_int,           required_argument,      &conf->nofile       },
        { 'u',  jconf_type_proto,               no_argument,      &conf->mode         },
        { 'U',  jconf_type_proto,               no_argument,      &conf->mode         },
        { 'v',  jconf_type_boolean,             no_argument,      &conf->verbose      },
        { '6',  jconf_type_boolean,             no_argument,      &conf->ipv6_first   },
#ifdef MODULE_TUNNEL
        { 'L',  jconf_type_address,       required_argument,      &conf->tunnel_addr  },
#endif
#ifdef MODULE_MANAGER
        { 'D',  jconf_type_string,              no_argument,      &conf->workdir      },
        { GETOPT_VAL_EXECUTABLE,  jconf_type_string,     -1,      &conf->executable   },
#else
        { 'D',  jconf_type_boolean,             no_argument,      &conf->remote_dns   },
#endif
#ifdef __ANDROID__
        { 'S',  jconf_type_string,        required_argument,      &conf->stat_path    },
        { 'V',  jconf_type_boolean,             no_argument,      &conf->vpn          },
#endif
#ifdef MODULE_REMOTE
        { 'd',  jconf_type_string,        required_argument,      &conf->nameserver   },
        { 'i',  jconf_type_string,        required_argument,      &conf->iface        },
        { GETOPT_VAL_MANAGER_ADDRESS, jconf_type_string, -1,      &conf->manager_addr },
#endif
        { GETOPT_VAL_FAST_OPEN,     jconf_type_boolean,  -1,      &conf->fast_open    },
        { GETOPT_VAL_ACL,           jconf_type_string,   -1,      &conf->acl          },
        { GETOPT_VAL_MTU,           jconf_type_int,      -1,      &conf->mtu          },
        { GETOPT_VAL_MPTCP,         jconf_type_boolean,  -1,      &conf->mptcp        },
        { GETOPT_VAL_NODELAY,       jconf_type_boolean,  -1,      &conf->no_delay     },
        { GETOPT_VAL_PLUGIN,        jconf_type_string,   -1,      &conf->plugin       },
        { GETOPT_VAL_PLUGIN_OPTS,   jconf_type_string,   -1,      &conf->plugin_opts  },
        { GETOPT_VAL_KEY,           jconf_type_string,   -1,      &conf->key          },
        { GETOPT_VAL_REUSE_PORT,    jconf_type_boolean,  -1,      &conf->reuse_port   },
        { GETOPT_VAL_LOG,           jconf_type_string,   -1,      &conf->log          },
        { GETOPT_VAL_PASSWORD,      jconf_type_string,
                                            required_argument,    &conf->password     },
        { GETOPT_VAL_HELP,          jconf_type_help,     no_argument,           NULL  },
        { '?',                      jconf_type_unknown,  -1,                    NULL  },
        { 0,                                         0,  no_argument,           NULL  }
    };

    for (jconf_args_t *option = options; option->name != 0; option++) {
        if (option->name != '?' &&
            option->has_arg != -1)
        {
            char optstr[3] = { [0] = option->name,
                               [1] = option->has_arg == required_argument ? ':' : 0 };
            short_options = ss_realloc(short_options, strlen(short_options) + strlen(optstr));
            strcat(short_options, optstr);
        }
    }

    opterr = 0;

    int c, curind;
    int conf_parsed = 0;

again:
    curind = optind;
    while ((c = getopt_long(argc, argv,
                            short_options, long_options, NULL)) != -1)
    {
        for (jconf_args_t *option = options; option->name != 0; option++) {
            if (option->name == c) {
                void *entry = option->targ;

                if (!conf_parsed) {
                    switch (option->type) {
                        case jconf_type_config:
                            optind = conf_parsed = 1;
                            parse_jconf(conf, optarg);
                            goto again;
                        default:
                            if ((optind == argc - 1)) {
                                optind = conf_parsed = 1;
                            } goto again;
                    }
                } else {
                    switch (option->type) {
                        case jconf_type_boolean:
                            *(int *)entry ^= 1;
                            break;
                        case jconf_type_int:
                            *(int *)entry = atoi(optarg);
                            break;
                        case jconf_type_string:
                            *(char **)entry = optarg;
                            break;
                        case jconf_type_address:
                            parse_addr(optarg, (ss_addr_t *)entry);
                            break;
                        case jconf_type_proto:
                            switch (c) {
                                case 'u':
                                    *(int *)entry = TCP_AND_UDP;
                                    break;
                                case 'U':
                                    *(int *)entry = UDP_ONLY;
                                    break;
                            } break;
                        case jconf_type_server: {
                            if (conf->remote_num < MAX_REMOTE_NUM) {
                                ss_addr_t addr;
                                parse_addr(optarg, &addr);
                                ss_remote_t *remote
                                    = ss_calloc(1, sizeof(ss_remote_t));
                                remote->addr = addr.host;
                                remote->port = addr.port;
                                ((ss_remote_t **)entry)[conf->remote_num++] = remote;
                            }
                        } break;
                        case jconf_type_help: {
                            usage();
                            exit(EXIT_SUCCESS);
                        } break;
                        case jconf_type_config: break;
                        default:
                        case jconf_type_unknown: {
                            // The option character is not recognized.
                            LOGE("Unrecognized option: %s",
                                 optopt ? (char []) { optopt } : argv[curind]);
                            opterr = 1;
                        } break;
                    }
                }
                break;
            }
        }
    }
    return opterr;
}
