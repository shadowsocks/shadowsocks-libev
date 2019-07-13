/*
 * manager.c - Shadowsocks service controller
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>

#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pwd.h>
#include <libcork/core.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "json.h"
#include "utils.h"
#include "netutils.h"
#include "manager.h"

int verbose          = 0;
char *executable     = "ss-server";
char *working_dir    = NULL;
int working_dir_size = 0;

static struct cork_hash_table *server_table;

static void
destroy_server(struct server *server)
{
// function used to free memories alloced in **get_server**
    if (server->method)
        ss_free(server->method);
    if (server->plugin)
        ss_free(server->plugin);
    if (server->plugin_opts)
        ss_free(server->plugin_opts);
    if (server->mode)
        ss_free(server->mode);
}

static void
build_config(char *prefix, struct manager_ctx *manager, struct server *server)
{
    jconf_t *conf = manager->conf;
    char *path    = NULL;
    int path_size = strlen(prefix) + strlen(server->port) + 20;

    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/.shadowsocks_%s.conf", prefix, server->port);
    FILE *f = fopen(path, "w+");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open config file");
        }
        ss_free(path);
        return;
    }
    fprintf(f, "{\n");
    fprintf(f, "\"server_port\":%d,\n", atoi(server->port));
    fprintf(f, "\"password\":\"%s\"", server->password);
    if (server->method)
        fprintf(f, ",\n\"method\":\"%s\"", server->method);
    else if (conf->method)
        fprintf(f, ",\n\"method\":\"%s\"", conf->method);
    if (server->fast_open[0])
        fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
    else if (conf->fast_open)
        fprintf(f, ",\n\"fast_open\": true");
    if (server->no_delay[0])
        fprintf(f, ",\n\"no_delay\": %s", server->no_delay);
    else if (conf->no_delay)
        fprintf(f, ",\n\"no_delay\": true");
    if (server->mode)
        fprintf(f, ",\n\"mode\":\"%s\"", server->mode);
    if (server->plugin)
        fprintf(f, ",\n\"plugin\":\"%s\"", server->plugin);
    if (server->plugin_opts)
        fprintf(f, ",\n\"plugin_opts\":\"%s\"", server->plugin_opts);
    fprintf(f, "\n}\n");
    fclose(f);
    ss_free(path);
}

static char *
construct_command_line(struct manager_ctx *manager, struct server *server)
{
    jconf_t *conf = manager->conf;
    static char cmd[BUF_SIZE];
    int i;
    int port;

    port = atoi(server->port);

    build_config(working_dir, manager, server);

    memset(cmd, 0, BUF_SIZE);
    snprintf(cmd, BUF_SIZE,
             "%s --manager-address %s -f %s/.shadowsocks_%d.pid -c %s/.shadowsocks_%d.conf",
             executable, conf->manager_addr, working_dir, port, working_dir, port);

    if (conf->acl != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --acl %s", conf->acl);
    }
    if (conf->timeout != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -t %s", conf->timeout);
    }
#ifdef HAVE_SETRLIMIT
    if (conf->nofile) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -n %d", conf->nofile);
    }
#endif
    if (conf->user != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -a %s", conf->user);
    }
    if (conf->verbose) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -v");
    }
    if (server->mode == NULL && conf->mode == UDP_ONLY) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -U");
    }
    if (server->mode == NULL && conf->mode == TCP_AND_UDP) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -u");
    }
    if (server->fast_open[0] == 0 && conf->fast_open) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --fast-open");
    }
    if (server->no_delay[0] == 0 && conf->no_delay) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --no-delay");
    }
    if (conf->ipv6_first) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -6");
    }
    if (conf->mtu) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --mtu %d", conf->mtu);
    }
    if (server->plugin == NULL && conf->plugin) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --plugin \"%s\"", conf->plugin);
    }
    if (server->plugin_opts == NULL && conf->plugin_opts) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --plugin-opts \"%s\"", conf->plugin_opts);
    }
    if (conf->nameserver) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -d \"%s\"", conf->nameserver);
    }
    if (conf->workdir)
    {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -D \"%s\"", conf->workdir);
    }
    for (i = 0; i < conf->remote_num; i++) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -s %s", conf->remotes[i]->addr);
    }

    if (conf->verbose) {
        LOGI("cmd: %s", cmd);
    }

    return cmd;
}

static char *
get_data(char *buf, int len)
{
    char *data;
    int pos = 0;

    while (pos < len && buf[pos] != '{')
        pos++;
    if (pos == len) {
        return NULL;
    }
    data = buf + pos - 1;

    return data;
}

static char *
get_action(char *buf, int len)
{
    char *action;
    int pos = 0;

    while (pos < len && isspace((unsigned char)buf[pos]))
        pos++;
    if (pos == len) {
        return NULL;
    }
    action = buf + pos;

    while (pos < len && (!isspace((unsigned char)buf[pos]) && buf[pos] != ':'))
        pos++;
    buf[pos] = '\0';

    return action;
}

static struct server *
get_server(char *buf, int len)
{
    char *data = get_data(buf, len);
    char error_buf[512];

    if (data == NULL) {
        LOGE("No data found");
        return NULL;
    }

    json_settings settings = { 0 };
    json_value *obj        = json_parse_ex(&settings, data, strlen(data), error_buf);

    if (obj == NULL) {
        LOGE("%s", error_buf);
        return NULL;
    }

    struct server *server = ss_malloc(sizeof(struct server));
    memset(server, 0, sizeof(struct server));
    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name        = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server_port") == 0) {
                if (value->type == json_string) {
                    strncpy(server->port, value->u.string.ptr, 7);
                } else if (value->type == json_integer) {
                    snprintf(server->port, 8, "%" PRIu64 "", value->u.integer);
                }
            } else if (strcmp(name, "password") == 0) {
                if (value->type == json_string) {
                    strncpy(server->password, value->u.string.ptr, 127);
                }
            } else if (strcmp(name, "method") == 0) {
                if (value->type == json_string) {
                    server->method = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "fast_open") == 0) {
                if (value->type == json_boolean) {
                    strncpy(server->fast_open, (value->u.boolean ? "true" : "false"), 8);
                }
            } else if (strcmp(name, "no_delay") == 0) {
                if (value->type == json_boolean) {
                    strncpy(server->no_delay, (value->u.boolean ? "true" : "false"), 8);
                }
            } else if (strcmp(name, "plugin") == 0) {
                if (value->type == json_string) {
                    server->plugin = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "plugin_opts") == 0) {
                if (value->type == json_string) {
                    server->plugin_opts = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "mode") == 0) {
                if (value->type == json_string) {
                    server->mode = strdup(value->u.string.ptr);
                }
            } else {
                LOGE("invalid data: %s", data);
                break;
            }
        }
    }

    json_value_free(obj);
    return server;
}

static int
parse_traffic(char *buf, int len, char *port, uint64_t *traffic)
{
    char *data = get_data(buf, len);
    char error_buf[512];
    json_settings settings = { 0 };

    if (data == NULL) {
        LOGE("No data found");
        return -1;
    }

    json_value *obj = json_parse_ex(&settings, data, strlen(data), error_buf);
    if (obj == NULL) {
        LOGE("%s", error_buf);
        return -1;
    }

    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name        = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (value->type == json_integer) {
                strncpy(port, name, 7);
                *traffic = value->u.integer;
            }
        }
    }

    json_value_free(obj);
    return 0;
}

static int
check_port(struct manager_ctx *manager, struct server *server)
{
    jconf_t *conf = manager->conf;
    bool both_tcp_udp = conf->mode == TCP_AND_UDP;
    int fd_count      = conf->remote_num * (both_tcp_udp ? 2 : 1);
    int bind_err      = 0;

    int *sock_fds = (int *)ss_malloc(fd_count * sizeof(int));
    memset(sock_fds, 0, fd_count * sizeof(int));

    struct sockaddr_storage *storage
        = ss_calloc(1, sizeof(struct sockaddr_storage));

    /* try to bind each interface */
    for (int i = 0; i < conf->remote_num; i++) {
        LOGI("try to bind address: %s, port: %s", conf->remotes[i]->addr, server->port);

        if (get_sockaddr(conf->remotes[i]->addr, server->port, storage, 1, conf->ipv6_first) == -1) {
            FATAL("failed to resolve %s", conf->remotes[i]->addr);
        }

        listen_ctx_t listen_ctx = {
            .iface  = conf->remotes[i]->iface,
            .addr   = storage,
        };

        if (conf->mode == UDP_ONLY) {
            sock_fds[i] = create_and_bind(storage, IPPROTO_UDP, &listen_ctx);
        } else {
            sock_fds[i] = create_and_bind(storage, IPPROTO_TCP, &listen_ctx);
        }

        if (both_tcp_udp) {
            sock_fds[i + conf->remote_num]
                        = create_and_bind(storage, IPPROTO_UDP, &listen_ctx);
        }

        if (sock_fds[i] == -1 || (both_tcp_udp && sock_fds[i + conf->remote_num] == -1)) {
            bind_err = -1;
            break;
        }
    }

    /* clean socks */
    for (int i = 0; i < fd_count; i++)
        if (sock_fds[i] > 0) {
            close(sock_fds[i]);
        }

    ss_free(sock_fds);

    return bind_err == -1 ? -1 : 0;
}

static int
add_server(struct manager_ctx *manager, struct server *server)
{
    int ret = check_port(manager, server);

    if (ret == -1) {
        LOGE("port is not available, please check.");
        return -1;
    }

    bool new = false;
    cork_hash_table_put(server_table, (void *)server->port, (void *)server, &new, NULL, NULL);

    char *cmd = construct_command_line(manager, server);
    if (system(cmd) == -1) {
        ERROR("add_server_system");
        return -1;
    }

    return 0;
}

static void
kill_server(char *prefix, char *pid_file)
{
    char *path = NULL;
    int pid, path_size = strlen(prefix) + strlen(pid_file) + 2;
    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/%s", prefix, pid_file);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open pid file");
        }
        ss_free(path);
        return;
    }
    if (fscanf(f, "%d", &pid) != EOF) {
        kill(pid, SIGTERM);
    }
    fclose(f);
    remove(path);
    ss_free(path);
}

static void
stop_server(char *prefix, char *port)
{
    char *path = NULL;
    int pid, path_size = strlen(prefix) + strlen(port) + 20;
    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/.shadowsocks_%s.pid", prefix, port);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open pid file");
        }
        ss_free(path);
        return;
    }
    if (fscanf(f, "%d", &pid) != EOF) {
        kill(pid, SIGTERM);
    }
    fclose(f);
    ss_free(path);
}

static void
remove_server(char *prefix, char *port)
{
    char *old_port            = NULL;
    struct server *old_server = NULL;

    cork_hash_table_delete(server_table, (void *)port, (void **)&old_port, (void **)&old_server);

    if (old_server != NULL) {
        destroy_server(old_server);
        ss_free(old_server);
    }

    stop_server(prefix, port);
}

static void
update_stat(char *port, uint64_t traffic)
{
    if (verbose) {
        LOGI("update traffic %" PRIu64 " for port %s", traffic, port);
    }
    void *ret = cork_hash_table_get(server_table, (void *)port);
    if (ret != NULL) {
        struct server *server = (struct server *)ret;
        server->traffic = traffic;
    }
}

static void
manager_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct manager_ctx *manager = (struct manager_ctx *)w;
    socklen_t len;
    ssize_t r;
    struct sockaddr_un claddr;
    char buf[BUF_SIZE] = { 0 };

    len = sizeof(struct sockaddr_un);
    r   = recvfrom(manager->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&claddr, &len);
    if (r == -1) {
        ERROR("manager_recvfrom");
        return;
    }

    if (r > BUF_SIZE / 2) {
        LOGE("too large request: %d", (int)r);
        return;
    }

    char *action = get_action(buf, r);
    if (action == NULL) {
        return;
    }

    if (strcmp(action, "add") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0 || server->password[0] == 0) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            if (server != NULL) {
                destroy_server(server);
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
        int ret = add_server(manager, server);

        char *msg;

        if (ret == -1) {
            msg     = "port is not available";
        } else {
            msg     = "ok";
        }

        if (sendto(manager->fd, msg, strlen(msg) - 1, 0,
                   (struct sockaddr *)&claddr, len) != 2) {
            ERROR("add_sendto");
        }
    } else if (strcmp(action, "list") == 0) {
        struct cork_hash_table_iterator iter;
        struct cork_hash_table_entry  *entry;
        char buf[BUF_SIZE];
        memset(buf, 0, BUF_SIZE);
        sprintf(buf, "[");

        cork_hash_table_iterator_init(server_table, &iter);
        while ((entry = cork_hash_table_iterator_next(&iter)) != NULL) {
            struct server *server = (struct server *)entry->value;
            char *method          = server->method ? server->method : manager->conf->method;
            size_t pos            = strlen(buf);
            size_t entry_len      = strlen(server->port) + strlen(server->password) + strlen(method);
            if (pos > BUF_SIZE - entry_len - 50) {
                if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
                    != pos) {
                    ERROR("list_sendto");
                }
                memset(buf, 0, BUF_SIZE);
                pos = 0;
            }
            sprintf(buf + pos, "\n\t{\"server_port\":\"%s\",\"password\":\"%s\",\"method\":\"%s\"},",
                    server->port, server->password, method);
        }

        size_t pos = strlen(buf);
        strcpy(buf + pos - 1, "\n]"); // Remove trailing ","
        pos = strlen(buf);
        if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
            != pos) {
            ERROR("list_sendto");
        }
    } else if (strcmp(action, "remove") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            if (server != NULL) {
                destroy_server(server);
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
        destroy_server(server);
        ss_free(server);

        char msg[3] = "ok";
        if (sendto(manager->fd, msg, 2, 0, (struct sockaddr *)&claddr, len) != 2) {
            ERROR("remove_sendto");
        }
    } else if (strcmp(action, "stat") == 0) {
        char port[8];
        uint64_t traffic = 0;

        if (parse_traffic(buf, r, port, &traffic) == -1) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            return;
        }

        update_stat(port, traffic);
    } else if (strcmp(action, "ping") == 0) {
        struct cork_hash_table_entry *entry;
        struct cork_hash_table_iterator server_iter;

        char buf[BUF_SIZE];

        memset(buf, 0, BUF_SIZE);
        sprintf(buf, "stat: {");

        cork_hash_table_iterator_init(server_table, &server_iter);

        while ((entry = cork_hash_table_iterator_next(&server_iter)) != NULL) {
            struct server *server = (struct server *)entry->value;
            size_t pos            = strlen(buf);
            if (pos > BUF_SIZE / 2) {
                buf[pos - 1] = '}';
                if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
                    != pos) {
                    ERROR("ping_sendto");
                }
                memset(buf, 0, BUF_SIZE);
            } else {
                sprintf(buf + pos, "\"%s\":%" PRIu64 ",", server->port, server->traffic);
            }
        }

        size_t pos = strlen(buf);
        if (pos > 7) {
            buf[pos - 1] = '}';
        } else {
            buf[pos] = '}';
            pos++;
        }

        if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
            != pos) {
            ERROR("ping_sendto");
        }
    }

    return;

ERROR_MSG:
    strcpy(buf, "err");
    if (sendto(manager->fd, buf, 3, 0, (struct sockaddr *)&claddr, len) != 3) {
        ERROR("error_sendto");
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

int
main(int argc, char **argv)
{
    USE_TTY();

    int pid_flags = 0;
    jconf_t conf  = jconf_default;

    if (parse_argopts(&conf, argc, argv) != 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (!(conf.remotes != NULL &&
        conf.remote_num > 0)) {
        FATAL("at least one server should be specified");
    }

    if (conf.manager_addr == NULL) {
        FATAL("invalid manager address");
    }

    pid_flags = conf.pid_path != NULL;
    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(conf.pid_path);
    }

#ifndef __MINGW32__
    // setuid
    if (conf.user && !run_as(conf.user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    if (conf.mtu > 0) {
        LOGI("setting MTU to %d", conf.mtu);
    }

    if (conf.mptcp) {
        LOGI("enabled multipath TCP");
    }

    if (conf.no_delay) {
        LOGI("enabled TCP no-delay");
    }

    if (conf.fast_open) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        conf.fast_open = 0;
#endif
    }

    verbose = conf.verbose;

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    struct manager_ctx manager = {
        .conf = &conf
    };

    // initialize ev loop
    struct ev_loop *loop = EV_DEFAULT;
    struct passwd *pw    = getpwuid(getuid());

    if (conf.workdir == NULL || strlen(conf.workdir) == 0) {
        conf.workdir = pw->pw_dir;
        // If home dir is still not defined or set to nologin/nonexistent, fall back to /tmp
        if (strstr(conf.workdir, "nologin") ||
            strstr(conf.workdir, "nonexistent") ||
            conf.workdir == NULL ||
            strlen(conf.workdir) == 0) {
            conf.workdir = "/tmp";
        }

        working_dir_size = strlen(conf.workdir) + 15;
        working_dir = ss_malloc(working_dir_size);
        snprintf(working_dir, working_dir_size, "%s/.shadowsocks", conf.workdir);
    } else {
        working_dir_size = strlen(conf.workdir) + 2;
        working_dir = ss_malloc(working_dir_size);
        snprintf(working_dir, working_dir_size, "%s", conf.workdir);
    }
    LOGI("working directory points to %s", working_dir);

    int err = mkdir(working_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (err != 0 && errno != EEXIST) {
        ERROR("mkdir");
        ss_free(working_dir);
        FATAL("unable to create working directory");
    }

    // Clean up all existed processes
    DIR *dp;
    struct dirent *ep;
    dp = opendir(working_dir);
    if (dp != NULL) {
        while ((ep = readdir(dp)) != NULL) {
            size_t len = strlen(ep->d_name);
            if (strcmp(ep->d_name + len - 3, "pid") == 0) {
                kill_server(working_dir, ep->d_name);
                if (verbose)
                    LOGI("kill %s", ep->d_name);
            }
        }
        closedir(dp);
    } else {
        ss_free(working_dir);
        FATAL("Couldn't open the directory");
    }

    server_table = cork_string_hash_table_new(MAX_PORT_NUM, 0);

    ss_port_password_t **port_password = conf.port_password;
    while (*port_password++ != NULL) {
        add_server(&manager, &(server_t) {
            .port = (*port_password)->port,
            .password = (*port_password)->password
        });
    }

    int sfd;
    ss_addr_t ip_addr = {};
    parse_addr(conf.manager_addr, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        struct sockaddr_un svaddr;
        sfd = socket(AF_UNIX, SOCK_DGRAM, 0);       /*  Create server socket */
        if (sfd == -1) {
            ss_free(working_dir);
            FATAL("socket");
        }

        setnonblocking(sfd);

        if (remove(conf.manager_addr) == -1 && errno != ENOENT) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        strncpy(svaddr.sun_path, conf.manager_addr, sizeof(svaddr.sun_path) - 1);

        if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }
    } else {
        struct sockaddr_storage storage = {};
        char *host = ip_addr.host, *port = ip_addr.port;
        if (get_sockaddr(host, port, &storage, 1, conf.ipv6_first) == -1) {
            FATAL("failed to resolve %s", host);
        }
        sfd = create_and_bind(&storage, IPPROTO_UDP, NULL);
        if (sfd == -1) {
            ss_free(working_dir);
            FATAL("socket");
        }
    }

    manager.fd = sfd;
    ev_io_init(&manager.io, manager_recv_cb, manager.fd, EV_READ);
    ev_io_start(loop, &manager.io);

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    struct cork_hash_table_entry *entry;
    struct cork_hash_table_iterator server_iter;

    cork_hash_table_iterator_init(server_table, &server_iter);

    while ((entry = cork_hash_table_iterator_next(&server_iter)) != NULL) {
        struct server *server = (struct server *)entry->value;
        stop_server(working_dir, server->port);
    }

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ss_free(working_dir);

    return 0;
}
