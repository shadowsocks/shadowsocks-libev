/*
 * server.c - Provide shadowsocks service
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

#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pwd.h>
#endif

#include <libcork/core.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "json.h"
#include "utils.h"
#include "manager.h"

#ifndef BUF_SIZE
#define BUF_SIZE 65535
#endif

int verbose          = 0;
char *executable     = "ss-server";
char *working_dir    = NULL;
int working_dir_size = 0;

static struct cork_hash_table *server_table;

#ifndef __MINGW32__
static int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

static void
build_config(char *prefix, struct server *server)
{
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
    fprintf(f, "\"server_port\":\"%s\",\n", server->port);
    fprintf(f, "\"password\":\"%s\",\n", server->password);
    fprintf(f, "}\n");
    fclose(f);
    ss_free(path);
}

static char *
construct_command_line(struct manager_ctx *manager, struct server *server)
{
    static char cmd[BUF_SIZE];
    int i;

    build_config(working_dir, server);

    memset(cmd, 0, BUF_SIZE);
    snprintf(cmd, BUF_SIZE,
             "%s -m %s --manager-address %s -f %s/.shadowsocks_%s.pid -c %s/.shadowsocks_%s.conf",
             executable, manager->method, manager->manager_address,
             working_dir, server->port, working_dir, server->port);

    if (manager->acl != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --acl %s", manager->acl);
    }
    if (manager->timeout != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -t %s", manager->timeout);
    }
#ifdef HAVE_SETRLIMIT
    if (manager->nofile) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -n %d", manager->nofile);
    }
#endif
    if (manager->user != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -a %s", manager->user);
    }
    if (manager->verbose) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -v");
    }
    if (manager->mode == UDP_ONLY) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -U");
    }
    if (manager->mode == TCP_AND_UDP) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -u");
    }
    if (manager->auth) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -A");
    }
    if (manager->fast_open) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --fast-open");
    }
    if (manager->mtu) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --mtu %d", manager->mtu);
    }
    if (manager->obfs) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " --obfs %s", manager->obfs);
    }
    for (i = 0; i < manager->nameserver_num; i++) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -d %s", manager->nameservers[i]);
    }
    for (i = 0; i < manager->host_num; i++) {
        int len = strlen(cmd);
        snprintf(cmd + len, BUF_SIZE - len, " -s %s", manager->hosts[i]);
    }

    if (verbose) {
        LOGI("cmd: %s", cmd);
    }

    return cmd;
}

static char *
get_data(char *buf, int len)
{
    char *data;
    int pos = 0;

    while (buf[pos] != '{' && pos < len)
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

    while (isspace((unsigned char)buf[pos]) && pos < len)
        pos++;
    if (pos == len) {
        return NULL;
    }
    action = buf + pos;

    while ((!isspace((unsigned char)buf[pos]) && buf[pos] != ':') && pos < len)
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
                    strncpy(server->port, value->u.string.ptr, 8);
                } else if (value->type == json_integer) {
                    snprintf(server->port, 8, "%" PRIu64 "", value->u.integer);
                }
            } else if (strcmp(name, "password") == 0) {
                if (value->type == json_string) {
                    strncpy(server->password, value->u.string.ptr, 128);
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
                strncpy(port, name, 8);
                *traffic = value->u.integer;
            }
        }
    }

    json_value_free(obj);
    return 0;
}

static void
add_server(struct manager_ctx *manager, struct server *server)
{
    bool new = false;
    cork_hash_table_put(server_table, (void *)server->port, (void *)server, &new, NULL, NULL);

    char *cmd = construct_command_line(manager, server);
    if (system(cmd) == -1) {
        ERROR("add_server_system");
    }
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
        ss_free(old_server);
    }

    stop_server(prefix, port);
}

static void
update_stat(char *port, uint64_t traffic)
{
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
    size_t r;
    struct sockaddr_un claddr;
    char buf[BUF_SIZE];

    memset(buf, 0, BUF_SIZE);

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
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
        add_server(manager, server);

        char msg[3] = "ok";
        if (sendto(manager->fd, msg, 2, 0, (struct sockaddr *)&claddr, len) != 2) {
            ERROR("add_sendto");
        }
    } else if (strcmp(action, "remove") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            if (server != NULL) {
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
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
create_server_socket(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, server_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM;              /* We want a UDP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_UDP;

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        server_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int ipv6only = host ? 1 : 0;
            setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(server_sock);
    }

    if (rp == NULL) {
        LOGE("cannot bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags         = 0;
    char *acl             = NULL;
    char *user            = NULL;
    char *password        = NULL;
    char *timeout         = NULL;
    char *method          = NULL;
    char *pid_path        = NULL;
    char *conf_path       = NULL;
    char *iface           = NULL;
    char *manager_address = NULL;
    char *obfs            = NULL;

    int auth      = 0;
    int fast_open = 0;
    int mode      = TCP_ONLY;
    int mtu       = 0;

#ifdef HAVE_SETRLIMIT
    static int nofile = 0;
#endif

    int server_num = 0;
    char *server_host[MAX_REMOTE_NUM];

    char *nameservers[MAX_DNS_NUM + 1];
    int nameserver_num = 0;

    jconf_t *conf = NULL;

    int option_index                    = 0;
    static struct option long_options[] = {
        { "fast-open",       no_argument,       0, 0 },
        { "acl",             required_argument, 0, 0 },
        { "manager-address", required_argument, 0, 0 },
        { "executable",      required_argument, 0, 0 },
        { "mtu",             required_argument, 0, 0 },
        { "obfs",            required_argument, 0, 0 },
        { "help",            no_argument,       0, 0 },
        {                 0,                 0, 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:l:k:t:m:c:i:d:a:n:huUvA",
                            long_options, &option_index)) != -1)
        switch (c) {
        case 0:
            if (option_index == 0) {
                fast_open = 1;
            } else if (option_index == 1) {
                acl = optarg;
            } else if (option_index == 2) {
                manager_address = optarg;
            } else if (option_index == 3) {
                executable = optarg;
            } else if (option_index == 4) {
                mtu = atoi(optarg);
            } else if (option_index == 5) {
                obfs = optarg;
            } else if (option_index == 6) {
                usage();
                exit(EXIT_SUCCESS);
            }
            break;
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                server_host[server_num++] = optarg;
            }
            break;
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            if (nameserver_num < MAX_DNS_NUM) {
                nameservers[nameserver_num++] = optarg;
            }
            break;
        case 'a':
            user = optarg;
            break;
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'A':
            auth = 1;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++)
                server_host[i] = conf->remote_addr[i].host;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
#ifdef TCP_FASTOPEN
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#endif
        if (conf->nameserver != NULL) {
            nameservers[nameserver_num++] = conf->nameserver;
        }
        if (auth == 0) {
            auth = conf->auth;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (obfs == 0) {
            obfs = conf->obfs;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
    }

    if (server_num == 0) {
        server_host[server_num++] = "0.0.0.0";
    }

    if (method == NULL) {
        method = "table";
    }

    if (timeout == NULL) {
        timeout = "60";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (server_num == 0 || manager_address == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
#endif
    }

    if (auth) {
        LOGI("onetime authentication enabled");
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    struct manager_ctx manager;
    memset(&manager, 0, sizeof(struct manager_ctx));

    manager.fast_open       = fast_open;
    manager.verbose         = verbose;
    manager.mode            = mode;
    manager.auth            = auth;
    manager.password        = password;
    manager.timeout         = timeout;
    manager.method          = method;
    manager.iface           = iface;
    manager.acl             = acl;
    manager.user            = user;
    manager.manager_address = manager_address;
    manager.hosts           = server_host;
    manager.host_num        = server_num;
    manager.nameservers     = nameservers;
    manager.nameserver_num  = nameserver_num;
    manager.mtu             = mtu;
    manager.obfs            = obfs;
#ifdef HAVE_SETRLIMIT
    manager.nofile = nofile;
#endif

    // initialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // setuid
    if (user != NULL && ! run_as(user)) {
        FATAL("failed to switch user");
    }

#ifndef __MINGW32__
    if (geteuid() == 0){
        LOGI("running from root user");
    }
#endif

    struct passwd *pw   = getpwuid(getuid());
    const char *homedir = pw->pw_dir;
    working_dir_size = strlen(homedir) + 15;
    working_dir      = ss_malloc(working_dir_size);
    snprintf(working_dir, working_dir_size, "%s/.shadowsocks", homedir);

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

    if (conf != NULL) {
        for (i = 0; i < conf->port_password_num; i++) {
            struct server *server = ss_malloc(sizeof(struct server));
            memset(server, 0, sizeof(struct server));
            strncpy(server->port, conf->port_password[i].port, 8);
            strncpy(server->password, conf->port_password[i].password, 128);
            add_server(&manager, server);
        }
    }

    int sfd;
    ss_addr_t ip_addr = { .host = NULL, .port = NULL };
    parse_addr(manager_address, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        struct sockaddr_un svaddr;
        sfd = socket(AF_UNIX, SOCK_DGRAM, 0);       /*  Create server socket */
        if (sfd == -1) {
            ss_free(working_dir);
            FATAL("socket");
        }

        setnonblocking(sfd);

        if (remove(manager_address) == -1 && errno != ENOENT) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        strncpy(svaddr.sun_path, manager_address, sizeof(svaddr.sun_path) - 1);

        if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }
    } else {
        sfd = create_server_socket(ip_addr.host, ip_addr.port);
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

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ss_free(working_dir);

    return 0;
}
