/*
 * plugin.c - Manage plugins
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

#ifndef __MINGW32__

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <libcork/core.h>
#include <libcork/os.h>

#include "utils.h"
#include "plugin.h"

#define CMD_RESRV_LEN 128

static int exit_code;
static struct cork_env *env = NULL;
static struct cork_exec *exec = NULL;
static struct cork_subprocess *sub = NULL;

static int
plugin_log__data(struct cork_stream_consumer *vself,
        const void *buf, size_t size, bool is_first)
{
    size_t  bytes_written = fwrite(buf, 1, size, stderr);
    /*  If there was an error writing to the file, then signal this
     *  to the producer */
    if (bytes_written == size) {
        return 0;
    } else {
        cork_system_error_set();
        return -1;
    }
}

static int
plugin_log__eof(struct cork_stream_consumer *vself)
{
    /*  We don't close the file, so there's nothing special to do at
     *  end-of-stream. */
    return 0;
}

static void
plugin_log__free(struct cork_stream_consumer *vself)
{
    return;
}

struct cork_stream_consumer plugin_log = {
    .data = plugin_log__data,
    .eof = plugin_log__eof,
    .free = plugin_log__free,
};

int
start_plugin(const char *plugin,
             const char *plugin_opts,
             const char *remote_host,
             const char *remote_port,
             const char *local_host,
             const char *local_port)
{
    char *new_path = NULL;
    char *cmd      = NULL;

    if (plugin == NULL)
        return -1;

    if (strlen(plugin) == 0)
        return 0;

    size_t plugin_len = strlen(plugin);
    size_t cmd_len = plugin_len + CMD_RESRV_LEN;
    cmd = ss_malloc(cmd_len);

    snprintf(cmd, cmd_len, "exec %s", plugin);

    env = cork_env_clone_current();
    const char *path = cork_env_get(env, "PATH");
    if (path != NULL) {
#ifdef __GLIBC__
        char *cwd = get_current_dir_name();
        if (cwd) {
#else
        char cwd[PATH_MAX];
        if (!getcwd(cwd, PATH_MAX)) {
#endif
            size_t path_len = strlen(path) + strlen(cwd) + 2;
            new_path = ss_malloc(path_len);
            snprintf(new_path, path_len, "%s:%s", cwd, path);
#ifdef __GLIBC__
            free(cwd);
#endif
        }
    }

    if (new_path != NULL)
        cork_env_add(env, "PATH", new_path);

    cork_env_add(env, "SS_REMOTE_HOST", remote_host);
    cork_env_add(env, "SS_REMOTE_PORT", remote_port);

    cork_env_add(env, "SS_LOCAL_HOST", local_host);
    cork_env_add(env, "SS_LOCAL_PORT", local_port);

    if (plugin_opts != NULL)
        cork_env_add(env, "SS_PLUGIN_OPTIONS", plugin_opts);

    exec = cork_exec_new_with_params("sh", "-c", cmd, NULL);

    cork_exec_set_env(exec, env);

    sub = cork_subprocess_new_exec(exec, NULL, NULL, &exit_code);

    int err = cork_subprocess_start(sub);

    ss_free(cmd);

    if (new_path != NULL)
        ss_free(new_path);

    return err;
}

uint16_t
get_local_port()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        return 0;
    }

    socklen_t len = sizeof(serv_addr);
    if (getsockname(sock, (struct sockaddr *)&serv_addr, &len) == -1) {
        return 0;
    }
    if (close (sock) < 0) {
        return 0;
    }

    return ntohs(serv_addr.sin_port);
}

void
stop_plugin()
{
    if (sub != NULL) {
        cork_subprocess_abort(sub);
        cork_subprocess_free(sub);
    }
}

int is_plugin_running()
{
    if (sub != NULL) {
        return cork_subprocess_is_finished(sub);
    }
    return 0;
}

#else

#include "stdint.h"

#include "utils.h"
#include "plugin.h"

int
start_plugin(const char *plugin,
             const char *plugin_opts,
             const char *remote_host,
             const char *remote_port,
             const char *local_host,
             const char *local_port)
{
    FATAL("Plugin is not supported on MinGW.");
    return -1;
}

uint16_t
get_local_port()
{
    FATAL("Plugin is not supported on MinGW.");
    return 0;
}

void
stop_plugin()
{
    FATAL("Plugin is not supported on MinGW.");
}

int
is_plugin_running()
{
    FATAL("Plugin is not supported on MinGW.");
    return 0;
}

#endif
