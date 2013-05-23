#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"
#include "redir.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

int getdestaddr(int fd, struct sockaddr_in *destaddr) {
    socklen_t socklen = sizeof(*destaddr);
    int error;

    error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
    if (error) {
        return -1;
    }
    return 0;
}

int setnonblocking(int fd) {
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_and_bind(const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo("0.0.0.0", port, &hints, &result);
    if (s != 0) {
        LOGD("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1)
            continue;

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void server_recv_cb (EV_P_ ev_io *w, int revents) {
    struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
    struct server *server = server_recv_ctx->server;
    struct remote *remote = server->remote;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r = recv(server->fd, remote->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        remote->buf_len = 0;
        remote->buf_idx = 0;
        close_and_free_server(EV_A_ server);
        if (remote != NULL) {
            ev_io_start(EV_A_ &remote->send_ctx->io);
        }
        return;
    } else if(r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf = encrypt(remote->buf, &r, server->e_ctx);

    int s = send(remote->fd, remote->buf, r, 0);
    if(s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf_len = r;
            remote->buf_idx = 0;
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            ev_io_start(EV_A_ &remote->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if(s < r) {
        remote->buf_len = r - s;
        remote->buf_idx = s;
        ev_io_stop(EV_A_ &server_recv_ctx->io);
        ev_io_start(EV_A_ &remote->send_ctx->io);
        return;
    }

}

static void server_send_cb (EV_P_ ev_io *w, int revents) {
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;
    if (server->buf_len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                server->buf_len, 0);
        if (s < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf_len) {
            // partly sent, move memory, wait for the next time to send
            server->buf_len -= s;
            server->buf_idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf_len = 0;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ &remote->recv_ctx->io);
            } else {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
    struct remote_ctx *remote_ctx = (struct remote_ctx *) (((void*)watcher)
            - sizeof(ev_io));
    struct remote *remote = remote_ctx->remote;
    struct server *server = remote->server;

    LOGD("remote timeout");

    ev_timer_stop(EV_A_ watcher);

    if (server == NULL) {
        close_and_free_remote(EV_A_ remote);
        return;
    }
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void remote_recv_cb (EV_P_ ev_io *w, int revents) {
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;
    if (server == NULL) {
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        server->buf_len = 0;
        server->buf_idx = 0;
        close_and_free_remote(EV_A_ remote);
        if (server != NULL) {
            ev_io_start(EV_A_ &server->send_ctx->io);
        }
        return;
    } else if(r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf = decrypt(server->buf, &r, server->d_ctx);
    int s = send(server->fd, server->buf, r, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < r) {
        server->buf_len = r - s;
        server->buf_idx = s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
        return;
    }
}

static void remote_send_cb (EV_P_ ev_io *w, int revents) {
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;
    struct server *server = remote->server;

    if (!remote_send_ctx->connected) {

        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_io_stop(EV_A_ &remote_send_ctx->io);
            ev_timer_stop(EV_A_ &remote_send_ctx->watcher);

            // send destaddr
            char *addr_to_send = malloc(BUF_SIZE);
            ssize_t addr_len = 0;
            addr_to_send[addr_len++] = 1;

            // handle IP V4 only
            size_t in_addr_len = sizeof(struct in_addr);
            memcpy(addr_to_send + addr_len, &server->destaddr.sin_addr, in_addr_len);
            addr_len += in_addr_len;
            memcpy(addr_to_send + addr_len, &server->destaddr.sin_port, 2);
            addr_len += 2;
            addr_to_send = encrypt(addr_to_send, &addr_len, server->e_ctx);

            int s = send(remote->fd, addr_to_send, addr_len, 0);
            free(addr_to_send);

            if (s < addr_len) {
                LOGE("failed to send remote addr.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }

            ev_io_start(EV_A_ &server->recv_ctx->io);
            ev_io_start(EV_A_ &remote->recv_ctx->io);

            return;
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else {
        if (remote->buf_len == 0) {
            // close and free
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else {
            // has data to send
            ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                    remote->buf_len, 0);
            if (s < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    ERROR("send");
                    // close and free
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
                return;
            } else if (s < remote->buf_len) {
                // partly sent, move memory, wait for the next time to send
                remote->buf_len -= s;
                remote->buf_idx += s;
                return;
            } else {
                // all sent out, wait for reading
                remote->buf_len = 0;
                remote->buf_idx = 0;
                ev_io_stop(EV_A_ &remote_send_ctx->io);
                if (server != NULL) {
                    ev_io_start(EV_A_ &server->recv_ctx->io);
                } else {
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }

    }
}

struct remote* new_remote(int fd, int timeout) {
    struct remote *remote;
    remote = malloc(sizeof(struct remote));
    remote->buf = malloc(BUF_SIZE);
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb, timeout, 0);
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->buf_len = 0;
    remote->buf_idx = 0;
    return remote;
}

void free_remote(struct remote *remote) {
    if (remote != NULL) {
        if (remote->server != NULL) {
            remote->server->remote = NULL;
        }
        free(remote->buf);
        free(remote->recv_ctx);
        free(remote->send_ctx);
        free(remote);
    }
}

void close_and_free_remote(EV_P_ struct remote *remote) {
    if (remote != NULL) {
        ev_timer_stop(EV_A_ &remote->send_ctx->watcher);
        ev_io_stop(EV_A_ &remote->send_ctx->io);
        ev_io_stop(EV_A_ &remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

struct server* new_server(int fd, int method) {
    struct server *server;
    server = malloc(sizeof(struct server));
    server->buf = malloc(BUF_SIZE);
    server->recv_ctx = malloc(sizeof(struct server_ctx));
    server->send_ctx = malloc(sizeof(struct server_ctx));
    server->fd = fd;
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    if (method) {
        server->e_ctx = malloc(sizeof(struct enc_ctx));
        server->d_ctx = malloc(sizeof(struct enc_ctx));
        enc_ctx_init(method, server->e_ctx, 1);
        enc_ctx_init(method, server->d_ctx, 0);
    } else {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }
    server->buf_len = 0;
    server->buf_idx = 0;
    return server;
}

void free_server(struct server *server) {
    if (server != NULL) {
        if (server->remote != NULL) {
            server->remote->server = NULL;
        }
        if (server->e_ctx != NULL) {
            EVP_CIPHER_CTX_cleanup(&server->e_ctx->evp);
            free(server->e_ctx);
        }
        if (server->d_ctx != NULL) {
            EVP_CIPHER_CTX_cleanup(&server->d_ctx->evp);
            free(server->d_ctx);
        }
        free(server->buf);
        free(server->recv_ctx);
        free(server->send_ctx);
        free(server);
    }
}

void close_and_free_server(EV_P_ struct server *server) {
    if (server != NULL) {
        ev_io_stop(EV_A_ &server->send_ctx->io);
        ev_io_stop(EV_A_ &server->recv_ctx->io);
        close(server->fd);
        free_server(server);
    }
}

static void accept_cb (EV_P_ ev_io *w, int revents) {
    struct listen_ctx *listener = (struct listen_ctx *)w;
    struct sockaddr_in destaddr;
    int err;

    int clientfd = accept(listener->fd, NULL, NULL);
    if (clientfd == -1) {
        ERROR("accept");
        return;
    }

    err = getdestaddr(clientfd, &destaddr);
    if (err) {
        ERROR("getdestaddr");
        return;
    }

    setnonblocking(clientfd);
    int opt = 1;
    setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(clientfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct addrinfo hints, *res;
    int sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int index = clock() % listener->remote_num;
    err = getaddrinfo(listener->remote_host[index], listener->remote_port, &hints, &res);
    if (err) {
        ERROR("getaddrinfo");
        return;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        ERROR("socket");
        close(sockfd);
        freeaddrinfo(res);
        return;
    }

    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Setup
    setnonblocking(sockfd);

    struct server *server = new_server(clientfd, listener->method);
    struct remote *remote = new_remote(sockfd, listener->timeout);
    server->remote = remote;
    remote->server = server;
    server->destaddr = destaddr;

    connect(sockfd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    // listen to remote connected event
    ev_io_start(EV_A_ &remote->send_ctx->io);
    ev_timer_start(EV_A_ &remote->send_ctx->watcher);
}

int main (int argc, char **argv) {

    int i, c;
    int pid_flags = 0;
    char *local_port = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;

    int remote_num = 0;
    char *remote_host[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    opterr = 0;

    while ((c = getopt (argc, argv, "f:s:p:l:k:t:m:c:")) != -1) {
        switch (c) {
            case 's':
                remote_host[remote_num++] = optarg;
                break;
            case 'p':
                remote_port = optarg;
                break;
            case 'l':
                local_port = optarg;
                break;
            case 'k':
                password = optarg;
                break;
            case 'f':
                pid_flags = 1;
                pid_path = optarg;
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
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++) {
                remote_host[i] = conf->remote_host[i];
            }
        }
        if (remote_port == NULL) remote_port = conf->remote_port;
        if (local_port == NULL) local_port = conf->local_port;
        if (password == NULL) password = conf->password;
        if (method == NULL) method = conf->method;
        if (timeout == NULL) timeout = conf->timeout;
    }

    if (remote_num == 0 || remote_port == NULL ||
            local_port == NULL || password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (timeout == NULL) timeout = "10";

    if (pid_flags) {
        demonize(pid_path);
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    // Setup keys
    LOGD("calculating ciphers...");
    int m = enc_init(password, method);

    // Setup socket
    int listenfd;
    listenfd = create_and_bind(local_port);
    if (listenfd < 0) {
        FATAL("bind() error..");
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        FATAL("listen() error.");
    }
    setnonblocking(listenfd);
    LOGD("server listening at port %s.", local_port);

    // Setup proxy context
    struct listen_ctx listen_ctx;
    listen_ctx.remote_num = remote_num;
    listen_ctx.remote_host = malloc(sizeof(char *) * remote_num);
    while (remote_num > 0) {
        int index = --remote_num;
        listen_ctx.remote_host[index] = remote_host[index];
    }
    listen_ctx.remote_port = remote_port;
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.fd = listenfd;
    listen_ctx.method = m;

    struct ev_loop *loop = ev_default_loop(0);
    if (!loop) {
        FATAL("ev_loop error.");
    }
    ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start (loop, &listen_ctx.io);
    ev_run (loop, 0);
    return 0;
}

