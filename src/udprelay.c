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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <openssl/md5.h>

#include "utils.h"
#include "udprelay.h"
#include "cache.h"

#ifdef UDPRELAY_REMOTE
#ifdef UDPRELAY_LOCAL
#error "UDPRELAY_REMOTE and UDPRELAY_LOCAL should not be both defined"
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define BUF_SIZE MAX_UDP_PACKET_SIZE

extern int verbose;
static char *iface;
static int remote_conn = 0;
static int server_conn = 0;

static int setnonblocking(int fd)
{
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#ifdef SET_INTERFACE
static int setinterface(int socket_fd, const char* interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(struct ifreq));
    return res;
}
#endif

static char *hash_key(const char *header, const int header_len, const struct sockaddr *addr)
{
    char key[384];

    // calculate hash key
    // assert header_len < 256
    memset(key, 0, 384);
    memcpy(key, addr, sizeof(struct sockaddr));
    memcpy(key + sizeof(struct sockaddr), header, header_len);

    return (char*) MD5((const uint8_t *)key, sizeof(struct sockaddr) + header_len, NULL);
}

static int parse_udprealy_header(const char* buf, const int buf_len, char *host, char *port)
{

    const uint8_t atyp = *(uint8_t*)buf;
    int offset = 1;
    // get remote addr and port
    if (atyp == 1)
    {
        // IP V4
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf_len > in_addr_len)
        {
            if (host != NULL)
            {
                inet_ntop(AF_INET, (const void *)(buf + offset),
                          host, INET_ADDRSTRLEN);
            }
            offset += in_addr_len;
        }
    }
    else if (atyp == 3)
    {
        // Domain name
        uint8_t name_len = *(uint8_t *)(buf + offset);
        if (name_len < buf_len && name_len < 255 && name_len > 0)
        {
            if (host != NULL)
            {
                memcpy(host, buf + offset + 1, name_len);
            }
            offset += name_len + 1;
        }
    }
    else if (atyp == 4)
    {
        // IP V6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf_len > in6_addr_len)
        {
            if (host != NULL)
            {
                inet_ntop(AF_INET6, (const void*)(buf + offset),
                          host, INET6_ADDRSTRLEN);
            }
            offset += in6_addr_len;
        }
    }

    if (offset == 1)
    {
        LOGE("invalid header with addr type %d", atyp);
        return 0;
    }

    if (port != NULL)
    {
        sprintf(port, "%d", ntohs(*(uint16_t *)(buf + offset)));
    }
    offset += 2;

    return offset;

}

int create_remote_socket(int ipv6)
{
    int s, remote_sock;

    if (ipv6)
    {
        // Try to bind IPv6 first
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(struct sockaddr_in6));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(0);
        remote_sock = socket(AF_INET6, SOCK_DGRAM , 0);
        if (remote_sock != -1)
        {
            if (bind(remote_sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
            {
                return remote_sock;
            }
        }
    }

    // Then bind to IPv4
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    remote_sock = socket(AF_INET, SOCK_DGRAM , 0);
    if (remote_sock == -1)
    {
        ERROR("Cannot create socket.");
        return -1;
    }

    if (bind(remote_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        FATAL("Cannot bind remote.");
        return -1;
    }

    return remote_sock;
}

int create_server_socket(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, server_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0)
    {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        server_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1)
            continue;

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(server_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
        {
            /* We managed to bind successfully! */
            break;
        }
        else
        {
            ERROR("bind");
        }

        close(server_sock);
    }

    if (rp == NULL)
    {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

struct remote_ctx *new_remote_ctx(int fd)
{
    struct remote_ctx *ctx = malloc(sizeof(struct remote_ctx));
    memset(ctx, 0, sizeof(struct remote_ctx));
    ctx->server_ctx = NULL;
    ctx->fd = fd;
    ev_io_init(&ctx->io, remote_recv_cb, fd, EV_READ);
    return ctx;
}

struct server_ctx * new_server_ctx(int fd)
{
    struct server_ctx *ctx = malloc(sizeof(struct server_ctx));
    memset(ctx, 0, sizeof(struct server_ctx));
    ctx->fd = fd;
    ev_io_init(&ctx->io, server_recv_cb, fd, EV_READ);
    return ctx;
}

#ifdef UDPRELAY_REMOTE
struct query_ctx *new_query_ctx(asyncns_query_t *query,
                                const uint8_t *buf, const int buf_len)
{
    struct query_ctx *ctx = malloc(sizeof(struct query_ctx));
    memset(ctx, 0, sizeof(struct query_ctx));
    ctx->buf = malloc(buf_len);
    ctx->buf_len = buf_len;
    memcpy(ctx->buf, buf, buf_len);
    ctx->query = query;
    ev_timer_init(&ctx->watcher, query_resolve_cb, 0.2, 0.5);
    return ctx;
}

void close_and_free_query(EV_P_ struct query_ctx *ctx)
{
    if (ctx != NULL)
    {
        ev_timer_stop(EV_A_ &ctx->watcher);
        if (ctx->buf != NULL)
        {
            free(ctx->buf);
        }
        free(ctx);
    }
}

#endif

void close_and_free_remote(EV_P_ struct remote_ctx *ctx)
{
    if (ctx != NULL)
    {
        close(ctx->fd);
        ev_timer_stop(EV_A_ &ctx->watcher);
        if (ctx->addr_header != NULL)
        {
            free(ctx->addr_header);
        }
        free(ctx);
    }
}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *) (((void*)watcher)
                                    - sizeof(ev_io));

    LOGE("UDP connection timeout");

    char *key = hash_key(remote_ctx->addr_header,
                         remote_ctx->addr_header_len, &remote_ctx->src_addr);
    cache_remove(remote_ctx->server_ctx->conn_cache, key);
    close_and_free_remote(EV_A_ remote_ctx);
}

#ifdef UDPRELAY_REMOTE
static void query_resolve_cb(EV_P_ ev_timer *watcher, int revents)
{
    int err;
    struct addrinfo *result, *rp;
    struct query_ctx *query_ctx = (struct query_ctx *)((void*)watcher);
    asyncns_t *asyncns = query_ctx->server_ctx->asyncns;
    asyncns_query_t *query = query_ctx->query;

    if (asyncns == NULL || query == NULL)
    {
        LOGE("invalid dns query.");
        close_and_free_query(EV_A_ query_ctx);
        return;
    }

    if (asyncns_wait(asyncns, 0) == -1)
    {
        // asyncns error
        FATAL("asyncns exit unexpectedly.");
    }

    if (!asyncns_isdone(asyncns, query))
    {
        // wait reolver
        return;
    }

    if (verbose)
    {
        LOGD("[udp] asyncns resolved.");
    }

    ev_timer_stop(EV_A_ watcher);

    err = asyncns_getaddrinfo_done(asyncns, query, &result);

    if (err)
    {
        ERROR("getaddrinfo");
    }
    else
    {
        // Use IPV4 address if possible
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            if (rp->ai_family == AF_INET) break;
        }

        if (rp == NULL)
        {
            rp = result;
        }

        int opt = 1;

        int remotefd = create_remote_socket(rp->ai_family == AF_INET6);
        if (remotefd != -1)
        {
            setnonblocking(remotefd);
#ifdef SO_NOSIGPIPE
            setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#ifdef SET_INTERFACE
            if (iface) setinterface(remotefd, iface);
#endif

            struct remote_ctx *remote_ctx = new_remote_ctx(remotefd);
            remote_ctx->src_addr = query_ctx->src_addr;
            remote_ctx->dst_addr = *rp->ai_addr;
            remote_ctx->server_ctx = query_ctx->server_ctx;
            remote_ctx->addr_header_len = query_ctx->addr_header_len;
            memcpy(remote_ctx->addr_header, query_ctx->addr_header, query_ctx->addr_header_len);

            // Add to conn cache
            char *key = hash_key(remote_ctx->addr_header,
                                 remote_ctx->addr_header_len, &remote_ctx->src_addr);
            cache_insert(query_ctx->server_ctx->conn_cache, key, (void *)remote_ctx);

            ev_io_start(EV_A_ &remote_ctx->io);

            int s = sendto(remote_ctx->fd, query_ctx->buf, query_ctx->buf_len, 0, &remote_ctx->dst_addr, sizeof(remote_ctx->dst_addr));

            if (s == -1)
            {
                ERROR("udprelay_sendto_remote");
                close_and_free_remote(EV_A_ remote_ctx);
            }

        }
        else
        {
            ERROR("udprelay bind() error..");
        }
    }

    // clean up
    asyncns_freeaddrinfo(result);
    close_and_free_query(EV_A_ query_ctx);
}
#endif

static void remote_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)w;
    struct server_ctx *server_ctx = remote_ctx->server_ctx;

    // server has been closed
    if (server_ctx == NULL)
    {
        LOGE("invalid server.");
        close_and_free_remote(EV_A_ remote_ctx);
        return;
    }

    if (verbose)
    {
        LOGD("[udp] remote receive a packet");
    }

    // triger the timer
    ev_timer_again(EV_A_ &remote_ctx->watcher);

    struct sockaddr src_addr;
    int addr_len = sizeof(src_addr);
    int addr_header_len = remote_ctx->addr_header_len;
    char *buf = malloc(BUF_SIZE);

    // recv
    ssize_t buf_len = recvfrom(remote_ctx->fd, buf, BUF_SIZE, 0, &src_addr, &addr_len);

    if (buf_len == -1)
    {
        // error on recv
        // simply drop that packet
        if (verbose)
        {
            ERROR("udprelay_server_recvfrom");
        }
        goto CLEAN_UP;
    }

#ifdef UDPRELAY_LOCAL
    buf = ss_decrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);

    int len = parse_udprealy_header(buf, buf_len, NULL, NULL);
    if (len == 0 || len != addr_header_len)
    {
        // error in parse header
        goto CLEAN_UP;
    }
    buf_len -= addr_header_len;
    memmove(buf, buf + addr_header_len, buf_len);
#endif

#ifdef UDPRELAY_REMOTE
    char *tmpbuf = malloc(buf_len + addr_header_len);
    memcpy(tmpbuf, remote_ctx->addr_header, addr_header_len);
    memcpy(tmpbuf + addr_header_len, buf, buf_len);
    free(buf);
    buf = tmpbuf;
    buf_len += addr_header_len;

    ss_encrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);
#endif

    int s = sendto(remote_ctx->fd, buf, buf_len, 0, &remote_ctx->src_addr, sizeof(remote_ctx->src_addr));

    if (s == -1)
    {
        ERROR("udprelay_sendto_local");
    }

CLEAN_UP:
    free(buf);

}

static void server_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_ctx = (struct server_ctx *)w;
    struct sockaddr src_addr;
    char *buf = malloc(BUF_SIZE);

    int addr_len = sizeof(src_addr);
    int offset = 0;

    ssize_t buf_len = recvfrom(server_ctx->fd, buf, BUF_SIZE, 0, &src_addr, &addr_len);

    if (buf_len == -1)
    {
        // error on recv
        // simply drop that packet
        if (verbose)
        {
            ERROR("udprelay_server_recvfrom");
        }
        goto CLEAN_UP;
    }

    if (verbose)
    {
        LOGD("[udp] server receive a packet.");
    }

#ifdef UDPRELAY_REMOTE
    buf = ss_decrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);
#endif

#ifdef UDPRELAY_LOCAL
    uint8_t frag = *(uint8_t*)(buf + 2);
    offset += 3;
#endif

    /*
     *
     * SOCKS5 UDP Request
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * SOCKS5 UDP Response
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * shadowsocks UDP Request (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Response (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Request and Response (after encrypted)
     * +-------+--------------+
     * |   IV  |    PAYLOAD   |
     * +-------+--------------+
     * | Fixed |   Variable   |
     * +-------+--------------+
     *
     */

    char host[256] = {0};
    char port[64] = {0};

    int addr_header_len = parse_udprealy_header(buf + offset,
                          buf_len - offset, host, port);
    if (addr_header_len == 0)
    {
        // error in parse header
        goto CLEAN_UP;
    }
    char *addr_header = buf + offset;
    char *key = hash_key(addr_header, addr_header_len, &src_addr);
    struct cache *conn_cache = server_ctx->conn_cache;

    struct remote_ctx *remote_ctx = NULL;
    cache_lookup(conn_cache, key, (void*)&remote_ctx);

    if (remote_ctx == NULL)
    {
        if (verbose)
        {
            LOGD("[udp] cache missed: %s:%s", host, port);
        }
    }
    else
    {
        if (verbose)
        {
            LOGD("[udp] cache hit: %s:%s", host, port);
        }
    }

#ifdef UDPRELAY_LOCAL

    if (frag)
    {
        LOGE("drop a message since frag is not 0, but %d", frag);
        goto CLEAN_UP;
    }

    if (remote_ctx == NULL)
    {

        struct addrinfo hints;
        struct addrinfo *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
        hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

        int s = getaddrinfo(server_ctx->remote_host, server_ctx->remote_port,
                            &hints, &result);
        if (s != 0 || result == NULL)
        {
            LOGE("getaddrinfo: %s", gai_strerror(s));
            goto CLEAN_UP;
        }

        // Bind to any port
        int remotefd = create_remote_socket(result->ai_family == AF_INET6);
        if (remotefd < 0)
        {
            ERROR("udprelay bind() error..");
            // remember to free addrinfo
            freeaddrinfo(result);
            goto CLEAN_UP;
        }
        setnonblocking(remotefd);

        // Init remote_ctx
        remote_ctx = new_remote_ctx(remotefd);
        remote_ctx->src_addr = src_addr;
        remote_ctx->dst_addr = *result->ai_addr;
        remote_ctx->server_ctx = server_ctx;
        remote_ctx->addr_header_len = addr_header_len;
        memcpy(remote_ctx->addr_header, addr_header, addr_header_len);

        // Add to conn cache
        cache_insert(conn_cache, key, (void *)remote_ctx);

        // Start remote io
        ev_io_start(EV_A_ &remote_ctx->io);

        // clean up
        freeaddrinfo(result);
    }

    buf_len -= 3;
    memmove(buf, buf + 3, buf_len);

    ss_encrypt_all(BUF_SIZE, buf, &buf_len, server_ctx->method);

    int s = sendto(remote_ctx->fd, buf, buf_len, 0, &remote_ctx->dst_addr, sizeof(remote_ctx->dst_addr));

    if (s == -1)
    {
        ERROR("udprelay_sendto_remote");
    }

#else

    buf_len -= offset;
    memmove(buf, buf + offset, buf_len);

    if (remote_ctx == NULL)
    {
        struct addrinfo hints;
        asyncns_query_t *query;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        query = asyncns_getaddrinfo(server_ctx->asyncns,
                                    host, port, &hints);

        if (query == NULL)
        {
            ERROR("udp_asyncns_getaddrinfo");
            goto CLEAN_UP;
        }

        struct query_ctx *query_ctx = new_query_ctx(query, buf, buf_len);
        query_ctx->server_ctx = server_ctx;
        query_ctx->addr_header_len = addr_header_len;
        query_ctx->src_addr = src_addr;
        memcpy(query_ctx->addr_header, addr_header, addr_header_len);

        ev_timer_start(EV_A_ &query_ctx->watcher);

    }
    else
    {

        int s = sendto(remote_ctx->fd, buf, buf_len, 0, &remote_ctx->dst_addr, sizeof(remote_ctx->dst_addr));

        if (s == -1)
        {
            ERROR("udprelay_sendto_remote");
        }

    }
#endif

CLEAN_UP:
    free(buf);

}

void free_cb(void *element)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)element;

    if (verbose)
    {
        LOGD("free a remote ctx");
    }

    close_and_free_remote(EV_DEFAULT, remote_ctx);
}

int udprelay_init(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
             const char *remote_host, const char *remote_port,
#endif
#ifdef UDPRELAY_REMOTE
             asyncns_t *asyncns,
#endif
             int method, const char *interface)
{


    iface = interface;

    // Inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // Inilitialize cache
    struct cache *conn_cache;
    cache_create(&conn_cache, MAX_UDP_CONN_NUM, free_cb);

    //////////////////////////////////////////////////
    // Setup server context

    // Bind to port
    int serverfd = create_server_socket(server_host, server_port);
    if (serverfd < 0)
    {
        FATAL("udprelay bind() error..");
    }
    setnonblocking(serverfd);

    struct server_ctx *server_ctx = new_server_ctx(serverfd);
    server_ctx->method = method;
    server_ctx->iface = iface;
    server_ctx->conn_cache = conn_cache;
#ifdef UDPRELAY_LOCAL
    server_ctx->remote_host = remote_host;
    server_ctx->remote_port = remote_port;
#endif
#ifdef UDPRELAY_REMOTE
    server_ctx->asyncns = asyncns;
#endif

    ev_io_start(loop, &server_ctx->io);

    return 0;
}

