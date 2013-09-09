#include "win32.h"

#ifdef setsockopt
#undef setsockopt
#endif

void winsock_init(void)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int ret;
    wVersionRequested = MAKEWORD(1, 1);
    ret = WSAStartup(wVersionRequested, &wsaData);
    if (ret != 0) {
        FATAL("Could not initialize winsock");
    }
    if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1) {
        WSACleanup();
        FATAL("Could not find a usable version of winsock");
    }
}

void winsock_cleanup(void)
{
    WSACleanup();
}

void ss_error(const char *s)
{
    LPVOID *msg = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                  NULL, WSAGetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) &msg, 0, NULL);
    if (msg != NULL) {
        LOGE("%s: %s", s, msg);
        LocalFree(msg);
    }
}

int setnonblocking(int fd)
{
    u_long iMode = 0;
    int iResult;
    iResult = ioctlsocket(fd, FIONBIO, &iMode);
    if (iResult != NO_ERROR) {
        LOGE("ioctlsocket failed with error: %ld\n", iResult);
    }
    return iResult;
}

size_t strnlen(const char *s, size_t maxlen)
{
    const char *end = memchr(s, 0, maxlen);
    return end ? (size_t) (end - s) : maxlen;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    struct sockaddr_storage ss;
    unsigned long s = size;
    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;
    switch (af) {
        case AF_INET:
            ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
            break;
        case AF_INET6:
            ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
            break;
        default:
            return NULL;
    }
    return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0) ? dst : NULL;
}
