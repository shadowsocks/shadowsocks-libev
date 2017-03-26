#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

void
usage()
{
    printf("\n");
    printf("shadowsocks-libev %s\n\n", VERSION);
    printf(
        "  maintained by Max Lv <max.c.lv@gmail.com> and Linus Yang <laokongzi@gmail.com>\n\n");
    printf("  usage:\n\n");
#ifdef MODULE_LOCAL
    printf("    ss-local\n");
#elif MODULE_REMOTE
    printf("    ss-server\n");
#elif MODULE_TUNNEL
    printf("    ss-tunnel\n");
#elif MODULE_REDIR
    printf("    ss-redir\n");
#elif MODULE_MANAGER
    printf("    ss-manager\n");
#endif
    printf("\n");
    printf(
        "       -s <server_host>           Host name or IP address of your remote server.\n");
    printf(
        "       -p <server_port>           Port number of your remote server.\n");
    printf(
        "       -l <local_port>            Port number of your local server.\n");
    printf(
        "       -k <password>              Password of your remote server.\n");
    printf(
        "       -m <encrypt_method>        Encrypt method: rc4-md5, \n");
    printf(
        "                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,\n");
    printf(
        "                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,\n");
    printf(
        "                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,\n");
    printf(
        "                                  camellia-128-cfb, camellia-192-cfb,\n");
    printf(
        "                                  camellia-256-cfb, bf-cfb,\n");
    printf(
        "                                  chacha20-ietf-poly1305,\n");
    printf(
        "                                  salsa20, chacha20 and chacha20-ietf.\n");
    printf(
        "                                  The default cipher is rc4-md5.\n");
    printf("\n");
    printf(
        "       [-a <user>]                Run as another user.\n");
    printf(
        "       [-f <pid_file>]            The file path to store pid.\n");
    printf(
        "       [-t <timeout>]             Socket timeout in seconds.\n");
    printf(
        "       [-c <config_file>]         The path to config file.\n");
#ifdef HAVE_SETRLIMIT
    printf(
        "       [-n <number>]              Max number of open files.\n");
#endif
#ifndef MODULE_REDIR
    printf(
        "       [-i <interface>]           Network interface to bind.\n");
#endif
    printf(
        "       [-b <local_address>]       Local address to bind.\n");
    printf("\n");
    printf(
        "       [-u]                       Enable UDP relay.\n");
#ifdef MODULE_REDIR
    printf(
        "                                  TPROXY is required in redir mode.\n");
#endif
    printf(
        "       [-U]                       Enable UDP relay and disable TCP relay.\n");
#ifdef MODULE_REMOTE
    printf(
        "       [-6]                       Resovle hostname to IPv6 address first.\n");
#endif
    printf("\n");
#ifdef MODULE_TUNNEL
    printf(
        "       [-L <addr>:<port>]         Destination server address and port\n");
    printf(
        "                                  for local port forwarding.\n");
#endif
#ifdef MODULE_REMOTE
    printf(
        "       [-d <addr>]                Name servers for internal DNS resolver.\n");
#endif
    printf(
        "       [--reuse-port]             Enable port reuse.\n");
#if defined(MODULE_REMOTE) || defined(MODULE_LOCAL) || defined(MODULE_REDIR)
    printf(
        "       [--fast-open]              Enable TCP fast open.\n");
    printf(
        "                                  with Linux kernel > 3.7.0.\n");
    printf(
        "       [--acl <acl_file>]         Path to ACL (Access Control List).\n");
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    printf(
        "       [--manager-address <addr>] UNIX domain socket address.\n");
#endif
#ifdef MODULE_MANAGER
    printf(
        "       [--executable <path>]      Path to the executable of ss-server.\n");
#endif
    printf(
        "       [--mtu <MTU>]              MTU of your network interface.\n");
#ifdef __linux__
    printf(
        "       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.\n");
#endif
#ifndef MODULE_MANAGER
    printf(
        "       [--key <key_in_base64>]    Key of your remote server.\n");
#endif
    printf(
        "       [--plugin <name>]          Enable SIP003 plugin. (Experimental)\n");
    printf(
        "       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)\n");
    printf("\n");
    printf(
        "       [-v]                       Verbose mode.\n");
    printf(
        "       [-h, --help]               Print this message.\n");
    printf("\n");
}

