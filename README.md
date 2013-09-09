shadowsocks-libev
=================

Intro
-----

[Shadowsocks-libev](http://shadowsocks.org) is a lightweight secured scoks5 
proxy for embedded devices and low end boxes.

It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy) maintained by 
[@madeye](https://github.com/madeye).

Current version: 1.4.0 | [![Build Status](https://travis-ci.org/madeye/shadowsocks-libev.png?branch=master)](https://travis-ci.org/madeye/shadowsocks-libev)

Changelog
---------

1.4.0 -- Sun, 08 Sep 2013 02:20:40 +0000

  * Add standard socks5 udp support.

1.3.3 -- Fri, 21 Jun 2013 09:59:20 +0800

  * Provide more info in verbose mode.

1.3.2 -- Sun, 09 Jun 2013 09:52:31 +0000

  * Fix some ciphers by @linusyang.

1.3.1 -- Tue, 04 Jun 2013 00:56:17 +0000

  * Support more cihpers: camellia, idea, rc2 and seed.

1.3 -- Thu, 16 May 2013 10:51:15 +0800

  * Able to bind connections to specific interface 
  * Support more ciphers: aes-128-cfb, aes-192-cfb, aes-256-cfb, bf-cfb, cast5-cfb, des-cfb

1.2 -- Tue, 07 May 2013 14:10:33 +0800

  * Close timeouted TCP connections 
  * Fix a high load issue

1.1 -- Wed, 10 Apr 2013 12:11:36 +0800

  * Fix a IPV6 resolve issue

1.0 -- Sat, 06 Apr 2013 16:59:15 +0800

  * Initial release

Features
--------

Shadowsocks-libev is writen in pure C and only depends on
[libev](http://software.schmorp.de/pkg/libev.html) and 
[openssl](http://www.openssl.org/).

In normal usage, the memory consumption is about 600KB and the CPU utilization is 
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU, 
32MB memory and 4MB flash).

Installation
------------

For Unix-like systems, especially Debian-based systems, 
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
    sudo apt-get install build-essential autoconf libtool libssl-dev
    ./configure && make
    sudo make install
```

For Windows, use either MinGW (msys) or Cygwin to build.
At the moment, only `ss-local` is supported to build against MinGW (msys).

If you are using MinGW (msys), please download OpenSSL source tarball
to the home directory of msys, and build it like this (may take a few minutes):

```bash
    tar zxf openssl-1.0.1e.tar.gz
    cd openssl-1.0.1e
    ./config --prefix="$HOME/prebuilt" --openssldir="$HOME/prebuilt/openssl"
    make && make install
```

Then, build the binary using the commands below, and all `.exe` files 
will be built at `$HOME/ss/bin`:

```bash
    ./configure --prefix="$HOME/ss" --with-openssl="$HOME/prebuilt"
    make && make install
```

Usage
-----

```
usage:

ss-[local|redir|server]
      -s <server_host>           host name or ip address of your remote server
      -p <server_port>           port number of your remote server
      -l <local_port>>           port number of your local server
      -k <password>              password of your remote server

      [-m <encrypt_method>]      encrypt method, supporting table, rc4,
                                 aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                 bf-cfb, camellia-128-cfb, camellia-192-cfb,
                                 camellia-256-cfb, cast5-cfb, des-cfb,
                                 idea-cfb, rc2-cfb and seed-cfb
      [-f <pid_file>]            valid path to the pid file
      [-t <timeout>]             socket timeout in seconds
      [-c <config_file>]         json format config file

      [-i <interface>]           specific network interface to bind,
                                 only avaliable in local and server modes
      [-b <local_address>]       specific local address to bind,
                                 only avaliable in local and redir modes
      [-u]                       udprelay mode to supprot udp traffic
                                 only avaliable in local and server modes
      [-v]                       verbose mode, debug output in console

notes:

    ss-redir provides a transparent proxy function and only works on the 
    Linux platform with iptables.

```

## Advanced usage

The latest shadowsocks-libev has provided a *redir* mode. You can configure your linux based box or router to proxy all tcp traffic transparently.

    # Create new chain
    root@Wrt:~# iptables -t nat -N SHADOWSOCKS
    
    # Ignore your shadowsocks server's addresses
    # It's very IMPORTANT, just be careful.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 123.123.123.123 -j RETURN

    # Ignore LANs and any other addresses you'd like to bypass the proxy
    # See Wikipedia and RFC5735 for full list of reserved networks.
    # See ashi009/bestroutetb for a highly optimized CHN route list.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN

    # Anything else should be redirected to shadowsocks's local port
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports 12345
    
    # Apply the rules
    root@Wrt:~# iptables -t nat -A OUTPUT -p tcp -j SHADOWSOCKS
    
    # Start the shadowsocks-redir
    root@Wrt:~# ss-redir -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid

## Security Tips

Although shadowsocks-libev can handle thousands of concurrent connections nicely, we still recommend to
set up your server's firewall rules to limit connections from each user.

    # Up to 32 connections are enough for normal usages
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

Copyright (C) 2013 Max Lv <max.c.lv@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
