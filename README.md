shadowsocks-libev
=================

Intro
-----

[Shadowsocks-libev](http://shadowsocks.org) is a lightweight secured scoks5 
proxy for embedded devices and low end boxes.

It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy) maintained by 
[@madeye](https://github.com/madeye).

Current version: 1.3 [![Build Status](https://travis-ci.org/madeye/shadowsocks-libev.png?branch=master)](https://travis-ci.org/madeye/shadowsocks-libev)

Changelog
---------

shadowsocks 1.3 -- Thu, 16 May 2013 10:51:15 +0800

  * Able to bind connections to specific interface 
  * Support more ciphers: aes-128-cfb, aes-192-cfb, aes-256-cfb, bf-cfb, cast5-cfb, des-cfb

shadowsocks 1.2 -- Tue, 07 May 2013 14:10:33 +0800

  * Close timeouted TCP connections 
  * Fix a high load issue

shadowsocks 1.1 -- Wed, 10 Apr 2013 12:11:36 +0800

  * Fix a IPV6 resolve issue

shadowsocks 1.0 -- Sat, 06 Apr 2013 16:59:15 +0800

  * Initial release

Features
--------

Shadowsocks-libev is writen in pure C and only depends on
[libev](http://software.schmorp.de/pkg/libev.html).

When statically linked and packaged for OpenWRT, the total package size is 23KB. 
In normal usage, the memory consumption is about 600KB and the CPU utilization is 
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU, 
32MB memory and 4MB flash).

Installation
------------

Build the binary like this:

```bash
    sudo apt-get install build-essential autoconf libtool
    ./configure && make
    sudo make install
```

Usage
-----

```
usage:

    ss-local -s server_host -p server_port -l local_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

    ss-redir -s server_host -p server_port -l local_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

    ss-server -s server_host -p server_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

options:

    encrypt_method:     table, rc4, aes-128-cfb, aes-192-cfb, aes-256-cfb,
                        bf-cfb, cast5-cfb, des-cfb
          pid_file:     valid path to the pid file
           timeout:     socket timeout in senconds
       config_file:     json format config file

notes:

    ss-redir provides a transparent proxy function and only works on the 
    Linux platform with iptables.

```

## Advanced usage

The latest shadowsocks-libev has provided a transparent mode. You can configure your linux based box or router to proxy all tcp traffic transparently.

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
