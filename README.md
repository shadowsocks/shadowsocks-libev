shadowsocks-libev
=================

Intro
-----

[Shadowsocks-libev](http://shadowsocks.org) is a lightweight secured scoks5 
proxy for embedded devices and low end boxes.

It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy) maintained by 
[@madeye](https://github.com/madeye) and [@linusyang](https://github.com/linusyang).

Current version: 1.4.2 | [![Build Status](https://travis-ci.org/madeye/shadowsocks-libev.png?branch=master)](https://travis-ci.org/madeye/shadowsocks-libev)

Changelog
---------

1.4.2 -- Sun, 05 Jan 2014 10:05:29 +0900

  * Fix the UDP relay issues.
  * Add syslog support.

1.4.1 -- Tue, 12 Nov 2013 03:57:21 +0000

  * Add multi-port support.
  * Add PolarSSL support by @linusyang.

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
[openssl](http://www.openssl.org/) or [polarssl](https://polarssl.org/).

In normal usage, the memory consumption is about 600KB and the CPU utilization is 
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU, 
32MB memory and 4MB flash).

Installation
------------

#### Notes about PolarSSL

* Default crypto library is OpenSSL. To build against PolarSSL,
specify `--with-crypto-library=polarssl` and  `--with-polarssl=/path/to/polarssl`
when running `./configure`.
* PolarSSL __1.2.5 or newer__ is required. Currently, PolarSSL does __NOT__ support 
CAST5-CFB, DES-CFB, IDEA-CFB, RC2-CFB and SEED-CFB.
* RC4 is only support by PolarSSL __1.3.0 or above__.

### Debian & Ubuntu

Add either of the following lines to your /etc/apt/sources.list

```
# Debian Wheezy, Ubuntu 12.04 or any distribution with libssl > 1.0.1
deb http://shadowsocks.org/debian wheezy main

# Debian Squeeze, Ubuntu 11.04, or any distribution with libssl > 0.9.8, but < 1.0.0
deb http://shadowsocks.org/debian squeeze main
```

Then,

``` bash
sudo apt-get update
sudo apt-get install shadowsocks

# Edit the configuration
sudo vim /etc/shadowsocks/config.json

# Start the service
sudo /etc/init.d/shadowsocks start
```

### CentOS

Install the compile tools
```bash
yum install -y gcc automake autoconf libtool make build-essential autoconf libtool gcc
yum install -y curl curl-devel zlib-devel openssl-devel perl perl-devel cpio expat-devel gettext-devel
```

Compile and install
```bash
./configure && make
make install
```

Create config.json
```bash
mkdir /etc/shadowsocks
vi /etc/shadowsocks/config.json
```
Then fill your infomation

Create the service file
```bash
vi /etc/rc.d/init.d/shadowsocks
```

Paste below code in vi
```bash
#!/bin/sh
### BEGIN INIT INFO
# Provides:          shadowsocks
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: lightweight secured scoks5 proxy
# Description:       Shadowsocks-libev is a lightweight secured 
#                    scoks5 proxy for embedded devices and low end boxes.
#                    
### END INIT INFO

# Author: Vinna

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

NAME=shadowsocks
DAEMON=/usr/local/bin/ss-server
prog=$(basename $DAEMON)

PIDFILE=/var/run/$NAME/$prog.pid
CONFFILE=/etc/$NAME/config.json

lockfile=/var/lock/subsys/$NAME/$prog

start()
{
    echo -n $"Starting $prog: "
    daemon $DAEMON -c $CONFFILE -f $PIDFILE
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}

stop()
{
	echo -n $"Stopping $prog: "
	killproc -p $PIDFILE $DAEMON
	RETVAL=$?
	[ $RETVAL -eq 0 ] && rm -f $lockfile
	echo
	return $retval
}

restart() {
    stop
    start
}

rh_status() {
    status $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}

case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart)
        $1
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
            ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart}"
        exit 2
esac
```
Then save and quit vi

Ctreate some folder
```bash
mkdir /var/run/shadowsocks
mkdir /var/lock/subsys/shadowsocks
```
Then start it
```bash
service shadowsocks start
```

### Linux

For Unix-like systems, especially Debian-based systems, 
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
sudo apt-get install build-essential autoconf libtool libssl-dev
./configure && make
sudo make install
```

### FreeBSD

```bash
su
cd /usr/ports/net/shadowsocks-libev
make install
```

Edit your config.json file. By default, it's located in /usr/local/etc/shadowsocks-libev

To enable shadowsocks-libev, add the following rc variable to your /etc/rc.conf file.

```
shadowsocks_libev_enable="YES"
```

Start the shadowsocks server:

```bash
service shadowsocks_libev start
```

### OpenWRT

```bash
# At OpenWRT build root
pushd package
git clone https://github.com/madeye/shadowsocks-libev.git
popd

# Enable shadowsocks-libev in network category 
make menuconfig

# Optional
make -j

# Build the package
make V=99 package/shadowsocks-libev/openwrt/compile
```

### Windows

For Windows, use either MinGW (msys) or Cygwin to build.
At the moment, only `ss-local` is supported to build against MinGW (msys).

If you are using MinGW (msys), please download OpenSSL or PolarSSL source tarball
to the home directory of msys, and build it like this (may take a few minutes):

* OpenSSL

```bash
tar zxf openssl-1.0.1e.tar.gz
cd openssl-1.0.1e
./config --prefix="$HOME/prebuilt" --openssldir="$HOME/prebuilt/openssl"
make && make install
```

* PolarSSL

```bash
tar zxf polarssl-1.3.2-gpl.tgz
cd polarssl-1.3.2
make lib WINDOWS=1
make install DESTDIR="$HOME/prebuilt"
```

Then, build the binary using the commands below, and all `.exe` files 
will be built at `$HOME/ss/bin`:

* OpenSSL

```bash
./configure --prefix="$HOME/ss" --with-openssl="$HOME/prebuilt"
make && make install
```

* PolarSSL

```bash
./configure --prefix="$HOME/ss" --with-crypto-library=polarssl --with-polarssl=$HOME/prebuilt
make && make install
```

Usage
-----

```
usage:

ss-[local|redir|server]
      -s <server_host>           host name or ip address of your remote server
      -p <server_port>           port number of your remote server
      -l <local_port>            port number of your local server
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
                                 only available in local and server modes
      [-b <local_address>]       specific local address to bind,
                                 only available in local and redir modes
      [-u]                       udprelay mode to supprot udp traffic
                                 only available in local and server modes
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
