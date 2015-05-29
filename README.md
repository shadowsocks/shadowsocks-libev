shadowsocks-libev
=================

Intro
-----

[Shadowsocks-libev](http://shadowsocks.org) is a lightweight secured socks5 
proxy for embedded devices and low end boxes.

It is a port of [shadowsocks](https://github.com/shadowsocks/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy) maintained by 
[@madeye](https://github.com/madeye) and [@linusyang](https://github.com/linusyang).

Current version: 2.2.1 | [Changelog](Changes)

Travis CI: [![Travis CI](https://travis-ci.org/shadowsocks/shadowsocks-libev.png?branch=master)](https://travis-ci.org/shadowsocks/shadowsocks-libev) | Jenkins Matrix: [![Jenkins](https://jenkins.shadowvpn.org/buildStatus/icon?job=Shadowsocks-libev)](https://jenkins.shadowvpn.org/job/Shadowsocks-libev/)

Features
--------

Shadowsocks-libev is writen in pure C and only depends on
[libev](http://software.schmorp.de/pkg/libev.html) and 
[openssl](http://www.openssl.org/) or [polarssl](https://polarssl.org/).

In normal usage, the memory footprint is about 600KB and the CPU utilization is 
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

#### Install from repository

Add GPG public key

```bash
wget -O- http://shadowsocks.org/debian/1D27208A.gpg | sudo apt-key add -
```

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
sudo apt-get install shadowsocks-libev
```

#### Build package from source

``` bash
cd shadowsocks-libev
sudo apt-get install build-essential autoconf libtool libssl-dev gawk debhelper
dpkg-buildpackage -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

#### Configure and start the service

```
# Edit the configuration
sudo vim /etc/shadowsocks-libev/config.json

# Start the service
sudo /etc/init.d/shadowsocks-libev start
```

### Fedora & RHEL

Supported distributions include
- Fedora 20, 21, rawhide
- RHEL 6, 7 and derivatives (including CentOS, Scientific Linux)

#### Install from repository

Enable repo via `dnf`:

```
su -c 'dnf copr enable librehat/shadowsocks'
```

Or download yum repo on [Fedora Copr](https://copr.fedoraproject.org/coprs/librehat/shadowsocks/) and put it inside `/etc/yum.repos.d/`. The release `Epel` is for RHEL and its derivatives.

Then, install `shadowsocks-libev` via `dnf`:

```bash
su -c 'dnf update'
su -c 'dnf install shadowsocks-libev'
```

or `yum`:

```bash
su -c 'yum update'
su -c 'yum install shadowsocks-libev'
```

### Linux

For Unix-like systems, especially Debian-based systems, 
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
sudo apt-get install build-essential autoconf libtool libssl-dev
./configure && make
sudo make install
```

Or you can run following command via root user, quick install it.
```bash
apt-get install build-essential autoconf libtool libssl-dev git-core -y
mkdir ~/software
cd ~/software
git clone https://github.com/shadowsocks/shadowsocks-libev.git
cd shadowsocks-libev
./configure --prefix=/usr
make && make install
```
Tested on ubuntu 15.04

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
git clone https://github.com/shadowsocks/shadowsocks-libev.git
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
    ss-[local|redir|server|tunnel]

       -s <server_host>           host name or ip address of your remote server

       -p <server_port>           port number of your remote server

       -l <local_port>            port number of your local server

       -k <password>              password of your remote server

       [-m <encrypt_method>]      encrypt method: table, rc4, rc4-md5,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  bf-cfb, camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, cast5-cfb, des-cfb, idea-cfb,
                                  rc2-cfb, seed-cfb, salsa20 and chacha20

       [-f <pid_file>]            the file path to store pid

       [-t <timeout>]             socket timeout in seconds

       [-c <config_file>]         the path to config file

       [-i <interface>]           network interface to bind,
                                  not available in redir mode

       [-b <local_address>]       local address to bind,
                                  not available in server mode

       [-u]                       enable udprelay mode,
                                  TPROXY is required in redir mode

       [-L <addr>:<port>]         specify destination server address and port
                                  for local port forwarding,
                                  only available in tunnel mode

       [-d <addr>]                setup name servers for internal DNS resolver,
                                  only available in server mode

       [--fast-open]              enable TCP fast open,
                                  only available in local and server mode,
                                  with Linux kernel > 3.7.0

       [--acl <acl_file>]         config file of ACL (Access Control List)
                                  only available in local and server mode

       [-v]                       verbose mode

notes:

    ss-redir provides a transparent proxy function and only works on the 
    Linux platform with iptables.

```

## Advanced usage

The latest shadowsocks-libev has provided a *redir* mode. You can configure your linux based box or router to proxy all tcp traffic transparently.

    # Create new chain
    root@Wrt:~# iptables -t nat -N SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -N SHADOWSOCKS
    
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

    # Add any UDP rules
    root@Wrt:~# ip rule add fwmark 0x01/0x01 table 100
    root@Wrt:~# ip route add local 0.0.0.0/0 dev lo table 100
    root@Wrt:~# iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01
    
    # Apply the rules
    root@Wrt:~# iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -A PREROUTING -j SHADOWSOCKS

    # Start the shadowsocks-redir
    root@Wrt:~# ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid

## Security Tips

Although shadowsocks-libev can handle thousands of concurrent connections nicely, we still recommend to
set up your server's firewall rules to limit connections from each user.

    # Up to 32 connections are enough for normal usages
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

Copyright (C) 2014 Max Lv <max.c.lv@gmail.com>

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
