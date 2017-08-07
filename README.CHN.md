# shadowsocks-libev

## 介绍

[Shadowsocks-libev](https://shadowsocks.org) 是一个面向嵌入式设备及低端设备的SOCKS5代理协议。 

这是一个 [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
的一个分支，最初由 [@clowwindy](https://github.com/clowwindy) 创建, 现在由
[@madeye](https://github.com/madeye) 和 [@linusyang](https://github.com/linusyang) 维护.

Travis CI测试状态: [![Travis CI](https://travis-ci.org/shadowsocks/shadowsocks-libev.svg?branch=master)](https://travis-ci.org/shadowsocks/shadowsocks-libev)

## 特性

Shadowsocks-libev 是基于 [libev](http://software.schmorp.de/pkg/libev.html) 而写的纯C语言版本shadowsocks. 它被设计成一个轻量级的shadowsocks, 目的是尽量减少资源消耗.

关于所有shadowsocks版本的特性对比，请参照这个[Wiki](https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## 准备工作

### 获取最新的源代码

为了获取最新的源代码，你还需要按照运行以下命令来更新必须的子模块：

```bash
git clone https://github.com/shadowsocks/shadowsocks-libev.git
cd shadowsocks-libev
git submodule update --init --recursive
```

### 使用最新的libsodium来搭建编译环境

shadowsocks-libev 至少需要``libsodium 1.0.8``版本或更高. 详情请参阅 [Directly build and install on UNIX-like system](#linux).

## 安装

### 按照Linux分支整理

- [Debian & Ubuntu](#debian--ubuntu)
    + [直接从软件源安装](#直接从软件源安装)
    + [通过源代码制作deb安装包](#通过源代码制作deb安装包)
    + [配置及启动服务](#配置及启动服务)
- [Fedora & RHEL](#fedora--rhel)
    + [在CentOS中编译安装](#在CentOS中编译安装)
    + [从软件源安装](#从软件源安装)
- [Archlinux](#archlinux)
- [NixOS](#nixos)
- [Nix](#nix)
- [Directly build and install on UNIX-like system](#linux)
- [FreeBSD](#freebsd)
- [OpenWRT](#openwrt)
- [OS X](#os-x)

* * *

### 编译前的配置工作

要想获得完整的配置选项，试试`configure --help`.

### Debian & Ubuntu

#### 直接从软件源安装

**注意: 软件源并不总是带有最新版本的shadowsocks-libev。如果你想获得最新版本，请直接通过源代码进行编译安装. (请往下看)**

Shadowsocks-libev 在以下分支的官方软件源中提供:

* Debian 9 或者更高 (包括 testing 和 unstable/sid)
* Ubuntu 16.10 或者更高

```bash
sudo apt update
sudo apt install shadowsocks-libev
```

对于 **Debian 8 (Jessie)**, 请直接在`jessie-backports`源中安装:
我们强烈建议你从`jessie-backports`源中安装 shadowsocks-libev.
请参阅这个教程: [Debian Backports](https://backports.debian.org).

```bash
sudo sh -c 'printf "deb http://httpredir.debian.org/debian jessie-backports main" > /etc/apt/sources.list.d/jessie-backports.list'
sudo apt update
sudo apt -t jessie-backports install shadowsocks-libev
```

对于**Ubuntu 14.04 and 16.04**,请直接通过作者的PPA进行安装：

```bash
sudo add-apt-repository ppa:max-c-lv/shadowsocks-libev
sudo apt-get update
sudo apt install shadowsocks-libev
```

#### 通过源代码制作deb安装包

这个方法支持这些分支：

* Debian 8, 9 or higher
* Ubuntu 14.04 LTS, 16.04 LTS, 16.10 or higher

比上述分支旧的系统无法使用`.deb`进行安装，请直接编译安装。

你可以通过以下命令制作shadowsocks-libev的安装包并安装所需的依赖:

```bash
mkdir -p ~/build-area/
cp ./scripts/build_deb.sh ~/build-area/
cd ~/build-area
./build_deb.sh
```
反之，请直接编译安装。请看下面的 [Linux](#linux) 部分 。

**给Debian 8 (Jessie) 用户的提示**:

我们依旧建议您使用`jessie-backports`源来安装shadowsocks-libev.如果您还是想进行编译安装，那么你需要手动从`jessie-backports`源中安装libsodium,而不是从默认源中安装。

详情请参见 [Debian Backports Website](https://backports.debian.org).

``` bash
cd shadowsocks-libev
sudo apt-get install --no-install-recommends devscripts equivs
mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
./autogen.sh && dpkg-buildpackage -b -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

#### 配置及启动服务

```
# 编辑配置文件
sudo vim /etc/shadowsocks-libev/config.json

# 编辑默认服务启动配置(debian)
sudo vim /etc/default/shadowsocks-libev

# 启动服务
sudo /etc/init.d/shadowsocks-libev start    # for sysvinit, or
sudo systemctl start shadowsocks-libev      # for systemd
```

### Fedora & RHEL

支持的分支：

* Fedora 22, 23, 24
* RHEL 6, 7 and derivatives (including CentOS, Scientific Linux)

#### 在CentOS中编译安装

如果你用的是CentOS 7，那么你需要安装这些依赖才能搭建编译环境：

```bash 
yum install epel-release -y
yum install gcc gettext autoconf libtool automake make pcre-devel asciidoc xmlto udns-devel libev-devel libsodium-devel mbedtls-devel -y
```

#### 从软件源安装

通过 `dnf` 开启软件源:

```
su -c 'dnf copr enable librehat/shadowsocks'
```

或者在 [Fedora Copr](https://copr.fedoraproject.org/coprs/librehat/shadowsocks/) 下载yum软件源并将其放在 `/etc/yum.repos.d/` 里面. `Epel` 版本是给RHEL及其衍生版本用的.

然后, 用`dnf`安装 `shadowsocks-libev` :

```bash
su -c 'dnf update'
su -c 'dnf install shadowsocks-libev'
```

或者 `yum`:

```bash
su -c 'yum update'
su -c 'yum install shadowsocks-libev'
```
### Archlinux

```bash
sudo pacman -S shadowsocks-libev
```

请参照 downstream [PKGBUILD](https://projects.archlinux.org/svntogit/community.git/tree/trunk?h=packages/shadowsocks-libev)
脚本来进行额外的修改和解决与Linux分支相关的bug.

### NixOS

```bash
nix-env -iA nixos.shadowsocks-libev
```

### Nix

```bash
nix-env -iA nixpkgs.shadowsocks-libev
```

### Linux

通常，你需要以下依赖:

* autotools (autoconf, automake, libtool)
* gettext
* pkg-config
* libmbedtls
* libsodium
* libpcre3 (old pcre library)
* libev
* libudns
* asciidoc (for documentation only)
* xmlto (for documentation only)

如果你的系统旧到以至于不提供libmbedtls 和 libsodium  (**v1.0.8**以后)，则你需要手动安装这些依赖，或者干脆更新系统(apt dist-upgrade).

反之, 请 **不要** 编译安装. 你应该直接跳过这个部分，然后从各大分支的软件源安装。

在一些分支下，你应该像这样安装依赖:

```bash
# 安装基本依赖
## Debian / Ubuntu
sudo apt-get install --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libudns-dev automake libmbedtls-dev libsodium-dev
## CentOS / Fedora / RHEL
sudo yum install gettext gcc autoconf libtool automake make asciidoc xmlto udns-devel libev-devel
## Arch
sudo pacman -S gettext gcc autoconf libtool automake make asciidoc xmlto udns libev

# 安装libsodium
export LIBSODIUM_VER=1.0.12
wget https://download.libsodium.org/libsodium/releases/libsodium-$LIBSODIUM_VER.tar.gz
tar xvf libsodium-$LIBSODIUM_VER.tar.gz
pushd libsodium-$LIBSODIUM_VER
./configure --prefix=/usr && make
sudo make install
popd
sudo ldconfig

# 安装MbedTLS
export MBEDTLS_VER=2.5.1
wget https://tls.mbed.org/download/mbedtls-$MBEDTLS_VER-gpl.tgz
tar xvf mbedtls-$MBEDTLS_VER-gpl.tgz
pushd mbedtls-$MBEDTLS_VER
make SHARED=1 CFLAGS=-fPIC
sudo make DESTDIR=/usr install
popd
sudo ldconfig

# 开始搭建编译环境并进行编译安装
./autogen.sh && ./configure && make
sudo make install
```

你可能需要手动安装缺失的软件包（用上文的`apt`、`yum`或者`dnf`都是可以的）

### FreeBSD

```bash
su
cd /usr/ports/net/shadowsocks-libev
make install
```

编辑config.json. 默认情况下，这个文件位于``/usr/local/etc/shadowsocks-libev.

为了启用shadowsocks-libev，你需要在/etc/rc.conf中添加这些RC变量:

```
shadowsocks_libev_enable="YES"
```

启动shadowsocks服务器服务:

```bash
service shadowsocks_libev start
```

### OpenWRT

这里有移植到OpenWRT的专用版Shadowsocks-libev:
[openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks).

### OS X
对于macOS，请使用[Homebrew](http://brew.sh) 来安装或者编译.

安装 Homebrew:

```bash
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```
安装 shadowsocks-libev:

```bash
brew install shadowsocks-libev
```

## 使用方法

你还可以通过``--help``来获取完整的功能列表.

```
    ss-[local|redir|server|tunnel|manager]

       -s <server_host>           host name or ip address of your remote server

       -p <server_port>           port number of your remote server

       -l <local_port>            port number of your local server

       -k <password>              password of your remote server

       -m <encrypt_method>        Encrypt method: rc4-md5,
                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,
                                  camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, bf-cfb,
                                  chacha20-poly1305, chacha20-ietf-poly1305
                                  salsa20, chacha20 and chacha20-ietf.

       [-f <pid_file>]            the file path to store pid

       [-t <timeout>]             socket timeout in seconds

       [-c <config_file>]         the path to config file

       [-i <interface>]           network interface to bind,
                                  not available in redir mode

       [-b <local_address>]       local address to bind

       [-u]                       enable udprelay mode,
                                  TPROXY is required in redir mode

       [-U]                       enable UDP relay and disable TCP relay,
                                  not available in local mode

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

       [--manager-address <addr>] UNIX domain socket address
                                  only available in server and manager mode

       [--executable <path>]      path to the executable of ss-server
                                  only available in manager mode

       [--plugin <name>]          Enable SIP003 plugin. (Experimental)
       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)

       [-v]                       verbose mode

注意:

    ss-redir 提供透明代理，但只能在Linux下结合iptables使用。

```

## 进阶用法

最新版的shadowsocks-libev拥有*重定向*功能。你可以通过在linux设备上通过此功能实现透明代理所有TCP流量。

    # Create new chain
    root@Wrt:~# iptables -t nat -N SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -N SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -N SHADOWSOCKS_MARK

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
    root@Wrt:~# ip route add local default dev lo table 100
    root@Wrt:~# ip rule add fwmark 1 lookup 100
    root@Wrt:~# iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01
    root@Wrt:~# iptables -t mangle -A SHADOWSOCKS_MARK -p udp --dport 53 -j MARK --set-mark 1

    # Apply the rules
    root@Wrt:~# iptables -t nat -A OUTPUT -p tcp -j SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -A PREROUTING -j SHADOWSOCKS
    root@Wrt:~# iptables -t mangle -A OUTPUT -j SHADOWSOCKS_MARK

    # Start the shadowsocks-redir
    root@Wrt:~# ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid

## 结合KCP使用

很简单，只要使用[kcptun](https://github.com/xtaci/kcptun)即可让shadowsocks用上[KCP](https://github.com/skywind3000/kcp)。

这项技术的目的是为了提供一个完全可配置的UDP协议来提升在差网络环境下的体验，例如高丢包的3G网络。


### 配置服务器端

```bash
server_linux_amd64 -l :21 -t 127.0.0.1:443 --crypt none --mtu 1200 --nocomp --mode normal --dscp 46 &
ss-server -s 0.0.0.0 -p 443 -k passwd -m chacha20 -u
```

### 配置客户端

```bash
client_linux_amd64 -l 127.0.0.1:1090 -r <server_ip>:21 --crypt none --mtu 1200 --nocomp --mode normal --dscp 46 &
ss-local -s 127.0.0.1 -p 1090 -k passwd -m chacha20 -l 1080 -b 0.0.0.0 &
ss-local -s <server_ip> -p 443 -k passwd -m chacha20 -l 1080 -U -b 0.0.0.0
```

## 安全提示

虽然shadowsocks-libev可以轻松搞定上千个连接，但我们还是强烈建议您限制每个用户的最大连接数:

    # 正常情况下限制每个用户32个连接
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## 版权声明

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2017, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

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
```
