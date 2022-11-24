# shadowsocks-libev

[![Build Status](https://travis-ci.com/shadowsocks/shadowsocks-libev.svg?branch=master)](https://travis-ci.com/shadowsocks/shadowsocks-libev) [![Snap Status](https://build.snapcraft.io/badge/shadowsocks/shadowsocks-libev.svg)](https://build.snapcraft.io/user/shadowsocks/shadowsocks-libev)

## Introdução

[Shadowsocks-libev](https://shadowsocks.org) é um SOCKS5 leve e seguro
proxy para dispositivos embutidos e caixas de baixo custo.

É uma porta de [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
criado por [@clowwindy](https://github.com/clowwindy) e mantido por
[@madeye](https://github.com/madeye) e [@linusyang](https://github.com/linusyang).

Versão atual: 3.3.5 | [Changelog](debian/changelog)

## Características

Shadowsocks-libev é escrito em C puro e depende de [libev](http://software.schmorp.de/pkg/libev.html). Ele foi projetado para ser uma implementação leve do protocolo shadowsocks, a fim de manter o uso de recursos o mais baixo possível.

Para obter uma lista completa de comparação de recursos entre diferentes versões de shadowsocks, consulte a [página da Wiki (https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## Começo rápido

Snap é a maneira recomendada de instalar os binários mais recentes.

### Instale o snap core

https://snapcraft.io/core

### Instalar a partir do snapcraft.io

Stable channel:

```bash
sudo snap install shadowsocks-libev
```

Edge channel:

```bash
sudo snap install shadowsocks-libev --edge
```

## Instalação

### Guia específico de distribuição

- [Debian & Ubuntu](#debian--ubuntu)
    + [Install from repository](#install-from-repository-not-recommended)
    + [Build deb package from source](#build-deb-package-from-source)
    + [Configure and start the service](#configure-and-start-the-service)
- [Fedora & RHEL](#fedora--rhel)
    + [Build from source with centos](#build-from-source-with-centos)
- [Archlinux & Manjaro](#archlinux--manjaro)
- [NixOS](#nixos)
- [Nix](#nix)
- [Directly build and install on UNIX-like system](#linux)
- [FreeBSD](#freebsd)
    + [Install](#install)
    + [Configuration](#configuration)
    + [Run](#run)
    + [Run as client](#run-as-client)
- [OpenWRT](#openwrt)
- [OS X](#os-x)
- [Windows (MinGW)](#windows-mingw)
- [Docker](#docker)

* * *

### Inicialize o ambiente de compilação

Este repositório usa submódulos, então você deve puxá-los antes de começar, usando:

```bash
git submodule update --init --recursive
```

### Guia de configuração de pré-compilação

Para obter uma lista completa das opções de tempo de configuração disponíveis,
tentar `configure --help`.

### Debian & Ubuntu

#### Instale a partir do repositório (não recomendado)

Shadowsocks-libev está disponível no repositório oficial para as seguintes distribuições:

* Debian 8 or higher, including oldoldstable (jessie), old stable (stretch), stable (buster), testing (bullseye) and unstable (sid)
* Ubuntu 16.10 or higher

```bash
sudo apt update
sudo apt install shadowsocks-libev
```

#### Compile o pacote deb a partir da fonte.

Distribuições suportadas:

* Debian 8, 9 or higher
* Ubuntu 14.04 LTS, 16.04 LTS, 16.10 or higher

Você pode construir shadowsocks-libev e todas as suas dependências por script:

```bash
mkdir -p ~/build-area/
cp ./scripts/build_deb.sh ~/build-area/
cd ~/build-area
./build_deb.sh
```

Para sistemas mais antigos, a construção de pacotes `.deb` não é suportada.
Por favor, tente construir e instalar diretamente da fonte. Veja a seção [Linux](#linux) abaixo.

**Nota para usuários do Debian 8 (Jessie) para construir seus próprios pacotes deb**:

Nós encorajamos você a instalar shadowsocks-libev de `jessie-backports-sloppy`. Se você insistir em compilar a partir da fonte, você precisará instalar manualmente o libsodium de `jessie-backports-sloppy`, **NÃO** libsodium no repositório principal.

Para mais informações sobre backports, você pode consultar [Debian Backports](https://backports.debian.org).

``` bash
cd shadowsocks-libev
sudo sh -c 'printf "deb http://deb.debian.org/debian jessie-backports main" > /etc/apt/sources.list.d/jessie-backports.list'
sudo sh -c 'printf "deb http://deb.debian.org/debian jessie-backports-sloppy main" >> /etc/apt/sources.list.d/jessie-backports.list'
sudo apt-get install --no-install-recommends devscripts equivs
mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
./autogen.sh && dpkg-buildpackage -b -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

**Nota para usuários do Debian 9 (Stretch) para construir seus próprios pacotes deb**:

Nós encorajamos você a instalar shadowsocks-libev de `stretch-backports`. Se você insistir em compilar a partir do código-fonte, precisará instalar manualmente o libsodium de `stretch-backports`, **NÃO** libsodium no repositório principal.

Para mais informações sobre backports, você pode consultar [Debian Backports](https://backports.debian.org).

``` bash
cd shadowsocks-libev
sudo sh -c 'printf "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
sudo apt-get install --no-install-recommends devscripts equivs
mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
./autogen.sh && dpkg-buildpackage -b -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

#### Configurar e iniciar o serviço

```
# Edit the configuration file
sudo vim /etc/shadowsocks-libev/config.json

# Edit the default configuration for debian
sudo vim /etc/default/shadowsocks-libev

# Start the service
sudo /etc/init.d/shadowsocks-libev start    # for sysvinit, or
sudo systemctl start shadowsocks-libev      # for systemd
```

### Fedora & RHEL

Distribuições suportadas:

* Recent Fedora versions (until EOL)
* RHEL 6, 7 and derivatives (including CentOS, Scientific Linux)

#### Construa a partir da fonte com centos

Se você estiver usando o CentOS 7, precisará instalar estes pré-requisitos para compilar a partir do código-fonte:

```bash
yum install epel-release -y
yum install gcc gettext autoconf libtool automake make pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel mbedtls-devel -y
```

### Archlinux & Manjaro

```bash
sudo pacman -S shadowsocks-libev
```

Consulte o script downstream [PKGBUILD](https://github.com/archlinux/svntogit-community/blob/packages/shadowsocks-libev/trunk/PKGBUILD) para modificações extras e bugs específicos da distribuição.

### NixOS

```bash
nix-env -iA nixos.shadowsocks-libev
```

### Nix

```bash
nix-env -iA nixpkgs.shadowsocks-libev
```

### Linux

Em geral, você precisa das seguintes dependências de compilação:

* autotools (autoconf, automake, libtool)
* gettext
* pkg-config
* libmbedtls
* libsodium
* libpcre3 (old pcre library)
* libev
* libc-ares
* asciidoc (for documentation only)
* xmlto (for documentation only)

Notas: Fedora 26 libsodium versão >= 1.0.12, então você pode instalar via dnf install libsodium em vez de compilar a partir da fonte.

Se seu sistema for muito antigo para fornecer libmbedtls e libsodium (posterior a **v1.0.8**), você precisará instalar essas bibliotecas manualmente ou atualizar seu sistema.

Se o seu sistema fornece essas bibliotecas, você **não deve** instalá-las a partir do código-fonte. Você deve ir para esta seção e instalá-las a partir do repositório de distribuição.

Para algumas das distribuições, você pode instalar dependências de compilação como esta:

```bash
# Installation of basic build dependencies
## Debian / Ubuntu
sudo apt-get install --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev pkg-config
## CentOS / Fedora / RHEL
sudo yum install gettext gcc autoconf libtool automake make asciidoc xmlto c-ares-devel libev-devel
## Arch
sudo pacman -S gettext gcc autoconf libtool automake make asciidoc xmlto c-ares libev

# Installation of libsodium
export LIBSODIUM_VER=1.0.16
wget https://download.libsodium.org/libsodium/releases/old/libsodium-$LIBSODIUM_VER.tar.gz
tar xvf libsodium-$LIBSODIUM_VER.tar.gz
pushd libsodium-$LIBSODIUM_VER
./configure --prefix=/usr && make
sudo make install
popd
sudo ldconfig

# Installation of MbedTLS
export MBEDTLS_VER=2.6.0
wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-$MBEDTLS_VER.tar.gz
tar xvf mbedtls-$MBEDTLS_VER.tar.gz
pushd mbedtls-$MBEDTLS_VER
make SHARED=1 CFLAGS="-O2 -fPIC"
sudo make DESTDIR=/usr install
popd
sudo ldconfig

# Start building
./autogen.sh && ./configure && make
sudo make install
```

Pode ser necessário instalar manualmente os softwares ausentes.

### FreeBSD
#### Install
Shadowsocks-libev está disponível na Coleção de Ports do FreeBSD. Você pode instalá-lo de qualquer maneira, `pkg` ou `ports`.

**pkg (recomendado)**

```bash
pkg install shadowsocks-libev
```

**portas**

```bash
cd /usr/ports/net/shadowsocks-libev
make install
```

#### Configuration
Edite seu arquivo `config.json`. Por padrão, está localizado em `/usr/local/etc/shadowsocks-libev`.

Para habilitar shadowsocks-libev, adicione a seguinte variável rc ao seu arquivo `/etc/rc.conf`:

```
shadowsocks_libev_enable="YES"
```

#### Executar

Inicie o servidor Shadowsocks:

```bash
service shadowsocks_libev start
```

#### Executar como cliente
Por padrão, shadowsocks-libev está rodando como um servidor no FreeBSD. Se você quiser iniciar o shadowsocks-libev no modo cliente, você pode modificar o script rc (`/usr/local/etc/rc.d/shadowsocks_libev`) manualmente.

```
# modify the following line from "ss-server" to "ss-local"
command="/usr/local/bin/ss-local"
```

Observe que é simplesmente uma solução alternativa, cada vez que você atualizar a porta, suas alterações serão substituídas pela nova versão.

### OpenWRT

O projeto OpenWRT é mantido aqui:
[openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks).

### OS X
Para OS X, use [Homebrew](http://brew.sh) para instalar ou compilar.

Instale o Homebrew:

```bash
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```
Instale shadowsocks-libev:

```bash
brew install shadowsocks-libev
```

### Windows (MinGW)
Para compilar binários nativos do Windows, o método recomendado é usar o Docker:

* No Windows: clique duas vezes em `make.bat` em `docker\mingw`
* No sistema do tipo Unix:

        cd shadowsocks-libev/docker/mingw
        make

Um tarball com binários de 32 bits e 64 bits será gerado no mesmo diretório.

Você também pode usar compiladores MinGW-w64 manualmente para compilar em shell do tipo Unix (MSYS2/Cygwin) ou compilar em sistemas semelhantes ao Unix (Linux/MacOS). Por favor, consulte os scripts de compilação em `docker/mingw`.

Atualmente você precisa usar uma biblioteca libev corrigida para MinGW:

* https://github.com/shadowsocks/libev/archive/mingw.zip

Observe que o TCP Fast Open (TFO) está disponível apenas no **Windows 10**, **1607** ou versão posterior (precisamente, build >= 14393). Se você estiver usando **1709** (compilação 16299) ou versão posterior, também precisará executar o seguinte comando no PowerShell/Prompt de comando **como administrador** e **reinicializar** para usar o TFO corretamente:

        netsh int tcp set global fastopenfallback=disabled

### Docker

Como você espera, basta puxar a imagem e executar.
```
docker pull shadowsocks/shadowsocks-libev
docker run -e PASSWORD=<password> -p<server-port>:8388 -p<server-port>:8388/udp -d shadowsocks/shadowsocks-libev
```

Mais informações sobre a imagem podem ser encontradas [aqui](docker/alpine/README.md).

## Utilização

Para obter uma lista detalhada e completa de todos os argumentos suportados,
você pode consultar as páginas de manual dos aplicativos, respectivamente.

    ss-[local|redir|server|tunnel|manager]

       -s <server_host>           Host name or IP address of your remote server.

       -p <server_port>           Port number of your remote server.

       -l <local_port>            Port number of your local server.

       -k <password>              Password of your remote server.

       -m <encrypt_method>        Encrypt method: rc4-md5,
                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,
                                  camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, bf-cfb,
                                  chacha20-ietf-poly1305,
                                  xchacha20-ietf-poly1305,
                                  salsa20, chacha20 and chacha20-ietf.
                                  The default cipher is chacha20-ietf-poly1305.

       [-a <user>]                Run as another user.

       [-f <pid_file>]            The file path to store pid.

       [-t <timeout>]             Socket timeout in seconds.

       [-c <config_file>]         The path to config file.

       [-n <number>]              Max number of open files.

       [-i <interface>]           Network interface to bind.
                                  (not available in redir mode)

       [-b <local_address>]       Local address to bind.
                                  For servers: Specify the local address to use 
                                  while this server is making outbound 
                                  connections to remote servers on behalf of the
                                  clients.
                                  For clients: Specify the local address to use 
                                  while this client is making outbound 
                                  connections to the server.

       [-u]                       Enable UDP relay.
                                  (TPROXY is required in redir mode)

       [-U]                       Enable UDP relay and disable TCP relay.
                                  (not available in local mode)

       [-T]                       Use tproxy instead of redirect. (for tcp)
                                  (only available in redir mode)

       [-L <addr>:<port>]         Destination server address and port
                                  for local port forwarding.
                                  (only available in tunnel mode)

       [-6]                       Resolve hostname to IPv6 address first.

       [-d <addr>]                Name servers for internal DNS resolver.
                                  (only available in server mode)

       [--reuse-port]             Enable port reuse.

       [--fast-open]              Enable TCP fast open.
                                  with Linux kernel > 3.7.0.
                                  (only available in local and server mode)

       [--acl <acl_file>]         Path to ACL (Access Control List).
                                  (only available in local and server mode)

       [--manager-address <addr>] UNIX domain socket address.
                                  (only available in server and manager mode)

       [--mtu <MTU>]              MTU of your network interface.

       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.

       [--no-delay]               Enable TCP_NODELAY.

       [--executable <path>]      Path to the executable of ss-server.
                                  (only available in manager mode)

       [-D <path>]                Path to the working directory of ss-manager.
                                  (only available in manager mode)

       [--key <key_in_base64>]    Key of your remote server.

       [--plugin <name>]          Enable SIP003 plugin. (Experimental)

       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)

       [-v]                       Verbose mode.

## proxy transparente

O mais recente shadowsocks-libev forneceu um modo *redir*. Você pode configurar sua caixa ou roteador baseado em Linux para fazer proxy de todo o tráfego TCP de forma transparente, o que é útil se você usar um roteador com OpenWRT.

    # Create new chain
    iptables -t nat -N SHADOWSOCKS
    iptables -t mangle -N SHADOWSOCKS

    # Ignore your shadowsocks server's addresses
    # It's very IMPORTANT, just be careful.
    iptables -t nat -A SHADOWSOCKS -d 123.123.123.123 -j RETURN

    # Ignore LANs and any other addresses you'd like to bypass the proxy
    # See Wikipedia and RFC5735 for full list of reserved networks.
    # See ashi009/bestroutetb for a highly optimized CHN route list.
    iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN

    # Anything else should be redirected to shadowsocks's local port
    iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports 12345

    # Add any UDP rules
    ip route add local default dev lo table 100
    ip rule add fwmark 1 lookup 100
    iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01

    # Apply the rules
    iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
    iptables -t mangle -A PREROUTING -j SHADOWSOCKS

    # Start the shadowsocks-redir
    ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid

## Proxy transparente (pure tproxy)

A execução deste script no host linux pode fazer proxy de todo o tráfego de saída desta máquina (exceto o tráfego enviado para o endereço reservado). Outros hosts na mesma LAN também podem alterar seu gateway padrão para o ip deste host linux (ao mesmo tempo, alterar o servidor dns para 1.1.1.1 ou 8.8.8.8, etc.) para fazer proxy de seu tráfego de saída.

> Claro, o proxy ipv6 é semelhante, basta alterar `iptables` para `ip6tables`, `ip` para `ip -6`, `127.0.0.1` para `::1`, e outros detalhes.

```shell
#!/bin/bash

start_ssredir() {
    # please modify MyIP, MyPort, etc.
    (ss-redir -s MyIP -p MyPort -m MyMethod -k MyPasswd -b 127.0.0.1 -l 60080 --no-delay -u -T -v </dev/null &>>/var/log/ss-redir.log &)
}

stop_ssredir() {
    kill -9 $(pidof ss-redir) &>/dev/null
}

start_iptables() {
    ##################### SSREDIR #####################
    iptables -t mangle -N SSREDIR

    # connection-mark -> packet-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --restore-mark
    iptables -t mangle -A SSREDIR -m mark --mark 0x2333 -j RETURN

    # please modify MyIP, MyPort, etc.
    # ignore traffic sent to ss-server
    iptables -t mangle -A SSREDIR -p tcp -d MyIP --dport MyPort -j RETURN
    iptables -t mangle -A SSREDIR -p udp -d MyIP --dport MyPort -j RETURN

    # ignore traffic sent to reserved addresses
    iptables -t mangle -A SSREDIR -d 0.0.0.0/8          -j RETURN
    iptables -t mangle -A SSREDIR -d 10.0.0.0/8         -j RETURN
    iptables -t mangle -A SSREDIR -d 100.64.0.0/10      -j RETURN
    iptables -t mangle -A SSREDIR -d 127.0.0.0/8        -j RETURN
    iptables -t mangle -A SSREDIR -d 169.254.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 172.16.0.0/12      -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.0.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.2.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.88.99.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 192.168.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 198.18.0.0/15      -j RETURN
    iptables -t mangle -A SSREDIR -d 198.51.100.0/24    -j RETURN
    iptables -t mangle -A SSREDIR -d 203.0.113.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 224.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 240.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 255.255.255.255/32 -j RETURN

    # mark the first packet of the connection
    iptables -t mangle -A SSREDIR -p tcp --syn                      -j MARK --set-mark 0x2333
    iptables -t mangle -A SSREDIR -p udp -m conntrack --ctstate NEW -j MARK --set-mark 0x2333

    # packet-mark -> connection-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --save-mark

    ##################### OUTPUT #####################
    # proxy the outgoing traffic from this machine
    iptables -t mangle -A OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    ##################### PREROUTING #####################
    # proxy traffic passing through this machine (other->other)
    iptables -t mangle -A PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    # hand over the marked package to TPROXY for processing
    iptables -t mangle -A PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
    iptables -t mangle -A PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
}

stop_iptables() {
    ##################### PREROUTING #####################
    iptables -t mangle -D PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null

    iptables -t mangle -D PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### OUTPUT #####################
    iptables -t mangle -D OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### SSREDIR #####################
    iptables -t mangle -F SSREDIR &>/dev/null
    iptables -t mangle -X SSREDIR &>/dev/null
}

start_iproute2() {
    ip route add local default dev lo table 100
    ip rule  add fwmark 0x2333        table 100
}

stop_iproute2() {
    ip rule  del   table 100 &>/dev/null
    ip route flush table 100 &>/dev/null
}

start_resolvconf() {
    # or nameserver 8.8.8.8, etc.
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
}

stop_resolvconf() {
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
}

start() {
    echo "start ..."
    start_ssredir
    start_iptables
    start_iproute2
    start_resolvconf
    echo "start end"
}

stop() {
    echo "stop ..."
    stop_resolvconf
    stop_iproute2
    stop_iptables
    stop_ssredir
    echo "stop end"
}

restart() {
    stop
    sleep 1
    start
}

main() {
    if [ $# -eq 0 ]; then
        echo "usage: $0 start|stop|restart ..."
        return 1
    fi

    for funcname in "$@"; do
        if [ "$(type -t $funcname)" != 'function' ]; then
            echo "'$funcname' not a shell function"
            return 1
        fi
    done

    for funcname in "$@"; do
        $funcname
    done
    return 0
}
main "$@"
```

## Dicas de segurança

Para qualquer servidor público, para evitar que os usuários acessem o localhost do seu servidor, adicione `--acl acl/server_block_local.acl` à linha de comando.

Embora shadowsocks-libev possa lidar bem com milhares de conexões simultâneas, ainda recomendamos
configurando as regras de firewall do seu servidor para limitar as conexões de cada usuário:

    # Up to 32 connections are enough for normal usage
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## Licença

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2018, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

Este programa é um software livre: você pode redistribuí-lo 
e/ou modificá-lo sob os termos da GNU General Public License 
conforme publicada pela Free Software Foundation, a versão 3
da Licença ou (a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que seja útil,
 mas SEM QUALQUER GARANTIA; sem mesmo a garantia implícita 
de COMERCIALIZAÇÃO ou ADEQUAÇÃO A UM DETERMINADO FIM.Veja
a Licença Pública Geral GNU para mais detalhes.

Você deve ter recebido uma cópia da GNU General Public License 
License juntamente com este programa. Caso contrário, 
consulte <http://www.gnu.org/licenses/>.
```
