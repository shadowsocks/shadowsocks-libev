FROM alpine

MAINTAINER Secbone <secbone@gmail.com>

ENV SS_VERSION 2.4.8
ENV SS_URL https://github.com/shadowsocks/shadowsocks-libev/archive/v$SS_VERSION.tar.gz
ENV SS_DIR shadowsocks-libev-$SS_VERSION
ENV SS_DEPENDENCE make gcc libc-dev autoconf libtool linux-headers openssl-dev asciidoc xmlto curl
ENV SS_PORT 8388

RUN apk --no-cache add --virtual ss-depd $SS_DEPENDENCE && \
    curl -L $SS_URL | tar -zxv && \
    cd $SS_DIR && \
    ./configure && \
    make install && \
    cd .. && \
    rm -rf $SS_DIR && \
    apk del ss-depd

ADD config.json /conf/shadowsocks.json

EXPOSE $SS_PORT

ENTRYPOINT ss-server -u -c /conf/shadowsocks.json -p $SS_PORT
