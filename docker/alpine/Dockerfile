#
# Dockerfile for shadowsocks-libev
#

FROM alpine as builder

COPY . /tmp/repo
RUN set -ex \
    # Build environment setup
    && apk add --no-cache \
         autoconf \
         automake \
         build-base \
         c-ares-dev \
         libev-dev \
         libtool \
         libsodium-dev \
         linux-headers \
         mbedtls-dev \
         pcre-dev \
    # Build & install
    && cd /tmp/repo \
    && ./autogen.sh \
    && ./configure --prefix=/usr --disable-documentation \
    && make install

# Download v2ray-plugin
RUN apk add --no-cache jq \
    && V2RAY_PLUGIN_VERSION=$(wget -q -O - https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | jq -r .name) \
    && wget https://github.com/shadowsocks/v2ray-plugin/releases/download/${V2RAY_PLUGIN_VERSION}/v2ray-plugin-linux-amd64-${V2RAY_PLUGIN_VERSION}.tar.gz \
    && tar xf v2ray-plugin-linux-amd64-${V2RAY_PLUGIN_VERSION}.tar.gz \
    && mv v2ray-plugin_linux_amd64 /usr/bin/v2ray-plugin

FROM alpine
LABEL maintainer="kev <noreply@datageek.info>, Sah <contact@leesah.name>"

ENV SERVER_ADDR 0.0.0.0
ENV SERVER_PORT 8388
ENV PASSWORD=
ENV METHOD      aes-256-gcm
ENV TIMEOUT     300
ENV DNS_ADDRS    8.8.8.8,8.8.4.4
ENV ARGS=

COPY --from=builder /usr/bin/ss-* /usr/bin/v2ray-plugin /usr/bin/

# Runtime dependencies setup
RUN apk add --no-cache \
    rng-tools \
    $(scanelf --needed --nobanner /usr/bin/ss-* \
    | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
    | sort -u)

USER nobody

CMD exec ss-server \
      -s $SERVER_ADDR \
      -p $SERVER_PORT \
      -k ${PASSWORD:-$(hostname)} \
      -m $METHOD \
      -t $TIMEOUT \
      -d $DNS_ADDRS \
      -u \
      $ARGS
