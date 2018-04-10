# Alpine with China mirror
FROM alpine
MAINTAINER wener <wenermail@gmail.com>

# Better for cache and dev
RUN apk add --no-cache --virtual .build-deps \
    alpine-sdk cmake \
    linux-headers libev-dev libsodium-dev mbedtls-static mbedtls-dev pcre-dev udns-dev
