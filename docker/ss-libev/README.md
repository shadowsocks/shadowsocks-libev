# Shadowsocks-libev for Docker

[![Docker pulls][pulls-image]][pulls-url]
[![Docker stars][stars-image]][stars-url]

A mini docker image of Shadowsocks-libev only 15M in size.

## Tags

- `2.4.6`
- `2.4.7`
- `2.4.8`, `latest`

## Usage

```
docker pull secbone/docker-ss-libev
```

```
docker run -d -p 8388:8388 secbone/docker-ss-libev

# custom config
docker run -d -v /path/to/config.json:/conf/shadowsocks.json -p <yourport>:8388 secbone/docker-ss-libev
```

## default config

- port: `8388`
- password: `iachshea`
- timeout: `60`
- method: `aes-256-cfb`

[pulls-image]: https://img.shields.io/docker/pulls/secbone/docker-ss-libev.svg?style=flat-square
[pulls-url]: https://hub.docker.com/r/secbone/docker-ss-libev/
[stars-image]: https://img.shields.io/docker/stars/secbone/docker-ss-libev.svg?style=flat-square
[stars-url]: https://hub.docker.com/r/secbone/docker-ss-libev/
