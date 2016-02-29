# Shadowsocks Dockerized

## About this image

This image is built to ease the deployment of the Shadowsocks server daemon with Docker.

For Shadowsocks clients, you want to visit http://shadowsocks.org/en/download/clients.html

### What is Shadowsocks

A secure socks5 proxy designed to protect your Internet traffic.

See http://shadowsocks.org/

### What is Docker

An open platform for distributed applications for developers and sysadmins.

See https://www.docker.com/

## How to use this image

### Start the daemon for the first time

```bash
$ docker run --name shadowsocks-app --detach --publish 58338:8338 shadowsocks/shadowsocks-libev -k "5ecret!"
```

To see all supported arguments, run

```bash
$ docker run --rm shadowsocks/shadowsocks-libev --help
```

To try the bleeding edge version of Shadowsocks, run with an `unstable` tag

```bash
$ docker run --name shadowsocks-app --detach --publish 58338:8338 shadowsocks/shadowsocks-libev:unstable -k "5ecret!"
```

### Stop the daemon

```bash
$ docker stop shadowsocks-app
```

### Start a stopped daemon

```bash
$ docker start shadowsocks-app
```

### Upgrade

Simply run a `docker pull` to upgrade the image.

```bash
$ docker pull shadowsocks/shadowsocks-libev
```

### Use in CoreOS

COMING SOON

### Use with `fig`

COMING SOON

## Limitations

### JSON Configuration File

This image doesn't support the JSON configuration at the moment. But I do plan to add the support in the future. So please stay tuned.

### Specifying Hostname & Port

Docker containers don't have the power to specify on what hostname or port of the host should the service listen to. These have to be specified using the `--publish` argument of `docker run`.

See [Docker run reference](https://docs.docker.com/reference/run/#expose-incoming-ports) for more details.

## References

* [Shadowsocks - Servers](http://shadowsocks.org/en/download/servers.html)
* [shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev/blob/master/README.md)
