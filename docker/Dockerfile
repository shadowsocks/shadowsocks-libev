FROM ubuntu:latest

MAINTAINER Sah Lee <contact@leesah.name>

ENV DEPENDENCIES git-core build-essential autoconf libtool libssl-dev
ENV BASEDIR /tmp
ENV CONFIGDIR /etc/shadowsocks
ENV CONFIGFILE $CONFIGDIR/shadowsocks.json
ENV PORT 8388

# Set up building environment
RUN apt-get update
RUN apt-get install -y $DEPENDENCIES

# Get the latest code, build and install
WORKDIR $BASEDIR
RUN git clone https://github.com/shadowsocks/shadowsocks-libev.git
WORKDIR $BASEDIR/shadowsocks-libev
RUN ./configure
RUN make
RUN make install

# Tear down building environment and delete git repository
WORKDIR $BASEDIR
RUN rm -rf $BASEDIR/shadowsocks-libev
RUN apt-get --purge autoremove -y $DEPENDENCIES

# Config file can be in a separated container
VOLUME ["$CONFIGDIR"]
ADD shadowsocks.json $CONFIGFILE

# Port in the config file won't take affect. Instead we'll use 8388.
EXPOSE $PORT

# Override the host and port in the config file.
CMD ss-server --fast-open -c $CONFIGFILE -s 0.0.0.0 -p $PORT
