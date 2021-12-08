#!/bin/sh

if [[ -f "$PASSWORD_FILE" ]]; then
    PASSWORD=$(cat "$PASSWORD_FILE")
fi

if [[ -f "/var/run/secrets/$PASSWORD_SECRET" ]]; then
    PASSWORD=$(cat "/var/run/secrets/$PASSWORD_SECRET")
fi

if [[ ! -z "$DNS_ADDRS" ]]; then
    ARGS="-d $DNS_ADDRS $ARGS"
fi

exec ss-server \
      -s $SERVER_ADDR \
      -p $SERVER_PORT \
      -k ${PASSWORD:-$(hostname)} \
      -m $METHOD \
      -t $TIMEOUT \
      -u \
      $ARGS
