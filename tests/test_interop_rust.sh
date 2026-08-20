#!/bin/bash
#
# Interoperability tests against shadowsocks-rust.
#
# The 2022 (SIP022) ciphers are only useful if they interoperate with other
# implementations, and a spec detail can be got wrong in a way that still
# round-trips against ourselves. This drives our binaries against
# shadowsocks-rust's in both directions.
#
# Skips (exit 0) when shadowsocks-rust is not installed, so it is safe to
# run everywhere. Install it with `brew install shadowsocks-rust` or
# `cargo install shadowsocks-rust`.

set -u

BIN_DIR="${SS_BIN_DIR:-build/shared/bin}"
ORIGIN_PORT=${ORIGIN_PORT:-18999}
SERVER_PORT=${SERVER_PORT:-18388}
LOCAL_PORT=${LOCAL_PORT:-18081}

result=0
SPID=""
LPID=""
HPID=""

cleanup() {
    [ -n "$SPID" ] && kill -9 "$SPID" 2>/dev/null
    [ -n "$LPID" ] && kill -9 "$LPID" 2>/dev/null
    [ -n "$HPID" ] && kill -9 "$HPID" 2>/dev/null
    wait 2>/dev/null
    return 0
}
trap cleanup EXIT

for tool in sslocal ssserver; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "SKIP: shadowsocks-rust ($tool) not installed"
        exit 0
    fi
done

for tool in curl python3 openssl; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "SKIP: $tool not available"
        exit 0
    fi
done

if [ ! -x "$BIN_DIR/ss-local" ] || [ ! -x "$BIN_DIR/ss-server" ]; then
    echo "SKIP: shadowsocks-libev binaries not found in $BIN_DIR"
    echo "      (set SS_BIN_DIR to override)"
    exit 0
fi

# A local origin server keeps the test off the network.
WWW_DIR="$(mktemp -d)"
echo "interop-ok" > "$WWW_DIR/index.html"
(cd "$WWW_DIR" && python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1) \
    > /dev/null 2>&1 &
HPID=$!
sleep 1

# Fetch through the SOCKS5 proxy and check we got the origin's content back.
fetch_through_proxy() {
    curl -s --max-time 15 --socks5-hostname "127.0.0.1:$LOCAL_PORT" \
        "http://127.0.0.1:$ORIGIN_PORT/" 2>/dev/null | grep -q "interop-ok"
}

run_case() {
    local desc="$1" server_cmd="$2" client_cmd="$3"

    printf '\e[0;36mrunning: %s\e[0m\n' "$desc"

    $server_cmd > /dev/null 2>&1 &
    SPID=$!
    sleep 1
    $client_cmd > /dev/null 2>&1 &
    LPID=$!
    sleep 2

    if fetch_through_proxy; then
        printf '\e[0;32mOK: %s\e[0m\n' "$desc"
    else
        printf '\e[0;31mFAILED: %s\e[0m\n' "$desc"
        result=1
    fi

    kill -9 "$SPID" "$LPID" 2>/dev/null
    wait "$SPID" "$LPID" 2>/dev/null
    SPID=""
    LPID=""
    # let the listening sockets go away before the next case binds them
    sleep 2
}

test_method() {
    local method="$1" key_size="$2"
    local psk

    psk="$(openssl rand -base64 "$key_size")"

    run_case "$method: libev client -> rust server" \
        "ssserver -s 127.0.0.1:$SERVER_PORT -k $psk -m $method" \
        "$BIN_DIR/ss-local -s 127.0.0.1 -p $SERVER_PORT -l $LOCAL_PORT -k $psk -m $method"

    run_case "$method: rust client -> libev server" \
        "$BIN_DIR/ss-server -s 127.0.0.1 -p $SERVER_PORT -k $psk -m $method" \
        "sslocal -b 127.0.0.1:$LOCAL_PORT -s 127.0.0.1:$SERVER_PORT -k $psk -m $method"
}

# SIP022. The key sizes are fixed by the spec.
test_method 2022-blake3-aes-128-gcm 16
test_method 2022-blake3-aes-256-gcm 32
test_method 2022-blake3-chacha20-poly1305 32

# A legacy AEAD cipher, to catch a regression that only affects the old path.
test_method aes-256-gcm 32

rm -rf "$WWW_DIR"

exit $result
