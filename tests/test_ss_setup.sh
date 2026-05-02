#!/usr/bin/env bash
###############################################################################
# test_ss_setup.sh -- Unit tests for ss-setup.sh utility functions
#
# Sources ss-setup.sh (which skips main() due to BASH_SOURCE guard) and
# exercises every pure/utility function that doesn't require a TUI backend.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SS_SETUP="${PROJECT_ROOT}/scripts/ss-setup.sh"

PASS=0
FAIL=0
TMPDIR_TEST=""

cleanup_test() {
    if [[ -n "$TMPDIR_TEST" && -d "$TMPDIR_TEST" ]]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup_test EXIT

TMPDIR_TEST=$(mktemp -d)

# Source the script under test (main() won't run due to BASH_SOURCE guard)
# shellcheck source=../scripts/ss-setup.sh
source "$SS_SETUP"

###############################################################################
# Test helpers
###############################################################################

assert_eq() {
    local test_name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name}" >&2
        echo "  expected: '${expected}'" >&2
        echo "  actual:   '${actual}'" >&2
    fi
}

assert_match() {
    local test_name="$1" pattern="$2" actual="$3"
    if [[ "$actual" =~ $pattern ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name}" >&2
        echo "  expected match: '${pattern}'" >&2
        echo "  actual:         '${actual}'" >&2
    fi
}

assert_ok() {
    local test_name="$1"
    shift
    if "$@" 2>/dev/null; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name} (command returned non-zero)" >&2
    fi
}

assert_fail() {
    local test_name="$1"
    shift
    if "$@" 2>/dev/null; then
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name} (expected failure but got success)" >&2
    else
        PASS=$((PASS + 1))
    fi
}

assert_contains() {
    local test_name="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name}" >&2
        echo "  expected to contain: '${needle}'" >&2
        echo "  actual:              '${haystack}'" >&2
    fi
}

assert_not_contains() {
    local test_name="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: ${test_name}" >&2
        echo "  expected NOT to contain: '${needle}'" >&2
        echo "  actual:                  '${haystack}'" >&2
    fi
}

###############################################################################
# Tests: AEAD_CIPHERS constant
###############################################################################

test_aead_ciphers_count() {
    assert_eq "AEAD_CIPHERS has 5 entries" "5" "${#AEAD_CIPHERS[@]}"
}

test_aead_ciphers_contains_chacha20() {
    local found=0
    for c in "${AEAD_CIPHERS[@]}"; do
        [[ "$c" == "chacha20-ietf-poly1305" ]] && found=1
    done
    assert_eq "AEAD_CIPHERS contains chacha20-ietf-poly1305" "1" "$found"
}

test_aead_ciphers_contains_aes256gcm() {
    local found=0
    for c in "${AEAD_CIPHERS[@]}"; do
        [[ "$c" == "aes-256-gcm" ]] && found=1
    done
    assert_eq "AEAD_CIPHERS contains aes-256-gcm" "1" "$found"
}

test_aead_ciphers_contains_aes128gcm() {
    local found=0
    for c in "${AEAD_CIPHERS[@]}"; do
        [[ "$c" == "aes-128-gcm" ]] && found=1
    done
    assert_eq "AEAD_CIPHERS contains aes-128-gcm" "1" "$found"
}

###############################################################################
# Tests: validate_port
###############################################################################

test_validate_port_valid() {
    assert_ok "validate_port 1" validate_port "1"
    assert_ok "validate_port 80" validate_port "80"
    assert_ok "validate_port 443" validate_port "443"
    assert_ok "validate_port 8388" validate_port "8388"
    assert_ok "validate_port 65535" validate_port "65535"
}

test_validate_port_invalid() {
    assert_fail "validate_port 0" validate_port "0"
    assert_fail "validate_port 65536" validate_port "65536"
    assert_fail "validate_port -1" validate_port "-1"
    assert_fail "validate_port abc" validate_port "abc"
    assert_fail "validate_port empty" validate_port ""
    assert_fail "validate_port 99999" validate_port "99999"
    assert_fail "validate_port 8.8" validate_port "8.8"
}

###############################################################################
# Tests: validate_instance_name
###############################################################################

test_validate_instance_name_valid() {
    assert_ok "instance: config" validate_instance_name "config"
    assert_ok "instance: my-server" validate_instance_name "my-server"
    assert_ok "instance: server_1" validate_instance_name "server_1"
    assert_ok "instance: Test123" validate_instance_name "Test123"
    assert_ok "instance: a" validate_instance_name "a"
    assert_ok "instance: A-B_c-1" validate_instance_name "A-B_c-1"
}

test_validate_instance_name_invalid() {
    assert_fail "instance: empty" validate_instance_name ""
    assert_fail "instance: has space" validate_instance_name "has space"
    assert_fail "instance: has.dot" validate_instance_name "has.dot"
    assert_fail "instance: has/slash" validate_instance_name "has/slash"
    assert_fail "instance: has@at" validate_instance_name "has@at"
    assert_fail "instance: has:colon" validate_instance_name "has:colon"
}

###############################################################################
# Tests: generate_password
###############################################################################

test_generate_password_nonempty() {
    local pw
    pw=$(generate_password 32)
    assert_match "password is non-empty" ".+" "$pw"
}

test_generate_password_length() {
    # base64 of 16 bytes = 24 chars (before newline strip)
    local pw
    pw=$(generate_password 16)
    # Should be at least 20 chars (base64 encoding of 16 bytes)
    local len=${#pw}
    if (( len >= 20 )); then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: password length too short: ${len} chars" >&2
    fi
}

test_generate_password_no_newlines() {
    local pw
    pw=$(generate_password 32)
    assert_not_contains "password has no newline" $'\n' "$pw"
}

test_generate_password_different() {
    local pw1 pw2
    pw1=$(generate_password 32)
    pw2=$(generate_password 32)
    if [[ "$pw1" != "$pw2" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: two passwords are identical: '${pw1}'" >&2
    fi
}

###############################################################################
# Tests: generate_random_port
###############################################################################

test_generate_random_port_range() {
    local port
    for _ in $(seq 1 10); do
        port=$(generate_random_port)
        if (( port >= 10000 && port <= 65000 )); then
            PASS=$((PASS + 1))
        else
            FAIL=$((FAIL + 1))
            echo "FAIL: random port ${port} out of range 10000-65000" >&2
        fi
    done
}

test_generate_random_port_numeric() {
    local port
    port=$(generate_random_port)
    assert_match "random port is numeric" "^[0-9]+$" "$port"
}

###############################################################################
# Tests: json_escape
###############################################################################

test_json_escape_plain() {
    local result
    result=$(json_escape "hello world")
    assert_eq "json_escape plain" "hello world" "$result"
}

test_json_escape_quotes() {
    local result
    result=$(json_escape 'say "hi"')
    assert_eq "json_escape quotes" 'say \"hi\"' "$result"
}

test_json_escape_backslash() {
    local result
    result=$(json_escape 'path\to\file')
    assert_eq "json_escape backslash" 'path\\to\\file' "$result"
}

test_json_escape_tab() {
    local result
    result=$(json_escape "col1	col2")
    assert_eq "json_escape tab" 'col1\tcol2' "$result"
}

test_json_escape_newline() {
    local result
    result=$(json_escape "line1
line2")
    assert_eq "json_escape newline" 'line1\nline2' "$result"
}

test_json_escape_empty() {
    local result
    result=$(json_escape "")
    assert_eq "json_escape empty" "" "$result"
}

###############################################################################
# Tests: urlencode
###############################################################################

test_urlencode_plain() {
    local result
    result=$(urlencode "hello")
    assert_eq "urlencode plain" "hello" "$result"
}

test_urlencode_space() {
    local result
    result=$(urlencode "hello world")
    assert_eq "urlencode space" "hello%20world" "$result"
}

test_urlencode_special() {
    local result
    result=$(urlencode "a=b&c=d")
    assert_eq "urlencode special" "a%3Db%26c%3Dd" "$result"
}

test_urlencode_semicolon() {
    local result
    result=$(urlencode "obfs-local;obfs=http")
    assert_eq "urlencode semicolon" "obfs-local%3Bobfs%3Dhttp" "$result"
}

test_urlencode_safe_chars() {
    local result
    result=$(urlencode "a-b_c.d~e")
    assert_eq "urlencode safe chars" "a-b_c.d~e" "$result"
}

test_urlencode_empty() {
    local result
    result=$(urlencode "")
    assert_eq "urlencode empty" "" "$result"
}

###############################################################################
# Tests: generate_ss_uri
###############################################################################

test_ss_uri_basic() {
    local uri
    uri=$(generate_ss_uri "aes-256-gcm" "testpass" "1.2.3.4" "8388" "" "")
    # Should start with ss://
    assert_match "ss uri starts with ss://" "^ss://" "$uri"
    # Should contain @host:port
    assert_contains "ss uri has host:port" "@1.2.3.4:8388" "$uri"
    # Should NOT have plugin query
    assert_not_contains "ss uri no plugin query" "/?plugin=" "$uri"
}

test_ss_uri_with_plugin() {
    local uri
    uri=$(generate_ss_uri "chacha20-ietf-poly1305" "mypass" "example.com" "443" "v2ray-plugin" "server;tls;host=example.com")
    assert_match "ss uri+plugin starts with ss://" "^ss://" "$uri"
    assert_contains "ss uri+plugin has host:port" "@example.com:443" "$uri"
    assert_contains "ss uri+plugin has plugin param" "/?plugin=" "$uri"
    # v2ray-plugin should be URL-encoded with the opts
    assert_contains "ss uri+plugin has v2ray" "v2ray-plugin" "$uri"
}

test_ss_uri_with_plugin_no_opts() {
    local uri
    uri=$(generate_ss_uri "aes-128-gcm" "pw" "10.0.0.1" "9000" "obfs-local" "")
    assert_contains "ss uri plugin-no-opts has plugin" "/?plugin=" "$uri"
    assert_contains "ss uri plugin-no-opts has obfs-local" "obfs-local" "$uri"
}

test_ss_uri_base64_encoding() {
    # Verify the userinfo part is valid base64url
    local uri
    uri=$(generate_ss_uri "aes-256-gcm" "test" "1.2.3.4" "8388" "" "")
    # Extract the base64 part between ss:// and @
    local b64_part
    b64_part=$(echo "$uri" | sed 's|^ss://\([^@]*\)@.*|\1|')
    # base64url should only contain [A-Za-z0-9_-]
    assert_match "ss uri base64url valid chars" "^[A-Za-z0-9_-]+$" "$b64_part"
}

###############################################################################
# Tests: write_json_config (server)
###############################################################################

test_write_json_config_basic() {
    local outfile="${TMPDIR_TEST}/server_basic.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="testpassword123"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "server json has server" '"server": "0.0.0.0"' "$content"
    assert_contains "server json has port" '"server_port": 8388' "$content"
    assert_contains "server json has password" '"password": "testpassword123"' "$content"
    assert_contains "server json has timeout" '"timeout": 300' "$content"
    assert_contains "server json has method" '"method": "aes-256-gcm"' "$content"
    assert_contains "server json has mode" '"mode": "tcp_and_udp"' "$content"
    assert_contains "server json has fast_open false" '"fast_open": false' "$content"
    assert_not_contains "server json no plugin" '"plugin"' "$content"
    # No trailing comma before closing brace
    assert_not_contains "server json no trailing comma" ',
}' "$content"
}

test_write_json_config_fast_open_true() {
    local outfile="${TMPDIR_TEST}/server_tfo.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="443"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="60"
    CFG_METHOD="chacha20-ietf-poly1305"
    CFG_MODE="tcp_only"
    CFG_FAST_OPEN="true"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "server json fast_open true" '"fast_open": true' "$content"
    assert_not_contains "server json fast_open not quoted" '"fast_open": "true"' "$content"
}

test_write_json_config_with_plugin() {
    local outfile="${TMPDIR_TEST}/server_plugin.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="443"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN="v2ray-plugin"
    CFG_PLUGIN_OPTS="server;tls;host=example.com"

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "server json has plugin" '"plugin": "v2ray-plugin"' "$content"
    assert_contains "server json has plugin_opts" '"plugin_opts": "server;tls;host=example.com"' "$content"
}

test_write_json_config_with_plugin_no_opts() {
    local outfile="${TMPDIR_TEST}/server_plugin_noopts.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN="obfs-local"
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "server json plugin no opts has plugin" '"plugin": "obfs-local"' "$content"
    assert_not_contains "server json plugin no opts has no plugin_opts" '"plugin_opts"' "$content"
}

test_write_json_config_password_special_chars() {
    local outfile="${TMPDIR_TEST}/server_special.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD='pass"word\with/special'
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    # Quotes and backslashes should be escaped
    assert_contains "special password escaped quote" '\"' "$content"
    assert_contains "special password escaped backslash" '\\' "$content"
}

###############################################################################
# Tests: write_client_json_config
###############################################################################

test_write_client_json_config_basic() {
    local outfile="${TMPDIR_TEST}/client_basic.json"
    CFG_CLIENT_SERVER="1.2.3.4"
    CFG_CLIENT_SERVER_PORT="8388"
    CFG_CLIENT_LOCAL_PORT="1080"
    CFG_CLIENT_PASSWORD="clientpw"
    CFG_CLIENT_METHOD="aes-256-gcm"
    CFG_CLIENT_PLUGIN=""
    CFG_CLIENT_PLUGIN_OPTS=""

    write_client_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "client json has server" '"server": "1.2.3.4"' "$content"
    assert_contains "client json has server_port" '"server_port": 8388' "$content"
    assert_contains "client json has local_address" '"local_address": "127.0.0.1"' "$content"
    assert_contains "client json has local_port" '"local_port": 1080' "$content"
    assert_contains "client json has password" '"password": "clientpw"' "$content"
    assert_contains "client json has method" '"method": "aes-256-gcm"' "$content"
    assert_contains "client json has timeout" '"timeout": 300' "$content"
    assert_contains "client json has mode" '"mode": "tcp_and_udp"' "$content"
    assert_not_contains "client json no plugin" '"plugin"' "$content"
}

test_write_client_json_config_with_plugin() {
    local outfile="${TMPDIR_TEST}/client_plugin.json"
    CFG_CLIENT_SERVER="example.com"
    CFG_CLIENT_SERVER_PORT="443"
    CFG_CLIENT_LOCAL_PORT="1080"
    CFG_CLIENT_PASSWORD="pw"
    CFG_CLIENT_METHOD="chacha20-ietf-poly1305"
    CFG_CLIENT_PLUGIN="v2ray-plugin"
    CFG_CLIENT_PLUGIN_OPTS="tls;host=example.com"

    write_client_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "client json plugin" '"plugin": "v2ray-plugin"' "$content"
    assert_contains "client json plugin_opts" '"plugin_opts": "tls;host=example.com"' "$content"
}

###############################################################################
# Tests: parse_existing_config (round-trip)
###############################################################################

test_parse_existing_config_roundtrip() {
    local outfile="${TMPDIR_TEST}/roundtrip.json"

    # Set known values
    CFG_SERVER="10.20.30.40"
    CFG_SERVER_PORT="9999"
    CFG_PASSWORD="roundtrip_pw"
    CFG_TIMEOUT="600"
    CFG_METHOD="aes-128-gcm"
    CFG_MODE="udp_only"
    CFG_FAST_OPEN="true"
    CFG_PLUGIN="obfs-local"
    CFG_PLUGIN_OPTS="obfs=http;obfs-host=example.com"

    write_json_config "$outfile"

    # Reset globals
    CFG_SERVER=""
    CFG_SERVER_PORT=""
    CFG_PASSWORD=""
    CFG_TIMEOUT=""
    CFG_METHOD=""
    CFG_MODE=""
    CFG_FAST_OPEN=""
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    # Parse back
    parse_existing_config "$outfile"

    assert_eq "roundtrip server" "10.20.30.40" "$CFG_SERVER"
    assert_eq "roundtrip port" "9999" "$CFG_SERVER_PORT"
    assert_eq "roundtrip password" "roundtrip_pw" "$CFG_PASSWORD"
    assert_eq "roundtrip timeout" "600" "$CFG_TIMEOUT"
    assert_eq "roundtrip method" "aes-128-gcm" "$CFG_METHOD"
    assert_eq "roundtrip mode" "udp_only" "$CFG_MODE"
    assert_eq "roundtrip fast_open" "true" "$CFG_FAST_OPEN"
    assert_eq "roundtrip plugin" "obfs-local" "$CFG_PLUGIN"
    assert_eq "roundtrip plugin_opts" "obfs=http;obfs-host=example.com" "$CFG_PLUGIN_OPTS"
}

test_parse_existing_config_no_plugin() {
    local outfile="${TMPDIR_TEST}/roundtrip_noplugin.json"

    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="simplepw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    # Reset and parse
    CFG_SERVER=""
    CFG_SERVER_PORT=""
    CFG_PASSWORD=""
    CFG_METHOD=""
    CFG_MODE=""
    CFG_PLUGIN="should_be_cleared_if_found"

    parse_existing_config "$outfile"

    assert_eq "roundtrip-noplugin server" "0.0.0.0" "$CFG_SERVER"
    assert_eq "roundtrip-noplugin port" "8388" "$CFG_SERVER_PORT"
    assert_eq "roundtrip-noplugin password" "simplepw" "$CFG_PASSWORD"
    assert_eq "roundtrip-noplugin method" "aes-256-gcm" "$CFG_METHOD"
    assert_eq "roundtrip-noplugin mode" "tcp_and_udp" "$CFG_MODE"
}

###############################################################################
# Tests: detect_os
###############################################################################

test_detect_os() {
    local os
    os=$(detect_os)
    # Should be one of the known values
    assert_match "detect_os returns known value" "^(linux|darwin|freebsd|openbsd|netbsd)$" "$os"
}

###############################################################################
# Tests: detect_arch
###############################################################################

test_detect_arch() {
    local arch
    arch=$(detect_arch)
    # Should be one of the known mapped values or raw uname -m
    assert_match "detect_arch returns a value" ".+" "$arch"
}

###############################################################################
# Tests: KNOWN_PLUGINS constant
###############################################################################

test_known_plugins_count() {
    assert_eq "KNOWN_PLUGINS has 4 entries" "4" "${#KNOWN_PLUGINS[@]}"
}

test_known_plugins_entries() {
    local found_simpleobfs=0 found_v2ray=0 found_xray=0 found_kcptun=0
    for p in "${KNOWN_PLUGINS[@]}"; do
        case "$p" in
            simple-obfs)    found_simpleobfs=1 ;;
            v2ray-plugin)   found_v2ray=1 ;;
            xray-plugin)    found_xray=1 ;;
            kcptun)         found_kcptun=1 ;;
        esac
    done
    assert_eq "KNOWN_PLUGINS has simple-obfs" "1" "$found_simpleobfs"
    assert_eq "KNOWN_PLUGINS has v2ray-plugin" "1" "$found_v2ray"
    assert_eq "KNOWN_PLUGINS has xray-plugin" "1" "$found_xray"
    assert_eq "KNOWN_PLUGINS has kcptun" "1" "$found_kcptun"
}

###############################################################################
# Tests: plugin_repo function
###############################################################################

test_plugin_repos() {
    assert_eq "plugin_repo simple-obfs" "shadowsocks/simple-obfs" "$(plugin_repo simple-obfs)"
    assert_eq "plugin_repo v2ray-plugin" "shadowsocks/v2ray-plugin" "$(plugin_repo v2ray-plugin)"
    assert_eq "plugin_repo xray-plugin" "teddysun/xray-plugin" "$(plugin_repo xray-plugin)"
    assert_eq "plugin_repo kcptun" "xtaci/kcptun" "$(plugin_repo kcptun)"
    assert_eq "plugin_repo unknown" "" "$(plugin_repo unknown)"
}

###############################################################################
# Tests: SS_SETUP_VERSION
###############################################################################

test_version_set() {
    assert_match "SS_SETUP_VERSION is semver" "^[0-9]+\.[0-9]+\.[0-9]+$" "$SS_SETUP_VERSION"
}

###############################################################################
# Tests: Config directory constant
###############################################################################

test_config_dir() {
    assert_eq "CONFIG_DIR" "/etc/shadowsocks-libev" "$CONFIG_DIR"
}

###############################################################################
# Tests: JSON output is valid (no trailing commas, booleans unquoted)
###############################################################################

test_json_no_trailing_comma() {
    local outfile="${TMPDIR_TEST}/no_trailing.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    # Check that the file doesn't have ",\n}" pattern (trailing comma)
    if grep -qP ',\s*\}' "$outfile" 2>/dev/null || grep -q ',$' "$outfile" 2>/dev/null; then
        # Try a more portable check
        local last_data_line
        last_data_line=$(grep -v '^[[:space:]]*[{}]' "$outfile" | tail -1)
        if [[ "$last_data_line" == *"," ]]; then
            FAIL=$((FAIL + 1))
            echo "FAIL: JSON has trailing comma on last data line: ${last_data_line}" >&2
        else
            PASS=$((PASS + 1))
        fi
    else
        PASS=$((PASS + 1))
    fi
}

test_json_booleans_unquoted() {
    local outfile="${TMPDIR_TEST}/bool_check.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="true"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_not_contains "boolean not quoted string" '"fast_open": "true"' "$content"
    assert_contains "boolean is unquoted true" '"fast_open": true' "$content"
}

test_json_integers_unquoted() {
    local outfile="${TMPDIR_TEST}/int_check.json"
    CFG_SERVER="0.0.0.0"
    CFG_SERVER_PORT="8388"
    CFG_PASSWORD="pw"
    CFG_TIMEOUT="300"
    CFG_METHOD="aes-256-gcm"
    CFG_MODE="tcp_and_udp"
    CFG_FAST_OPEN="false"
    CFG_PLUGIN=""
    CFG_PLUGIN_OPTS=""

    write_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "server_port is unquoted int" '"server_port": 8388' "$content"
    assert_not_contains "server_port not quoted string" '"server_port": "8388"' "$content"
    assert_contains "timeout is unquoted int" '"timeout": 300' "$content"
    assert_not_contains "timeout not quoted string" '"timeout": "300"' "$content"
}

###############################################################################
# Tests: Client JSON integers unquoted
###############################################################################

test_client_json_integers_unquoted() {
    local outfile="${TMPDIR_TEST}/client_int_check.json"
    CFG_CLIENT_SERVER="1.2.3.4"
    CFG_CLIENT_SERVER_PORT="443"
    CFG_CLIENT_LOCAL_PORT="1080"
    CFG_CLIENT_PASSWORD="pw"
    CFG_CLIENT_METHOD="aes-256-gcm"
    CFG_CLIENT_PLUGIN=""
    CFG_CLIENT_PLUGIN_OPTS=""

    write_client_json_config "$outfile"

    local content
    content=$(cat "$outfile")

    assert_contains "client server_port unquoted" '"server_port": 443' "$content"
    assert_contains "client local_port unquoted" '"local_port": 1080' "$content"
    assert_contains "client timeout unquoted" '"timeout": 300' "$content"
}

###############################################################################
# Run all tests
###############################################################################

echo "Running ss-setup unit tests..."
echo

# Constants
test_aead_ciphers_count
test_aead_ciphers_contains_chacha20
test_aead_ciphers_contains_aes256gcm
test_aead_ciphers_contains_aes128gcm
test_known_plugins_count
test_known_plugins_entries
test_plugin_repos
test_version_set
test_config_dir

# Validation
test_validate_port_valid
test_validate_port_invalid

test_validate_instance_name_valid
test_validate_instance_name_invalid

# Password generation
test_generate_password_nonempty
test_generate_password_length
test_generate_password_no_newlines
test_generate_password_different

# Random port
test_generate_random_port_range
test_generate_random_port_numeric

# JSON escaping
test_json_escape_plain
test_json_escape_quotes
test_json_escape_backslash
test_json_escape_tab
test_json_escape_newline
test_json_escape_empty

# URL encoding
test_urlencode_plain
test_urlencode_space
test_urlencode_special
test_urlencode_semicolon
test_urlencode_safe_chars
test_urlencode_empty

# ss:// URI
test_ss_uri_basic
test_ss_uri_with_plugin
test_ss_uri_with_plugin_no_opts
test_ss_uri_base64_encoding

# Server JSON config
test_write_json_config_basic
test_write_json_config_fast_open_true
test_write_json_config_with_plugin
test_write_json_config_with_plugin_no_opts
test_write_json_config_password_special_chars

# Client JSON config
test_write_client_json_config_basic
test_write_client_json_config_with_plugin
test_client_json_integers_unquoted

# Parse existing config (round-trip)
test_parse_existing_config_roundtrip
test_parse_existing_config_no_plugin

# Platform detection
test_detect_os
test_detect_arch

# JSON validity
test_json_no_trailing_comma
test_json_booleans_unquoted
test_json_integers_unquoted

echo
echo "================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
