#!/bin/bash
#
# Guest init script (PID 1) for ss-redir transparent proxy test.
# Runs inside a QEMU Alpine Linux VM.
#
# Flow:
#   1. Mount filesystems and load kernel modules
#   2. Configure networking (QEMU user-mode: guest 10.0.2.15, host 10.0.2.2)
#   3. Start ss-redir pointing at ss-server on the host
#   4. Run ss-nat to set up iptables REDIRECT rules
#   5. Test with curl through the transparent proxy
#   6. Print REDIR_TEST_PASS or REDIR_TEST_FAIL to serial console
#

set -e

# --- helpers ----------------------------------------------------------------

pass() {
    echo ""
    echo "========================================="
    echo "REDIR_TEST_PASS"
    echo "========================================="
    sync
    echo o > /proc/sysrq-trigger
    sleep 10
}

fail() {
    local msg="${1:-unknown error}"
    echo ""
    echo "========================================="
    echo "REDIR_TEST_FAIL: $msg"
    echo "========================================="
    sync
    echo o > /proc/sysrq-trigger
    sleep 10
}

# --- mount filesystems ------------------------------------------------------

mount -t proc     proc     /proc
mount -t sysfs    sysfs    /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /tmp /run
mount -t devpts   devpts   /dev/pts
mount -t tmpfs    tmpfs    /tmp
mount -t tmpfs    tmpfs    /run

# Enable sysrq for clean poweroff
echo 1 > /proc/sys/kernel/sysrq

echo "=== Guest init starting ==="

# --- load kernel modules ----------------------------------------------------

for mod in \
    virtio_net \
    ip_tables iptable_nat iptable_filter \
    nf_nat nf_conntrack \
    xt_REDIRECT xt_set xt_tcpudp \
    ip_set ip_set_hash_net; do
    modprobe "$mod" 2>/dev/null || echo "WARN: failed to load $mod (may be built-in)"
done

echo "=== Kernel modules loaded ==="

# --- configure network ------------------------------------------------------

# Find the non-lo network interface
IFACE=""
for f in /sys/class/net/*/type; do
    iface=$(basename "$(dirname "$f")")
    if [ "$iface" != "lo" ]; then
        IFACE="$iface"
        break
    fi
done

if [ -z "$IFACE" ]; then
    fail "no network interface found"
fi

echo "=== Using network interface: $IFACE ==="

ip link set lo up
ip link set "$IFACE" up
ip addr add 10.0.2.15/24 dev "$IFACE"
ip route add default via 10.0.2.2

# DNS (QEMU user-mode DNS forwarder)
echo "nameserver 10.0.2.3" > /etc/resolv.conf

# Wait for link to come up
sleep 2

# Connectivity check
echo "=== Checking connectivity to host ==="
if ! ping -c 2 -W 5 10.0.2.2; then
    fail "cannot reach host at 10.0.2.2"
fi

echo "=== Host reachable ==="

# --- start ss-redir ---------------------------------------------------------

echo "=== Starting ss-redir ==="
/usr/bin/ss-redir -c /etc/ss-redir.json -v &
SS_REDIR_PID=$!
sleep 3

if ! kill -0 "$SS_REDIR_PID" 2>/dev/null; then
    fail "ss-redir died immediately"
fi

echo "=== ss-redir running (PID $SS_REDIR_PID) ==="

# --- run ss-nat (set up iptables REDIRECT) ----------------------------------

echo "=== Running ss-nat ==="
if ! /usr/bin/ss-nat -s 10.0.2.2 -l 1080 -o; then
    fail "ss-nat failed"
fi

echo "=== ss-nat rules applied ==="

# Show iptables state for debugging
echo "=== iptables -t nat -L -n ==="
iptables -t nat -L -n 2>&1 || true
echo "=== ipset list ==="
ipset list 2>&1 || true

# --- test with curl ---------------------------------------------------------

echo "=== Testing transparent proxy with curl ==="

# Try multiple URLs for reliability (captive portal detection endpoints
# are lightweight and highly available)

# Test 1: Mozilla captive portal
echo "--- Test 1: detectportal.firefox.com ---"
BODY=$(curl -s --connect-timeout 15 -m 30 http://detectportal.firefox.com/success.txt 2>&1) || true
echo "Response: $BODY"
if echo "$BODY" | grep -q "success"; then
    echo "Test 1 PASSED"
    pass
fi

# Test 2: Google (expect redirect or 200)
echo "--- Test 2: www.google.com ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 15 -m 30 http://www.google.com/ 2>&1) || true
echo "HTTP code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "Test 2 PASSED"
    pass
fi

# Test 3: Apple captive portal
echo "--- Test 3: captive.apple.com ---"
BODY=$(curl -s --connect-timeout 15 -m 30 http://captive.apple.com/ 2>&1) || true
echo "Response: $BODY"
if echo "$BODY" | grep -qi "success"; then
    echo "Test 3 PASSED"
    pass
fi

# If we get here, all tests failed
fail "all curl tests failed"
