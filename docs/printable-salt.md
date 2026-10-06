# Experimental printable TCP salt

`ss-local --printable-salt` chooses a prefix length uniformly from 6–12 bytes
for each outgoing TCP salt, then replaces that prefix with independent, uniformly
sampled printable ASCII bytes (`0x20`–`0x7e`).
It is disabled by default and accepts only `chacha20-ietf-poly1305` and
`aes-256-gcm`, including when the cipher comes from a configuration file or URL.
Other ciphers fail at startup. Enable it with the CLI flag or the
`printable_salt` configuration key; either one turns it on, and the key is
ignored by the other binaries.

```sh
ss-local -c client.json --printable-salt
```

```json
{ "server": "example.com", "server_port": 8388, "password": "...",
  "method": "chacha20-ietf-poly1305", "printable_salt": true }
```

The salt remains 32 bytes. The remaining 20–26 bytes retain their original secure
random values. Length sampling uses libsodium `6 + randombytes_uniform(7)`;
character sampling uses `randombytes_uniform(95)` immediately
before key derivation and transmission on the first nonempty TCP encryption call.
Empty writes do not consume the salt; later writes do not change it. For a selected length `L`, the conditional salt entropy
is `(32 - L) * 8 + L * log2(95)`, at least **238.84 bits** (at `L = 12`).
This is also a conservative min-entropy bound for the mixture; the random length
is not an independent secret field whose entropy can simply be added. Salt uniqueness
remains essential. There are no extra framing bytes, messages, or round trips.

UDP salt generation, server responses, authenticated framing, replay rejection,
and AEAD-2022 are unchanged. No SIP003 plugin or fixed protocol marker is added.
This is not TLS impersonation, nor a promise of censorship resistance.

The prefix introduces a statistical fingerprint: every enabled connection starts
with six printable bytes, versus `(95 / 256)^6`, approximately 0.26%, for a
uniformly random salt. The bytes vary independently, but the printable property
is fixed. The constrained span now varies; the untouched tail may also start
with printable bytes, so there is no explicit boundary marker. The 6–12 range
is an experimental tradeoff, not an optimized or measured defense. Increasing
the span can strengthen other ASCII statistics even as the boundary varies. A classifier could combine it with subsequent encrypted bytes, packet
lengths, endpoint information, or probing. High salt entropy does not imply low
detectability.

## Rationale and limits

The [USENIX Security 2023 study](https://gfw.report/publications/usenixsecurity23/en/)
reported an exemption for six leading printable bytes in the first TCP payload.
Its [follow-up](https://github.com/gfw-report/usenixsecurity23-artifact) reports that
the measured dynamic blocking stopped in March 2023. This is historical evidence;
present-day behavior must be measured on the route of interest.
[Outline prefixing](https://developer.getoutline.org/vpn/advanced/prefixing/)
provides related deployment precedent. The
[AEAD specification](https://shadowsocks.org/doc/aead.html) describes salt-based
key derivation and the requirement for unique salts.

An application write does not determine TCP packet boundaries. Packet captures
must establish whether the actual first transmitted payload contains all six
bytes. This experiment does not establish protection against every active probe,
long-term blocking, or other classifiers.

## Local reproduction

Build an independent stock checkout from the base revision before applying this
change, then configure/build this branch with the same toolchain:

```sh
cmake -S . -B build-printable -G Ninja -DSS_DEPENDENCY_MODE=system \
  -DWITH_STATIC=OFF -DWITH_DOC_MAN=OFF -DWITH_DOC_HTML=OFF
cmake --build build-printable --parallel
ctest --test-dir build-printable --output-on-failure
python3 tests/interop.py --self --bin build-printable/bin \
  --server-bin build-printable-stock/bin/ss-server --printable-salt
python3 tests/interop.py --bin build-printable/bin --printable-salt
python3 tests/interop.py --self --bin build-printable/bin
python3 tests/stress_test.py --bin build-printable/bin --size 10
uvx ruff==0.15.6 check --select E9,F63,F7,F82 tests scripts
python3 scripts/check_cli_docs.py
python3 -m unittest discover -s tests -p test_cli_docs.py
```

The crypto tests exercise disabled/enabled behavior, empty first writes, unchanged
salt tails, exact framing length, subsequent writes, byte-at-a-time decryption,
tampering, and replay rejection. CLI tests check cipher rejection and local-only
exposure. Interoperability tests verify concurrent bidirectional TCP and UDP;
the default full suite covers all supported AEAD-2022 variants too.

## Route experiment

`tests/printable_salt_experiment.py` runs two 30-minute phases against isolated
instances of a stock remote `ssserver`. It requires Linux with Python, tcpdump,
`/usr/local/bin/ssserver` and `/usr/local/bin/sslocal`, verified SSH host trust,
two unused reachable high ports, and local passwordless access to tcpdump through
sudo. Inspect listeners and firewall rules first. The runner does not modify
firewalls or existing services. Its remote echo origin binds to loopback only.

```sh
python3 tests/printable_salt_experiment.py \
  --host root@SERVER --host-key-alias VERIFIED_KNOWN_HOST \
  --address SERVER_IPV4 --interface en0 \
  --stock-bin build-printable-stock/bin/ss-local \
  --modified-bin build-printable/bin/ss-local \
  --ports 32181 32182 --output build-artifacts/printable-salt/route
python3 tests/check_printable_pcap.py \
  build-artifacts/printable-salt/route/client.pcap --ports 32181 32182 \
  --events build-artifacts/printable-salt/route/events.jsonl
```

Fresh credentials are generated for each run. Proxy environment variables are
removed from child processes. Clients swap server ports between phases. Each
mode attempts a verified 1 KiB echo transfer every five seconds and ten 10 MiB
echo transfers per phase. Upload and download run concurrently. Every 30 seconds,
an SSH round trip verifies management health, process health, local listeners,
and a verified transfer through each server using server-local stock clients.
The run stops on a failed health check. Remote processes have a 65-minute watchdog
and are stopped when their controlling SSH input closes or no control command
arrives for 60 seconds. Normal cleanup removes
experimental processes and temporary configs and retrieves packet captures.

JSONL results record transfer success, error/timeout/reset messages, integrity
failures, elapsed time, and effective payload throughput. `socks_handshake_ms` is
local SOCKS setup time, **not** remote connection latency. Use small-transfer
completion time for an end-to-end latency measure. Throughput is one-way payload
bytes divided by bidirectional echo completion time; it is not link capacity.
Large tests share the route with each other and the scheduled small tests.

Captures use a 160-byte snapshot to retain TCP headers and salt prefixes while
limiting size. Both packet captures and the raw results remain in a private local
output directory; do not publish raw captures without reviewing address metadata.
The packet checker accepts a first payload only after observing its SYN, checks
its sequence number, and evaluates bytes in the packet itself.

Call a result promising only when modified traffic repeatedly succeeds while
stock traffic fails, including after crossover, with healthy server-local
controls. Persistent port blocking makes crossover inconclusive. If both work,
report compatibility and measured performance only. If both fail, investigate
captured failures before choosing another modification. A one-hour run cannot
establish long-term GFW resistance.

## Additional experiments

See [outer-transport experiments](encoding-experiments.md) for Base85,
low-popcount encoding, and verified TLS prototypes. These require matching relays
at both endpoints and are separate from the production CLI flag.

Recorded results: [2026-09-23 measurements and limitations](measurements/printable-salt-2026-09-23/README.md).

The archived 2026-09-23 measurements used the original fixed six-byte prefix.
They do not evaluate this variable-length revision.
