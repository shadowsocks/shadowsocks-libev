# Outer-transport experiments

These Python prototypes extend the printable-salt investigation. They wrap the
TCP ciphertext of unchanged Shadowsocks peers. They are research fixtures, not
production plugins. Both endpoints need a matching relay; UDP is not wrapped.
The original `--printable-salt` flag remains a separate, disabled-by-default,
wire-compatible client option.

Base64 has been dropped from the active experiments. Earlier measurements are
retained unchanged in the historical report linked below.

## Candidates and tradeoffs

| Mode | Transformation | Bulk expansion | Main observable property |
|---|---|---:|---|
| raw | Transparent relay control | 0% | Ordinary Shadowsocks ciphertext |
| printable salt | Random 6–12-byte printable prefix, tested separately | 0% | First six bytes always printable |
| Base85 | Base85 records with newline separators | About 25.01% | Wider printable alphabet |
| lowpop85 | Base85 symbols mapped to 85 low-popcount byte values | About 25.01% | Restricted alphabet, mostly zero bits |
| TLS | Verified TLS 1.3 with two-byte inner record lengths | Variable; handshake plus TLS records | Actual OpenSSL TLS handshake and record behavior |

The bulk expansion figures include delimiters/padding for 16 KiB input records.
Small writes have proportionally more framing overhead. EOF is represented by
an empty encoded record, allowing TCP half-close through the relays. Base85 records preserve every ciphertext byte. The low-popcount mapping is public and
reversible; its symbols have at most three set bits, with `0xff` as a separator.
It is a simple baseline, **not** the keyed bit-shuffling construction from the
[modified-Shadowsocks implementation](https://gfw.report/blog/modified_shadowsocks/en/).

Base85 and lowpop85 have about `log2(85) = 6.41` bits per symbol. None destroys information or
makes the underlying encryption weaker merely by encoding it. Conversely,
lower byte entropy does not establish lower detectability: these encodings have
recognizable alphabets. A capable classifier can decode them or learn their
patterns. The low-popcount variant is particularly easy to distinguish from
uniform bytes.

TLS uses a fresh, short-lived experiment certificate, verified by the client,
with hostname `experiment.invalid`. It is genuine TLS, not a fabricated TLS
prefix. It does not imitate a browser or carry HTTP, and the self-signed
certificate and OpenSSL handshake can themselves be fingerprinted. No existing
server certificate, key, or service is reused or modified.

## Local screening

```sh
python3 tests/experiments/test_transport.py
python3 tests/experiments/benchmark.py \
  --output build-artifacts/printable-salt/encoding-screen.json
python3 tests/experiments/local_interop.py --bin build-printable-stock/bin \
  --output build-artifacts/printable-salt/encoding-local-interop.json
```

The tests cover fragmented and coalesced records, malformed/truncated input,
record size limits, half-close (including TLS), certificate verification,
concurrency, and empty readiness connections.
Local interoperability exercises all four relay modes around an independently
built stock server/client pair, with both supported ciphers, concurrent payloads
from one byte to one MiB, and a verified ten MiB bidirectional transfer.

The synthetic benchmark uses uniform random bytes as a ciphertext model. It
measures byte histograms, popcount, expansion, and encode/decode speed, and checks
2,000 independent 100-byte samples per mode against the four published
[historical byte-statistic exemptions](https://gfw.report/publications/usenixsecurity23/en/).
Those classifier results are simulated, not observed firewall decisions.
These timings measure the Python prototypes, not the inherent speed of each format.

## Route screening

After verifying SSH trust, route, unused ports, available disk, and server health:

```sh
python3 tests/experiments/route_screen.py \
  --host root@SERVER --host-key-alias VERIFIED_KNOWN_HOST \
  --address SERVER_IPV4 --stock-bin build-printable-stock/bin/ss-local \
  --ports 32220 32221 32222 32223 \
  --output build-artifacts/printable-salt/encoding-route-v2
python3 tests/experiments/analyze.py \
  build-artifacts/printable-salt/encoding-route-v2
```

The protocol is saved before outcomes are observed. Four two-minute phases rotate
each mode over every port. Each mode attempts a verified one KiB transfer every
five seconds, plus one ten MiB transfer per phase: 100 transfers per mode, 400 in
total. Raw mode traverses the same relay architecture, providing a control for
Python relay overhead. The backend is one unchanged stock server using
`chacha20-ietf-poly1305`; all phases use fresh test credentials from the same run.

Server-local clients verify each entire relay/crypto path at phase start and
every 30 seconds. Management or local-control failure aborts the run. Ports and
listeners are isolated; no firewall rule or production service is changed.
A remote watchdog bounds the supervisor lifetime; a 60-second control-command
timeout also stops it if a broken SSH path never delivers EOF. Cleanup stops owned processes,
removes private configs and certificate keys, and retrieves captures.

Captures include full experiment packets and the SSH control flow. They contain
address metadata and are kept in a private output directory. The analyzer reports
first-arriving payloads separately from payloads at the TCP stream start: packet
reordering can make these differ. It also separates other source addresses from
the test client and looks for exact replayed opening payloads. A matching replay
from another address is evidence of replay traffic, not sufficient attribution
to a particular actor. A lack of observed probes is not proof of resistance.

Performance figures are end-to-end echo timings with concurrent traffic sharing
the same route and a small server. TLS includes a fresh connection handshake.
Small-transfer completion time is the latency metric; local SOCKS handshake time
is not remote RTT. Bulk throughput counts payload bytes once, though the echo
moves them in both directions. An eight-minute all-success result establishes only
short-run compatibility and measured prototype performance. It cannot establish
long-term censorship resistance or a speed advantage from a small sample.

Recorded results: [2026-09-23 measurements and limitations](measurements/printable-salt-2026-09-23/README.md).
