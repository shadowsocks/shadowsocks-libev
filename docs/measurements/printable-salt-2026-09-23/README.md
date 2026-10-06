# Printable salt and outer-transport results — 2026-09-23

## Conclusion

The opt-in printable-salt implementation is interoperable and adds no framing
bytes. Base64, Base85, low-popcount encoding, and verified TLS prototypes also
transferred data successfully around unchanged Shadowsocks peers.

**Neither planned field trial completed.** Both stopped on loss of the direct
SSH management path. All recorded transfer outcomes succeeded, including the
raw controls, so there is **no demonstrated availability or censorship-resistance
advantage**. Some in-flight outcomes could be omitted by the logger at abort;
these are not counted as successes. The logger was subsequently fixed.

Three unsolicited exact replays were captured against raw Shadowsocks openings,
including raw traffic on two different ports in the rotated experiment. None
were observed against printable-salt or outer-transport openings in these
captures. This is a limited observation of replay traffic, not attribution to
the GFW or proof of protection. The original acceptance criterion—modified
traffic repeatedly succeeding while stock fails, including after crossover—was
not met.

## Environment and reproducibility

- Direct Mac `en0` route; the proxy-free address lookup reported China Mobile,
  Anhui. The Singapore server saw the same mainland source address.
- All measurement child processes had proxy environment variables removed.
- Base source: `d52ddf2bcee97d799c74f54bf63533351a05324c`.
  An independent `git archive` checkout was built before edits.
- Local stock and modified C builds: Release, system dependencies, macOS arm64.
  Remote peer: unchanged shadowsocks-rust 1.24.0, Linux x86-64.
- Remote stock binary SHA-256:
  `bbb26b41ad6ef40fd9a9ab399009ddff14ec22b1a04b77288671d9fa50dd9b06`.
- Fresh credentials, isolated temporary listeners, loopback-only echo origins,
  no firewall changes, and no production service changes.
- [Salt reproduction](../../printable-salt.md) and
  [outer-transport reproduction](../../encoding-experiments.md).

## Local validation

Regular and sanitizer CMake/CTest builds passed **25/25** tests each. The suite
includes first-write/empty-write behavior, exact framing overhead, salt-tail
preservation, byte-fragmented decryption, tampering, replay rejection, CLI cipher
validation, enabled interoperability, and experiment supervisor cleanup.

Independent stock-C and Rust interoperability passed for both supported ciphers.
Default TCP/UDP interoperability passed for all six AEAD/AEAD-2022 methods.
The repository's 10 MiB stress tests passed for all three standard AEAD ciphers.
Python lint, CLI documentation checks, and documentation unit tests passed.

Loopback packet captures checked 32 enabled and 32 disabled connections per
cipher. All 64 enabled first transmitted payloads began with six printable
bytes; none of the 64 disabled samples happened to do so. All payloads followed
the observed SYN sequence correctly. See [packet results](local-packets.json).

All five outer-relay modes passed local testing with both ciphers: four
concurrent transfers per case and a verified 10 MiB echo transfer. Codec tests
cover fragmentation, coalescing, malformed records, size limits, concurrency,
empty readiness connections, half-close, and TLS certificate verification.
Supervisor tests verify real backend/listener cleanup after EOF, silence, and
termination. See [local results](local-transports.json).

## Salt field trial: aborted before crossover

Planned: two 30-minute phases, swapping stock/modified clients between ports
32181 and 32182; a one KiB transfer every five seconds plus ten 10 MiB transfers
per mode per phase.

Observed: approximately 16 minutes, from 10:20:21 UTC until cleanup at 10:36:30.
Each mode recorded **197 successful outcomes**: 191 small and six large transfers.
All 32 completed health checks passed, including verified server-local transfers.
The next control exchange failed when SSH stopped responding. No port crossover
was reached. Median small-transfer completion times were 173.4 ms stock and
172.6 ms modified. Large-transfer medians were 23.89 and 27.25 Mbps respectively;
these six samples under shared load do not establish a speed difference.

Both endpoint captures confirm 197 legitimate transmitted openings per mode.
All 197 modified openings had the required first-packet prefix. A different
source replayed a stock opening's entire 79 bytes **3.109 seconds** later. The
server sent no application bytes in that replay connection; this alone does not
prove replay rejection, because the opening contained only a destination header.
Replay rejection is separately tested in the crypto unit tests.

[Sanitized summary](salt-aborted.json) · [recorded events](salt-events.jsonl).

## Outer-transport field trial: interrupted fourth rotation

Planned: five two-minute phases across five ports; every mode visits every port,
with 24 small transfers and one 10 MiB transfer per phase. The raw control uses
the same Python relay architecture. Server-local controls exercise each complete
relay/crypto path at every phase start and every 30 seconds.

Observed: three complete phases and part of the fourth, starting 10:43 UTC and
aborting at 10:50:53 UTC. All 19 completed health checkpoints passed. Values below
are **recorded outcomes**, not a claim that every scheduled or in-flight attempt
completed. Four large transfers per mode were recorded. Timings include shared
route/server load and concurrent bulk traffic; tail latency is substantial.

| Mode | Recorded success | Small median ms | Small p95 ms | Large median Mbps |
|---|---:|---:|---:|---:|
| raw | 92/92 | 182.7 | 2646.3 | 12.73 |
| base64 | 93/93 | 181.2 | 2382.5 | 5.42 |
| base85 | 92/92 | 186.9 | 2382.6 | 4.11 |
| lowpop85 | 92/92 | 197.5 | 2383.1 | 3.79 |
| tls | 92/92 | 280.9 | 3078.0 | 4.80 |

The full endpoint captures match these recorded connection counts. All encoded
client openings meet a published historical byte-statistic exemption; only one
of 92 raw openings does. This is evaluation of captured bytes against historical
rules, not an observation that a firewall applied those rules.

At the server, three TLS connections had later TCP data arrive before the stream
start. Their first-arriving payload did not match the historical exemptions;
the eventual stream-start payload did. This is why packet arrival and application
write boundaries must not be conflated.

Two other source addresses replayed exact 79-byte raw openings, one on port
32220 in phase one after **3.930 seconds**, and one on port 32223 in phase four
after **0.936 seconds**. No equivalent replay was observed for the other modes.
The low counts and incomplete rotation prevent a strong comparative conclusion.

[Sanitized summary](encoding-aborted.json) · [recorded events](encoding-events.jsonl).
Short calibration runs and the superseded run containing empty readiness
connections remain in the private artifact directory and are excluded above.

## SSH failure and cleanup

The client capture's last SSH request found in the server capture was sent at
10:50:38.585912 UTC. Starting at **10:50:43.584421 UTC**, ten captured client SSH
payload packets, including retransmissions, were absent from the server capture.
Both captures reported zero kernel capture drops. This supports forward-path
loss for the management connection; it does not identify the cause or actor.
See [packet comparison](ssh-path.json).

Fresh direct SSH connections also temporarily timed out. Recovery through the
existing local HTTP proxy reached the healthy server from a different egress IP.
That alternate route was used only for recovery and cleanup, not measurements.
Direct SSH subsequently recovered. The retrieved server capture's SHA-256
matched the remote file:
`4c86092fe8b7ca6dcdd77c5e4017c937d28a8d2ded9fba07d75d5786c6db2477`.

All experimental processes/listeners, temporary remote files and certificate
keys were removed. Original TCP/UDP listeners remained unchanged. No temporary
firewall rules were created. Raw captures, build hashes, test logs, recovery
verification, and reproduction helpers are retained locally under
`build-artifacts/printable-salt/` (not committed).

The failed control connection exposed two harness limitations, now fixed:
remote cleanup now has a 60-second control-message deadline in addition to its
lifetime watchdog, and transfer workers persist outcomes directly rather than
waiting for the control loop to collect them. These fixes were validated locally;
no further live load was started after the second management failure.

## Encoding tradeoff

The synthetic benchmark found bulk expansion of 33.36% for Base64 and 25.01% for
Base85/lowpop85. Their empirical symbol entropies were about 6.00 and 6.41 bits per
byte; lowpop85 averaged 2.44 one-bits per byte. Every transformed 100-byte sample
passed at least one historical exemption, versus five of 2,000 raw samples.
See [synthetic measurements](synthetic-encodings.json).

These encodings retain all ciphertext information while introducing recognizable
alphabets. Printable salt is cheapest but imposes a fixed printable property on
the first six bytes. TLS uses a real protocol but adds connection setup and has
its own handshake/certificate fingerprint. The measurements do not justify
selecting any candidate as a proven censorship-resistant transport.
