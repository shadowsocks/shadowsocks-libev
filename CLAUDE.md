# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

shadowsocks-libev is a lightweight SOCKS5 proxy written in pure C. Version 3.3.6, licensed under GPLv3.

## Build Commands

### CMake (sole build system)

```bash
git submodule update --init --recursive
mkdir -p build && cd build
cmake ..
make
sudo make install
```

On macOS, CMake should auto-detect library paths. If needed, specify paths:
```bash
cmake .. -DCMAKE_PREFIX_PATH="/usr/local/opt/mbedtls;/usr/local/opt/libsodium"
```

CMake outputs binaries to `build/bin/` (static) and `build/shared/bin/` (shared).

### Build Dependencies

- cmake (>= 3.2), a C compiler (gcc or clang), pkg-config
- libmbedtls, libsodium (>= 1.0.4), libpcre3, libev, libc-ares
- asciidoc + xmlto (documentation only)

### CMake Options

- `-DWITH_EMBEDDED_SRC=OFF`: use system libcork/libipset/libbloom instead of bundled submodules
- `-DWITH_DOC_MAN=OFF`: skip man page generation
- `-DENABLE_CONNMARKTOS=ON`: Linux netfilter conntrack QoS support
- `-DENABLE_NFTABLES=ON`: nftables firewall integration
- `-DDISABLE_SSP=ON`: disable stack protector
- `-DBUILD_TESTING=OFF`: disable unit tests

## Testing

### Unit Tests (CTest)

```bash
cd build
ctest --output-on-failure
```

10 unit test modules cover: base64, buffer, crypto, json, jconf, cache, ppbloom, rule, netutils, utils.

### Integration Tests

Integration tests use Python and require `curl` and `dig` to be available:
```bash
bash tests/test.sh
```

The test harness (`tests/test.py`) starts ss-server, ss-local, and ss-tunnel locally, then runs curl through the SOCKS5 proxy and dig through the tunnel. Each test config in `tests/*.json` exercises a different cipher.

Run a single cipher test:
```bash
python tests/test.py --bin build/bin/ -c tests/aes-gcm.json
```

## Code Formatting

Uses **uncrustify** with the config at `.uncrustify.cfg`. Key settings: 4-space indent, no tabs, 120-column width, K&R brace style (braces on same line).

## Architecture

### Binaries (all in `src/`)

Each binary is compiled with a module define that controls conditional compilation:

| Binary | Define | Purpose |
|---|---|---|
| `ss-local` | `MODULE_LOCAL` | SOCKS5 client proxy |
| `ss-server` | `MODULE_REMOTE` | Server-side proxy |
| `ss-tunnel` | `MODULE_TUNNEL` | Port forwarding tunnel (implies `MODULE_LOCAL`) |
| `ss-redir` | `MODULE_REDIR` | Transparent proxy via iptables (Linux only, implies `MODULE_LOCAL`) |
| `ss-manager` | `MODULE_MANAGER` | Multi-server manager daemon |

A shared library `libshadowsocks-libev` is also built from the ss-local sources with `-DLIB_ONLY`. Its public API is in `src/shadowsocks.h`.

### Source Organization (`src/`)

**Shared by all binaries:**
- `utils.c` - logging, system utilities
- `jconf.c` / `json.c` - JSON config file parsing
- `netutils.c` - network address utilities
- `cache.c` - hash-based LRU connection cache
- `udprelay.c` - UDP relay implementation (shared, but uses `#ifdef MODULE_*` for per-binary behavior)

**Crypto layer** (two parallel implementations behind a common `crypto_t` interface):
- `crypto.c` / `crypto.h` - crypto initialization, key derivation (HKDF), buffer management. Defines `crypto_t` with function pointers for encrypt/decrypt.
- `stream.c` - stream cipher implementation (CFB mode via mbedTLS)
- `aead.c` - AEAD cipher implementation (AES-GCM via mbedTLS, ChaCha20-Poly1305 via libsodium)
- `ppbloom.c` - ping-pong bloom filter for nonce replay detection

**ACL (Access Control Lists):**
- `acl.c` / `rule.c` - IP/domain-based routing rules using libipset

**Plugin support:**
- `plugin.c` - SIP003 plugin subprocess management

### Bundled Submodules

Three git submodules in the repo root (can be replaced with system libs via `-DWITH_EMBEDDED_SRC=OFF`):
- `libcork/` - data structures (dllist, hash-table, buffers)
- `libipset/` - IP set operations for ACL
- `libbloom/` - bloom filter implementation

### Event Loop

All binaries use **libev** for async I/O. The connection lifecycle follows stages defined in `src/common.h`: `STAGE_INIT` -> `STAGE_HANDSHAKE` -> `STAGE_RESOLVE` -> `STAGE_STREAM` -> `STAGE_STOP`. Each binary defines its own `listen_ctx_t`, `server_t`, and `remote_t` structs (note: "server" in `local.h` means the local-side connection, "remote" means the ss-server side).

### Compiler Flags

Default flags from `CMakeLists.txt`: `-g -O2 -Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE`

The `-Werror` flag means all warnings are errors - new code must compile warning-free.
