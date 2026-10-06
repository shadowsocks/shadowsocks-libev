#!/usr/bin/env python3
"""Exercise each outer transport around independently built stock Shadowsocks."""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from interop import TCPHandler, TCPOrigin, free_port, peers, tcp_case  # noqa: E402
from transport import MODES  # noqa: E402


def certificate(directory):
    cert, key = directory / 'certificate.pem', directory / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '1', '-subj', '/CN=experiment.invalid',
                    '-addext', 'subjectAltName=DNS:experiment.invalid'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return cert, key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    binary = Path(args.bin).resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='ss-encoding-') as temp, TCPOrigin(('127.0.0.1', 0), TCPHandler) as origin:
        cert, key = certificate(Path(temp))
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for method in ('chacha20-ietf-poly1305', 'aes-256-gcm'):
                for mode in MODES:
                    server, remote, bridge, local = [free_port() for _ in range(4)]
                    common = [sys.executable, str(Path(__file__).with_name('transport.py')), '--mode', mode]
                    commands = [
                        [str(binary / 'ss-server'), '-s', '127.0.0.1', '-p', str(server), '-m', method, '-k', 'local-encoding-test'],
                        common + ['--role', 'server', '--listen-port', str(remote), '--target-port', str(server),
                                  '--certificate', str(cert), '--key', str(key)],
                        common + ['--role', 'client', '--listen-port', str(bridge), '--target-port', str(remote),
                                  '--certificate', str(cert)],
                        [str(binary / 'ss-local'), '-s', '127.0.0.1', '-p', str(bridge), '-l', str(local), '-m', method, '-k', 'local-encoding-test'],
                    ]
                    with peers(commands, [server, remote, bridge, local]):
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                            pending = [pool.submit(tcp_case, local, origin.server_address[1], size)
                                       for size in (1, 16383, 65536, 1048576)]
                            for task in pending:
                                task.result(timeout=30)
                        start = time.monotonic()
                        tcp_case(local, origin.server_address[1], 10 * 1024 * 1024)
                        duration = time.monotonic() - start
                    result = dict(mode=mode, cipher=method, concurrent_transfers=4, success=True,
                                  large_bytes=10 * 1024 * 1024, large_seconds=duration,
                                  echo_mbps=10 * 1024 * 1024 * 8 / duration / 1e6)
                    results.append(result)
                    print(json.dumps(result), flush=True)
        finally:
            origin.shutdown()
    Path(args.output).write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
