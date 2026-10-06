#!/usr/bin/env python3
"""Eight-minute, four-port Latin-square screening of experimental outer transports.

Run after the original salt crossover completes, on unused high ports. This is
compatibility/performance screening, not evidence of lasting censorship resistance.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import tempfile
import time
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from interop import free_port, peers  # noqa: E402
from printable_salt_experiment import transfer  # noqa: E402
from local_interop import certificate  # noqa: E402
from transport import MODES  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--host-key-alias', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--stock-bin', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--interface', default='en0')
    parser.add_argument('--ports', nargs=len(MODES), type=int, default=list(range(32200, 32200 + len(MODES))))
    parser.add_argument('--phase-seconds', type=int, default=120)
    parser.add_argument('--large-bytes', type=int, default=10 * 1024 * 1024)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (out / 'events.jsonl').exists():
        parser.error('use a fresh output directory')
    env = {key: value for key, value in os.environ.items() if not key.lower().endswith('_proxy')}
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o',
           'HostKeyAlias=' + args.host_key_alias, '-o', 'ConnectTimeout=8', '-o',
           'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', args.host]
    directory = subprocess.check_output(ssh + ['mktemp -d /tmp/ss-encoding.XXXXXXXX'], env=env, text=True).strip()
    root = Path(__file__).parent
    remote = capture = None
    log_lock = threading.Lock()
    def emit(record):
        record['utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        with log_lock, (out / 'events.jsonl').open('a') as output:
            output.write(json.dumps(record) + '\n')
    def measured_transfer(meta, proxy, origin, size):
        emit(dict(meta, event='attempt', size=size))
        result = transfer(proxy, origin, size)
        emit(dict(**meta, **result))
        return result
    def upload(name, content):
        subprocess.run(ssh + ['umask 077; cat > ' + shlex.quote(directory + '/' + name)],
                       input=content, check=True, env=env)
    def exchange(record):
        remote.stdin.write(json.dumps(record) + '\n')
        remote.stdin.flush()
        assert select.select([remote.stdout], [], [], 12)[0], 'management health timeout'
        line = remote.stdout.readline()
        assert line, 'remote supervisor stopped'
        return json.loads(line)
    # Persist the schedule before observing outcomes.
    (out / 'protocol.json').write_text(json.dumps(dict(modes=MODES, ports=args.ports,
        phases=len(MODES), phase_seconds=args.phase_seconds, small_interval_seconds=5,
        small_bytes=1024, large_per_phase=1, large_bytes=args.large_bytes,
        rotation=f'mode i uses port (i + phase_index) modulo {len(MODES)}',
        acceptance='screening only; all-success is compatibility, not censorship resistance'), indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='ss-encoding-cert-') as temporary:
        cert, key = certificate(Path(temporary))
        password = base64.b64encode(os.urandom(32)).decode()
        try:
            for name in ('transport.py', 'route_server.py'):
                upload(name, (root / name).read_bytes())
            upload('certificate.pem', cert.read_bytes())
            upload('key.pem', key.read_bytes())
            with (out / 'remote.log').open('w') as remote_log, (out / 'capture.log').open('w') as capture_log:
                remote = subprocess.Popen(ssh + ['python3 -u ' + shlex.quote(directory + '/route_server.py')],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=remote_log, text=True, env=env)
                ready = exchange(dict(ports=args.ports, password=password))
                assert ready['ready']
                capture = subprocess.Popen(['sudo', '-n', 'tcpdump', '-i', args.interface,
                    '-U', '-s', '0', '-w', str(out / 'client.pcap'), 'host ' + args.address +
                    ' and tcp and (' + ' or '.join('port ' + str(port) for port in args.ports) + ' or port 22)'],
                    stderr=capture_log, stdout=subprocess.DEVNULL, env=env, start_new_session=True)
                time.sleep(1)
                assert capture.poll() is None
                emit(dict(event='start', **ready))
                with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
                    for phase in range(len(MODES)):
                        mapping = [MODES[(index - phase) % len(MODES)] for index in range(len(MODES))]
                        health = exchange(dict(event='phase', modes=mapping))
                        emit(dict(event='phase_start', phase=phase + 1, port_modes=mapping, **health))
                        assert health['healthy'], 'server-local phase control failed'
                        commands, ports, proxies = [], [], []
                        for index, mode in enumerate(MODES):
                            bridge, proxy = free_port(), free_port()
                            port = args.ports[(index + phase) % len(MODES)]
                            commands.append([sys.executable, str(root / 'transport.py'), '--role', 'client',
                                '--mode', mode, '--listen-port', str(bridge), '--target-host', args.address,
                                '--target-port', str(port), '--certificate', str(cert)])
                            commands.append([str(Path(args.stock_bin).resolve()), '-s', '127.0.0.1',
                                '-p', str(bridge), '-b', '127.0.0.1', '-l', str(proxy), '-k', password,
                                '-m', 'chacha20-ietf-poly1305'])
                            ports.extend((bridge, proxy))
                            proxies.append((mode, proxy, port))
                        with peers(commands, ports, env):
                            start = time.monotonic()
                            pending = []
                            for tick in range((args.phase_seconds + 4) // 5):
                                time.sleep(max(0, start + tick * 5 - time.monotonic()))
                                if tick % 6 == 0:
                                    health = exchange(dict(event='health'))
                                    emit(dict(event='health', phase=phase + 1, **health))
                                    assert health['healthy'], 'server-local/management health failed'
                                for mode, proxy, port in proxies:
                                    for size in ([1024, args.large_bytes] if tick == 0 else [1024]):
                                        meta = dict(event='transfer', phase=phase + 1, tick=tick, mode=mode, port=port)
                                        pending.append((meta, pool.submit(measured_transfer, meta, proxy, ready['origin'], size)))
                                remaining = []
                                for meta, future in pending:
                                    if future.done():
                                        future.result()
                                    else:
                                        remaining.append((meta, future))
                                pending = remaining
                            for meta, future in pending:
                                future.result()
                            time.sleep(max(0, start + args.phase_seconds - time.monotonic()))
                        emit(dict(event='phase_complete', phase=phase + 1))
                emit(dict(event='complete'))
        except BaseException as error:
            emit(dict(event='aborted', reason=type(error).__name__ + ': ' + str(error).replace(password, '<redacted>')))
            raise
        finally:
            if remote is not None and remote.poll() is None:
                try:
                    remote.stdin.write(json.dumps(dict(event='stop')) + '\n')
                    remote.stdin.flush()
                    remote.wait(timeout=15)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    remote.terminate()
                    remote.wait(timeout=15)
            if capture is not None and capture.poll() is None:
                subprocess.run(['sudo', '-n', 'kill', '-INT', '--', '-' + str(capture.pid)], check=False)
                capture.wait(timeout=10)
            copied = True
            for name in ('server.pcap', 'capture.log'):
                with (out / ('remote-' + name)).open('wb') as output:
                    result = subprocess.run(ssh + ['cat ' + shlex.quote(directory + '/' + name)], stdout=output, env=env)
                    copied &= result.returncode == 0
            if copied:
                subprocess.run(ssh + ['rm -rf -- ' + shlex.quote(directory)], check=True, env=env)
            emit(dict(event='cleanup', remote_exit=remote.returncode if remote else None, captures_retrieved=copied))


if __name__ == '__main__':
    main()
