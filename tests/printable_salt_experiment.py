#!/usr/bin/env python3
"""One-hour two-port crossover. Requires previously verified SSH host trust.

Uses an existing stock ssserver (Rust) on the remote host, with isolated ports,
configs, echo origin and packet capture. Does not change firewall rules.
Results contain no password; captures/configs live in private directories.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import threading

from interop import peers, receive, socks

REMOTE = r'''
import contextlib, json, os, signal, socketserver, subprocess, sys, tempfile, threading, time
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            while True:
                data = self.request.recv(65536)
                if not data: break
                self.request.sendall(data)
        except OSError: pass
class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
cfg = json.loads(sys.stdin.readline())
processes = []
controls = []
def stop(*args): raise SystemExit()
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
with tempfile.TemporaryDirectory(prefix='ss-printable-') as tmp, contextlib.ExitStack() as stack:
    origin = stack.enter_context(Origin(('127.0.0.1', 0), Echo))
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        for port in cfg['ports']:
            path = tmp + '/' + str(port) + '.json'
            with open(path, 'w') as f:
                json.dump(dict(server='0.0.0.0', server_port=port,
                               password=cfg['password'], method='chacha20-ietf-poly1305',
                               mode='tcp_only'), f)
            log = stack.enter_context(open(tmp + '/' + str(port) + '.log', 'wb'))
            processes.append(subprocess.Popen(['/usr/local/bin/ssserver', '-c', path], stdout=log, stderr=log))
        for index, port in enumerate(cfg['ports']):
            import socket
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                local_port = reserve.getsockname()[1]
            path = tmp + '/control-' + str(port) + '.json'
            with open(path, 'w') as f:
                json.dump(dict(server='127.0.0.1', server_port=port,
                               local_address='127.0.0.1', local_port=local_port,
                               password=cfg['password'], method='chacha20-ietf-poly1305'), f)
            log = stack.enter_context(open(tmp + '/control-' + str(port) + '.log', 'wb'))
            processes.append(subprocess.Popen(['/usr/local/bin/sslocal', '-c', path], stdout=log, stderr=log))
            controls.append(local_port)
        capture = subprocess.Popen(['tcpdump', '-i', 'any', '-U', '-s', '160', '-w',
                                    cfg['capture'], 'tcp and (' + ' or '.join('port '+str(p) for p in cfg['ports']) + ')'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(capture)
        time.sleep(1)
        assert all(p.poll() is None for p in processes)
        print(json.dumps(dict(ready=True, origin=origin.server_address[1])), flush=True)
        # stdin closes if the controlling SSH process dies. Bound lifetime too.
        def watchdog():
            time.sleep(3900)
            os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=watchdog, daemon=True).start()
        import select
        while select.select([sys.stdin], [], [], 60)[0]:
            line = sys.stdin.readline()
            if not line or line.strip() == 'stop': break
            healthy = all(p.poll() is None for p in processes)
            import socket
            for port in cfg['ports']:
                try:
                    with socket.create_connection(('127.0.0.1', port), 2): pass
                except OSError: healthy = False
            # Verify each server locally through an independent Rust client.
            import struct
            def exact(sock, count):
                data = b''
                while len(data) < count:
                    part = sock.recv(count - len(data))
                    if not part: raise OSError('short control read')
                    data += part
                return data
            verified = []
            for port in controls:
                try:
                    with socket.create_connection(('127.0.0.1', port), 2) as sock:
                        sock.settimeout(2)
                        sock.sendall(bytes([5, 1, 0]))
                        assert exact(sock, 2) == bytes([5, 0])
                        sock.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1]) + struct.pack('!H', origin.server_address[1]))
                        head = exact(sock, 4)
                        assert head[:3] == bytes([5, 0, 0])
                        exact(sock, 6 if head[3] == 1 else 18)
                        payload = os.urandom(1024)
                        sock.sendall(payload)
                        assert exact(sock, 1024) == payload
                    verified.append(True)
                except (OSError, AssertionError):
                    verified.append(False)
            print(json.dumps(dict(healthy=healthy and all(verified), local_transfers=verified)), flush=True)
    finally:
        for p in reversed(processes):
            if p.poll() is None: p.send_signal(signal.SIGINT)
        for p in processes:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        origin.shutdown()
'''


def transfer(proxy, origin, size):
    start = time.monotonic()
    result = dict(size=size, success=False)
    try:
        sock, _ = socks(proxy, 1, ('127.0.0.1', origin))
        result['socks_handshake_ms'] = (time.monotonic() - start) * 1000
        payload = os.urandom(size)
        with sock, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            sock.settimeout(20)
            upload = pool.submit(sock.sendall, payload)
            assert receive(sock, size) == payload, 'integrity mismatch'
            upload.result(timeout=25)
        result['success'] = True
    except (OSError, AssertionError, TimeoutError) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    result['seconds'] = time.monotonic() - start
    result['mbps'] = size * 8 / result['seconds'] / 1e6 if result['success'] else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--host-key-alias', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--stock-bin', required=True)
    parser.add_argument('--modified-bin', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--interface', default='en0')
    parser.add_argument('--ports', nargs=2, type=int, default=[32181, 32182])
    parser.add_argument('--phase-seconds', type=int, default=1800)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (out / 'events.jsonl').exists():
        parser.error('use a fresh output directory')
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o',
           'HostKeyAlias=' + args.host_key_alias, '-o', 'ConnectTimeout=8',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', args.host]
    remote_dir = subprocess.check_output(ssh + ['mktemp -d /tmp/ss-printable-capture.XXXXXXXX'], env=env, text=True).strip()
    capture_path = remote_dir + '/server.pcap'
    password = base64.b64encode(os.urandom(32)).decode()
    local_capture = None
    remote = None
    log_lock = threading.Lock()
    def emit(record):
        record['utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        with log_lock, (out / 'events.jsonl').open('a') as f:
            f.write(json.dumps(record) + '\n')
    def measured_transfer(meta, proxy, origin, size):
        emit(dict(meta, event='attempt', size=size))
        result = transfer(proxy, origin, size)
        emit(dict(**meta, **result))
        return result
    try:
        remote_log = (out / 'remote.log').open('w')
        remote = subprocess.Popen(ssh + ['python3 -u -c ' + shlex.quote(REMOTE)], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=remote_log, text=True)
        remote.stdin.write(json.dumps(dict(ports=args.ports, password=password, capture=capture_path)) + '\n')
        remote.stdin.flush()
        ready = json.loads(remote.stdout.readline())
        assert ready['ready']
        origin = ready['origin']
        capture_log = (out / 'capture.log').open('w')
        local_capture = subprocess.Popen(['sudo', '-n', 'tcpdump', '-i', args.interface,
            '-U', '-s', '160', '-w', str(out / 'client.pcap'), 'host ' + args.address + ' and tcp and (' +
            ' or '.join('port ' + str(p) for p in args.ports) + ')'], stderr=capture_log, env=env, start_new_session=True)
        time.sleep(1)
        assert local_capture.poll() is None, 'local capture unavailable'
        emit(dict(event='start', ports=args.ports, phase_seconds=args.phase_seconds, origin=origin))
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for phase in (0, 1):
                commands = []
                local_ports = [32183, 32184]
                for mode, binary in enumerate((args.stock_bin, args.modified_bin)):
                    command = [str(Path(binary).resolve()), '-s', args.address, '-p', str(args.ports[mode ^ phase]),
                               '-b', '127.0.0.1', '-l', str(local_ports[mode]), '-k', password,
                               '-m', 'chacha20-ietf-poly1305']
                    if mode:
                        command.append('--printable-salt')
                    commands.append(command)
                with peers(commands, local_ports, env):
                    start = time.monotonic()
                    pending = []
                    for tick in range((args.phase_seconds + 4) // 5):
                        time.sleep(max(0, start + tick * 5 - time.monotonic()))
                        if tick % 6 == 0:
                            # Round-trip SSH is the management health control.
                            remote.stdin.write('health\n')
                            remote.stdin.flush()
                            import select
                            assert select.select([remote.stdout], [], [], 8)[0], 'management health timeout'
                            line = remote.stdout.readline()
                            assert line, 'management connection closed'
                            health = json.loads(line)
                            emit(dict(event='health', phase=phase + 1, **health))
                            assert health['healthy'], 'server health failed'
                        for mode, proxy in enumerate(local_ports):
                            sizes = [1024]
                            # Ten evenly spaced large transfers per phase/mode.
                            if tick in {int(i * (args.phase_seconds // 5) / 10) for i in range(10)}:
                                sizes.append(10 * 1024 * 1024)
                            for size in sizes:
                                meta = dict(event='transfer', phase=phase + 1, tick=tick,
                                            mode='modified' if mode else 'stock', port=args.ports[mode ^ phase])
                                pending.append((meta, pool.submit(measured_transfer, meta, proxy, origin, size)))
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
        if remote is not None:
            if remote.poll() is None:
                try:
                    remote.stdin.write('stop\n')
                    remote.stdin.flush()
                    remote.wait(timeout=15)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    remote.terminate()
                    remote.wait(timeout=15)
            remote_log.close()
        if local_capture is not None:
            subprocess.run(['sudo', '-n', 'kill', '-INT', '--', '-' + str(local_capture.pid)], check=False)
            local_capture.wait(timeout=10)
            capture_log.close()
        # Keep the remote capture if retrieval fails.
        with (out / 'server.pcap').open('wb') as f:
            copied = subprocess.run(ssh + ['cat ' + shlex.quote(capture_path)], stdout=f, env=env)
        if copied.returncode == 0:
            subprocess.run(ssh + ['rm -rf -- ' + shlex.quote(remote_dir)], check=True, env=env)
        emit(dict(event='cleanup', remote_exit=remote.returncode if remote else None,
                  capture_retrieved=copied.returncode == 0))


if __name__ == '__main__':
    main()
