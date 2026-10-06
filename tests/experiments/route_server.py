#!/usr/bin/env python3
"""Private remote supervisor for route_screen.py; JSON commands on SSH stdin."""
import asyncio
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile

from transport import serve


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


async def echo(reader, writer):
    try:
        while data := await asyncio.wait_for(reader.read(65536), 30):
            writer.write(data)
            await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


def stop(processes):
    for process in reversed(processes):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


async def check_control(port, origin_port):
    writer = None
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        writer.write(bytes([5, 1, 0]))
        await writer.drain()
        assert await reader.readexactly(2) == bytes([5, 0])
        writer.write(bytes([5, 1, 0, 1, 127, 0, 0, 1]) + origin_port.to_bytes(2, 'big'))
        await writer.drain()
        header = await reader.readexactly(4)
        assert header[:3] == bytes([5, 0, 0])
        await reader.readexactly(6 if header[3] == 1 else 18)
        data = os.urandom(1024)
        writer.write(data)
        await writer.drain()
        assert await reader.readexactly(len(data)) == data
        return True
    except (OSError, AssertionError, asyncio.IncompleteReadError):
        return False
    finally:
        if writer:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


async def main():
    reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()
    pipe, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    cfg = json.loads(await asyncio.wait_for(reader.readline(), 30))
    directory = Path(__file__).parent
    processes, phase_processes, servers, controls = [], [], [], []
    # A controller disconnect or a bounded lifetime closes all owned resources.
    task = asyncio.current_task()
    loop.call_later(1200, task.cancel)
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    with tempfile.TemporaryDirectory(prefix='ss-encoding-config-') as temp, contextlib.ExitStack() as stack:
        def spawn(binary, config, name):
            path = Path(temp) / (name + '.json')
            path.write_text(json.dumps(config))
            log = stack.enter_context((Path(temp) / (name + '.log')).open('wb'))
            return subprocess.Popen([binary, '-c', str(path)], stdout=log, stderr=log)
        origin = await asyncio.start_server(echo, '127.0.0.1', 0)
        origin_port = origin.sockets[0].getsockname()[1]
        backend = free_port()
        common = dict(server='127.0.0.1', server_port=backend, password=cfg['password'],
                      method='chacha20-ietf-poly1305', mode='tcp_only')
        try:
            processes.append(spawn(cfg.get('server_binary', '/usr/local/bin/ssserver'), common, 'backend'))
            capture_log = stack.enter_context((directory / 'capture.log').open('wb'))
            if cfg.get('capture', True):
                processes.append(subprocess.Popen(['tcpdump', '-i', 'any', '-U', '-s', '0', '-w',
                    str(directory / 'server.pcap'), 'tcp and (' + ' or '.join('port ' + str(p) for p in cfg['ports'])
                    + ' or (host ' + os.environ['SSH_CONNECTION'].split()[0] + ' and port 22))'],
                    stdout=subprocess.DEVNULL, stderr=capture_log))
            await asyncio.sleep(1)
            assert all(p.poll() is None for p in processes)
            print(json.dumps(dict(ready=True, origin=origin_port, backend=backend, client_address=os.environ['SSH_CONNECTION'].split()[0])), flush=True)
            # Missing control commands also stop the service if the SSH
            # connection is blackholed and never delivers EOF.
            while line := await asyncio.wait_for(reader.readline(), cfg.get('control_timeout', 60)):
                command = json.loads(line)
                if command['event'] == 'stop':
                    break
                if command['event'] == 'phase':
                    stop(phase_processes)
                    phase_processes.clear()
                    for server in servers:
                        server.close()
                        await server.wait_closed()
                    servers.clear()
                    controls.clear()
                    for index, mode in enumerate(command['modes']):
                        port = cfg['ports'][index]
                        server = await serve('server', mode, ('0.0.0.0', port), ('127.0.0.1', backend),
                                             str(directory / 'certificate.pem'), str(directory / 'key.pem'))
                        servers.append(server)
                        client = await serve('client', mode, ('127.0.0.1', 0), ('127.0.0.1', port),
                                             str(directory / 'certificate.pem'))
                        servers.append(client)
                        control_port = free_port()
                        config = dict(common, server_port=client.sockets[0].getsockname()[1],
                                      local_address='127.0.0.1', local_port=control_port)
                        phase_processes.append(spawn('/usr/local/bin/sslocal', config, 'control-' + str(index)))
                        controls.append(control_port)
                    await asyncio.sleep(.4)
                checks = await asyncio.gather(*(asyncio.wait_for(check_control(port, origin_port), 5)
                                                for port in controls), return_exceptions=True)
                healthy = all(p.poll() is None for p in processes + phase_processes)
                values = [result is True for result in checks]
                print(json.dumps(dict(healthy=healthy and all(values), local_transfers=values)), flush=True)
        finally:
            pipe.close()
            stop(phase_processes)
            stop(processes)
            for server in servers + [origin]:
                server.close()
                await server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
