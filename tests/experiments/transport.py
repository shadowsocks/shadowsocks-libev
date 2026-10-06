#!/usr/bin/env python3
"""Experimental TCP outer transports. Not a production plugin or crypto scheme.

Run a client relay in front of stock ss-local's remote connection and a server
relay in front of an unchanged ss-server. TLS uses a verified experiment CA.
"""
import argparse
import asyncio
from base64 import b85decode, b85encode
import contextlib
import ssl

MODES = ('raw', 'base85', 'lowpop85', 'tls')
B85 = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
LOW = bytes(sorted(range(256), key=lambda value: (value.bit_count(), value))[:85])
TO_LOW = bytes.maketrans(B85, LOW)
FROM_LOW = bytes.maketrans(LOW, B85)
BLOCK = 16384


def encode(mode, data):
    if mode == 'raw':
        return data
    if mode == 'tls':
        return len(data).to_bytes(2, 'big') + data
    result = b85encode(data)
    return result.translate(TO_LOW) + b'\xff' if mode == 'lowpop85' else result + b'\n'


def decode(mode, data):
    if mode == 'lowpop85':
        if any(value not in LOW for value in data):
            raise ValueError('invalid low-popcount symbol')
        data = data.translate(FROM_LOW)
    return b85decode(data)


async def read_record(reader, mode):
    if mode == 'raw':
        return await reader.read(BLOCK)
    if mode == 'tls':
        length = int.from_bytes(await reader.readexactly(2), 'big')
        if length > BLOCK:
            raise ValueError('oversized TLS record')
        return await reader.readexactly(length)
    delimiter = b'\xff' if mode == 'lowpop85' else b'\n'
    frame = await reader.readuntil(delimiter)
    if len(frame) > (BLOCK * 5 + 3) // 4 + 1:
        raise ValueError('oversized encoded record')
    return decode(mode, frame[:-1])


async def pump(reader, writer, mode, encoding, initial=None):
    while True:
        if initial is not None:
            data, initial = initial, None
        else:
            data = await asyncio.wait_for(reader.read(BLOCK) if encoding else read_record(reader, mode), 30)
        if encoding:
            writer.write(encode(mode, data))
        elif data:
            writer.write(data)
        await writer.drain()
        if not data:
            if (not encoding or mode == 'raw') and writer.can_write_eof():
                writer.write_eof()
            return


def tls_context(role, certificate, key=None):
    if role == 'server':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
    else:
        context = ssl.create_default_context(cafile=certificate)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


async def relay(reader, writer, role, mode, target, context=None):
    upstream = None
    tasks = []
    try:
        initial = None
        if role == 'client':
            # Readiness probes and idle connections must not emit empty outer
            # records or TLS handshakes that contaminate the route experiment.
            initial = await asyncio.wait_for(reader.read(BLOCK), 30)
            if not initial:
                return
        kwargs = {}
        if mode == 'tls' and role == 'client':
            kwargs = dict(ssl=context, server_hostname='experiment.invalid', ssl_handshake_timeout=10)
        remote_reader, upstream = await asyncio.wait_for(asyncio.open_connection(*target, **kwargs), 10)
        tasks = [asyncio.create_task(pump(reader, upstream, mode, role == 'client', initial)),
                 asyncio.create_task(pump(remote_reader, writer, mode, role != 'client'))]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            task.result()
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for peer in (writer, upstream):
            if peer is not None:
                peer.close()
                with contextlib.suppress(OSError, TimeoutError):
                    await asyncio.wait_for(peer.wait_closed(), 3)


async def serve(role, mode, listen, target, certificate=None, key=None):
    context = tls_context(role, certificate, key) if mode == 'tls' else None
    kwargs = dict(ssl=context, ssl_handshake_timeout=10) if mode == 'tls' and role == 'server' else {}
    return await asyncio.start_server(
        lambda reader, writer: relay(reader, writer, role, mode, target, context), *listen, **kwargs)


async def main(args):
    server = await serve(args.role, args.mode, (args.listen_host, args.listen_port),
                         (args.target_host, args.target_port), args.certificate, args.key)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('client', 'server'), required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--listen-host', default='127.0.0.1')
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--target-host', default='127.0.0.1')
    parser.add_argument('--target-port', type=int, required=True)
    parser.add_argument('--certificate')
    parser.add_argument('--key')
    asyncio.run(main(parser.parse_args()))
