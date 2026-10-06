#!/usr/bin/env python3
"""Codec boundaries, fragmentation, bad records and relay half-close tests."""
import asyncio
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from transport import BLOCK, MODES, decode, encode, read_record, serve


class CodecTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_records(self):
        for mode in MODES[1:]:
            for size in (0, 1, 2, 3, 4, 5, 31, 32, BLOCK):
                with self.subTest(mode=mode, size=size):
                    data = os.urandom(size)
                    wire = encode(mode, data)
                    reader = asyncio.StreamReader()
                    task = asyncio.create_task(read_record(reader, mode))
                    for index in range(0, len(wire), 7):
                        reader.feed_data(wire[index:index + 7])
                        await asyncio.sleep(0)
                    reader.feed_eof()
                    self.assertEqual(await task, data)

    async def test_coalesced_records(self):
        for mode in MODES[1:]:
            reader = asyncio.StreamReader()
            reader.feed_data(encode(mode, b'one') + encode(mode, b'two') + encode(mode, b''))
            for expected in (b'one', b'two', b''):
                self.assertEqual(await read_record(reader, mode), expected)

    async def test_invalid_and_truncated(self):
        for mode in MODES[1:]:
            reader = asyncio.StreamReader()
            reader.feed_data(encode(mode, b'something')[:-1])
            reader.feed_eof()
            with self.assertRaises(asyncio.IncompleteReadError):
                await read_record(reader, mode)
        for mode, invalid in [('base85', b'/'), ('lowpop85', b'\xff')]:
            with self.assertRaises(ValueError):
                decode(mode, invalid)
        reader = asyncio.StreamReader()
        reader.feed_data((BLOCK + 1).to_bytes(2, 'big'))
        with self.assertRaises(ValueError):
            await read_record(reader, 'tls')

    async def test_empty_client_does_not_connect_upstream(self):
        calls = []
        async def connected(reader, writer):
            calls.append(True)
            writer.close()
            await writer.wait_closed()
        target = await asyncio.start_server(connected, '127.0.0.1', 0)
        async with target:
            for mode in MODES[:-1]:
                client = await serve('client', mode, ('127.0.0.1', 0), target.sockets[0].getsockname()[:2])
                async with client:
                    _, writer = await asyncio.open_connection(*client.sockets[0].getsockname()[:2])
                    writer.close()
                    await writer.wait_closed()
                    await asyncio.sleep(.03)
        self.assertEqual(calls, [])

    async def test_tls_half_close_and_certificate_verification(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl CLI is needed for temporary test certificates')
        from local_interop import certificate
        calls = []
        async def reverse(reader, writer):
            calls.append(True)
            data = await reader.read()
            writer.write(data[::-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        with tempfile.TemporaryDirectory() as temp:
            good, bad = Path(temp) / 'good', Path(temp) / 'bad'
            good.mkdir()
            bad.mkdir()
            cert, key = certificate(good)
            wrong, _ = certificate(bad)
            origin = await asyncio.start_server(reverse, '127.0.0.1', 0)
            server = await serve('server', 'tls', ('127.0.0.1', 0),
                                 origin.sockets[0].getsockname()[:2], str(cert), str(key))
            async with origin, server:
                for trusted, succeeds in ((cert, True), (wrong, False)):
                    client = await serve('client', 'tls', ('127.0.0.1', 0),
                                         server.sockets[0].getsockname()[:2], str(trusted))
                    async with client:
                        reader, writer = await asyncio.open_connection(*client.sockets[0].getsockname()[:2])
                        writer.write(b'certificate-and-half-close-test')
                        writer.write_eof()
                        result = await asyncio.wait_for(reader.read(), 5)
                        self.assertEqual(result, b'tset-esolc-flah-dna-etacifitrec' if succeeds else b'')
                        writer.close()
                        await writer.wait_closed()
            self.assertEqual(len(calls), 1, 'bad certificate must not reach the backend')

    async def test_half_close_and_concurrent_relay(self):
        async def reverse(reader, writer):
            data = await reader.read()
            writer.write(data[::-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        origin = await asyncio.start_server(reverse, '127.0.0.1', 0)
        target = origin.sockets[0].getsockname()[:2]
        async with origin:
            for mode in MODES[:-1]:
                server = await serve('server', mode, ('127.0.0.1', 0), target)
                remote = server.sockets[0].getsockname()[:2]
                client = await serve('client', mode, ('127.0.0.1', 0), remote)
                address = client.sockets[0].getsockname()[:2]
                async def check():
                    reader, writer = await asyncio.open_connection(*address)
                    data = os.urandom(BLOCK * 3 + 7)
                    writer.write(data)
                    writer.write_eof()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 5), data[::-1])
                    writer.close()
                    await writer.wait_closed()
                async with server, client:
                    await asyncio.gather(*(check() for _ in range(4)))


if __name__ == '__main__':
    unittest.main()
