#!/usr/bin/env python3
"""Run the real supervisor/backend and verify cleanup on lost control input."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

BINARY = None


class SupervisorTests(unittest.TestCase):
    def check_cleanup(self, trigger):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('route_server.py', 'transport.py'):
                shutil.copy(Path(__file__).with_name(name), root / name)
            env = dict(os.environ, SSH_CONNECTION='127.0.0.1 1 127.0.0.1 22')
            with (root / 'log').open('w+') as log:
                process = subprocess.Popen([sys.executable, str(root / 'route_server.py')],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=env)
                try:
                    process.stdin.write(json.dumps(dict(password='supervisor-test-only', ports=[],
                        capture=False, server_binary=str(BINARY), control_timeout=.3 if trigger == 'timeout' else 60)) + '\n')
                    process.stdin.flush()
                    import select
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'supervisor startup timeout')
                    ready = json.loads(process.stdout.readline())
                    self.assertTrue(ready['ready'])
                    for port in (ready['origin'], ready['backend']):
                        with socket.create_connection(('127.0.0.1', port), .5):
                            pass
                    if trigger == 'eof':
                        process.stdin.close()
                    elif trigger == 'signal':
                        process.send_signal(signal.SIGTERM)
                    process.wait(timeout=5)
                    if trigger == 'eof':
                        self.assertEqual(process.returncode, 0)
                    for port in (ready['origin'], ready['backend']):
                        with self.assertRaises(OSError):
                            socket.create_connection(('127.0.0.1', port), .2)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if not process.stdin.closed:
                        process.stdin.close()
                    process.stdout.close()

    def test_control_eof(self):
        self.check_cleanup('eof')

    def test_control_silence(self):
        self.check_cleanup('timeout')

    def test_termination_signal(self):
        self.check_cleanup('signal')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', required=True)
    args = parser.parse_args()
    BINARY = Path(args.bin).resolve() / 'ss-server'
    unittest.main(argv=[__file__])
