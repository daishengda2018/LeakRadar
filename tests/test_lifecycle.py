"""隔离目录与假 ADB/Shark 验证真实 HTTP 和后台进程生命周期。"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


class Lifecycle(unittest.TestCase):
    def test_start_twice_http_auth_job_and_stop(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(source / "src", root / "src")
            tools = root / "bin"
            tools.mkdir()
            adb = tools / "adb"
            adb.write_text(f"#!{sys.executable}\nimport sys\n"
                           "print('List of devices attached\\nfixture-device\\tdevice' if sys.argv[1:] == ['devices'] else '123')\n")
            shark = tools / "shark-cli"
            shark.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                             "if '--version' in sys.argv: print('2.14')\n"
                             "elif 'dump-process' in sys.argv: Path('heap.hprof').write_bytes(b'fixture')\n"
                             "else: print('HEAP ANALYSIS RESULT\\n0 APPLICATION LEAKS\\n0 LIBRARY LEAKS\\n0 UNREACHABLE OBJECTS\\nAnalysis duration: 1 ms')\n")
            adb.chmod(0o755)
            shark.chmod(0o755)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            env = dict(os.environ, PYTHONPATH=str(root / "src"), LEAK_PORT=str(port),
                       LEAK_PACKAGE="com.example.fixture", LEAK_TOKEN="fixture-token",
                       LEAK_HOST="127.0.0.1", DEVICE_SERIAL="fixture-device",
                       PATH=str(tools) + os.pathsep + os.environ["PATH"])
            def control(action):
                return subprocess.run([sys.executable, '-m', 'leak_detector.control', action],
                                      env=env, capture_output=True, text=True, timeout=20)
            try:
                first = control('start')
                self.assertEqual(0, first.returncode, first.stderr)
                state = json.loads((root / '.runtime/service.json').read_text())
                second = control('start')
                self.assertEqual(0, second.returncode, second.stderr)
                self.assertEqual(state, json.loads((root / '.runtime/service.json').read_text()))
                body = json.dumps({'packageName': 'com.example.fixture', 'pid': 123,
                                   'retainedCount': 1, 'reason': 'fixture',
                                   'timestamp': int(time.time() * 1000)}).encode()
                url = f'http://127.0.0.1:{port}/leak-event'
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with self.assertRaises(urllib.error.HTTPError) as error:
                    opener.open(urllib.request.Request(url, data=body), timeout=3)
                self.assertEqual(401, error.exception.code)
                request = urllib.request.Request(url, data=body,
                                                 headers={'Authorization': 'Bearer fixture-token'})
                with opener.open(request, timeout=3) as response:
                    accepted = json.load(response)
                result = root / 'reports' / accepted['jobId'] / 'result.json'
                for _ in range(50):
                    if result.exists(): break
                    time.sleep(.1)
                self.assertEqual('no_leaks_found', json.loads(result.read_text())['status'])
            finally:
                stopped = control('stop')
                self.assertEqual(0, stopped.returncode, stopped.stderr)
            self.assertFalse((root / '.runtime/service.json').exists())
