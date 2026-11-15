import http.client
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_HOST = "try-grantlatch.manykiln.com"
PUBLIC_BASE_URL = "https://" + PUBLIC_HOST


class HostingContractTests(unittest.TestCase):
    @staticmethod
    def unused_loopback_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    def setUp(self):
        self.port = self.unused_loopback_port()
        environment = os.environ.copy()
        for name in ("HOST", "SECURE_COOKIE", "ALLOWED_ORIGINS"):
            environment.pop(name, None)
        environment.update({
            "DEMO_HOST": "127.0.0.1",
            "PORT": str(self.port),
            "PUBLIC_BASE_URL": PUBLIC_BASE_URL,
            "DEMO_HTTPS_TERMINATED": "true",
        })
        self.process = subprocess.Popen(
            [sys.executable, "demo.py"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def tearDown(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.process.stdout is not None:
            self.process.stdout.close()

    def request(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
        try:
            connection.request("GET", path, headers={"Host": PUBLIC_HOST})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def wait_until_ready(self):
        deadline = time.monotonic() + 8
        last_error = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                self.fail(f"demo exited before becoming ready ({self.process.returncode}): {output}")
            try:
                return self.request("/healthz")
            except OSError as error:
                last_error = error
                time.sleep(0.05)
        self.fail(f"demo did not become ready: {last_error}")

    def test_platform_contract_starts_and_accepts_public_host(self):
        status, _, body = self.wait_until_ready()
        self.assertEqual((status, body), (200, b"ok"))

        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("; Secure", headers["Set-Cookie"])
        self.assertIn((PUBLIC_BASE_URL + "/static/style.css").encode(), body)
        self.assertIn((PUBLIC_BASE_URL + "/audit").encode(), body)


if __name__ == "__main__":
    unittest.main()
