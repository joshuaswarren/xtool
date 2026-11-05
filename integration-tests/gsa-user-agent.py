#!/usr/bin/env python3
"""Check the real login client's request header without external networking."""

import argparse
import http.client
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import cast

MARKER = "xtool-fixture-user-agent"
ALLOWED = {"gsa.apple.com:443", "mac-ani.jkcoxson.com:443"}


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext):
        self.context = context
        self.observed: list[dict[str, str]] = []
        self.ready = threading.Event()
        super().__init__(("127.0.0.1", 0), ProxyHandler)


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = cast(ProxyServer, self.server)
        self.request.settimeout(3)
        try:
            connect = self.rfile.readline(65536).decode("ascii").split()
            http.client.parse_headers(self.rfile)
            if len(connect) != 3 or connect[0] != "CONNECT" or connect[1] not in ALLOWED:
                self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            with server.context.wrap_socket(self.request, server_side=True) as tls:
                self.respond(tls, server)
        except (OSError, ValueError, http.client.HTTPException) as error:
            print(f"fixture transport: {error}", file=sys.stderr)

    @staticmethod
    def respond(tls: ssl.SSLSocket, server: ProxyServer) -> None:
        with tls.makefile("rb") as stream:
            request = stream.readline(65536).decode("ascii").strip()
            headers = http.client.parse_headers(stream)
        if request.startswith("GET /v3/client_info "):
            body = json.dumps({"client_info": "fixture-client-info", "user_agent": MARKER}).encode()
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            return
        if "/grandslam/GsService2/lookup " in request:
            server.observed.append({"request": request, "user_agent": headers.get("User-Agent", "")})
            server.ready.set()
        tls.sendall(b"HTTP/1.1 503 Fixture stop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def certificate(root: Path) -> ssl.SSLContext:
    key, cert = root / "key.pem", root / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=xtool-fixture.invalid"], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def capture(binary: Path, root: Path, server: ProxyServer, timeout: float) -> list[dict[str, str]]:
    home = root / "home"
    (home / ".local/share").mkdir(parents=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home),
           "LD_LIBRARY_PATH": str(binary.parent) + os.pathsep + str(Path.home() / ".local/lib"),
           "XTL_HTTP_PROXY": f"127.0.0.1:{server.server_address[1]}",
           "XTL_DISABLE_TLS_VALIDATION": "1"}
    process = subprocess.Popen([str(binary), "auth", "login", "-m", "password",
                                "-u", "fixture@example.invalid", "-p", "fixture-password"],
                               env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + timeout
        while not server.ready.is_set() and process.poll() is None and time.monotonic() < deadline:
            server.ready.wait(0.05)
    finally:
        if process.poll() is None:
            process.kill()
        output, _ = process.communicate(timeout=5)
        print(output.decode("utf-8", "replace"))
    return server.observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xtool", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        print("REFUSED: run inside an isolated loopback-only network namespace", file=sys.stderr)
        return 3
    with tempfile.TemporaryDirectory(prefix="xtool-gsa-fixture-") as temporary:
        root = Path(temporary)
        with ProxyServer(certificate(root)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                observed = capture(args.xtool.resolve(), root, server, args.timeout)
            finally:
                server.shutdown()
                thread.join(timeout=5)
    print(json.dumps({"observed": observed, "expected_user_agent": MARKER}, indent=2))
    if not observed:
        print("INCONCLUSIVE: no real GrandSlam lookup request captured", file=sys.stderr)
        return 3
    if observed[0]["user_agent"] != MARKER:
        print("RED: lookup did not use the provider's user-agent", file=sys.stderr)
        return 2
    print("GREEN: the compiled client used the provider's user-agent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
