#!/usr/bin/env python3
"""Recording reverse proxy for real WSUS exchanges (milestone M0).

Listens locally, forwards every request unchanged to an upstream WSUS, streams
the response back unchanged, and writes each exchange to a numbered directory:

    <out>/000001/request.headers   raw request line and headers
    <out>/000001/request.body      request body bytes as sent by the client
    <out>/000001/response.headers  raw status line and headers from upstream
    <out>/000001/response.body     response body bytes as sent by upstream
    <out>/000001/meta.json         timestamp, method, path, SOAPAction, status,
                                   durations, sizes and sha256 of both bodies

Raw captures contain cookies, tokens, signed URLs and host identities. They must
never be committed. Run sanitize-capture.py to produce a shareable copy.

Standard library only. Stdout carries only per-exchange summaries without
headers, bodies or query strings.
"""

import argparse
import datetime
import hashlib
import http.client
import json
import os
import signal
import socketserver
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_UPSTREAM = "http://10.83.20.149:8530"
CHUNK = 64 * 1024
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class Recorder:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.lock = threading.Lock()
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        existing = [int(n) for n in os.listdir(out_dir) if n.isdigit()]
        self.counter = max(existing, default=0)

    def new_exchange(self):
        with self.lock:
            self.counter += 1
            n = self.counter
        d = os.path.join(self.out_dir, "%06d" % n)
        os.mkdir(d, 0o700)
        return n, d


def format_headers(first_line, pairs):
    out = [first_line]
    out.extend("%s: %s" % (k, v) for k, v in pairs)
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1", "replace")


def soap_action(headers):
    for k, v in headers:
        if k.lower() == "soapaction":
            return v.strip().strip('"')
    for k, v in headers:
        if k.lower() == "content-type":
            for part in v.split(";"):
                part = part.strip()
                if part.lower().startswith("action="):
                    return part[7:].strip().strip('"')
    return None


class TeeReader:
    """Reads exactly `length` bytes from rfile, hashing and saving them."""

    def __init__(self, rfile, length, sink):
        self.rfile, self.left, self.sink = rfile, length, sink
        self.sha = hashlib.sha256()
        self.size = 0

    def read(self, n=CHUNK):
        if self.left <= 0:
            return b""
        data = self.rfile.read(min(n, self.left))
        if not data:
            self.left = 0
            return b""
        self.left -= len(data)
        self.sha.update(data)
        self.size += len(data)
        self.sink.write(data)
        return data


def read_chunked(rfile):
    body = bytearray()
    while True:
        line = rfile.readline(65537)
        size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            while rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                pass
            return bytes(body)
        body += rfile.read(size)
        rfile.readline(65537)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wsus-capture-proxy"

    def log_message(self, fmt, *args):  # silence default logging (may contain secrets)
        pass

    def handle_any(self):
        cfg = self.server.cfg
        t0 = time.monotonic()
        n, d = cfg.recorder.new_exchange()
        meta = {
            "exchange": n,
            "timestamp": utc_now(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "soap_action": None,
            "status": None,
            "error": None,
        }
        req_pairs = list(self.headers.items())
        meta["soap_action"] = soap_action(req_pairs)
        write_private(
            os.path.join(d, "request.headers"),
            format_headers("%s %s %s" % (self.command, self.path, self.request_version), req_pairs),
        )
        req_sha = hashlib.sha256()
        req_size = 0
        resp_sha = hashlib.sha256()
        resp_size = 0
        t_connect = t_ttfb = t_req_done = None
        conn = None
        try:
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            clen = self.headers.get("Content-Length")
            with open(os.path.join(d, "request.body"), "wb") as req_f:
                os.fchmod(req_f.fileno(), 0o600)
                buffered = None
                tee = None
                if "chunked" in te:
                    buffered = read_chunked(self.rfile)
                    req_f.write(buffered)
                    req_sha.update(buffered)
                    req_size = len(buffered)
                    meta["request_was_chunked"] = True
                elif clen:
                    tee = TeeReader(self.rfile, int(clen), req_f)
                conn = http.client.HTTPConnection(cfg.up_host, cfg.up_port, timeout=cfg.timeout)
                tc = time.monotonic()
                conn.connect()
                t_connect = time.monotonic() - tc
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                sent_host = False
                for k, v in req_pairs:
                    lk = k.lower()
                    if lk in HOP_BY_HOP or lk in ("expect", "content-length"):
                        continue
                    if lk == "host":
                        sent_host = True
                        if cfg.upstream_host:
                            v = cfg.upstream_host
                    conn.putheader(k, v)
                if not sent_host:
                    conn.putheader("Host", cfg.upstream_host or "%s:%d" % (cfg.up_host, cfg.up_port))
                if buffered is not None:
                    conn.putheader("Content-Length", str(len(buffered)))
                elif tee is not None:
                    conn.putheader("Content-Length", str(tee.left))
                conn.putheader("Connection", "close")
                conn.endheaders()
                if buffered:
                    conn.send(buffered)
                elif tee is not None:
                    while True:
                        data = tee.read()
                        if not data:
                            break
                        conn.send(data)
                    req_sha, req_size = tee.sha, tee.size
                t_req_done = time.monotonic()
                resp = conn.getresponse()
                t_ttfb = time.monotonic()

            resp_pairs = resp.getheaders()
            meta["status"] = resp.status
            write_private(
                os.path.join(d, "response.headers"),
                format_headers("HTTP/%s %d %s" % ("1.1" if resp.version == 11 else "1.0", resp.status, resp.reason), resp_pairs),
            )
            has_body = self.command != "HEAD" and resp.status not in (204, 304) and resp.status >= 200
            chunked = bool(resp.chunked) and has_body
            has_len = resp.getheader("Content-Length") is not None
            self.send_response_only(resp.status, resp.reason)
            for k, v in resp_pairs:
                if k.lower() in HOP_BY_HOP:
                    continue
                self.send_header(k, v)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            elif has_body and not has_len:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            t_body0 = time.monotonic()
            client_ok = True
            with open(os.path.join(d, "response.body"), "wb") as resp_f:
                os.fchmod(resp_f.fileno(), 0o600)
                while has_body:
                    data = resp.read1(CHUNK)
                    if not data:
                        break
                    resp_sha.update(data)
                    resp_size += len(data)
                    resp_f.write(data)
                    if client_ok:
                        try:
                            if chunked:
                                self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
                            else:
                                self.wfile.write(data)
                        except (BrokenPipeError, ConnectionResetError):
                            client_ok = False
                            meta["error"] = "client disconnected during response; capture continues"
                            self.close_connection = True
            if chunked and client_ok:
                self.wfile.write(b"0\r\n\r\n")
            if client_ok:
                self.wfile.flush()
            meta["upstream_body_ms"] = round((time.monotonic() - t_body0) * 1000, 3)
        except Exception as exc:  # recorded, not printed with details
            meta["error"] = "%s: %s" % (type(exc).__name__, exc)
            self.close_connection = True
            if meta["status"] is None:
                try:
                    msg = b"upstream error\n"
                    self.send_response_only(502, "Bad Gateway")
                    self.send_header("Content-Length", str(len(msg)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(msg)
                    meta["status"] = 502
                except Exception:
                    pass
        finally:
            if conn is not None:
                conn.close()
            t1 = time.monotonic()
            meta["request_body_bytes"] = req_size
            meta["request_body_sha256"] = req_sha.hexdigest()
            meta["response_body_bytes"] = resp_size
            meta["response_body_sha256"] = resp_sha.hexdigest()
            meta["durations_ms"] = {
                "total": round((t1 - t0) * 1000, 3),
                "upstream_connect": None if t_connect is None else round(t_connect * 1000, 3),
                "time_to_first_response_byte": None if t_ttfb is None else round((t_ttfb - t0) * 1000, 3),
                "request_sent": None if t_req_done is None else round((t_req_done - t0) * 1000, 3),
            }
            write_private(
                os.path.join(d, "meta.json"),
                (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode(),
            )
            if not cfg.quiet:
                path_only = urllib.parse.urlsplit(self.path).path
                sys.stdout.write(
                    "#%06d %s %s %s %s bytes=%d/%d %dms\n"
                    % (n, self.command, path_only, meta["status"], "ERR" if meta["error"] else "ok",
                       req_size, resp_size, round((t1 - t0) * 1000))
                )
                sys.stdout.flush()

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = handle_any


class ProxyServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class Config:
    def __init__(self, upstream, out_dir, timeout=300.0, upstream_host=None, quiet=False):
        u = urllib.parse.urlsplit(upstream)
        if u.scheme != "http" or not u.hostname:
            raise SystemExit("upstream must be an http:// URL (TLS is not supported)")
        self.up_host = u.hostname
        self.up_port = u.port or 80
        self.timeout = timeout
        self.upstream_host = upstream_host
        self.quiet = quiet
        self.recorder = Recorder(out_dir)


def make_server(listen_host, listen_port, cfg):
    srv = ProxyServer((listen_host, listen_port), Handler)
    srv.cfg = cfg
    return srv


# ---------------------------------------------------------------- self test

SECRET_BLOB = "U0VDUkVUQ09PS0lFQkxPQjEyMzQ1Njc4OTA="
SELFTEST_SOAP_RESPONSE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    '<GetCookieResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
    "<GetCookieResult><Expiration>2030-01-01T00:00:00Z</Expiration>"
    "<EncryptedData>%s</EncryptedData></GetCookieResult></GetCookieResponse>"
    "</soap:Body></soap:Envelope>" % SECRET_BLOB
).encode()


def selftest_blob(size):
    out = bytearray()
    i = 0
    while len(out) < size:
        out += hashlib.sha256(b"blob%d" % i).digest()
        i += 1
    return bytes(out[:size])


LARGE_SIZE = 3 * 1024 * 1024 + 17


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, status, headers, body):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_POST(self):
        import gzip

        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = gzip.compress(SELFTEST_SOAP_RESPONSE, mtime=0)
        self.reply(200, [("Content-Type", "text/xml; charset=utf-8"), ("Content-Encoding", "gzip"),
                         ("Set-Cookie", "SessionId=topsecretsession; Path=/")], body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/Content/"):
            blob = selftest_blob(LARGE_SIZE)
            rng = self.headers.get("Range")
            if rng and rng.startswith("bytes="):
                a, b = rng[6:].split("-")
                a, b = int(a), int(b) if b else LARGE_SIZE - 1
                self.reply(206, [("Content-Type", "application/octet-stream"),
                                 ("Content-Range", "bytes %d-%d/%d" % (a, b, LARGE_SIZE))], blob[a:b + 1])
            else:
                self.reply(200, [("Content-Type", "application/octet-stream")], blob)
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            for part in (b"alpha", b"beta", b"gamma" * 1000):
                self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/signed":
            self.reply(302, [("Location", "http://10.83.20.149:8530/Content/x?sig=SECRETSIG&se=2030")], b"")
        else:
            self.reply(404, [], b"nope")

    do_HEAD = do_GET


def start_selftest_stack(out_dir):
    """Start fake upstream and proxy on loopback; return (proxy_port, shutdown)."""
    fake = ProxyServer(("127.0.0.1", 0), FakeUpstream)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    cfg = Config("http://127.0.0.1:%d" % fake.server_address[1], out_dir, quiet=True)
    proxy = make_server("127.0.0.1", 0, cfg)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    def shutdown():
        proxy.shutdown()
        fake.shutdown()
        proxy.server_close()
        fake.server_close()

    return proxy.server_address[1], shutdown


def generate_selftest_capture(out_dir):
    """Drive the proxy against the fake upstream; returns expected facts."""
    port, shutdown = start_selftest_stack(out_dir)
    facts = {}
    try:
        def request(method, path, headers=None, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            data = r.read()
            hdrs = r.getheaders()
            c.close()
            return r.status, hdrs, data

        soap = (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            b"<GetCookie><computerInfo><DnsName>wsushost01.corp.example</DnsName></computerInfo>"
            b"<authCookies><AuthorizationCookie><PlugInId>SimpleTargeting</PlugInId>"
            b"<CookieData>QVVUSENPT0tJRURBVEE=</CookieData></AuthorizationCookie></authCookies>"
            b"</GetCookie></soap:Body></soap:Envelope>"
        )
        st, hd, data = request("POST", "/ClientWebService/client.asmx", {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"',
            "Cookie": "MyCookie=sessionsecret", "Authorization": "Bearer topsecrettoken",
            "Accept-Encoding": "gzip", "Host": "10.83.20.149:8530"}, soap)
        facts["soap"] = (st, data)
        st, hd, data = request("GET", "/Content/AB/file.bin?token=abcdef&Expires=99")
        facts["large"] = (st, data)
        st, hd, data = request("GET", "/Content/AB/file.bin", {"Range": "bytes=1000-5000"})
        facts["range"] = (st, data)
        st, hd, data = request("GET", "/chunked")
        facts["chunked"] = (st, data)
        st, hd, data = request("GET", "/signed")
        facts["redirect"] = (st, dict(hd))
        st, hd, data = request("HEAD", "/Content/AB/file.bin")
        facts["head"] = (st, dict(hd), data)
    finally:
        shutdown()
    return facts


def run_self_test():
    import gzip

    blob = selftest_blob(LARGE_SIZE)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "raw")
        f = generate_selftest_capture(out)
        assert f["soap"][0] == 200 and gzip.decompress(f["soap"][1]) == SELFTEST_SOAP_RESPONSE, "gzip body altered"
        assert f["large"] == (200, blob), "large GET altered"
        assert f["range"] == (206, blob[1000:5001]), "range GET altered"
        assert f["chunked"] == (200, b"alphabeta" + b"gamma" * 1000), "chunked body altered"
        assert f["redirect"][0] == 302 and f["redirect"][1]["Location"].endswith("sig=SECRETSIG&se=2030")
        assert f["head"][0] == 200 and f["head"][2] == b"" and int(f["head"][1]["Content-Length"]) == LARGE_SIZE
        dirs = sorted(os.listdir(out))
        assert dirs == ["%06d" % i for i in range(1, 7)], dirs
        m = json.load(open(os.path.join(out, "000001", "meta.json")))
        assert m["method"] == "POST" and m["status"] == 200 and m["error"] is None
        assert m["soap_action"].endswith("/ClientWebService/GetCookie")
        raw = open(os.path.join(out, "000001", "response.body"), "rb").read()
        assert raw == f["soap"][1] and hashlib.sha256(raw).hexdigest() == m["response_body_sha256"]
        m2 = json.load(open(os.path.join(out, "000002", "meta.json")))
        assert m2["response_body_sha256"] == hashlib.sha256(blob).hexdigest() and m2["response_body_bytes"] == LARGE_SIZE
        req_h = open(os.path.join(out, "000001", "request.headers"), "rb").read()
        assert b"Cookie: MyCookie=sessionsecret" in req_h, "request headers not recorded raw"
    print("capture-proxy self-test passed")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--upstream", default=DEFAULT_UPSTREAM, help="upstream WSUS base URL (default %(default)s)")
    ap.add_argument("--listen", default="127.0.0.1", help="listen address (default %(default)s)")
    ap.add_argument("--port", type=int, default=8530, help="listen port (default %(default)s)")
    ap.add_argument("--out", help="output directory for raw captures (use a gitignored location)")
    ap.add_argument("--upstream-host", help="override the Host header sent upstream (default: keep the client's)")
    ap.add_argument("--timeout", type=float, default=300.0, help="upstream socket timeout seconds")
    ap.add_argument("--quiet", action="store_true", help="no per-exchange stdout lines")
    ap.add_argument("--self-test", action="store_true", help="run against a local fake upstream and exit")
    a = ap.parse_args()
    if a.self_test:
        run_self_test()
        return
    if not a.out:
        ap.error("--out is required")
    cfg = Config(a.upstream, a.out, a.timeout, a.upstream_host, a.quiet)
    srv = make_server(a.listen, a.port, cfg)
    if a.listen not in ("127.0.0.1", "::1", "localhost"):
        sys.stderr.write("warning: listening on %s; the proxy has no access control\n" % a.listen)
    sys.stdout.write("listening on %s:%d -> %s:%d, writing to %s\n"
                     % (a.listen, a.port, cfg.up_host, cfg.up_port, a.out))
    sys.stdout.flush()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
