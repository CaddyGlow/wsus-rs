#!/usr/bin/env python3
"""Sanitize a raw capture-proxy directory into a shareable copy.

Reads <raw>/NNNNNN/{request,response}.{headers,body} and meta.json and writes
the same layout to <out>, plus sanitize-manifest.json recording what was
redacted (counts by category, never the secret values) and the sha256 of every
ORIGINAL file. Structure is preserved: element names, attribute names, query
parameter names, header names, base64 lengths and URL shapes survive so the
fixtures stay useful for codec tests.

Redacted by default:
  * header values: Cookie, Set-Cookie, Authorization, Proxy-Authorization
  * element text: EncryptedData, CookieData, Password (same-length filler)
  * every URL query string value (names kept) in bodies, headers and meta
  * Windows domain SIDs S-1-5-21-... (stable per-value placeholders)
  * every value passed via --redact / --redact-file (hostnames, IPs, computer
    names; case-insensitive, URL-encoded form included, UTF-16LE scanned)

gzip and deflate bodies of text content are decompressed, redacted and
recompressed as gzip (Content-Length is updated). Bodies with no change are
copied byte for byte. Other binary bodies are copied unchanged (or emptied
with --omit-binary-bodies) and scanned for residual --redact values.
Exit status 3 means a --redact value still appears in the output.
"""

import argparse
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.parse
import zlib
from collections import Counter

DEFAULT_REDACT_HEADERS = ["Cookie", "Set-Cookie", "Authorization", "Proxy-Authorization"]
DEFAULT_REDACT_ELEMENTS = ["EncryptedData", "CookieData", "Password"]
TEXT_TYPES = ("xml", "text", "json", "html", "soap", "javascript")
URL_QUERY_RE = re.compile(r"(https?://[^\s\"'<>?#]*|(?<![\w.-])/[^\s\"'<>?#]*)\?([^\s\"'<>#]*)")
SID_RE = re.compile(r"\bS-1-5-21-(\d+)-(\d+)-(\d+)((?:-\d+)?)")
B64_RE = re.compile(r"[A-Za-z0-9+/=\s]*")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


class Redactor:
    def __init__(self, values, headers, elements, keep_query):
        self.values = sorted({v for v in values if v}, key=len, reverse=True)
        self.headers = {h.lower() for h in headers}
        self.elements = list(elements)
        self.keep_query = set(keep_query)
        self.counts = Counter()
        self.placeholders = {}
        self.sids = {}
        self.pats = []
        for v in self.values:
            forms = {v, urllib.parse.quote(v, safe=""), urllib.parse.quote(v)}
            alt = "|".join(re.escape(f) for f in sorted(forms, key=len, reverse=True))
            if re.fullmatch(r"[\d.]+", v) or ":" in v and _is_ip(v):
                pat = r"(?<![\d.])(?:%s)(?!\d|\.\d)" % alt
            else:
                pat = alt
            self.pats.append((v, re.compile(pat, re.I)))
        el = "|".join(re.escape(e) for e in self.elements)
        self.elem_re = (
            re.compile(r"(<((?:[\w.-]+:)?(?:%s))(?:\s[^>]*)?>)([^<]*)(</\2\s*>)" % el, re.S) if el else None
        )

    def placeholder(self, value):
        if value not in self.placeholders:
            n = len(self.placeholders) + 1
            if _is_ip(value) and "." in value:
                ph = "192.0.2.%d" % n if n < 255 else "198.51.100.%d" % (n - 254)
            elif "." in value:
                ph = "host%d.invalid" % n
            else:
                ph = "REDACTED%d" % n
            self.placeholders[value] = ph
        return self.placeholders[value]

    def explicit(self, text):
        for v, pat in self.pats:
            def sub(m, v=v):
                self.counts["explicit_value"] += 1
                ph = self.placeholder(v)
                return ph
            text = pat.sub(sub, text)
        return text

    def sids_sub(self, text):
        def sub(m):
            key = m.group(1, 2, 3)
            if key not in self.sids:
                n = len(self.sids) + 1
                self.sids[key] = (1000000000 + n, 2000000000 + n, 3000000000 + n)
            self.counts["sid"] += 1
            return "S-1-5-21-%d-%d-%d%s" % (*self.sids[key], m.group(4))
        return SID_RE.sub(sub, text)

    def query_sub(self, text):
        def fix(m):
            sep = "&amp;" if "&amp;" in m.group(2) else "&"
            parts = re.split(r"&amp;|&", m.group(2))
            out = []
            for p in parts:
                name, eq, val = p.partition("=")
                if eq and val and urllib.parse.unquote_plus(name) not in self.keep_query:
                    out.append(name + "=REDACTED")
                    self.counts["url_query_value"] += 1
                else:
                    out.append(p)
            return m.group(1) + "?" + sep.join(out)
        return URL_QUERY_RE.sub(fix, text)

    def elements_sub(self, text):
        if not self.elem_re:
            return text

        def sub(m):
            body = m.group(3)
            if not body.strip():
                return m.group(0)
            name = m.group(2).split(":")[-1]
            self.counts["element:" + name] += 1
            if B64_RE.fullmatch(body):
                body = re.sub(r"[A-Za-z0-9+/]", "A", body)
            else:
                body = "REDACTED"
            return m.group(1) + body + m.group(4)
        return self.elem_re.sub(sub, text)

    def text(self, s):
        s = self.elements_sub(s)
        s = self.query_sub(s)
        s = self.sids_sub(s)
        return self.explicit(s)

    def header_value(self, name, value):
        if name.lower() in self.headers:
            self.counts["header:" + name.title()] += 1
            return "REDACTED"
        return self.text(value)


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def sanitize_headers(raw, red):
    text = raw.decode("latin-1")
    lines = text.split("\r\n")
    out = []
    for i, line in enumerate(lines):
        if i == 0:
            out.append(red.text(line))
        elif ":" in line:
            k, _, v = line.partition(":")
            out.append("%s: %s" % (k, red.header_value(k, v.strip())))
        else:
            out.append(line)
    return "\r\n".join(out).encode("latin-1", "replace")


def header_get(raw, name):
    for line in raw.decode("latin-1").split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == name.lower():
            return v.strip()
    return ""


def set_content_length(raw, length):
    lines = raw.decode("latin-1").split("\r\n")
    for i, line in enumerate(lines[1:], 1):
        if line.lower().startswith("content-length:"):
            lines[i] = "%s: %d" % (line.split(":")[0], length)
    return "\r\n".join(lines).encode("latin-1")


def decode_text(data):
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16"), "utf-16"
    try:
        if data.startswith(b"\xef\xbb\xbf"):
            return data[3:].decode("utf-8"), "utf-8-sig"
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return None, None


def encode_text(text, enc):
    if enc == "utf-16":
        return b"\xff\xfe" + text.encode("utf-16-le")
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode()
    return text.encode()


def sanitize_body(data, hdr_raw, red, omit_binary):
    """Returns (new_body, new_headers, note)."""
    ctype = header_get(hdr_raw, "Content-Type").lower() if hdr_raw else ""
    cenc = header_get(hdr_raw, "Content-Encoding").lower() if hdr_raw else ""
    if not data:
        return data, hdr_raw, "empty"
    payload, wrapper = data, None
    try:
        if cenc in ("gzip", "x-gzip"):
            payload, wrapper = gzip.decompress(data), "gzip"
        elif cenc == "deflate":
            payload, wrapper = zlib.decompress(data), "deflate"
    except (OSError, zlib.error, EOFError):
        return data, hdr_raw, "undecodable_compressed_copied"
    text, enc = decode_text(payload)
    looks_text = any(t in ctype for t in TEXT_TYPES) or (text is not None and text.lstrip()[:1] in ("<", "{"))
    if text is None or not looks_text:
        if omit_binary:
            return b"", set_content_length(hdr_raw, 0) if hdr_raw else hdr_raw, "binary_omitted"
        return data, hdr_raw, "binary_copied"
    before = dict(red.counts)
    new = red.text(text)
    if new == text:
        return data, hdr_raw, "text_unchanged"
    out = encode_text(new, enc)
    if wrapper:
        out = gzip.compress(out, mtime=0) if wrapper == "gzip" else zlib.compress(out)
    if hdr_raw and header_get(hdr_raw, "Content-Length"):
        hdr_raw = set_content_length(hdr_raw, len(out))
    return out, hdr_raw, "text_redacted" + ("_recompressed_" + wrapper if wrapper else "")


def sanitize_meta(meta, red):
    meta.pop("client", None)

    def walk(x):
        if isinstance(x, str):
            return red.text(x)
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        return x
    return walk(meta)


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def residual_scan(data, values):
    hits = 0
    low = data.lower()
    for v in values:
        for form in (v.encode(), v.encode("utf-16-le"), urllib.parse.quote(v, safe="").encode()):
            if form.lower() in low:
                hits += 1
                break
    return hits


def sanitize_tree(src, dst, red, omit_binary, allow_residual=False):
    if os.path.exists(dst) and os.listdir(dst):
        raise SystemExit("output directory %s exists and is not empty" % dst)
    if os.path.realpath(dst).startswith(os.path.realpath(src) + os.sep):
        raise SystemExit("output must not be inside the raw capture directory")
    os.makedirs(dst, exist_ok=True)
    manifest = {"tool": "sanitize-capture.py", "version": 1, "exchanges": [], "residual": []}
    names = sorted(n for n in os.listdir(src) if n.isdigit() and os.path.isdir(os.path.join(src, n)))
    for n in names:
        sd, dd = os.path.join(src, n), os.path.join(dst, n)
        os.mkdir(dd)
        files = {}
        hdrs = {}
        for side in ("request", "response"):
            hp, bp = os.path.join(sd, side + ".headers"), os.path.join(sd, side + ".body")
            hraw = open(hp, "rb").read() if os.path.exists(hp) else b""
            braw = open(bp, "rb").read() if os.path.exists(bp) else b""
            before = Counter(red.counts)
            new_h = sanitize_headers(hraw, red) if hraw else hraw
            new_b, new_h2, note = sanitize_body(braw, new_h, red, omit_binary)
            # body-driven Content-Length edits apply to the (already sanitized) headers
            for name, orig, new in ((side + ".headers", hraw, new_h2), (side + ".body", braw, new_b)):
                if not (orig or new) and not os.path.exists(os.path.join(sd, name)):
                    continue
                write(os.path.join(dd, name), new)
                files[name] = {
                    "original_sha256": sha256(orig), "original_size": len(orig),
                    "sanitized_sha256": sha256(new), "sanitized_size": len(new),
                    "changed": orig != new,
                }
                if name.endswith(".body"):
                    files[name]["treatment"] = note
                if red.values:
                    r = residual_scan(new, red.values)
                    if r:
                        manifest["residual"].append({"exchange": n, "file": name, "values_found": r})
            delta = {k: v - before.get(k, 0) for k, v in red.counts.items() if v - before.get(k, 0)}
            files[side + ".redactions"] = delta
            hdrs[side] = new_h2
        mp = os.path.join(sd, "meta.json")
        if os.path.exists(mp):
            meta = json.load(open(mp))
            orig_meta = open(mp, "rb").read()
            meta = sanitize_meta(meta, red)
            meta["sanitized"] = True
            meta["request_body_sha256"] = files.get("request.body", {}).get("sanitized_sha256", sha256(b""))
            meta["response_body_sha256"] = files.get("response.body", {}).get("sanitized_sha256", sha256(b""))
            meta["request_body_bytes"] = files.get("request.body", {}).get("sanitized_size", 0)
            meta["response_body_bytes"] = files.get("response.body", {}).get("sanitized_size", 0)
            new_meta = (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode()
            write(os.path.join(dd, "meta.json"), new_meta)
            files["meta.json"] = {"original_sha256": sha256(orig_meta), "sanitized_sha256": sha256(new_meta)}
            if red.values:
                r = residual_scan(new_meta, red.values)
                if r:
                    manifest["residual"].append({"exchange": n, "file": "meta.json", "values_found": r})
            try:
                orig = json.loads(orig_meta)
                files["original_body_hashes_recorded_in_raw_meta"] = {
                    "request": orig.get("request_body_sha256"), "response": orig.get("response_body_sha256")}
            except ValueError:
                pass
        manifest["exchanges"].append({"exchange": n, "files": files})
    manifest["redaction_totals"] = dict(sorted(red.counts.items()))
    manifest["settings"] = {
        "redact_header_names": sorted(red.headers),
        "redact_element_names": red.elements,
        "explicit_redact_value_count": len(red.values),
        "kept_query_params": sorted(red.keep_query),
    }
    write(os.path.join(dst, "sanitize-manifest.json"), (json.dumps(manifest, indent=2) + "\n").encode())
    return manifest


def load_values(args):
    vals = list(args.redact or [])
    for f in args.redact_file or []:
        with open(f) as fh:
            vals += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    return vals


def self_test():
    spec = importlib.util.spec_from_file_location(
        "capture_proxy", os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture-proxy.py"))
    cp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cp)
    with tempfile.TemporaryDirectory() as tmp:
        raw, out = os.path.join(tmp, "raw"), os.path.join(tmp, "clean")
        cp.generate_selftest_capture(raw)
        red = Redactor(["10.83.20.149", "wsushost01.corp.example"], DEFAULT_REDACT_HEADERS,
                       DEFAULT_REDACT_ELEMENTS, [])
        m = sanitize_tree(raw, out, red, False)
        assert not m["residual"], m["residual"]
        blob_all = b""
        for root, _, fs in os.walk(out):
            for f in fs:
                blob_all += open(os.path.join(root, f), "rb").read()
        for secret in (b"sessionsecret", b"topsecrettoken", b"topsecretsession", b"SECRETSIG",
                       b"10.83.20.149", b"wsushost01", b"QVVUSENPT0tJRURBVEE", cp.SECRET_BLOB.encode(),
                       b"token=abcdef"):
            assert secret not in blob_all, secret
        resp = gzip.decompress(open(os.path.join(out, "000001", "response.body"), "rb").read()).decode()
        import xml.dom.minidom
        xml.dom.minidom.parseString(resp)
        assert "<EncryptedData>" + "A" * (len(cp.SECRET_BLOB) - 1) + "=</EncryptedData>" in resp
        h = open(os.path.join(out, "000001", "response.headers"), "rb").read().decode()
        assert "Set-Cookie: REDACTED" in h
        assert "Content-Length: %d" % len(open(os.path.join(out, "000001", "response.body"), "rb").read()) in h
        req = open(os.path.join(out, "000001", "request.body"), "rb").read().decode()
        assert "<DnsName>host" in req and "<CookieData>" in req
        # large binary unchanged byte for byte, original hash recorded
        e2 = [e for e in m["exchanges"] if e["exchange"] == "000002"][0]["files"]["response.body"]
        assert not e2["changed"] and e2["original_sha256"] == e2["sanitized_sha256"]
        e1 = [e for e in m["exchanges"] if e["exchange"] == "000001"][0]["files"]["response.body"]
        rawmeta = json.load(open(os.path.join(raw, "000001", "meta.json")))
        assert e1["original_sha256"] == rawmeta["response_body_sha256"] and e1["changed"]
        loc = open(os.path.join(out, "000005", "response.headers"), "rb").read().decode()
        assert "sig=REDACTED&se=REDACTED" in loc, loc
        assert "abcdef" not in json.dumps(m) and "sessionsecret" not in json.dumps(m)
        assert json.load(open(os.path.join(out, "000002", "meta.json")))["path"].endswith("?token=REDACTED&Expires=REDACTED")
        # residual detection
        red2 = Redactor(["Content-Type"], [], [], [])
        out2 = os.path.join(tmp, "clean2")
        m2 = sanitize_tree(raw, out2, Redactor(["abcdefXYZ"], [], [], []), False)
        assert not m2["residual"]
        os.mkdir(os.path.join(tmp, "raw3"))
        os.mkdir(os.path.join(tmp, "raw3", "000001"))
        open(os.path.join(tmp, "raw3", "000001", "response.body"), "wb").write(b"\x00\x01hostA\x02")
        m3 = sanitize_tree(os.path.join(tmp, "raw3"), os.path.join(tmp, "out3"),
                           Redactor(["hostA"], [], [], []), False)
        assert m3["residual"], "residual scan should flag binary content"
    print("sanitize-capture self-test passed")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("raw", nargs="?", help="raw capture directory from capture-proxy.py")
    ap.add_argument("out", nargs="?", help="output directory for the sanitized copy (must not exist or be empty)")
    ap.add_argument("--redact", action="append", metavar="VALUE", help="hostname, IP, computer name or other literal to redact (repeatable)")
    ap.add_argument("--redact-file", action="append", metavar="FILE", help="file with one value per line")
    ap.add_argument("--redact-header", action="append", default=[], metavar="NAME", help="extra header names to redact")
    ap.add_argument("--redact-element", action="append", default=[], metavar="NAME", help="extra XML element names whose text is redacted")
    ap.add_argument("--keep-query-param", action="append", default=[], metavar="NAME", help="query parameter whose value is kept")
    ap.add_argument("--omit-binary-bodies", action="store_true", help="write empty files for non-text bodies (hashes stay in the manifest)")
    ap.add_argument("--allow-residual", action="store_true", help="exit 0 even if a --redact value remains in the output")
    ap.add_argument("--self-test", action="store_true", help="run an end to end test with a local fake upstream")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if not a.raw or not a.out:
        ap.error("raw and out directories are required")
    red = Redactor(load_values(a), DEFAULT_REDACT_HEADERS + a.redact_header,
                   DEFAULT_REDACT_ELEMENTS + a.redact_element, a.keep_query_param)
    m = sanitize_tree(a.raw, a.out, red, a.omit_binary_bodies)
    print("sanitized %d exchanges into %s" % (len(m["exchanges"]), a.out))
    for k, v in m["redaction_totals"].items():
        print("  %s: %d" % (k, v))
    if m["residual"]:
        print("RESIDUAL: %d file(s) still contain a --redact value; see sanitize-manifest.json" % len(m["residual"]), file=sys.stderr)
        if not a.allow_residual:
            sys.exit(3)


if __name__ == "__main__":
    main()
