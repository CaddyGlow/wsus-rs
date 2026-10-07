# WSUS capture tooling (milestone M0)

Two stdlib-only Python 3 scripts for recording real WSUS exchanges and turning
them into shareable fixtures. See `docs/wsus-implementation-plan.md` sections 3
and 15 and `docs/wsus-protocol-inventory.md`.

## Rule: raw captures are never committed

Raw captures contain cookies, `EncryptedData` blobs, signed URLs, hostnames, IP
addresses, computer names and SIDs. Keep them outside version control, in a
gitignored directory. The repository `.gitignore` does not yet cover this; add
a line such as `/captures-raw/` (or use a directory outside the repository,
for example `~/wsus-captures-raw/`). Only the output of `sanitize-capture.py`,
after review, may be committed (for example under `crates/.../tests/fixtures/`).
The proxy creates directories mode 0700 and files mode 0600.

## capture-proxy.py

```
scripts/wsus/capture-proxy.py --out captures-raw/run1 \
    [--upstream http://10.83.20.149:8530] [--listen 127.0.0.1] [--port 8530]
```

Point the client (WUA policy, `wuauclt`, or a test tool) at the proxy instead
of the WSUS server. The proxy forwards each request unchanged and streams the
response back unchanged: SOAP POSTs, large content GETs, `Range`/206, gzip
(`Content-Encoding` is never decoded) and chunked responses. Each exchange is
written to `<out>/NNNNNN/`:

| File | Content |
| --- | --- |
| `request.headers` | request line and headers as received (raw text) |
| `request.body` | request body bytes |
| `response.headers` | upstream status line and headers (raw text) |
| `response.body` | response body bytes exactly as sent by upstream |
| `meta.json` | timestamp, method, path, SOAPAction, status, error, durations (total, connect, first byte, request sent, body), body sizes and sha256 |

Notes and limits:

- HTTP only (WSUS default port 8530). TLS upstreams are not supported.
- Hop-by-hop headers are dropped, `Expect` is dropped, and `Connection: close`
  is used upstream (one upstream connection per exchange). Connection-bound
  authentication (NTLM/Kerberos) is therefore not preserved; WSUS client
  endpoints are anonymous.
- The client `Host` header is forwarded unchanged. If the upstream rejects it
  or emits URLs that must match, use `--upstream-host`. Server-generated URLs
  that name the real WSUS host appear in responses as-is; that is evidence, and
  also something to redact (below).
- Chunked request bodies are decoded and forwarded with `Content-Length`;
  `meta.json` notes `request_was_chunked`.
- The default bind is loopback. Binding elsewhere (for a guest VM) has no
  access control; use an isolated network.
- Stdout carries only `#NNNNNN METHOD path status ok|ERR bytes ms` lines. No
  headers, bodies or query strings are printed. Upstream failures return 502 and
  are recorded in `meta.json`.

## sanitize-capture.py

```
scripts/wsus/sanitize-capture.py captures-raw/run1 sanitized/run1 \
    --redact 10.83.20.149 --redact wsus01.corp.example --redact WSUS01 \
    --redact-file extra-values.txt
```

Redacted by default:

- Header values: `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`
  (more via `--redact-header`).
- Element text of `EncryptedData`, `CookieData`, `Password` (more via
  `--redact-element`). Base64 content is replaced by `A` characters of the same
  length so decoders still see valid base64 of the same shape.
- Every URL query value in bodies, headers, request lines and `meta.json`;
  parameter names are kept (`?sig=REDACTED&se=REDACTED`). Keep chosen values
  with `--keep-query-param`.
- Domain SIDs `S-1-5-21-...` become stable placeholders (well-known SIDs stay).
- Every `--redact` value, case-insensitive and URL-encoded forms included.
  IPv4 addresses become `192.0.2.N`, dotted names `hostN.invalid`, others
  `REDACTEDN`, consistently across the run. Computer names and hostnames are
  only redacted when you list them, so list every one you know of, including
  ones that appear in `DnsName`, `ClientId` and `TargetID` elements.

Behavior:

- gzip/deflate text bodies are decompressed, redacted, recompressed as gzip and
  `Content-Length` is updated. Unchanged bodies are copied byte for byte.
- Non-text bodies (CABs, ESD, binaries) are copied unchanged, or emptied with
  `--omit-binary-bodies`. They are only scanned for literal `--redact` values.
- `sanitize-manifest.json` records, per exchange and file, the sha256 and size
  of the ORIGINAL and the sanitized content, the treatment, and redaction counts
  by category. It never contains redacted values. The sanitized `meta.json` has
  the client address removed and body hashes replaced by the sanitized ones.
- After writing, every output file is scanned for the `--redact` values (plain,
  UTF-16LE, URL-encoded). Any hit is listed under `residual` in the manifest and
  the script exits 3 (`--allow-residual` to override).
- The output directory must be empty or absent and outside the raw directory.

Review the sanitized output by eye before committing: the scripts cannot know
about secrets they were not told about (for example a hostname in an
unlisted form, or secrets inside compressed binary payloads).

## Self-tests

```
python3 scripts/wsus/capture-proxy.py --self-test
python3 scripts/wsus/sanitize-capture.py --self-test
```

Both use a fake upstream on loopback only and contact no other host. The first
checks byte-exact pass-through (gzip, 3 MiB GET, Range, chunked, HEAD, redirect)
and recorded hashes. The second runs the full capture then sanitize pipeline and
checks that secrets are gone, XML still parses, original hashes are in the
manifest, and the residual scan fires.

## probe-wsusss.py (milestone M5)

```
scripts/wsus/probe-wsusss.py --origin http://10.83.20.149:8530 \
    --cabextract ../cabinet/target/debug/cabextract categories
scripts/wsus/probe-wsusss.py --origin ... revisions --product GUID --classification GUID \
    [--anchor 'N,YYYY-MM-DD HH:MM:SS.fff'] [--delta]
scripts/wsus/probe-wsusss.py --origin ... update-data UPDATEID@REV [...] --out-dir DIR
```

A stateless MS-WSUSSS probe for a lab upstream: it runs the anonymous DSS handshake
and one operation, and it contacts only the `--origin` you give (point `--origin` at
`capture-proxy.py` to record the exchange). `categories` lists the products and
classifications with ids (needs a `cabextract`, for example the one
`cargo build --manifest-path ../cabinet/Cargo.toml --features cli` builds, to read `XmlUpdateBlobCompressed`). It is
not this project's client; `docs/fixtures/wsus-m0-wsusss/README.md` records which
fixtures came from it and which from the Rust importer.
