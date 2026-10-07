#!/usr/bin/env python3
"""Minimal MS-WSUSSS probe for a lab upstream WSUS (milestone M5). Stdlib only.

Plain SOAP 1.1 POSTs, no state: every command runs the DSS handshake
(GetAuthConfig is skipped, the authorization service path is fixed) and then one
operation. It exists to look at what a real upstream sends and to produce the
exchanges that `capture-proxy.py` records (point --origin at the proxy). It is NOT
this project's client (`wsus-client`), and it contacts only the origin you give it.

    probe-wsusss.py --origin http://10.83.20.149:8530 categories
    probe-wsusss.py --origin ... revisions --config
    probe-wsusss.py --origin ... revisions --product GUID --classification GUID \\
        [--anchor 'N,YYYY-MM-DD HH:MM:SS.fff'] [--delta]
    probe-wsusss.py --origin ... update-data UPDATEID@REV [...] [--out-dir DIR]

`XmlUpdateBlobCompressed` is a Cabinet with one LZX member `blob` holding UTF-16LE XML
(inventory 9.5). Decoding needs a cabextract: pass `--cabextract` pointing at the
sibling cabinet repository's `cabextract` binary (`cargo build --manifest-path ../cabinet/Cargo.toml --features cli`) or any tool with
the interface `CABEXTRACT -o NEWDIR FILE.cab`.
"""
import argparse
import base64
import html
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

NS = "http://www.microsoft.com/SoftwareDistribution"
DSS_NS = NS + "/Server/DssAuthWebService"
SYNC = "/ServerSyncWebService/ServerSyncWebService.asmx"
AUTH = "/DssAuthWebService/DssAuthWebService.asmx"


def post(origin, path, action, body):
    env = (
        '<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        + body
        + "</soap:Body></soap:Envelope>"
    )
    req = urllib.request.Request(
        origin + path,
        data=env.encode(),
        headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action}"'},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as f:
            return f.status, f.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def handshake(origin, account, guid):
    status, body = post(
        origin,
        AUTH,
        DSS_NS + "/GetAuthorizationCookie",
        f'<GetAuthorizationCookie xmlns="{DSS_NS}"><accountName>{account}</accountName>'
        f"<accountGuid>{guid}</accountGuid></GetAuthorizationCookie>",
    )
    m = re.search(r"<CookieData>(.*?)</CookieData>", body)
    if status != 200 or not m:
        sys.exit(f"GetAuthorizationCookie failed: {status} {body[:300]}")
    status, body = post(
        origin,
        SYNC,
        NS + "/GetCookie",
        f'<GetCookie xmlns="{NS}"><authCookies><AuthorizationCookie><PlugInId>DssTargeting'
        f"</PlugInId><CookieData>{m.group(1)}</CookieData></AuthorizationCookie></authCookies>"
        "<protocolVersion>1.20</protocolVersion></GetCookie>",
    )
    m = re.search(r"<GetCookieResult>(.*?)</GetCookieResult>", body, re.S)
    if status != 200 or not m:
        sys.exit(f"GetCookie failed: {status} {body[:300]}")
    return "<cookie>" + m.group(1) + "</cookie>"


def call(origin, cookie, op, inner):
    return post(origin, SYNC, f"{NS}/{op}", f'<{op} xmlns="{NS}">{cookie}{inner}</{op}>')


def revisions(body):
    return re.findall(r"<UpdateID>(.*?)</UpdateID><RevisionNumber>(\d+)", body)


def update_ids(ids):
    return "<updateIds>" + "".join(
        f"<UpdateIdentity><UpdateID>{i}</UpdateID><RevisionNumber>{r}</RevisionNumber>"
        "</UpdateIdentity>" for i, r in ids
    ) + "</updateIds>"


def documents(body, cabextract):
    """Yield ((id, rev), xml text) for each item of a GetUpdateData response."""
    for item in re.findall(r"<ServerSyncUpdateData>(.*?)</ServerSyncUpdateData>", body, re.S):
        ident = re.search(r"<UpdateID>(.*?)</UpdateID><RevisionNumber>(\d+)", item).groups()
        blob = re.search(r"<XmlUpdateBlobCompressed>(.*?)</XmlUpdateBlobCompressed>", item, re.S)
        if blob:
            if not cabextract:
                yield ident, None
                continue
            with tempfile.TemporaryDirectory() as d:
                cab = os.path.join(d, "a.cab")
                with open(cab, "wb") as f:
                    f.write(base64.b64decode(blob.group(1)))
                subprocess.run(
                    [cabextract, "-o", os.path.join(d, "o"), cab], check=True, capture_output=True
                )
                with open(os.path.join(d, "o", "blob"), "rb") as f:
                    yield ident, f.read().decode("utf-16-le")
        else:
            text = re.search(r"<XmlUpdateBlob>(.*?)</XmlUpdateBlob>", item, re.S)
            yield ident, html.unescape(text.group(1)) if text else None


def id_list(tag, ids, delta):
    if not ids:
        return ""
    return f"<{tag}>" + "".join(
        f"<IdAndDelta><Id>{i}</Id><Delta>{'true' if delta else 'false'}</Delta></IdAndDelta>"
        for i in ids
    ) + f"</{tag}>"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--origin", required=True)
    ap.add_argument("--account", default="probe.lab.invalid")
    ap.add_argument("--guid", default="6f1c2f6e-3f0b-4d3a-9b1e-0d2f6a1c5e12")
    ap.add_argument("--cabextract", help="path of a cabextract (for compressed blobs)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("categories", help="list products and classifications with titles")
    r = sub.add_parser("revisions")
    r.add_argument("--config", action="store_true", help="GetConfig=true (categories)")
    r.add_argument("--anchor")
    r.add_argument("--product", action="append", default=[])
    r.add_argument("--classification", action="append", default=[])
    r.add_argument("--delta", action="store_true")
    u = sub.add_parser("update-data")
    u.add_argument("ids", nargs="+", help="UPDATEID@REVISION")
    u.add_argument("--out-dir")
    args = ap.parse_args()

    cookie = handshake(args.origin, args.account, args.guid)
    if args.cmd == "revisions":
        flt = (
            (f"<Anchor>{args.anchor}</Anchor>" if args.anchor else "")
            + f"<GetConfig>{'true' if args.config else 'false'}</GetConfig>"
            + id_list("Categories", args.product, args.delta)
            + id_list("Classifications", args.classification, args.delta)
        )
        status, body = call(args.origin, cookie, "GetRevisionIdList", f"<filter>{flt}</filter>")
        anchor = re.search(r"<Anchor>(.*?)</Anchor>", body)
        print(status, "revisions", len(revisions(body)), "anchor", anchor.group(1) if anchor else None)
    elif args.cmd == "update-data":
        ids = [tuple(i.split("@")) for i in args.ids]
        status, body = call(args.origin, cookie, "GetUpdateData", update_ids(ids))
        print(status, len(body), "bytes")
        for ident, xml in documents(body, args.cabextract):
            print(ident, None if xml is None else f"{len(xml)} characters")
            if args.out_dir and xml is not None:
                os.makedirs(args.out_dir, exist_ok=True)
                with open(os.path.join(args.out_dir, f"{ident[0]}-r{ident[1]}.xml"), "w", encoding="utf-8") as f:
                    f.write(xml)
    else:
        status, body = call(args.origin, cookie, "GetRevisionIdList", "<filter><GetConfig>true</GetConfig></filter>")
        ids = revisions(body)
        for i in range(0, len(ids), 100):
            status, body = call(args.origin, cookie, "GetUpdateData", update_ids(ids[i : i + 100]))
            for ident, xml in documents(body, args.cabextract):
                m = re.search(r'CategoryType="(\w+)"', xml or "")
                if m and m.group(1) in ("Product", "UpdateClassification"):
                    title = re.findall(r"<upd:Title>(.*?)</upd:Title>", xml)
                    en = re.search(r"<upd:Language>en</upd:Language><upd:Title>(.*?)</upd:Title>", xml)
                    print(m.group(1), ident[0], ident[1], en.group(1) if en else (title[0] if title else ""))


if __name__ == "__main__":
    main()
