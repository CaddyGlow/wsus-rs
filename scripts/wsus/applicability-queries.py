#!/usr/bin/env python3
"""List every distinct fact query the stored WSUS catalog needs.

Reads the revision JSON files kept by the WUSP client (default
~/vm-lab/wsus-m0/client-run5/state/meta/revisions, env WSUS_REAL_REVISIONS;
each file holds the Core fragment text under core.xml), walks every
ApplicabilityRules element with the same rules as the Rust evaluator
(crates/wsus-protocol/src/applicability) and writes queries.json:

    {"schema": "wsus-applicability-queries/1", "generated": "...", "queries": [
        {"kind": "reg_value", "view": "native", "subkey": "SOFTWARE\\X",
         "value": "V", "updates": ["<update-id>_<revision>", ...]}, ...]}

The query objects are exactly the fact entries of the snapshot format that
scripts/wsus/collect-facts.ps1 writes (minus "result"), so the collector
echoes them back. Queries inside a RegKeyLoop body that name HKEY_LOOP_TARGET
carry "loop_parent" (the loop key) and a sub-key relative to each child; the
collector expands them per child.

Only operators the Rust evaluator implements and accepts are walked: an
element that is unknown, malformed, or carries an attribute the evaluator does
not model is unsupported and contributes no query, like the Rust parser. OS
wide facts (Windows version, architecture, language, MUI) are not queries;
the collector always records them.

Usage: applicability-queries.py [--revisions DIR] [--out queries.json]
Python 3, standard library only.
"""
import argparse
import datetime
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_REVISIONS = Path.home() / "vm-lab/wsus-m0/client-run5/state/meta/revisions"
MAX_DEPTH = 128

NS = {
    "schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules": "base",
    "schemas.microsoft.com/msus/2002/12/MsiApplicabilityRules": "msi",
    "schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules": "logical",
    "schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsDriver": "driver",
}
UPDATE_NS = "schemas.microsoft.com/msus/2002/12/Update"
PREFIX = {"b": "base", "bar": "base", "m": "msi", "msiar": "msi", "msi": "msi",
          "d": "driver", "drv": "driver", "l": "logical", "lar": "logical"}

LOGICAL = {"And", "Or", "Not", "True", "False"}
BASE = {"RegKeyExists", "RegValueExists", "RegDword", "RegSz", "RegExpandSz",
        "RegSzToVersion", "RegKeyLoop", "FileExists", "FileExistsPrependRegSz",
        "FileVersion", "FileVersionPrependRegSz", "FileCreated",
        "FileCreatedPrependRegSz", "FileModified", "FileModifiedPrependRegSz",
        "FileSize", "FileSizePrependRegSz", "WindowsVersion", "WindowsLanguage",
        "MuiInstalled", "MuiLanguageInstalled", "SystemMetric", "Processor", "Platform",
        "NumberOfProcessors", "ClusteredOS", "ClusterResourceOwner", "WmiQuery",
        "InstalledOnce", "GenericQuery", "LicenseDword"}
MSI = {"MsiProductInstalled", "MsiFeatureInstalledForProduct",
       "MsiComponentInstalledForProduct", "MsiPatchInstalledForProduct",
       "MsiPatchInstalled", "MsiPatchSuperseded", "MsiPatchInstallable",
       "MsiApplicationInstalled", "MsiApplicationSuperseded",
       "MsiApplicationInstallable"}
ANYFAM = {"CbsPackageInstalledByIdentity", "ProductReleaseVersion"}
NO_SEMANTICS = {"ProductReleaseVersion", "Platform", "MuiLanguageInstalled", "NumberOfProcessors",
                "ClusteredOS", "ClusterResourceOwner", "InstalledOnce", "GenericQuery",
                "MsiPatchInstalled", "MsiPatchSuperseded", "MsiPatchInstallable",
                "MsiApplicationInstalled", "MsiApplicationSuperseded",
                "MsiApplicationInstallable"}


class Bad(Exception):
    pass


def expected_family(name):
    if name in LOGICAL:
        return "logical"
    if name in BASE:
        return "base"
    if name in MSI:
        return "msi"
    if name in ANYFAM:
        return None
    raise Bad("unknown operator")


def split_tag(tag):
    """(declared family or None, bare name) for an ElementTree tag."""
    ns = None
    if tag.startswith("{"):
        ns, tag = tag[1:].split("}", 1)
    m = re.search(r"[.:]", tag)
    prefix, bare = (tag[: m.start()], tag[m.end():]) if m else (None, tag)
    fam_p = None
    if prefix is not None:
        fam_p = PREFIX.get(prefix.lower())
        if fam_p is None:
            raise Bad("unknown prefix")
    fam_n = None
    if ns is not None:
        n = re.sub(r"^https?://", "", ns.strip())
        if n == UPDATE_NS:
            fam_n = None
        elif n in NS:
            fam_n = NS[n]
        else:
            raise Bad("unknown namespace")
    if fam_p and fam_n and fam_p != fam_n:
        raise Bad("prefix/namespace mismatch")
    return fam_p or fam_n, bare


def is_dec(s, maxv=None):
    t = s.strip()
    return bool(re.fullmatch(r"[0-9]+", t)) and (maxv is None or int(t) <= maxv)


def is_int32(s):
    return bool(re.fullmatch(r"[+-]?[0-9]+", s.strip())) and -2**31 <= int(s) < 2**31


def is_bool(s):
    return s.strip() in ("true", "false", "1", "0")


def is_version(s):
    t = s.strip()
    return bool(re.fullmatch(r"[0-9]+(\.[0-9]+){3}", t)) and all(int(p) < 2**32 for p in t.split("."))


def is_msi_version(s):
    t = s.strip()
    return bool(re.fullmatch(r"[0-9]+(\.[0-9]+){0,3}", t)) and all(int(p) < 2**32 for p in t.split("."))


def is_time(s):
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})", s.strip())
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    try:
        datetime.datetime(y, mo, d, h, mi, se)
    except ValueError:
        return False
    z = m.group(8)
    if z != "Z" and (int(z[1:3]) > 23 or int(z[4:6]) > 59):
        return False
    return True


def is_cmp(s):
    return s.strip().lower() in ("lessthan", "lessthanorequalto", "equalto",
                                 "greaterthanorequalto", "greaterthan")


def is_strcmp(s):
    return s.strip().lower() in ("equalto", "beginswith", "contains", "endswith")


def is_loop(s):
    return s.strip().lower() in ("any", "all", "none")


def is_regtype(s):
    return s.strip().upper().startswith("REG_")


def canon_key(s):
    return re.sub(r"\\+", r"\\", s.replace("/", "\\")).strip("\\").lower()


def canon_guid(s):
    return "{" + s.strip().lstrip("{").rstrip("}").upper() + "}"


# attribute spec: name -> validator (None means any string)
KEYR = {"Key": None, "Subkey": None}          # required key attributes
KEYO = {"RegType32": is_bool}                  # optional key attributes
VALR = dict(KEYR, Value=None)                  # required value attributes


def spec(**kw):
    return kw


def check(el, required, optional, no_children=True):
    """Raise Bad unless attributes match; no unqualified extras allowed."""
    attrs = {k: v for k, v in el.attrib.items() if not k.startswith("{")}
    for k, v in attrs.items():
        validator = required.get(k, optional.get(k, "missing"))
        if validator == "missing":
            raise Bad("unexpected attribute " + k)
        if validator is not None and not validator(v):
            raise Bad("bad attribute " + k)
    for k in required:
        if k not in attrs:
            raise Bad("missing attribute " + k)
    if no_children and len(el):
        raise Bad("unexpected children")
    return attrs


def key_of(attrs):
    if attrs["Key"].strip() not in ("HKEY_LOCAL_MACHINE", "HKEY_LOOP_TARGET"):
        raise Bad("bad Key")
    view = "wow32" if attrs.get("RegType32", "false").strip() in ("true", "1") else "native"
    return attrs["Key"].strip() == "HKEY_LOOP_TARGET", view, attrs["Subkey"]


def file_loc(el, attrs, prepend):
    if prepend:
        loop, view, sub = key_of(attrs)
        if loop:
            raise Bad("loop target in PrependRegSz")
        return {"kind": "reg_sz", "view": view, "subkey": sub, "value": attrs["Value"]}
    if "Csidl" in attrs:
        return {"kind": "csidl", "csidl": int(attrs["Csidl"])}
    return {"kind": "absolute"}


def children_texts(el, name):
    out = []
    for c in el:
        tag = c.tag.split("}")[-1]
        bare = re.split(r"[.:]", tag)[-1]
        if bare != name:
            continue
        t = (c.text or "").strip()
        if not t:
            raise Bad("empty " + name)
        out.append(t)
    if not out:
        raise Bad("no " + name)
    return out


def only_children(el, names):
    for c in el:
        tag = c.tag.split("}")[-1]
        if re.split(r"[.:]", tag)[-1] not in names:
            raise Bad("unexpected child")


class Walker:
    def __init__(self):
        self.out = []

    def emit(self, q, loop_parent=None):
        self.out.append((q, loop_parent))

    def walk(self, el, lp, depth=0):
        if depth >= MAX_DEPTH:
            return
        try:
            declared, bare = split_tag(el.tag)
            exp = expected_family(bare)
            if declared and exp and declared != exp:
                raise Bad("wrong family")
            self.known(el, bare, lp, depth)
        except Bad:
            return

    def kids(self, el, lp, depth):
        return list(el)

    def known(self, el, bare, lp, depth):
        if bare in ("True", "False"):
            check(el, {}, {})
            return
        if bare in ("And", "Or", "Not"):
            check(el, {}, {}, no_children=False)
            kids = list(el)
            if not kids or (bare == "Not" and len(kids) != 1):
                raise Bad("operands")
            for k in kids:
                self.walk(k, lp, depth + 1)
            return
        if bare in NO_SEMANTICS:
            raise Bad("no semantics")
        if bare == "RegKeyLoop":
            a = check(el, dict(KEYR, TrueIf=is_loop), KEYO, no_children=False)
            if len(el) != 1:
                raise Bad("loop body")
            loop, view, sub = key_of(a)
            if loop:
                # nested loop through a loop target: not supported by the walker
                return
            self.emit({"kind": "reg_subkeys", "view": view, "subkey": sub})
            self.walk(el[0], (view, sub), depth + 1)
            return
        if bare == "RegKeyExists":
            a = check(el, KEYR, KEYO)
            self.reg(a, None, lp)
            return
        if bare == "RegValueExists":
            a = check(el, KEYR, dict(KEYO, Value=None, Type=is_regtype))
            self.reg(a, a.get("Value", ""), lp)
            return
        if bare == "RegDword":
            a = check(el, dict(VALR, Comparison=is_cmp, Data=lambda s: is_dec(s, 2**32 - 1)), KEYO)
            self.reg(a, a["Value"], lp)
            return
        if bare in ("RegSz", "RegExpandSz"):
            a = check(el, dict(VALR, Comparison=is_strcmp, Data=None), KEYO)
            self.reg(a, a["Value"], lp)
            return
        if bare == "RegSzToVersion":
            a = check(el, dict(VALR, Comparison=is_cmp, Data=is_version), KEYO)
            self.reg(a, a["Value"], lp)
            return
        if bare.startswith("File"):
            prepend = bare.endswith("PrependRegSz")
            base = bare[: -len("PrependRegSz")] if prepend else bare
            extra = dict(VALR) if prepend else {}
            opt = dict(KEYO) if prepend else {"Csidl": is_int32}
            if base == "FileExists":
                req = dict(Path=None, **extra)
                opt = dict(opt, Size=lambda s: is_dec(s, 2**64 - 1), Version=is_version)
            elif base == "FileVersion":
                req = dict(Path=None, Comparison=is_cmp, Version=is_version, **extra)
            elif base == "FileCreated":
                req = dict(Path=None, Comparison=is_cmp, Created=is_time, **extra)
            elif base == "FileModified":
                req = dict(Path=None, Comparison=is_cmp, Modified=is_time, **extra)
            elif base == "FileSize":
                req = dict(Path=None, Comparison=is_cmp, Size=lambda s: is_dec(s, 2**64 - 1), **extra)
            else:
                raise Bad("file op")
            a = check(el, req, opt)
            self.emit({"kind": "file", "location": file_loc(el, a, prepend), "path": a["Path"]})
            return
        if bare in ("WindowsVersion", "WindowsLanguage", "MuiInstalled", "Processor"):
            return  # OS-wide facts
        if bare == "SystemMetric":
            a = check(el, dict(Comparison=is_cmp, Index=is_int32, Value=is_int32), {})
            self.emit({"kind": "system_metric", "index": int(a["Index"])})
            return
        if bare == "LicenseDword":
            a = check(el, dict(Value=None, Comparison=is_cmp, Data=lambda s: is_dec(s, 2**32 - 1)), {})
            self.emit({"kind": "license_dword", "name": a["Value"]})
            return
        if bare == "WmiQuery":
            a = check(el, dict(WqlQuery=None), {"Namespace": None})
            self.emit({"kind": "wmi_query", "namespace": a.get("Namespace", "root\\cimv2"),
                       "query": a["WqlQuery"]})
            return
        if bare == "MsiProductInstalled":
            a = check(el, dict(ProductCode=None),
                      dict(VersionMin=is_msi_version, VersionMax=is_msi_version,
                           ExcludeVersionMin=is_bool, ExcludeVersionMax=is_bool,
                           Language=is_dec))
            self.emit({"kind": "msi_product", "product": canon_guid(a["ProductCode"])})
            return
        if bare == "MsiFeatureInstalledForProduct":
            a = check(el, {}, dict(AllFeaturesRequired=is_bool, AllProductsRequired=is_bool),
                      no_children=False)
            only_children(el, ("Feature", "Product"))
            feats, prods = children_texts(el, "Feature"), children_texts(el, "Product")
            for p in prods:
                for f in feats:
                    self.emit({"kind": "msi_feature", "product": canon_guid(p), "feature": f})
            return
        if bare == "MsiComponentInstalledForProduct":
            a = check(el, {}, dict(AllComponentsRequired=is_bool, AllProductsRequired=is_bool),
                      no_children=False)
            only_children(el, ("Component", "Product"))
            comps, prods = children_texts(el, "Component"), children_texts(el, "Product")
            for p in prods:
                for c in comps:
                    self.emit({"kind": "msi_component", "product": canon_guid(p),
                               "component": canon_guid(c)})
            return
        if bare == "MsiPatchInstalledForProduct":
            a = check(el, dict(PatchCode=None, ProductCode=None), {})
            self.emit({"kind": "msi_patch", "product": canon_guid(a["ProductCode"]),
                       "patch": canon_guid(a["PatchCode"])})
            return
        if bare == "CbsPackageInstalledByIdentity":
            a = check(el, dict(PackageIdentity=None), {})
            self.emit({"kind": "cbs_package", "identity": a["PackageIdentity"].strip()})
            return
        raise Bad("unknown")

    def reg(self, attrs, value, lp):
        loop, view, sub = key_of(attrs)
        if loop:
            if lp is None:
                return
            view, parent = lp
            q = {"kind": "reg_key", "view": view, "subkey": sub} if value is None else \
                {"kind": "reg_value", "view": view, "subkey": sub, "value": value}
            self.emit(q, parent)
            return
        if value is None:
            self.emit({"kind": "reg_key", "view": view, "subkey": sub})
        else:
            self.emit({"kind": "reg_value", "view": view, "subkey": sub, "value": value})


def norm_key(q, loop_parent):
    """De-duplication key, the same normalisation as the Rust FactQuery."""
    k = q["kind"]
    if k in ("reg_key", "reg_subkeys"):
        n = (k, q["view"], canon_key(q["subkey"]))
    elif k == "reg_value":
        n = (k, q["view"], canon_key(q["subkey"]), q["value"].lower())
    elif k == "file":
        loc = q["location"]
        if loc["kind"] == "reg_sz":
            loc = ("reg_sz", loc["view"], canon_key(loc["subkey"]), loc["value"].lower())
        else:
            loc = tuple(sorted(loc.items()))
        n = (k, loc, re.sub(r"\\+", r"\\", q["path"].replace("/", "\\")).strip("\\").lower())
    elif k == "license_dword":
        n = (k, q["name"].lower())
    elif k == "wmi_query":
        n = (k, canon_key(q["namespace"]), q["query"].strip())
    elif k == "msi_feature":
        n = (k, q["product"], q["feature"].lower())
    elif k == "cbs_package":
        n = (k, q["identity"].lower())
    else:
        n = (k,) + tuple(v for _, v in sorted(q.items()) if _ != "kind")
    return n + (canon_key(loop_parent) if loop_parent else None,)


def rules_xml(core):
    m = re.search(r"<ApplicabilityRules\b.*?</ApplicabilityRules>|<ApplicabilityRules\s*/>", core, re.S)
    return m.group(0) if m else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revisions", default=os.environ.get("WSUS_REAL_REVISIONS", str(DEFAULT_REVISIONS)))
    ap.add_argument("--out", default="queries.json")
    args = ap.parse_args()
    rev_dir = Path(args.revisions)
    if not rev_dir.is_dir():
        print(f"revisions directory not found: {rev_dir}", file=sys.stderr)
        return 1
    queries = {}
    n_rev = n_rules = n_bad = 0
    for path in sorted(rev_dir.glob("*.json")):
        d = json.loads(path.read_text())
        n_rev += 1
        text = rules_xml(d["core"]["xml"])
        if text is None:
            continue
        n_rules += 1
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            n_bad += 1
            continue
        w = Walker()
        for section in root:
            sname = re.split(r"[.:]", section.tag.split("}")[-1])[-1]
            if sname in ("IsInstalled", "IsInstallable", "IsSuperseded"):
                for c in section:
                    w.walk(c, None)
        stem = path.stem
        for q, parent in w.out:
            k = norm_key(q, parent)
            item = queries.setdefault(k, {"query": q, "loop_parent": parent, "updates": []})
            if stem not in item["updates"]:
                item["updates"].append(stem)
    out = []
    for item in queries.values():
        e = dict(item["query"])
        if item["loop_parent"]:
            e["loop_parent"] = item["loop_parent"]
        e["updates"] = item["updates"]
        out.append(e)
    doc = {
        "schema": "wsus-applicability-queries/1",
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": str(rev_dir),
        "revisions": n_rev,
        "revisions_with_rules": n_rules,
        "queries": out,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
    kinds = {}
    for e in out:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"{n_rev} revisions, {n_rules} with rules ({n_bad} unparsable), {len(out)} distinct queries -> {args.out}")
    for k, c in sorted(kinds.items(), key=lambda x: -x[1]):
        print(f"  {k:14} {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
