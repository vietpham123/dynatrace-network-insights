#!/usr/bin/env python3
"""
Bundle the modules/*-extension source trees into base64 zips embedded in the app for
download-to-build. Regenerates network-insights-app/ui/app/lib/extensionBundles.ts.

Run after editing any modules/*-extension (from anywhere):
    python3 scripts/bundle_extensions.py
"""
import zipfile, base64, io, os, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")
OUT_TS = os.path.join(ROOT, "network-insights-app/ui/app/lib/extensionBundles.ts")

BUNDLES = [
    {"dir": "netbox-extension",             "name": "custom:cno.network.netbox",       "display": "NetBox source",              "file": "cno-netbox-extension-source.zip",       "kind": "python"},
    {"dir": "oxidized-extension",           "name": "custom:cno.network.compliance",   "display": "Compliance / config-change", "file": "cno-compliance-extension-source.zip",   "kind": "python"},
    {"dir": "snmp-interfaces-extension",    "name": "custom:cno.network.interfaces",   "display": "SNMP interfaces",            "file": "cno-snmp-extension-source.zip",         "kind": "declarative"},
    # The two halves of topology, and they are useless apart. controlplane PRODUCES cno.dep.uses by
    # polling LLDP; dependency CONSUMES it and materialises the Smartscape edges. Only the consumer
    # was ever bundled, so anyone following the app could build the half that renders topology and
    # had no way to get the half that discovers it — the page then sits empty with nothing to blame.
    {"dir": "controlplane-extension",       "name": "custom:cno.network.controlplane", "display": "LLDP topology (producer)",   "file": "cno-controlplane-extension-source.zip", "kind": "python"},
    {"dir": "network-dependency-extension", "name": "custom:cno.network.dependency",   "display": "Dependency / topology",      "file": "cno-dependency-extension-source.zip",   "kind": "declarative"},
]

# Build artefacts, never source. controlplane-extension carries build/, dist/ and two stale
# *.egg-info trees totalling ~580K — including dist/*.zip, a BUILT copy of the very extension
# being bundled, which would nest a signed artefact inside the source download.
SKIP_DIRS = {"__pycache__", "build", "dist", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}


def _skip(dirpath: str, root: str) -> bool:
    parts = os.path.relpath(dirpath, root).split(os.sep)
    return any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts)


def main():
    out = []
    for b in BUNDLES:
        root = os.path.join(MODULES, b["dir"])
        if not os.path.isdir(root):
            print(f"MISSING {b['dir']}"); continue
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for dp, _, files in os.walk(root):
                if _skip(dp, root):
                    continue
                for f in sorted(files):
                    if f.endswith(".pyc") or f.endswith(".egg-link"):
                        continue
                    full = os.path.join(dp, f)
                    z.write(full, os.path.join(b["dir"], os.path.relpath(full, root)))
        out.append({**b, "b64": base64.b64encode(buf.getvalue()).decode(), "bytes": len(buf.getvalue())})

    ts  = "// AUTO-GENERATED — extension source bundles (base64 zips) for download-to-build.\n"
    ts += "// Regenerate with scripts/bundle_extensions.py after editing any modules/*-extension.\n"
    ts += "export type ExtBundle = { name: string; display: string; file: string; kind: \"python\" | \"declarative\"; b64: string };\n\n"
    ts += "export const EXTENSION_BUNDLES: Record<string, ExtBundle> = {\n"
    for b in out:
        ts += (f'  "{b["dir"]}": {{ name: {json.dumps(b["name"])}, display: {json.dumps(b["display"])}, '
               f'file: {json.dumps(b["file"])}, kind: {json.dumps(b["kind"])}, b64: {json.dumps(b["b64"])} }},\n')
    ts += "};\n"
    with open(OUT_TS, "w") as fh:
        fh.write(ts)
    print(f"wrote {os.path.relpath(OUT_TS, ROOT)}")
    for b in out:
        print(f"  {b['dir']:32} zip {b['bytes']:>6}B")


if __name__ == "__main__":
    main()
