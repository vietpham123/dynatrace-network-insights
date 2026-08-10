#!/usr/bin/env python3
"""
Ensure the Dynatrace enrichment custom fields exist on dcim.device (idempotent).

These are the fields Workflow B (the closed-loop "Reconcile NetBox" button) writes
back: the OBSERVED Dynatrace identity/health stamped onto the DECLARED NetBox record.
Enrichment only — it never redefines intent, so declared-vs-observed independence
(and therefore drift detection + n=2 verification) survives.

Handles both NetBox 4.x (`object_types`) and 3.x (`content_types`).
Run on the VM: set -a; . ~/.dep-env; set +a; python3 netbox_dt_customfields.py
"""
import json, os, urllib.request, urllib.error

NB  = os.environ.get("NETBOX_URL", "http://localhost:8000").rstrip("/")
NBT = os.environ["NETBOX_TOKEN"]
H = {"Authorization": f"Token {NBT}", "Content-Type": "application/json", "Accept": "application/json"}


def api(method, path, body=None):
    req = urllib.request.Request(f"{NB}/api{path}", method=method,
                                 data=json.dumps(body).encode() if body else None, headers=H)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, (json.load(r) if r.status not in (204,) else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


FIELDS = [
    ("dynatrace_entity_id", "Dynatrace entity ID",  "text", "network:device entityId (observed by Dynatrace)"),
    ("dynatrace_health",    "Dynatrace health",     "text", "Observed health: healthy / degraded / down"),
    ("dynatrace_last_seen", "Dynatrace last seen",  "text", "Last time Dynatrace observed this device"),
    ("dynatrace_status",    "Dynatrace status",     "text", "observed / proposed / unmonitored"),
]

made = 0
for name, label, ftype, desc in FIELDS:
    st, ex = api("GET", f"/extras/custom-fields/?name={name}")
    if isinstance(ex, dict) and ex.get("count"):
        continue
    # NetBox 4.x key first, then 3.x fallback
    payload = {"name": name, "label": label, "type": ftype, "description": desc}
    st, resp = api("POST", "/extras/custom-fields/", {**payload, "object_types": ["dcim.device"]})
    if st >= 400:
        st, resp = api("POST", "/extras/custom-fields/", {**payload, "content_types": ["dcim.device"]})
    if st >= 400:
        raise RuntimeError(f"create {name} -> {st}: {resp}")
    made += 1
    print(f"  created {name}")

print(f"custom fields ensured ({made} created, {len(FIELDS)} total)")
