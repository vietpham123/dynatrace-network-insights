#!/usr/bin/env python3
"""
CLOSED-LOOP EXECUTOR — the on-prem side of Workflow B's optional "apply".

Workflow B (in-tenant "Reconcile NetBox" button) DECIDES what NetBox needs; this
EXECUTOR APPLIES it, because only something on-prem can reach the private NetBox.
In production this is an ActiveGate extension; in the lab it is this script.

It writes ONLY observed enrichment onto the DECLARED record (never redefines intent):
  dynatrace_entity_id  <- the network:device entityId (the DT<->CMDB back-link)
  dynatrace_health     <- healthy / down   (from live reachability)
  dynatrace_last_seen  <- now (UTC)
  dynatrace_status     <- observed

Match is by the CANONICAL KEY (mgmt IP), falling back to name — the same reconciliation
discipline the whole architecture rests on.

Usage on the VM:
  set -a; . ~/.dep-env; set +a
  python3 apply_netbox.py --device LAB-ACCESS-1     # one device (the "automate this one")
  python3 apply_netbox.py --all                     # enrich every observed device
  python3 apply_netbox.py --all --dry-run           # show, write nothing
"""
import argparse, datetime, json, os, urllib.parse, urllib.request, urllib.error

NB  = os.environ.get("NETBOX_URL", "http://localhost:8000").rstrip("/")
NBT = os.environ["NETBOX_TOKEN"]
DT  = os.environ["DT_URL"].rstrip("/")
TOK = os.environ["DT_TOKEN"]


def nb(method, path, body=None):
    req = urllib.request.Request(f"{NB}/api{path}", method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Token {NBT}",
                                          "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r) if r.status not in (204,) else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode()[:250]}")


def nb_all(path):
    """Every result across ALL pages. A bare ?limit=N silently truncates a fleet
    larger than N, so reconcile would 'not find' real devices and act on a partial
    view. Follow the `next` link instead."""
    out, url, guard = [], f"{NB}/api{path}", 0
    while url and guard < 200:
        guard += 1
        req = urllib.request.Request(url, headers={"Authorization": f"Token {NBT}",
                                                   "Accept": "application/json"})
        page = json.load(urllib.request.urlopen(req, timeout=20))
        out.extend(page.get("results", []))
        url = page.get("next")
    if url:
        print(f"WARNING: paging guard hit for {path}; {len(out)} rows may be INCOMPLETE")
    return out


def dt(path):
    req = urllib.request.Request(f"{DT}{path}", headers={"Authorization": f"Api-Token {TOK}"})
    return json.load(urllib.request.urlopen(req))


def observed():
    """network:device entities (entityId, name, ip) + live reachability -> health."""
    sel = urllib.parse.quote('type("network:device")')
    ents = dt(f"/api/v2/entities?entitySelector={sel}&fields=%2Bproperties&from=-24h").get("entities", [])
    by_ip, by_name = {}, {}
    for e in ents:
        eid, name = e["entityId"], e.get("displayName", "")
        by_name[name.lower()] = eid
        props = e.get("properties", {}) or {}
        ips = props.get("ipAddress") or props.get("dt.ip_addresses") or ""
        for ip in str(ips).replace(";", ",").split(","):
            ip = ip.strip()
            if ip:
                by_ip[ip] = eid
    # reachability: which mgmt IPs are answering SNMP right now
    up = set()
    try:
        q = urllib.parse.quote("cno.if.oper_status:splitBy(device.address):count")
        res = dt(f"/api/v2/metrics/query?metricSelector={q}&from=-10m&resolution=Inf")
        for r in res.get("result", []):
            for s in r.get("data", []):
                ip = (s.get("dimensions") or [None])[0]
                if ip and any(v for v in s.get("values", []) if v):
                    up.add(ip)
    except Exception as ex:
        print(f"  (reachability query skipped: {ex})")
    return by_ip, by_name, up


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.device and not a.all:
        ap.error("give --device NAME or --all")

    by_ip, by_name, up = observed()
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    devs = nb_all("/dcim/devices/?limit=200")
    n = 0
    for d in devs:
        name = d["name"]
        if a.device and name.lower() != a.device.lower():
            continue
        if d["role"]["slug"] == "server":
            continue
        ip = ((d.get("primary_ip4") or {}).get("address") or "").split("/")[0]
        eid = by_ip.get(ip) or by_name.get(name.lower())
        if not eid:
            print(f"  {name:18} — no network:device entity observed yet, skip")
            continue
        health = "healthy" if ip in up else "down"
        cf = {"dynatrace_entity_id": eid, "dynatrace_health": health,
              "dynatrace_last_seen": now, "dynatrace_status": "observed"}
        if a.dry_run:
            print(f"  {name:18} <= {eid}  health={health}  (dry-run)")
        else:
            nb("PATCH", f"/dcim/devices/{d['id']}/", {"custom_fields": cf})
            print(f"  {name:18} enriched: entity={eid} health={health}")
        n += 1
    print(f"{'would enrich' if a.dry_run else 'enriched'} {n} device(s)")


if __name__ == "__main__":
    main()
