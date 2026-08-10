#!/usr/bin/env python3
"""
Create the monitoring configurations for the Python extensions (controlplane, netbox) from
fleet.json. Destructive and idempotent: deletes existing configs for each extension first, so a
device leaving fleet.json leaves the tenant.

ONE CONFIG PER DEVICE FOR CONTROLPLANE, and that is forced, not a style choice. Its activation
schema carries a SINGLE `community` for the whole `deviceList`, while this fleet uses a distinct
community per device. That matters more than it looks: each snmpsim responder serves its entire
data directory keyed BY COMMUNITY, so polling 10.88.40.46 with the community of a different
device returns that other device's walk under the UPS's address — wrong data, silently, with no
error anywhere.

ONLY DEVICES THAT SPEAK LLDP GET A CONTROLPLANE CONFIG. Access points, the UPS, the PDU and the
console server do not participate in LLDP, so polling them for neighbours costs SNMP round trips
to learn nothing. (The AP case is real and worth remembering: in this lab the wireless AP is
genuinely invisible to LLDP, which is why NetBox cabling exists as the second topology source.)
"""
import json, os, sys, urllib.request, urllib.error

BASE = os.environ.get("DT_ENV_URL") or sys.exit(
    "set DT_ENV_URL — the ENVIRONMENT domain (https://<tenant>.live.dynatrace.com), not .apps"
)
SCOPE = os.environ.get("DT_AG_SCOPE") or sys.exit(
    "set DT_AG_SCOPE — the ActiveGate group scope, e.g. ag_group-net-prod"
)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLEET = os.path.join(ROOT, "deploy/lab/snmpsim/fleet.json")
LLDP_ROLES = {"wan_edge", "core_switch", "access_switch"}


def api(method, path, body=None):
    req = urllib.request.Request(
        f"{BASE}/api/v2/{path}", method=method,
        headers={"Authorization": f"Api-Token {os.environ['DT_TOKEN']}",
                 "Content-Type": "application/json"})
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=60) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:300]}


def wipe(ext):
    _, listing = api("GET", f"extensions/{ext}/monitoringConfigurations?pageSize=100")
    for c in listing.get("items", []):
        api("DELETE", f"extensions/{ext}/monitoringConfigurations/{c['objectId']}")
    return len(listing.get("items", []))


def post(ext, value, label):
    code, resp = api("POST", f"extensions/{ext}/monitoringConfigurations",
                     [{"scope": SCOPE, "value": value}])
    ok = str(code).startswith("2")
    print(f"   {label:<34} HTTP {code} {'' if ok else json.dumps(resp)[:190]}")
    return ok


def main():
    fleet = {k: v for k, v in json.load(open(FLEET)).items() if not k.startswith("_")}

    ext = "custom:cno.network.controlplane"
    print(f"== controlplane: removed {wipe(ext)} existing config(s) ==")
    made = 0
    for name, d in sorted(fleet.items()):
        if d.get("role") not in LLDP_ROLES:
            continue
        made += post(ext, {
            "enabled": True,
            "description": f"LLDP topology: {name} ({d['ip']})",
            "version": "0.1.1",
            "activationContext": "REMOTE",
            "primaryFields": [], "primaryTags": [],
            "pythonRemote": {
                "deviceList": d["ip"],
                "collectLldp": True,
                "collectRouting": False,   # off by default; an upgrade must never switch on a
                                           # new ingest stream silently
                "excludeEndpoints": True,
                "intervalSeconds": 900,
                "version": "v2c",
                "community": d["community"],
                # The v3 enum fields are REQUIRED NON-NULL even when version is v2c — the schema
                # validates them unconditionally and rejects the whole config with three
                # constraint violations if they are omitted. They are inert for v2c.
                "securityLevel": "authPriv",
                "authProtocol": "sha",
                "privProtocol": "aes",
                "timeoutSeconds": 5, "retries": 2, "maxRepetitions": 10,
            },
        }, name)
    print(f"   -> {made} controlplane config(s)")

    ext = "custom:cno.network.netbox"
    print(f"== netbox: removed {wipe(ext)} existing config(s) ==")
    token = os.environ.get("NETBOX_TOKEN", "")
    if not token:
        print("   SKIPPED — NETBOX_TOKEN not set")
        return
    # NetBox runs in docker ON the ActiveGate host, so localhost is correct here and would NOT be
    # on a customer deployment. dtApiToken is left unset: the uses_network edge (host -> device)
    # needs a Dynatrace API token, and that is a separate decision from inventory ingest.
    post(ext, {
        "enabled": True,
        "description": "NetBox inventory, power chain and cabling",
        "version": "0.0.3",
        "activationContext": "REMOTE",
        "primaryFields": [], "primaryTags": [],
        "pythonRemote": {
            "netboxUrl": "http://localhost:8000",
            "netboxToken": token,
            "intervalSeconds": 60,
            "emitDataLinks": True,
        },
    }, "netbox inventory")


if __name__ == "__main__":
    if "DT_TOKEN" not in os.environ:
        sys.exit("DT_TOKEN not set")
    main()
