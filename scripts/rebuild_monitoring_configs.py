#!/usr/bin/env python3
"""
Rebuild the SNMP monitoring configurations from fleet.json. Destructive and idempotent.

WHY. gyz had ELEVEN configurations for what is now a nine-device fleet, every one of them pinned
to extension version 0.0.7. Ten of the eleven pointed at devices that no longer exist (sites 2
and 3, removed in the simulator rebuild) and the eleventh still listed 10.88.40.42, a device
deleted when two single-uplink routers were replaced by one multi-circuit edge.

Those pins are also why uploading 0.0.9 and then 0.0.14 changed nothing: the ActiveGate follows
the version on the MONITORING CONFIGURATION, not the environment-active version. An extension can
sit "active" at 0.0.14 while every device is still polled by 0.0.7, silently and indefinitely.

This deletes every existing configuration and writes one per ROLE from fleet.json, which makes
orphans structurally impossible — a device that leaves fleet.json leaves the tenant.

FEATURE SETS ARE SET EXPLICITLY, never inherited. An existing config with featureSets [] stays []
across a version change with no prompt and no warning, so a migration silently loses every gated
metric. Creating fresh sidesteps that, and also sidesteps any question about the masked community: a GET
returns it as ***…***. NOTE, measured 2026-08-05: writing that mask back does NOT break polling on
this API — the platform preserves the stored secret (tested with an unchanged PUT and with a field
change carrying eleven masked communities; all devices kept polling for ten minutes). The original
note here said it "can break polling", which was speculation and later got hardened into a stated
hazard in the customer deployment guide before anyone tested it.

Communities here still come from fleet.json rather than from a GET, because not depending on
undocumented masking behaviour is the better habit — but it is a preference, not a rescue.

  DELIBERATELY OFF:
    LLDP topology        - the declarative datasource mangles binary chassis-ids; the Python
                           controlplane extension is the working source.
    UPS battery voltage  - optional in RFC 1628. On a UPS that does not implement it, enabling it
                           kills every OTHER power metric on that device.
"""
import json, os, sys, urllib.request, urllib.error

BASE = os.environ.get("DT_ENV_URL") or sys.exit(
    "set DT_ENV_URL — the ENVIRONMENT domain (https://<tenant>.live.dynatrace.com), not .apps"
)
EXT = "custom:cno.network.interfaces"
VERSION = "0.0.14"
SCOPE = os.environ.get("DT_AG_SCOPE") or sys.exit(
    "set DT_AG_SCOPE — the ActiveGate group scope, e.g. ag_group-net-prod"
)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLEET = os.path.join(ROOT, "deploy/lab/snmpsim/fleet.json")

# role -> additional feature sets beyond the default Interfaces set
ROLE_SETS = {
    "wan_edge":     ["Interfaces", "Cisco device health"],
    "core_switch":  ["Interfaces", "Cisco device health"],
    "access_switch":["Interfaces", "Cisco device health"],
    "ap":           ["Interfaces"],
    "console":      ["Interfaces"],
    "power":        ["Interfaces"],          # refined below by kind
}
# SCALAR-ONLY, NO "Interfaces" — and this is a correctness requirement, not a saving.
# `Interfaces` is the only table:true subgroup and therefore the only thing that issues SNMP
# GetBulk. Management cards routinely answer GetNext in milliseconds and never answer GetBulk at
# all (measured on a CyberPower OR2200LCDRTXL2U; extension.yaml documents the same signature on a
# Netgear GSM7248V2). extension.yaml line ~158 states it outright: "A config that does not enable
# Interfaces issues zero GetBulk and this failure is gone."
#
# An earlier version of this file granted "Interfaces" to ups and pdu anyway, which put the UPS
# and PDU configs into a permanent ERROR state — the two that stayed red after the UPS OID fix
# cleared the other two. Losing ifTable on a UPS costs nothing real: cno.device.uptime is
# ungated and always collected, so these devices still appear in the fleet roster.
KIND_SETS = {"ups": ["UPS power"], "pdu": ["PDU power"]}


def api(method, path, body=None):
    tok = os.environ["DT_TOKEN"]
    req = urllib.request.Request(f"{BASE}/api/v2/{path}", method=method,
                                 headers={"Authorization": f"Api-Token {tok}",
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


def main():
    fleet = {k: v for k, v in json.load(open(FLEET)).items() if not k.startswith("_")}

    print("== 1. delete every existing configuration ==")
    _, listing = api("GET", f"extensions/{EXT}/monitoringConfigurations?pageSize=100")
    for c in listing.get("items", []):
        oid = c["objectId"]
        code, _ = api("DELETE", f"extensions/{EXT}/monitoringConfigurations/{oid}")
        print(f"   delete {oid[:18]}… HTTP {code}")

    print("== 2. group the fleet by feature-set requirement ==")
    groups = {}
    for name, d in fleet.items():
        sets = KIND_SETS.get(d.get("kind")) or ROLE_SETS.get(d.get("role"), ["Interfaces"])
        groups.setdefault(tuple(sets), []).append((name, d))
    for sets, members in groups.items():
        print(f"   {', '.join(sets):<38} {len(members)} device(s): {' '.join(m[0] for m in members)}")

    print("== 3. create one configuration per group ==")
    created = 0
    for sets, members in groups.items():
        value = {
            "enabled": True,
            "description": f"CNO fleet: {', '.join(sorted(m[0] for m in members))}",
            "version": VERSION,
            "featureSets": list(sets),
            "activationContext": "REMOTE",
            "primaryFields": [], "primaryTags": [],
            "snmp": {"devices": [
                {"ip": d["ip"], "port": 161,
                 "authentication": {"type": "SNMPv2c", "useCredentialVault": False,
                                    "community": d["community"]},
                 "primaryFields": [], "primaryTags": []}
                for _, d in sorted(members)
            ]},
        }
        code, resp = api("POST", f"extensions/{EXT}/monitoringConfigurations",
                         [{"scope": SCOPE, "value": value}])
        ok = str(code).startswith("2")
        created += ok
        detail = "" if ok else json.dumps(resp)[:200]
        print(f"   {', '.join(sets):<38} HTTP {code} {detail}")

    print(f"== done: {created}/{len(groups)} configurations created ==")


if __name__ == "__main__":
    if "DT_TOKEN" not in os.environ:
        sys.exit("DT_TOKEN not set")
    main()
