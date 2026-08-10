#!/usr/bin/env python3
# API-source bridge — the API analog of the SNMP poll. Polls a controller's device API
# (vManage /dataservice/device) and ingests reachability into Grail as cno.if.oper_status, so
# API-sourced devices show in the app alongside SNMP-polled ones. source="sdwan-api" tags origin;
# cno.dep.uses hub-spoke edges draw the fabric in Topology. Point API_CTRL_URL/TOKEN at a real
# vManage and it works unchanged.
import json, os, urllib.request

CTRL  = os.environ.get("API_CTRL_URL", "http://127.0.0.1:9443")
TOKEN = os.environ.get("API_CTRL_TOKEN", "cno-sdwan-ro")
DT    = os.environ["DT_URL"].rstrip("/")
TOK   = os.environ["DT_TOKEN"]
HUB   = "sdwan-hub-01"
# WHERE THE FABRIC LANDS. Without this the SD-WAN devices are an ISLAND: branch->hub edges drew a
# neat little star connected to nothing, so Topology showed an SD-WAN fabric floating beside a
# datacentre it demonstrably exchanges traffic with, and RCA could never walk from a branch
# outage to a datacentre cause. A real hub terminates branch tunnels and hands off to the DC core.
#
# THE TOPOLOGY GRAPH KEYS ON device.address, NOT ON THE NAME — and this bridge was emitting
# names only. Every SD-WAN edge therefore arrived with null endpoints, matched no device, and was
# discarded by the graph as "both ends outside this site". The fabric was not merely misplaced,
# it was STRUCTURALLY UNRENDERABLE, and adding the hub->core edge did nothing until this was
# fixed. Both address and name are emitted now: the address is the join key, the name is the
# label. (Same lesson as Topology.tsx's own header — names are labels, addresses are identity.)
DC_CORE      = os.environ.get("CNO_DC_CORE", "LAB-9300-1-1")
DC_CORE_ADDR = os.environ.get("CNO_DC_CORE_ADDR", "10.88.40.43")


def controller_devices():
    req = urllib.request.Request(f"{CTRL}/dataservice/device", headers={"X-Auth-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r).get("data", [])


def ingest(lines):
    body = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(
        f"{DT}/api/v2/metrics/ingest", data=body,
        headers={"Authorization": f"Api-Token {TOK}", "Content-Type": "text/plain; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status


def main():
    devs = controller_devices()
    # resolve the hub's address up front — a branch edge needs it as upstream.address, and the
    # controller does not guarantee the hub is listed before its branches.
    hub_ip = next((d["system-ip"] for d in devs if d["host-name"].lower() == HUB), "")
    lines = []
    for d in devs:
        name = d["host-name"].lower()
        ip = d["system-ip"]
        up = 1 if d.get("reachability") == "reachable" else 0
        lines.append(f"cno.if.oper_status,sys_name={name},device.address={ip},source=sdwan-api {up}")
        # hub-spoke: each reachable branch edge depends on the hub (draws the fabric in Topology)
        if name != HUB and up:
            lines.append(f"cno.dep.uses,device.name={name},device.address={ip},"
                         f"upstream.name={HUB},upstream.address={hub_ip},"
                         f"link_type=sdwan,discovery=api 1")
        # The hub itself depends on the DC core for onward delivery — this is the edge that joins
        # the fabric to the rest of the estate. Direction follows the same "depends on" convention
        # as everything else: downstream CALLS upstream (access -> core -> wan-edge).
        if name == HUB and up:
            lines.append(f"cno.dep.uses,device.name={name},device.address={ip},"
                         f"upstream.name={DC_CORE},upstream.address={DC_CORE_ADDR},"
                         f"link_type=sdwan,discovery=api 1")
    status = ingest(lines) if lines else 0
    print(f"api_bridge: {len(devs)} devices from controller, emitted {len(lines)} lines -> HTTP {status}")


if __name__ == "__main__":
    main()
