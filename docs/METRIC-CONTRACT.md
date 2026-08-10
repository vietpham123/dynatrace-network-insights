# The `cno.*` metric contract

**Network Insights is a view over a metric model, not over a particular extension.** Anything that
emits the keys and dimensions below appears in the app — whether it came from SNMP, a vendor API,
a controller, or a script you wrote this afternoon.

This document is the contract in prose. [`contract.json`](contract.json) is the same thing in a
form a script or an AI agent can check against, and
[`../scripts/verify_contract.py`](../scripts/verify_contract.py) reads that file and tells you
which parts of the app your data currently satisfies.

> **Who this is for.** You know Dynatrace — Grail, DQL, metrics, entities, the Credential Vault.
> You may never have built an extension. Nothing here assumes you have; where extension mechanics
> matter, they are spelled out.

---

## The short version

To make a device appear in Network Insights, emit **one metric with two dimensions**:

| | |
|---|---|
| Metric | `cno.device.uptime` |
| Dimension | `device.address` — the management IP |
| Dimension | `sys_name` — the device name |

That's the whole minimum. `cno.device.uptime` is sysUpTime from MIB-II
(`1.3.6.1.2.1.1.3.0`) — every SNMP agent on earth answers it, and it isn't gated behind a feature
set. If your extension already polls anything, it can almost certainly emit this.

Everything beyond that is additive, and you can stop at any point.

---

## The six tiers

Each tier unlocks more of the app. They are **cumulative in usefulness, not in dependency** — you
do not have to complete one to start another, and stopping early is a legitimate outcome.

### 1. Roster — the device exists

**Unlocks:** the Devices list, Overview counts, liveness, site and role assignment.

Emit **either** of these, with both dimensions:

```
cno.device.uptime      dimensions: sys_name, device.address
cno.if.oper_status     dimensions: sys_name, device.address
```

The app builds its roster from the union of the two, so either will do. If a device emits neither,
it does not exist as far as the app is concerned — no page will show it, however much other data
you send.

### 2. Interfaces — per-port visibility

**Unlocks:** interface tables on Device Detail, throughput and error charts, NetFlow interface joins.

Everything here carries `if_index` in addition to the device dimensions.

**Required**

```
cno.if.oper_status     dimensions: sys_name, device.address, if_index
```

**Strongly recommended** — without these the tier technically passes but the page is thin:

```
cno.if.admin_status        device.address, if_index
cno.if.high_speed          device.address, if_index
cno.if.in_octets.count     device.address, if_index
cno.if.out_octets.count    device.address, if_index
cno.if.in_errors.count     device.address, if_index, if_descr
cno.if.out_errors.count    device.address, if_index
```

`if_descr` is what the UI shows as the interface name. Without it, interfaces are listed by index —
correct, but unreadable.

### 3. Device health — CPU and memory

**Unlocks:** the CPU and memory tiles on Device Detail.

```
cno.device.cpu_usage       sys_name, device.address
cno.device.memory_used     device.address
cno.device.memory_free     device.address
```

Optional, and its absence is **not a fault** — most estates don't expose these over SNMP. The app
also falls back to `com.dynatrace.extension.network_device.cpu_usage`, so Dynatrace's own SNMP
extensions partially satisfy this tier without you doing anything.

### 4. Topology — how devices connect

**Unlocks:** the Topology page, and the upstream walk Network RCA uses to suppress downstream noise.

```
cno.dep.uses    dimensions: device.address, upstream.address,
                            device.name, upstream.name,
                            link_type, discovery
```

| Dimension | Values | Meaning |
|---|---|---|
| `discovery` | `lldp`, `netbox`, `manual` | where this edge came from |
| `link_type` | `data`, `power` | which fabric it belongs to |

`discovery` is not bookkeeping — the app renders it. An edge seen by **both** LLDP and the CMDB is
*confirmed*; **LLDP only** is *undocumented* (plugged in, nobody wrote it down); **CMDB only** is
*documented but not advertised*. Power links are always CMDB-only and are never reported as drift,
because no protocol discovers which outlet feeds which device.

> **If you emit edges from both ends of a link, both ends must compute the same direction.** Two
> opposing edges break the RCA suppression walk. Use only signals both ends can see.

### 5. Power — UPS and PDU

**Unlocks:** UPS and PDU tiles, and the power domain in Topology.

```
cno.power.ups.charge_pct          device.address
cno.power.ups.minutes_remaining   device.address
cno.power.ups.load_pct            device.address
cno.power.ups.battery_status      device.address
cno.power.ups.output_watts        device.address
cno.power.pdu.load                device.address
cno.power.pdu.status              device.address
```

Any one of charge, minutes-remaining or PDU load satisfies the tier.

### 6. Inventory — reconciliation

**Unlocks:** CMDB reconciliation — what the system of record says versus what is actually there.

```
cno.inv.device    dimensions: device.name, device.address, device.role
```

Only relevant if you have a system of record to reconcile against.

---

## Log sources, for the pages that aren't metric-driven

Three parts of the app read logs rather than metrics.

| Page | Match on | Required fields |
|---|---|---|
| NetFlow, Investigate | `isNotNull(flow.type)` | `flow.type`, `flow.sampler.address` |
| Config & Compliance | `log.source == "network.config"` | `log.source` |
| Topology diagnostics | `log.source == "network.lldp"` | `log.source`, `lldp.record` |

For LLDP, only records where `lldp.record == "link"` become edges. A `device` record means the poll
succeeded and found no neighbours — a different fact from a failed poll, and the app distinguishes
them.

**Flow is the cost lever** in any deployment. It arrives as logs, and log volume is what moves the
bill. The app's look-back picker defaults tight (−2h) for exactly this reason.

---

## Identity: `device.address` is the join key

Everything keys on the management IP. Three consequences, and the first one is irreversible:

- **Two devices sharing one address collapse into a single entity.** Routine after a merger, and
  normal for DR pairs.
- **Device entities cannot be deleted** — the API returns `405` — and they never age out. Entities
  with 90+ days of zero data are still listed.
- **Renumbering orphans the old entity permanently.** The old addresses keep their entities forever;
  the new ones arrive as strangers.

**Settle addressing before onboarding at scale.** This is the one decision in the whole deployment
that cannot be undone.

---

## The other rule: what you name your extension

Separate from the metrics, and it catches people.

For the app to treat your devices as *configured* — the "not monitored" diagnostic on the Fleet
page, and the retire action — your **extension name** must contain one of:

```
snmp  cisco  meraki  palo  fortinet  arista  juniper  f5  netflow  sflow  network
```

`custom:acme.snmp.wan` passes. `custom:acme.wan` does not.

This does **not** affect whether your metrics render — that's governed entirely by the tiers above.
An extension can fail this rule and still populate every page, while its devices read "not
monitored" on the Fleet diagnostic. The two systems are independent, which is exactly why the
symptom is confusing.

---

## Checking your work

```bash
# everything currently reporting
python3 scripts/verify_contract.py --context <your-dtctl-context>

# one device
python3 scripts/verify_contract.py --context <ctx> --device 10.1.1.1

# just show me the queries — no tenant needed
python3 scripts/verify_contract.py --print-queries
```

It reports each tier as PASS or FAIL, and where something is partial it names the specific
dimension that is missing. That distinction matters more than it sounds: a metric that is present
but missing one dimension fails in the least helpful way available — the data is in Grail, the
query returns rows, and the page is empty.

It also distinguishes **"no data"** from **"could not ask"**. A failed query is not evidence that
your estate has gone silent.

Requires `dtctl` authenticated with `dtctl auth login`. Browser SSO grants the platform scopes
needed to run DQL; API tokens cannot.

---

## A worked example

[`../scripts/api_bridge.py`](../scripts/api_bridge.py) is a complete, working implementation of
this contract from a **non-SNMP** source. It polls a Cisco SD-WAN controller's device API and
ingests the results as `cno.if.oper_status` with `source="sdwan-api"`, plus `cno.dep.uses` edges
for the hub-and-spoke fabric.

The app cannot tell the difference between those devices and SNMP-polled ones. That is the contract
working as intended, and it's the shortest path to understanding it — read that file before writing
your own.

---

## Six things that fail silently

Every one of these produces a plausible-looking wrong answer rather than an error. They're listed
with machine-checkable conditions in [`contract.json`](contract.json) under `pitfalls`.

1. **Empty `featureSets`.** Feature sets are opt-in and are *not* inherited across a version change.
   A configuration with `featureSets: []` keeps that value silently and every gated metric stops —
   while still reporting status OK. **The status field is not the test.**
2. **`Interfaces` on a UPS or PDU.** It's the only feature set issuing SNMP GetBulk; management
   cards answer GetNext but never GetBulk. Result: a 15-second timeout every poll and a
   configuration permanently in ERROR.
3. **`UPS battery voltage` enabled blind.** Optional in RFC 1628. On an all-or-nothing agent a
   single unimplemented OID makes the *whole* request fail, killing every other power metric with
   it. Measured: 10 OIDs returned nothing; the same batch minus one returned 9 of 9 in 9 ms.
4. **The configuration pins the version, not the environment.** An extension can be active at one
   version while every device is still polled by an older one, indefinitely.
5. **Multi-aggregate `timeseries { a=…, b=… }`.** It inner-joins on the by-dimensions, so one empty
   metric drops every other column. Use `| append [ … ]`. This has bitten this codebase four times.
6. **The SNMP extension's `LLDP topology` feature set.** The declarative datasource decodes binary
   OCTET STRINGs as text, and the chassis ID is a MAC — it arrives mangled, destroying the join key
   that is the entire point. Use the controlplane extension instead.

---

*Contract version 1.0.0 — verified against app 0.107.0 and
`custom:cno.network.interfaces` 0.0.14, 2026-08-10.*
