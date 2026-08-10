# CNO Interface Degradation RCA workflow (Lane A)

> **Superseded (2026-07-29).** This interface logic was merged into the unified
> **"CNO - Network RCA"** workflow (see [[network-rca-workflow]]) as **Lane A**, and the standalone
> "CNO - Interface Degradation RCA" workflow was **DELETED from the tenant**. Kept below as historical
> reference — do not deploy this standalone.

The interface-granularity companion to the device/chain reasoner ([[suppression-workflow]]).
The device reasoner owns whole-device and power-domain outages; but a device can stay reachable
while individual ports fail — this workflow catches that **partial** case, which the device
reasoner (device-level: "is the device answering SNMP?") correctly ignores.

Structure (AutomationEngine, 3-min interval — `interface_degradation_workflow.json`):
- task `classify` (DQL): per device, `cno.if.oper_status` + `cno.if.admin_status` per interface, -5m
    -> keep devices that are UP but have ≥1 **admin-enabled** interface oper-down; `down_list` + up/down counts.
- task `entities` (DQL): name->entityId map (reused from Lane B).
- task `evidence` (DQL): `network.config` + `cisco.syslog` logs, -45m (for the CoPilot narrative).
- task `emit` (run-javascript): ONE `AvailabilityEvent` per partial device, **stable title**
    `Interface degradation on <device>`, down-interface list in properties -> Davis renews one
    problem (no per-interface storm). Davis CoPilot adds a best-effort narrative. `timeout:8`.

## The critical encoding (why `admin_status` is load-bearing)

`cno.if.oper_status` is **raw SNMP ifOperStatus** (`oid .2.2.1.8`): **up=1, down=2** — no normalization
(extension.yaml). So a down interface reports **2** (not `<1`); every "oper_status BELOW 1" threshold
only ever fired on **no-data** (whole device stopped). And oper-down **alone** is normal — real switches
carry many admin-down (disabled/unused) ports at oper=2 as baseline. The genuine fault is
**admin-up (`admin_status==1`) AND oper-down (`oper_status==2`)** — enabled but not working. The
`admin==1` filter is ESSENTIAL; without it the classify false-matched 11 devices / 30+ disabled ports.

VERIFIED (2026-07-28): 2 admin-up interfaces (Gi1/0/1, Gi1/0/2) flipped oper-down on `lab-9300-1-1`
(device stayed up) -> ONE consolidated card, 27 interfaces still up, ZERO storm; the disabled ports
correctly ignored; device/chain Lane B stayed silent. (`iface_fault.py` on the netops VM injects it.)

## Where it fits (workflows vs. detectors)

Lane A + Lane B **replace the state/availability detectors** (interface-down, device-unreachable,
power-lost) with consolidated, root-caused, storm-free correlation. Detectors **remain** for signals a
state model can't see: metric thresholds (errors, utilization, latency), statistical/baseline anomalies
(Davis adaptive), and sub-minute speed (a metric event as the fast event-driven trigger). See
[[../../docs/ALERTING-STRATEGY]].

## Deploy

- **Via the app** (recommended): open **Network Insights → Configuration → Interface RCA** and use
  **Download workflow JSON** → import into the Workflows app. The app can't install workflows
  (`automation:workflows:write` is first-party-only), so this is the one manual step.
- **Via dtctl**: `dtctl apply -f interface_degradation_workflow.json --context <ctx>`.

Imports **disabled** (workflows bill per run); Dynatrace requires a one-time owner authorization on
first run (this is also what enables the Davis CoPilot narrative call).
