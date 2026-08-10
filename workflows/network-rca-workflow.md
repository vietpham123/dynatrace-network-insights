# CNO Network RCA workflow

ONE unified deterministic reasoner (id `db012054-8865-47db-b3ba-284047b0e691`) that merges the two
earlier workflows — device/chain "CNO - Network Dependency Suppression" ([[suppression-workflow]]) and
"CNO - Interface Degradation RCA" ([[interface-degradation-workflow]]), **both now DELETED from the
tenant**. A single 3-min poll routes every device down one of two lanes; a down device has no interface
data, so no device is ever in both lanes.

Structure (AutomationEngine, 3-min interval — `network_rca_workflow.json`, **6 tasks**):
- task `reach`    (DQL): `cno.if.oper_status` by sys_name, -2m -> which devices answer SNMP (`is_up`).
- task `edges`    (DQL): `cno.dep.uses` -> the downstream->upstream dependency graph.
- task `entities` (DQL): name->entityId map, -2h window (so a currently-down device still resolves).
- task `classify` (DQL): per device, `cno.if.oper_status` + `cno.if.admin_status` per interface, -5m
    -> keep devices that are UP but have ≥1 **admin-enabled** interface oper-down; `down_list` + up/down counts.
- task `evidence` (DQL): `network.config` + `cisco.syslog` logs, -45m (for the CoPilot narrative).
- task `emit`     (run-javascript): routes each device and emits ONE card per root / per degraded device.

## The two lanes (one pass, mutually exclusive)

**Lane B — device / chain RCA (device *down*).** A device NOT reporting SNMP is down. Walk the
NetBox-declared dependency graph (`cno.dep.uses`) to the root: a down device whose upstream is also down
= SYMPTOM (suppressed); a down device with all upstreams up = ROOT CAUSE. **Power-domain aware** — a dead
PDU roots the switches it fed. Emits ONE `AvailabilityEvent` per root, targeted at that root's **specific
entityId**, titled by fault type: `Power domain failure: X` / `Site isolated: WAN edge X down` /
`Device failure: X down`.

**Lane A — interface RCA (device *up*, ports down).** A reachable device can still have individual ports
fail. Emits ONE consolidated `Interface degradation on <device>` card listing the down interfaces —
**never one-per-interface**.

Both cards carry a **best-effort** Davis-CoPilot narrative (empty tenant-wide today — a separate known
gap) and a `dt.event.group_label`. Stable titles + entityId targeting + `timeout:8` (> the 3-min poll)
-> Davis renews ONE problem each (auto-resolves ~8m after recovery); no storm.

## The critical encoding (why `admin_status` is load-bearing)

`cno.if.oper_status` is **raw SNMP ifOperStatus** (`oid .2.2.1.8`): **up=1, down=2** — NO normalization
(extension.yaml). So a down interface reports **2** (not `<1`), and oper-down **alone** is normal — real
switches carry many admin-down (disabled/unused) ports at oper=2 as baseline. The genuine fault is
**admin-up (`admin_status==1`) AND oper-down (`oper_status==2`)** — enabled but not working. The
`admin==1` filter is ESSENTIAL; without it the classify false-matched **30+ disabled ports across 11
devices**.

## Where it fits (workflow vs. detectors)

The unified workflow **replaces the state/availability detectors** (interface-down, device-unreachable,
power-lost) with consolidated, root-caused, storm-free correlation — **3 of the 4 CNO detectors are now
redundant with it**. Detectors **remain** for signals a state model can't see: metric thresholds
(errors, utilization, latency — the interface **error-burst** detector stays), statistical/baseline
anomalies (Davis adaptive), and sub-minute speed (a metric event as the fast event-driven trigger). See
[[../../docs/ALERTING-STRATEGY]].

## Deploy

- **Via the app** (recommended): open **Network Insights → Configuration → Network RCA** and use
  **Download workflow JSON** → import into the Workflows app. The app can't install workflows
  (`automation:workflows:write` is first-party-only), so this is the one manual step. It CAN deploy the
  metric-event detectors (`settings:objects:write`).
- **Via dtctl**: `dtctl apply -f network_rca_workflow.json --context <ctx>`.

Imports **disabled** (workflows bill per run); Dynatrace requires a one-time owner authorization on
first run — which is also what enables the Davis-CoPilot narrative call.

## VERIFIED (2026-07-29, merged)

On the lab tenant: 2 admin-up ports down on `lab-9300-1-1` (device UP) -> ONE interface-degradation card;
`lab-console-1` stopped (device DOWN) -> ONE device-failure card. Both isolated, disabled ports ignored,
ZERO storm; no device in both lanes.
