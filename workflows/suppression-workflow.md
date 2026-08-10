# CNO Network Dependency Suppression workflow

> **Superseded (2026-07-29).** This device/chain logic was merged into the unified
> **"CNO - Network RCA"** workflow (see [[network-rca-workflow]]) as **Lane B**, and the standalone
> "CNO - Network Dependency Suppression" workflow was **DELETED from the tenant**. Kept below as
> historical reference — do not deploy this standalone.

The BDO suppression pattern (REPRODUCE §5) reborn on a clean foundation — the dependency
graph is built LIVE from NetBox-declared Smartscape edges (`cno.dep.uses`), not a hardcoded
NODES map. Old BDO workflow (dba02420) DISABLED, kept for reference.

Structure (AutomationEngine, 3-min interval):
- task `reach`    (DQL): `cno.if.oper_status` by sys_name, -2m -> which devices answer SNMP
- task `edges`    (DQL): `cno.dep.uses` -> the downstream->upstream graph
- task `entities` (DQL): `cno.if.oper_status` by {sys_name, dt.entity.network:device}, -2h
    -> name->entityId map (2h window so a currently-down device still resolves)
- task `suppress` (run-javascript, deploy/alerting/suppress_workflow.js):
    roster-diff -> down set; a down device whose upstream is also down = SYMPTOM (suppressed);
    down device with all upstreams up = ROOT CAUSE; emits ONE AvailabilityEvent per root,
    targeted at that root's SPECIFIC entity.

VERIFIED (v2): killed core-1 + console-1 -> roots:[lab-9300-1-1], suppressed:[lab-console-1]
-> one root-cause event. Two alarms became one root cause.

## v3 — storm fix (2026-07-23)

The Davis merge test exposed a defect: v2 emitted against the broad `type("network:device")`
selector with a title that varied by suppressed-count, so Davis could not dedup and opened a
NEW problem every poll — **29 duplicate "Network root cause" problems** observed. v3 fixes it:
- **resolve each root's specific entityId** (via the new `entities` task, 2h window so a
  down device still resolves) and target `entityId("CUSTOM_DEVICE-..")` — the event lands ON
  the root device, not the whole fleet;
- **stable title** per root (`Network root cause: X down`) — suppression detail moves to
  properties (which update the open problem instead of forking a new one) + a
  `dt.event.group_label` correlation hint;
- **timeout:8** (> 3-min poll) so re-posting RENEWS one problem and it auto-resolves ~8m
  after recovery.

Also note the Davis merge finding ([[DAVIS-MERGE-FINDINGS]]): Davis *natively* collapses the
network cascade to one problem rooted at the switch (35->1). This workflow therefore should
NOT duplicate Davis's network-internal correlation — its non-redundant value is power-domain
causality, cross-domain (app<->network), deterministic/explainable root cause, and n=2
independence.

Deploy: dtctl apply workflow -f suppress_workflow.json  (requires OAuth). Detectors: see README.md.
