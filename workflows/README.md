# CNO alerting layer

Davis anomaly detectors (`builtin:davis.anomaly-detectors`) — an **optional, nice-to-have
detection layer**. They raise granular per-signal problems in the Alerts view and stamp
`cno.signature`. **They are NOT required for root cause.** The unified **Network RCA workflow**
([[network-rca-workflow]]) reads `cno.if.oper_status` + `cno.if.admin_status` + `cno.dep.uses`
**directly** and `createEvent`s the root-cause card — it does *not* consume detector problems
(verified: its 6 tasks query the metrics; none read Davis problems or `cno.signature`). It now
covers interface up/down itself, so **3 of the 4 detectors below are redundant with it** (the
error-burst detector stays); add detectors for the per-signal granularity a state model can't see
(errors, utilization, latency, baselines), not to make RCA work.

## Install
Detectors **require OAuth**, not an Api-Token (settings validation rejects an Api-Token:
"request was not done using oAuth"). The definitions are captured in `detectors.json`;
create them with:

    dtctl exec function -f create_detectors.js --data - --context <ctx> < detectors.json

`create_detectors.js` is **idempotent** — it skips any detector whose title already exists,
so re-running never stacks duplicates. Run once per tenant; safe to re-run.
(The earlier plain-POST version had no existence check — that is what produced the
9-detectors-for-4 duplicate set on the lab tenant.)

## The four detectors
Each stamps `cno.signature` — a fault-class label (handy for filtering; the workflow reads metrics directly and does not depend on it).

| Title | Signature | Detects | Source metric | Needs |
|---|---|---|---|---|
| CNO - Interface operationally down | `link-down`    | port/cable down (ifOperStatus)  | `cno.if.oper_status`                                   | SNMP interface extension |
| CNO - Device unreachable (ping)    | `device-down`  | device not answering ICMP       | `dt.synthetic.multi_protocol.availability` (< 100) | **NAM/synthetic monitor** on the device |
| CNO - PDU/power infeed lost        | `power-domain` | PDU / power infeed lost          | `dt.synthetic.multi_protocol.availability` (< 100) | **NAM/synthetic monitor** on the PDU |
| CNO - Interface error burst        | `bad-link`     | dirty optic / CRC storm          | `cno.if.in_errors.count` (rate:1m)                 | SNMP interface extension **emitting errors** |

### Dependencies to know before you ship
- **NAM dependency (device-down, power-domain):** both key off *synthetic multiprotocol
  (NAM) availability* — metric `dt.synthetic.multi_protocol.availability`. **Dynatrace renamed
  this** from the old `builtin:synthetic.multiProtocol.availability`; a detector pinned to the
  old key silently stops firing (that is exactly what happened on the lab tenant). They only
  fire where a NAM/synthetic ICMP monitor watches the device (and the PDU) from a private
  location — no NAM monitors → those two never fire.
- **error-burst now uses `cno.if.in_errors.count`** (rewired away from the generic
  `snmp-generic-device` extension, which the handoff says is *not* part of this solution).
  This requires the SNMP interface extension build to actually **emit** those error counters —
  they are defined in `extension.yaml`, but an older deployed build may not emit them yet, in
  which case rebuild/re-sign/redeploy the extension. `cno.power.pdu.status` (a ServerTech
  0-9 outlet-status code) is emitted too but is *not* a clean threshold source — NAM
  availability is the better power signal.

See `docs/FAULT-SIGNATURE-MATRIX.md` for the injection→signature mapping and
`docs/ALERTING-STRATEGY.md` for the storm-to-story design.
