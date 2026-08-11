import { useDql } from "@dynatrace-sdk/react-hooks";
import { getEnvironmentUrl } from "@dynatrace-sdk/app-environment";
import { useTimeframe } from "./timeframe";
import { useConfiguredDevices } from "./provision";
import { useAcknowledgedDevices } from "./lifecycle";
import { fleetRowState } from "./metrics";

// Build deep links by hand from the environment base. getAppLink() URL-encodes its
// pageToken, which mangles multi-segment routes + query params (the "lands on the app
// home" symptom), so we concatenate the exact routes verified against real URLs.
function envBase(): string {
  try { return getEnvironmentUrl().replace(/\/$/, ""); } catch { return ""; }
}

// A SPECIFIC Davis problem: /problem/<internal id> — the internal id is event.id,
// NOT the P-xxxx display_id.
export function problemLink(pid?: string): string {
  const b = envBase();
  return pid && b ? `${b}/ui/apps/dynatrace.davis.problems/problem/${pid}` : "";
}

// A device's entity page in Infrastructure & Operations. dt.entity.network:device
// IS a CUSTOM_DEVICE-… id → drops straight into fullPageId.
export function entityLink(entityId?: string): string {
  const b = envBase();
  return entityId && b ? `${b}/ui/apps/dynatrace.infraops/explorer/Network/Network%20devices?perspective=Health&fullPageId=${entityId}` : "";
}

// Site grouping is customer-owned (assigned in the app, stored app-side) — see lib/sites.ts.
// It is deliberately NOT derived from hostnames, so it works on any naming convention.

// Shared, canonical queries. useDql already caches each result for 60s (TanStack
// Query under the hood), but only for IDENTICAL query strings. Pages used to run
// slightly-different fleet/Davis queries, so they never shared that cache. Routing
// them through these hooks makes the strings identical → one fetch, reused across
// every page, with a longer staleTime for data that changes slowly.

// Roster = every device seen in 24h, INCLUDING currently-down ones (an outage shows as
// down instead of the row silently vanishing). Liveness = answered in the last 5m. Two
// queries: roster caches long, liveness refreshes fast; merged into up/down in useFleet.
// IDENTITY IS THE MANAGEMENT ADDRESS, NOT THE NAME.
// sys_name is operator-supplied and frequently absent — a real Netgear GSM7248V2 in the lab
// returns the literal string "n/a", and switches routinely ship with no sysName at all. These
// queries used to key on sys_name, which meant:
//   * `dedup device` on the NAME silently DROPPED every unnamed device but one — they vanished
//     from the fleet rather than showing up as duplicates;
//   * liveness matched by name, so unnamed devices shared one up/down state.
// device.address is the same field the extension builds entity ids from
// (idPattern: network_device_{device.address}), so it is unique by construction.
//
// NAME FRESHNESS. The roster spans 24h, and a device that is RENAMED reports under both names
// inside that window. `dedup ip` keeps an ARBITRARY row, so it kept the OLD name — observed
// live: a switch renamed to `fortress` still listed as `Starscream`, and its neighbour renamed
// to `outpost` still listed by its IP, for hours. The fix is not a cleverer dedup: the roster's
// job is "which addresses existed in 24h", and the CURRENT name is a separate question best
// answered by recent data. So the roster now returns every (name, address) pair it saw and
// useFleet picks — preferring the name seen in the last 5 minutes (carried on the liveness
// query, which costs nothing extra), then the name with the most datapoints.
// A DEVICE WITHOUT INTERFACES IS STILL A DEVICE.
//
// Both queries keyed on `cno.if.oper_status` alone, which silently defined "the fleet" as
// "things with an ifTable". A UPS has no interfaces, so it could be perfectly monitored and
// still never appear in Devices — and because it never appeared in the list, there was no way
// to click through to the DeviceDetail page that renders its battery and runtime tiles.
// Measured 2026-08-03, right after the feature-set migration started collecting UPS power:
//   cno.device.uptime     ups-1=10  fortress=16  outpost=16     <- all three
//   cno.if.oper_status              fortress=1456 outpost=784   <- switches only
//
// `cno.device.uptime` is the better key: it is sysUpTime from MIB-II, which every SNMP agent
// answers, and it sits in the extension's DEFAULT feature set so it is always collected. But it
// cannot simply REPLACE the interface key — API-sourced devices (the ConfigureApi track) emit
// `cno.if.oper_status` with source=sdwan-api and no uptime at all, so a uptime-only roster would
// drop them. It has to be a union of both.
//
// WHY `append` AND NOT A MULTI-AGGREGATE timeseries. The obvious form —
//   timeseries { ifs=count(cno.if.oper_status), upt=count(cno.device.uptime) }, by:{...}
// INNER-JOINS on the by-dimensions, so a device missing either metric is dropped entirely.
// Measured: that form returned the two switches and silently omitted the UPS, i.e. it reproduced
// the exact bug it was meant to fix. `nonempty:false` does not change it. Appending two separate
// timeseries and summarising keeps devices that appear in only one.
// THE ONE DEFINITION OF "IS THIS DEVICE REPORTING".
//
// Exported because it was implemented three times and fixed once. On 2026-08-03 the roster below
// was corrected for the UPS problem; lib/lifecycle.ts and the RCA workflow's `reach`/`entities`
// sat two files away, kept asking `cno.if.oper_status` alone, and stayed broken until 2026-08-11
// — by which point the Devices page listed a UPS while the lifecycle logic could not see it and
// the RCA could never observe it as down. Three answers to one question.
//
// Anything deciding whether a device is reporting builds its query from THIS, so the next change
// happens once. Callers supply the window and the dimensions they need.
export const livenessUnion = (window: string, by: string, fields: string) =>
  `timeseries upt=count(cno.device.uptime), by:{${by}}, from:${window}
| fields ${fields}, n=arraySum(upt)
| append [ timeseries seen=count(cno.if.oper_status), by:{${by}}, from:${window}
           | fields ${fields}, n=arraySum(seen) ]`;

const ROSTER_DQL = `timeseries upt=count(cno.device.uptime), by:{sys_name, \`device.address\`}, from:-24h
| fields device=sys_name, ip=\`device.address\`, n=arraySum(upt)
| append [ timeseries seen=count(cno.if.oper_status), by:{sys_name, \`device.address\`}, from:-24h
           | fields device=sys_name, ip=\`device.address\`, n=arraySum(seen) ]
| summarize n=sum(n), by:{device, ip}
| filter n>0 | sort ip, n desc`;
const LIVENESS_DQL = `timeseries upt=count(cno.device.uptime), by:{\`device.address\`, sys_name}, from:-5m
| fields ip=\`device.address\`, device=sys_name, n=arraySum(upt)
| append [ timeseries recent=count(cno.if.oper_status), by:{\`device.address\`, sys_name}, from:-5m
           | fields ip=\`device.address\`, device=sys_name, n=arraySum(recent) ]
| summarize n=sum(n), by:{ip, device}
| filter n>0 | fields ip, device`;

// DEVICES WE CAN SEE BUT DO NOT POLL.
//
// The fleet used to be defined purely as "addresses that produced cno.if.oper_status" — i.e.
// devices WE poll. Anything else did not exist as far as the app was concerned, which made two
// things wrong at once: the Devices page under-reported the network, and Topology drew these
// devices RED (absent from the liveness set reads identically to "down").
//
// LLDP already tells us about them: a neighbour that advertises a management address is a real
// device on the network, whoever monitors it. They are merged in as monitored:false, which the
// UI renders as "not monitored" — a third state distinct from up and down, because we have not
// contacted them and cannot claim they are healthy OR broken.
//
// Deliberately sourced from OUR OWN lldp records rather than the shared network:device entity
// type: that type is shared across solutions on this tenant (it currently also holds wan1 and
// leaf1 from a different app), and reading it would re-open the §B7 foreign-data leak.
const NEIGHBOURS_DQL = `fetch logs, from:-2h
| filter \`log.source\` == "network.lldp" and \`lldp.record\` == "link"
| filter isNotNull(\`lldp.remote_mgmt_address\`) and \`lldp.remote_mgmt_address\` != ""
| dedup \`lldp.remote_mgmt_address\`, sort:{timestamp desc}
| fields ip=\`lldp.remote_mgmt_address\`, device=\`lldp.remote_sys_name\`, cls=\`lldp.remote_class\``;

// The RCA workflow consolidates + names each root cause in event.name (e.g. "Power domain
// failure: lab-pdu-1") and leaves Davis's native root_cause_entity_name NULL — so we key off
// the network:device entity type, NOT isNotNull(root_cause_entity_name). That old clause was
// stale from the pre-workflow "Davis-native RCA" model: it filtered out every workflow problem,
// rendering a false "all clear" while a problem was active (the false-all-clear failure mode).
const davisDql = (tf: string) => `fetch dt.davis.problems, from:${tf}
| filter arrayIndexOf(affected_entity_types, "dt.entity.network:device") >= 0 or matchesPhrase(event.name, "infrastructure")
| dedup display_id, sort:{event.start desc}
| fieldsAdd n=arraySize(affected_entity_ids)
| fields id=display_id, pid=event.id, name=event.name, status=event.status, root=root_cause_entity_name, cat=event.category, n
| sort id desc | limit 15`;

const eventsDql = (tf: string, scope: string) => `fetch logs, from:${tf}
| filter \`log.source\` == "cisco.syslog" or \`log.source\` == "snmptraps" or \`log.source\` == "network.config"
${scope}
| sort timestamp desc
| fields timestamp, source=\`log.source\`, dev=\`host.name\`, content
| limit 50`;

/** `ip` is the identity (stable, unique). `device` is the raw sys_name and may be absent or
 *  junk. `label` is what to SHOW — never use it as a key. */
export type FleetRow = { device: string; ip: string; label: string; up: boolean; monitored: boolean };

/** True when SNMP gave us nothing usable as a display name. Real devices return "n/a",
 *  "", "unknown" or the literal "noSuchObject" when sysName was never configured. */
export function isBlankName(n: unknown): boolean {
  const s = String(n ?? "").trim().toLowerCase();
  return s === "" || s === "n/a" || s === "na" || s === "unknown" || s === "null" || s.startsWith("nosuch");
}

/** Display name for a device: the sysName when it is meaningful, otherwise the management IP.
 *  Showing "n/a" in a device list is worse than showing the address the operator can act on. */
export function deviceLabel(name: unknown, ip: unknown): string {
  return isBlankName(name) ? String(ip ?? "unknown") : String(name);
}

/** DQL predicate restricting LOG records to the monitored fleet.
 *
 *  Without this the app shows any producer's logs that happen to use the same `log.source`.
 *  Observed live on a shared tenant: 690 SNMP traps belonging to a different solution's
 *  Arista lab appeared in the Events view, attributed to devices we do not monitor. The
 *  metric-backed views were unaffected because `cno.*` is our own namespace — only the
 *  log-backed ones leak, which is why it went unnoticed.
 *
 *  Matches on `device.address` (traps, compliance, config) OR `host.name` (syslog), because
 *  no single field is present on every source. An empty fleet yields `| limit 0`: while the
 *  roster is still loading it is correct to show nothing rather than someone else's devices.
 */
export function fleetLogScope(rows: FleetRow[]): string {
  const lit = (v: string) => `"${String(v).replace(/(["\\])/g, "\\$1")}"`;
  const ips = Array.from(new Set(rows.map((r) => r.ip).filter(Boolean))).map(lit);
  const names = Array.from(new Set(rows.map((r) => r.device).filter((n) => n && !isBlankName(n)))).map(lit);
  const parts: string[] = [];
  if (ips.length) parts.push(`in(\`device.address\`, {${ips.join(",")}})`);
  if (names.length) parts.push(`in(\`host.name\`, {${names.join(",")}})`);
  return parts.length ? `| filter ${parts.join(" or ")}` : "| limit 0";
}

// Fleet = the 24h roster merged with 5m liveness → each device carries real up/down
// (a down device stays visible as down, not vanished). onboard/retire call refresh().
// Both halves are joined on the management ADDRESS — see the note above ROSTER_DQL.
export function useFleet() {
  const roster = useDql({ query: ROSTER_DQL }, { staleTime: 120000 });
  const live = useDql({ query: LIVENESS_DQL }, { staleTime: 30000 });
  const nbrs = useDql({ query: NEIGHBOURS_DQL }, { staleTime: 120000 });
  // WHAT MAKES A DEVICE DISAPPEAR — and what deliberately no longer does.
  //
  // This used to DELETE any roster row whose address had no monitoring configuration, to make
  // "retired means gone" true. It was the wrong lever and it caused both of the bugs it was
  // reported for: the fleet flashing in at its full size and then shrinking (rows depended on a
  // second, slower fetch), and the fleet settling three devices SHORT of what was configured.
  // One line, reachable on every render, able to erase a live device — and when it fired wrongly
  // there was nothing on screen to say so. Config-absence is now an OBSERVATION, not a delete.
  //
  // Retirement is an EXPLICIT ACT instead: acknowledging a device (lib/lifecycle.ts, stored in
  // app-state) removes it from Fleet, from Overview's totals and from Topology, and leaves it
  // visible only on the Retired tab. That is the behaviour originally asked for, and it cannot
  // silently swallow a device that is still reporting, because a human has to perform it.
  const { ips: configuredIps, failed: cfgFailed, isLoading: cfgLoading, diag: cfgDiag } = useConfiguredDevices();
  const { acked } = useAcknowledgedDevices();
  // Only ever used to LABEL a row (monitored true/false), never to remove one. Unknown intent
  // therefore means "assume monitored" — greying the whole fleet for a second while the config
  // call lands would be its own flash, in the other direction. Callers additionally hold their
  // paint until cfgLoading clears (see isLoading below), so that transitional value is not
  // normally rendered at all: without that hold the fleet visibly came up LIVE and then dropped
  // to unconfigured a moment later, which is the same flash one layer down from the row set.
  const intentKnown = !cfgLoading && !cfgFailed && configuredIps.size > 0;
  const rosterRows: any[] = (roster.data as any)?.records ?? [];
  const liveRows: any[] = (live.data as any)?.records ?? [];
  const liveSet = new Set(liveRows.map((r: any) => String(r.ip)));

  // Current name per address, from the last 5 minutes. This WINS over the 24h roster so a
  // rename is visible on the next poll instead of lingering for a day (see ROSTER_DQL).
  const liveName: Record<string, string> = {};
  liveRows.forEach((r: any) => { if (r.ip && !isBlankName(r.device)) liveName[String(r.ip)] = String(r.device); });

  // One row per ADDRESS. Rows arrive sorted by (ip, n desc), so the first occurrence of an
  // address already carries its best-attested historical name — used only when the device has
  // not reported in the last 5 minutes (i.e. it is down and has no current name to offer).
  const rows: FleetRow[] = [];
  const seen = new Set<string>();
  // Reporting, but nothing asked for it — shown as "not monitored", never hidden. Kept as a list
  // so the Fleet page can say WHY the table is smaller than the roster instead of leaving the
  // difference unexplained (the config read is Bearer-only, so the app is the only place it is
  // observable at all).
  const unconfigured: string[] = [];
  const retired: string[] = [];
  rosterRows.forEach((r: any) => {
    const ip = String(r.ip);
    if (!ip || seen.has(ip)) return;
    seen.add(ip);
    // See fleetRowState (lib/metrics.ts) for the rule and its tests. Two ways out of the fleet,
    // both requiring positive knowledge rather than an absence:
    //   - an explicit acknowledgement, or
    //   - not configured AND not reporting — nobody asked for it and it is not talking.
    // The second is only reachable when intentKnown is true, i.e. the configuration read
    // actually succeeded. That guard is the whole safety story: the read spent this project
    // silently returning zero devices (the platform API answers with a BARE ARRAY and the code
    // read `.items`), which made every device look unconfigured. Under that failure this rule
    // does nothing at all, and eleven long-dead addresses stop being rendered as red faults.
    const state = fleetRowState({
      configured: configuredIps.has(ip), live: liveSet.has(ip), intentKnown, acked: !!acked[ip],
    });
    if (state === "retired") { retired.push(ip); return; }
    if (state === "unmanaged") unconfigured.push(ip);
    const name = liveName[ip] ?? r.device;
    rows.push({ device: name, ip, label: deviceLabel(name, ip), up: state === "up", monitored: state !== "unmanaged" });
  });

  // Append LLDP-discovered devices we do NOT poll. up:false here means "unknown", not "down" —
  // callers must branch on `monitored` before reporting a device as failed.
  ((nbrs.data as any)?.records ?? []).forEach((r: any) => {
    const ip = String(r.ip || "");
    if (!ip || seen.has(ip)) return;      // already monitored — the monitored row wins
    seen.add(ip);
    rows.push({ device: r.device || "", ip, label: deviceLabel(r.device, ip), up: false, monitored: false });
  });
  // isLoading MUST include the intent fetch, not just the roster query. The filter above changes
  // which rows exist, so reporting "loaded" before intent arrives makes every consumer render the
  // UNFILTERED fleet and then re-render the filtered one — the fleet visibly appears and then
  // vanishes a moment later. Observed live: 28 devices flashing up, then settling. Both states
  // were "correct" for their inputs; showing the first one at all was the bug.
  return {
    rows,
    // LIVENESS DECIDES up/down, SO ITS ABSENCE IS NOT "DOWN".
    // live.isLoading and live.error were both computed and then never read. liveSet is built from
    // that query's rows, and `up: liveSet.has(ip)` treats an empty set as "nothing is reachable" —
    // so a liveness query that is merely PENDING, or that FAILED outright, renders the entire
    // fleet red with no error anywhere on screen. A total-outage claim is the loudest thing this
    // page can say and it was the default for a failure it never reported.
    // Both are now consumed: pending holds the paint, failed surfaces as an error instead of a
    // verdict. Same rule as the roster and the intent read — absence is not evidence.
    isLoading: roster.isLoading || live.isLoading || cfgLoading,
    error: roster.error || live.error,
    // WHAT EACH SOURCE ACTUALLY RETURNED. The fleet is a join of three reads and a device's
    // rendered state is a function of all three, so "why is this device down / grey / missing"
    // is unanswerable from the row alone. None of the three can be run from a shell (the config
    // read is Bearer-only, DQL needs Grail scopes the API token does not have), which is what
    // made a wrong join cost an afternoon of inference from screenshots. Reported, not logged.
    sources: {
      rosterCount: seen.size,
      liveCount: liveSet.size,
      // In the 24h roster but absent from the 5m liveness set — i.e. every device the app is
      // calling DOWN. If a device is here and the tenant says it is reporting, the liveness
      // query is what to look at, not the device.
      down: rows.filter((r) => r.monitored && !r.up).map((r) => r.ip),
      retired,
    },
    intent: { unconfigured, configured: Array.from(configuredIps).sort(), known: intentKnown, failed: cfgFailed, ...cfgDiag },
    refresh: () => { (roster as any).forceRefetch?.(); (live as any).forceRefetch?.(); (nbrs as any).forceRefetch?.(); },
  };
}

// Davis root-caused network problems (Overview shows the top one, Alerts the list).
export function useDavis() {
  const { tf } = useTimeframe();
  const q = useDql({ query: davisDql(tf) }, { staleTime: 60000 });
  const rows: any[] = (q.data as any)?.records ?? [];
  return { rows, isLoading: q.isLoading, error: q.error };
}

// Live paging feed — traps / syslog / config (Overview shows a few, Events more).
export function useEvents() {
  const { tf } = useTimeframe();
  // scoped to the monitored fleet — see fleetLogScope
  const fleet = useFleet();
  const q = useDql({ query: eventsDql(tf, fleetLogScope(fleet.rows)) }, { staleTime: 30000 });
  const rows: any[] = (q.data as any)?.records ?? [];
  return { rows, isLoading: q.isLoading, error: q.error };
}

/* ============================================================================
   CAPABILITY SILENCE — "this is switched on and producing nothing"

   The gap this closes was found on TWO tenants independently. In the CNO lab
   `cno.power.pdu.*` has had zero datapoints for 30 days with nothing saying so. On a
   customer's production tenant, a bespoke ServerTech PDU extension — enabled, configured,
   iterated to v0.0.17 — currently has zero entities across all ten of its types, and nothing
   tells them either.

   So an operator enables a capability, gets silence, and cannot distinguish "I have no PDU"
   from "the OIDs are wrong for my model" from "the feature set never took". All three look
   identical, and the last two are faults.

   Silence is NOT presented as a fault here. A customer with no PDU is not broken — the panel
   reports quiet, and lets the person who knows their own estate decide whether that is
   expected. Reporting it as an error would be the same overreach in the other direction.
   ============================================================================ */
export type CapabilitySignal = { id: string; label: string; hint: string; datapoints: number };

const CAPS: { id: string; label: string; metric: string; hint: string }[] = [
  { id: "iface", label: "Interfaces",        metric: "cno.if.oper_status",            hint: "the default set — silence here means nothing is polling at all" },
  { id: "cpu",   label: "Device health",     metric: "cno.device.cpu_usage",          hint: "Cisco-only. Most switches do not expose CPU or memory over SNMP at all, so quiet is normal on a mixed fleet" },
  { id: "ups",   label: "UPS power",         metric: "cno.power.ups.charge_pct",      hint: "needs the UPS feature set and a UPS answering RFC 1628" },
  { id: "upsv",  label: "UPS battery volts", metric: "cno.power.ups.battery_voltage", hint: "its own feature set on purpose — one unimplemented OID returns noSuchName for a whole SNMPv1 request" },
  { id: "pdu",   label: "PDU power",         metric: "cno.power.pdu.load",            hint: "ServerTech OIDs, never verified against hardware — quiet here may mean the OIDs are wrong, not that you have no PDU" },
  { id: "inv",   label: "NetBox inventory",  metric: "cno.inv.device",                hint: "needs the NetBox extension and an API token" },
  { id: "dep",   label: "Topology edges",    metric: "cno.dep.uses",                  hint: "from LLDP adjacency or NetBox cabling" },
];

export function useCapabilitySignals(): { rows: CapabilitySignal[]; isLoading: boolean; error?: unknown } {
  // APPEND, NEVER a multi-aggregate `timeseries { a=count(X), b=count(Y) }`. That form INNER-JOINS,
  // so a single metric with no data zeroes every other column — and this panel exists precisely to
  // report metrics with no data, which made it the worst possible place for that bug. It was
  // written the wrong way first and reported ALL SEVEN capabilities as silent while interfaces
  // were producing 17,262 datapoints. Fourth time this trap has bitten in this codebase.
  //
  // A capability with no data produces NO ROW rather than a zero, which is why the caller maps
  // over CAPS and defaults, instead of trusting the result set to be complete.
  const q = useDql({
    query: CAPS.map((c, i) =>
      i === 0
        ? `timeseries n=count(${c.metric}), from:-6h | fields cap="${c.id}", n=arraySum(n)`
        : `| append [ timeseries n=count(${c.metric}), from:-6h | fields cap="${c.id}", n=arraySum(n) ]`,
    ).join(" ") + " | summarize n=sum(n), by:{cap}",
  });
  const byCap: Record<string, number> = {};
  (((q.data as any)?.records ?? []) as any[]).forEach((r) => { byCap[String(r.cap)] = Number(r.n) || 0; });
  const rows = CAPS.map((c) => ({ id: c.id, label: c.label, hint: c.hint, datapoints: byCap[c.id] || 0 }));
  // A FAILED query yields an empty record set, which maps to zero datapoints for every capability
  // and would announce that the entire estate has gone silent. That is the loudest possible false
  // alarm from this panel, whose whole purpose is to be trusted about silence. Surface the error
  // and let the caller refuse to render a verdict.
  return { rows, isLoading: q.isLoading, error: q.error };
}
