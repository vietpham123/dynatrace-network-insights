import React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t, mono } from "../theme";
import { Panel, StatTile, Pill, Tag, QueryErr } from "../components/ui";
import { entityLink, deviceLabel } from "../lib/data";
import { outerTs } from "../lib/netflow";

import { useRoles, roleFor, orientByRole } from "../lib/roles";
import { useTimeframe } from "../lib/timeframe";
import { fmt, badge } from "../lib/format";
import { RetireAction } from "../components/RetireAction";
const num = (v: any) => Math.round(Number(v) || 0);
// escape a device name for safe interpolation into a DQL double-quoted string literal (route param → DQL)
const esc = (s: string) => s.replace(/(["\\])/g, "\\$1");
const mbps = (v: any) => { const n = Number(v) || 0; return n <= 0 ? "—" : n >= 10 ? String(Math.round(n)) : n.toFixed(1); };
// RFC 1628 UPS-MIB enums
const osrcLabel = (v: any) => ({ 2: "no output", 3: "on line", 4: "bypass", 5: "on battery", 6: "booster", 7: "reducer" } as Record<number, string>)[num(v)] || "—";
const bstatusLabel = (v: any) => ({ 1: "unknown", 2: "normal", 3: "low", 4: "depleted" } as Record<number, string>)[num(v)] || "—";
// upsOutputPower subtitle. A flat 0 W beside a non-zero percent load is NOT "no draw" — it is an
// unimplemented object. Measured on the lab CyberPower OR2200LCDRTXL2U 2026-08-03: upsOutputPower
// and upsOutputCurrent both return INTEGER 0 while upsOutputPercentLoad reports 34–37%. Printing
// "0 W drawn" next to "37%" states something false about a UPS carrying a Proxmox cluster, and
// nothing in the tile contradicts it — the same failure shape as the old unitless "Output load 850".
const wattsSub = (watts: unknown, loadPct: unknown, suffix = "") =>
  watts == null ? "percent of capacity"
    : num(watts) === 0 && num(loadPct) > 0 ? "output watts not reported by this unit"
    : `${num(watts)} W${suffix}`;

export const DeviceDetail = () => {
  const { name = "" } = useParams();
  const dev = decodeURIComponent(name);
  const nav = useNavigate();
  const { map: roleMap } = useRoles();
  // Only the HISTORICAL panels (logs, compliance) follow the look-back picker. The interface,
  // throughput and power panels are deliberately "now" — a 7-day average of oper_status would
  // be meaningless as a status indicator — so they keep their own tight fixed windows.
  const { tf } = useTimeframe();

  // The route param is normally the management ADDRESS (stable, unique) but older links —
  // and Topology, whose edge data carries only names — still pass a sys_name. Accept either
  // and prefer the address.
  //
  // Why this matters: sys_name is operator-supplied and often absent. A real Netgear
  // GSM7248V2 here reports the literal "n/a", so keying purely on the name merged every
  // unnamed device onto one page — and "n/a" contains a slash, which breaks the route.
  const byAddr = /^\d{1,3}(\.\d{1,3}){3}$/.test(dev);
  const SEL = byAddr ? `\`device.address\`=="${esc(dev)}"` : `sys_name=="${esc(dev)}"`;

  // Role must be known before the power query (it branches pdu vs ups), i.e. before the
  // info query returns. When routed by address we already have the key; a name-routed link
  // (Topology) falls back to the hostname guess, same as before.
  const role = roleFor(roleMap, byAddr ? dev : "", dev);

  // "IS THIS DEVICE UP" MUST NOT MEAN "DOES IT HAVE INTERFACES".
  //
  // This keyed on cno.if.oper_status alone, so `isUp` was false for anything without an ifTable
  // and the header rendered a confident red **down · Reachability 0% · no response** for a device
  // answering SNMP perfectly. Observed live 2026-08-03 on the lab UPS (10.0.10.146) the moment the
  // feature-set migration made it visible in Devices at all.
  //
  // Unioned with cno.device.uptime — sysUpTime from MIB-II, answered by every SNMP agent and in
  // the extension's DEFAULT feature set. Same `append`+`summarize` shape as the fleet roster in
  // lib/data.ts, and for the same reason: a multi-aggregate timeseries inner-joins on the
  // by-dimensions and silently drops any device missing either metric.
  const INFO_BY = "by:{sys_name, \`dt.entity.network:device\`, \`device.address\`}";
  const INFO_FIELDS = "fields entity=\`dt.entity.network:device\`, ip=\`device.address\`, sysName=sys_name, n";
  const info = useDql({ query: `timeseries s=count(cno.if.oper_status), ${INFO_BY}, from:-2h | fieldsAdd n=arraySum(s) | filter n>0 and ${SEL} | ${INFO_FIELDS}
| append [ timeseries u=count(cno.device.uptime), ${INFO_BY}, from:-2h | fieldsAdd n=arraySum(u) | filter n>0 and ${SEL} | ${INFO_FIELDS} ]
| summarize n=sum(n), by:{entity, ip, sysName} | sort n desc | limit 1` });
  // CPU, read from OUR namespace, and SCOPED to this device.
  //
  // Was: an unscoped query for every network:device entity in the tenant, then a client-side
  // pick of ours out of the result. It displayed the right number, but on a shared tenant it
  // read a different solution's devices to do it (this tenant also carries wan1/leaf1 from
  // another app) — the same class of over-reach as §B7.
  //
  // Coalesces two keys on purpose: cno.device.cpu_usage is ours, and the Dynatrace-prefixed
  // one covers the customer who is ALSO running Dynatrace's generic SNMP extension, where the
  // CPU figure comes from their collector rather than ours.
  // APPEND, not a multi-aggregate timeseries. The coalesce below is the whole point of this query
  // — take ours, else theirs — but wrapping it in `timeseries { mine=.., theirs=.. }` INNER-JOINED
  // the two, so a row existed only where BOTH sources reported and the fallback could never fire.
  // Measured 2026-08-03: cno.device.cpu_usage had 0 series, the Dynatrace one had 1, the join
  // returned 0 and the CPU panel rendered empty while a CPU figure was sitting right there.
  // Ours first, theirs second, first non-null wins.
  const cpuQ = useDql({ query:
      `timeseries a=avg(cno.device.cpu_usage), by:{sys_name, \`device.address\`}, from:-15m | filter ${SEL} | fieldsAdd v=arrayLast(arrayRemoveNulls(a)) | filter isNotNull(v) | fields v`
    + ` | append [ timeseries b=avg(com.dynatrace.extension.network_device.cpu_usage), by:{sys_name, \`device.address\`}, from:-15m | filter ${SEL} | fieldsAdd v=arrayLast(arrayRemoveNulls(b)) | filter isNotNull(v) | fields v ]`
    + ` | limit 1` });
  // SAFE multi-aggregate: both metrics come from the SAME SNMP subgroup and are emitted in one
  // poll, so a series can never carry one without the other (measured equal). If you add a
  // metric from a DIFFERENT group here it becomes an inner join and starts dropping rows —
  // use outerTs() from lib/netflow.ts instead. See the note there.
  const thruQ = useDql({ query: `timeseries inb=max(cno.if.in_octets.count), outb=max(cno.if.out_octets.count), by:{sys_name, \`device.address\`}, from:-30m, interval:5m | filter ${SEL} | fieldsAdd inMbps=arrayAvg(arrayDelta(inb))*8/1000000/300, outMbps=arrayAvg(arrayDelta(outb))*8/1000000/300 | fields inMbps, outMbps` });
  // SPINE = oper_status. Inner-joining the octet counters dropped 31 of 140 interfaces on the
  // reference fleet (9 of them up and passing traffic) because *_octets.count only exists on 109.
  const ifQ = useDql({ query: outerTs(
      { as: "oper",  expr: "avg(cno.if.oper_status)" },
      [{ as: "admin", expr: "avg(cno.if.admin_status)" },
       { as: "speed", expr: "avg(cno.if.high_speed)" },
       { as: "inb",   expr: "max(cno.if.in_octets.count)" },
       { as: "outb",  expr: "max(cno.if.out_octets.count)" }],
      { sys_name: "sys_name", if_index: "if_index", "`device.address`": "`device.address`" },
      "-30m", "5m", SEL)
    + ` | fieldsAdd o=arrayLast(oper), a=arrayLast(admin), sp=arrayLast(speed), inMbps=arrayAvg(arrayDelta(inb))*8/1000000/300, outMbps=arrayAvg(arrayDelta(outb))*8/1000000/300, idx=toLong(if_index) | fields idx, if_index, o, a, sp, inMbps, outMbps | sort idx asc` });
  const logQ = useDql({ query: `fetch logs, from:${tf} | filter \`host.name\` == "${esc(dev)}" and (\`log.source\`=="network.config" or \`log.source\`=="cisco.syslog" or \`log.source\`=="snmptraps") | sort timestamp desc | fields timestamp, source=\`log.source\`, content | limit 12` });
  // Parent/child dependency (from the topology edges) — Davis uses this tree to suppress
  // downstream symptoms.
  //
  // MATCHED ON THE ADDRESS when we have one. These used to filter on device.name/upstream.name,
  // which broke as soon as a device was renamed or reported no name. Observed live 2026-08-01:
  // `outpost` showed its parent only by accident (a stale edge row still carried the literal
  // "10.0.10.3", which happened to equal the address in the route), while `fortress` showed NO
  // children at all — its edges say upstream.name="fortress" but the route carries 10.0.10.2,
  // so nothing matched. Same defect as the Topology name-join; same fix.
  //
  // The `named` sort key breaks dedup ties toward a REAL name over an address-shaped
  // placeholder: a renamed device reports under both names for the 2h window, and without
  // this the stale row won and the child rendered as "10.0.10.3" instead of "outpost".
  // ONE query for every edge TOUCHING this device, either end, with the direction decided in
  // TypeScript rather than baked into two DQL filters.
  //
  // The split used to happen in the query: "rows where I am the device" were parents, "rows where
  // I am the upstream" were children. That hard-codes the collector's stored direction as truth,
  // and it is a heuristic — LLDP adjacency is undirected, so the extension guesses from the
  // advertised capability bitmap. Measured 2026-08-03: `fortress`, a GS752TP access switch,
  // advertises bridge+router exactly as the UCG Ultra gateway does, the ranks tied, an arbitrary
  // chassis-id sort broke it, and this panel showed the WAN gateway as a CHILD of the access
  // switch while the Topology page drew that same gateway on the top tier from its assigned role.
  // Fetching both directions lets orientByRole() correct it where the customer has said otherwise.
  const DEP_ANY = byAddr
    ? `(\`device.address\`=="${esc(dev)}" or \`upstream.address\`=="${esc(dev)}")`
    : `(\`device.name\`=="${esc(dev)}" or \`upstream.name\`=="${esc(dev)}")`;
  const DEP_BY = "by:{\`device.name\`, \`device.address\`, \`upstream.name\`, \`upstream.address\`, link_type}";
  const depQ = useDql({ query: `timeseries e=count(cno.dep.uses), ${DEP_BY}, from:-2h | fieldsAdd n=arraySum(e) | filter n>0 and ${DEP_ANY} | fields dName=\`device.name\`, dIp=\`device.address\`, uName=\`upstream.name\`, uIp=\`upstream.address\`, link_type` });
  // device-centric ISO-27001: which controls THIS device fails, and why
  const compQ = useDql({ query: `fetch logs, from:${tf} | filter log.source == "network.compliance" and \`host.name\`=="${esc(dev)}" | filter isNotNull(\`compliance.control\`) | dedup \`compliance.control\`, sort:{timestamp desc} | fields control=\`compliance.control\`, name=\`compliance.control_name\`, status=\`compliance.status\`, platform=\`compliance.platform_label\`, verified=\`compliance.verified\` | sort control` });
  // Power (UPS RFC 1628 / PDU ServerTech) — only power gear reports these.
  //
  // ⚠️ A MULTI-AGGREGATE timeseries INNER-JOINS, so ONE ABSENT SERIES ERASES ALL THE OTHERS.
  // This asked for seven ups.* metrics in a single `timeseries { … }`. On the lab CyberPower only
  // four of the seven exist — upsOutputPower and upsOutputCurrent are unimplemented (they return a
  // literal 0), and battery voltage sits behind a feature set that is off by default. Measured
  // 2026-08-03 against the live tenant:
  //     7-metric query  -> 0 rows
  //     3-metric query  -> charge=82  uload=36  umins=17
  // So the panel rendered "No power data yet — the extension just activated" on a UPS that had
  // been streaming charge, load, runtime and output source for an hour. The message was not just
  // empty, it was WRONG about the cause, which is the worst kind of empty state.
  //
  // Same trap as the fleet roster in lib/data.ts, and it will recur anywhere a device reports a
  // PARTIAL set of a metric family — i.e. on most real hardware. Fix: one timeseries per metric,
  // appended, then pivoted with max(if(k=="…")). A missing series becomes a null field instead of
  // deleting the row.
  const pwrPivot = (metrics: Record<string, string>) => {
    const keys = Object.keys(metrics);
    const one = (k: string) =>
      `timeseries v=avg(${metrics[k]}), by:{sys_name, \`device.address\`}, from:-30m | filter ${SEL} | fields sys_name, k="${k}", v=arrayLast(arrayRemoveNulls(v))`;
    return [
      one(keys[0]),
      ...keys.slice(1).map((k) => `| append [ ${one(k)} ]`),
      `| summarize ${keys.map((k) => `${k}=max(if(k=="${k}",v))`).join(", ")}`,
    ].join("\n");
  };
  const pwrQ = useDql({ query: role === "pdu"
    ? pwrPivot({ pload: "cno.power.pdu.load", pstatus: "cno.power.pdu.status" })
    : pwrPivot({
        charge:  "cno.power.ups.charge_pct",
        bstatus: "cno.power.ups.battery_status",
        osrc:    "cno.power.ups.output_source",
        uwatts:  "cno.power.ups.output_watts",
        uload:   "cno.power.ups.load_pct",
        umins:   "cno.power.ups.minutes_remaining",
        bvolt:   "cno.power.ups.battery_voltage",
      }) });

  const infoRow = (info.data as any)?.records?.[0];
  // TRI-STATE, not boolean. `!!infoRow` was false while the query was still in flight and false
  // when it FAILED, so a slow or erroring query rendered the device as DOWN — "Reachability 0% ·
  // no response" in red, asserting the device did not answer when in truth we never successfully
  // asked. Only a query that came back with no row is evidence of down.
  const reachKnown = !info.isLoading && !info.error;
  const isUp: boolean | null = reachKnown ? !!infoRow : null;
  const entity = infoRow?.entity;
  const ip = infoRow?.ip || "—";
  // Show the sysName when it means something, else the address. Never render a raw "n/a".
  const label = deviceLabel(infoRow?.sysName ?? (byAddr ? "" : dev), infoRow?.ip ?? dev);
  const cpuRow = (cpuQ.data as any)?.records?.[0];
  const cpu = cpuRow?.v != null ? num(cpuRow.v) : undefined;
  const thru = (thruQ.data as any)?.records?.[0];
  // num(undefined) is 0, so a device with no octet counters read "Throughput 0 Mbps" — a
  // measurement that was never taken. 9 up-and-passing-traffic interfaces on the reference fleet
  // have no counters at all; see the outerTs note in lib/netflow.ts.
  const total = thru == null || (thru.inMbps == null && thru.outMbps == null)
    ? null : num(thru.inMbps) + num(thru.outMbps);
  const ifaces: any[] = (ifQ.data as any)?.records ?? [];
  const up = ifaces.filter((i) => num(i.o) === 1).length;
  const logs: any[] = (logQ.data as any)?.records ?? [];
  // Classify each neighbour as parent or child. Start from the direction the collector stored,
  // then let an EXPLICIT customer role assignment on both ends override it — the authority order
  // roles.ts sets out. Dedup on (neighbour address, link_type), preferring a real name over an
  // address-shaped placeholder, which is what the old `named` sort key did in DQL.
  const parents: any[] = [];
  const children: any[] = [];
  // provenance, so the panel can say WHERE the direction came from instead of stating it flatly
  const dirSrc = { role: 0, collector: 0 };
  {
    const rows: any[] = (depQ.data as any)?.records ?? [];
    const best = new Map<string, { name: string; ip: string; link: string; parent: boolean }>();
    rows.forEach((e) => {
      const selfIsDevice = byAddr ? e.dIp === dev : e.dName === dev;
      const selfIp = String((selfIsDevice ? e.dIp : e.uIp) ?? "");
      const nbName = String((selfIsDevice ? e.uName : e.dName) ?? "");
      const nbIp = String((selfIsDevice ? e.uIp : e.dIp) ?? "");
      // stored semantics are `device -> upstream`, so when WE are the device end the neighbour
      // is our upstream
      let nbIsParent = selfIsDevice;
      const o = orientByRole(roleMap, selfIp, nbIp);
      if (o === -1) nbIsParent = true;        // roles say we sit below the neighbour
      else if (o === 1) nbIsParent = false;   // roles say the neighbour sits below us
      if (o === 0) dirSrc.collector++; else dirSrc.role++;
      const key = `${nbIp || nbName}|${e.link_type}`;
      const prev = best.get(key);
      // prefer the row that carries a real name rather than an address placeholder
      if (!prev || (prev.name === prev.ip && nbName !== nbIp)) {
        best.set(key, { name: nbName, ip: nbIp, link: String(e.link_type ?? ""), parent: nbIsParent });
      }
    });
    Array.from(best.values())
      .sort((a, b) => (a.name || a.ip).localeCompare(b.name || b.ip))
      .forEach((v) => {
        if (v.parent) parents.push({ parent: v.name, parentIp: v.ip, link_type: v.link });
        else children.push({ child: v.name, childIp: v.ip, link_type: v.link });
      });
  }
  type ControlRow = { control?: string; name?: string; status?: string; platform?: string; verified?: string };
  const controls: ControlRow[] = (((compQ.data as { records?: ControlRow[] } | undefined)?.records) ?? [])
    .slice().sort((x, y) => (x.status === y.status ? 0 : x.status === "fail" ? -1 : 1));
  // n/a controls (not applicable to this platform) are excluded from the denominator —
  // a control that cannot apply is neither a pass nor a failure.
  const scored = controls.filter((c) => c.status === "pass" || c.status === "fail");
  const compPass = scored.filter((c) => c.status === "pass").length;
  const compPlatform = controls[0]?.platform;
  const compUnverified = controls.some((c) => String(c.verified) === "false");
  const pwr = (pwrQ.data as any)?.records?.[0] ?? {};
  const hasUps = pwr.charge != null || pwr.osrc != null;
  const hasPdu = pwr.pload != null;

  // A FAILED QUERY IS NOT AN EMPTY RESULT. This page runs eight of them and displayed neither
  // state, so a permissions gap or a Grail hiccup rendered as blank panels — indistinguishable
  // from a device that genuinely has no UPS, no neighbours, no compliance controls. Name what
  // failed; the customer can then tell "not configured" from "we could not ask".
  const failed = ([
    ["reachability", info], ["CPU", cpuQ], ["throughput", thruQ], ["interfaces", ifQ],
    ["logs", logQ], ["neighbours", depQ], ["compliance", compQ], ["power", pwrQ],
  ] as const).filter(([, q]) => (q as any)?.error).map(([n2]) => n2);

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1100 }}>
      {failed.length > 0 && (
        <div style={{ border: `1px solid ${t.down}`, borderRadius: 8, padding: "10px 14px", background: t.downBg }}>
          <QueryErr label={failed.join(", ")} />
        </div>
      )}
      <button onClick={() => nav("/devices")} style={{ background: "none", border: "none", color: t.subtle, cursor: "pointer", fontSize: 13, textAlign: "left", padding: 0 }}>‹ Devices</button>
      <Flex alignItems="center" gap={12} flexWrap="wrap">
        <Heading level={2}><span style={{ ...mono }}>{label}</span></Heading>
        <Pill status={isUp == null ? "neutral" : isUp ? "up" : "down"}>{isUp == null ? "unknown" : isUp ? "up" : "down"}</Pill>
        <span style={{ ...mono, fontSize: 13, color: t.subtle }}>{ip} · {role}</span>
      </Flex>

      {/* WHICH TILES TO SHOW IS DECIDED BY THE DATA, NOT BY AN OPERATOR-ASSIGNED ROLE.
          These branched on `role` alone, so a UPS whose role had not been assigned (the default,
          "other") got CPU / Throughput / Interfaces — three tiles that are structurally meaningless
          for it — while its battery, load and runtime were computed and thrown away. Observed live
          2026-08-03 on 10.0.10.146: header read "— · other", every tile empty or zero.
          A device answering UPS-MIB IS a UPS; that is the device telling us, not a hostname guess
          of the kind this codebase deliberately rejects. `role` still wins when set, so an operator
          can always override. */}
      <Flex gap={12} flexWrap="wrap">
        {role === "ups" || (hasUps && role !== "pdu") ? (
          <>
            <StatTile label="Power source" value={osrcLabel(pwr.osrc)} sub="mains vs battery" accent={num(pwr.osrc) === 3 ? t.up : t.down} />
            <StatTile label="Battery" value={pwr.charge != null ? `${num(pwr.charge)}%` : "—"} sub={bstatusLabel(pwr.bstatus)} accent={num(pwr.charge) >= 50 ? t.up : num(pwr.charge) >= 20 ? t.warn : t.down} />
            <StatTile label="Runtime remaining" value={pwr.umins != null ? `${num(pwr.umins)}` : "—"} sub="minutes on battery" accent={pwr.umins != null && num(pwr.umins) < 10 ? t.down : t.accent} />
          </>
        ) : role === "pdu" || hasPdu ? (
          <>
            <StatTile label="Infeed load" value={pwr.pload != null ? `${num(pwr.pload)}` : "—"} sub="×0.01 A" accent={t.accent} />
            <StatTile label="Feed status" value={num(pwr.pstatus) === 1 ? "normal" : "—"} sub="infeed A" accent={num(pwr.pstatus) === 1 ? t.up : t.down} />
            <StatTile label="Interfaces" value={ifaces.length} sub={`${up} up`} accent={t.accent} />
          </>
        ) : (
          <>
            <StatTile label="CPU" value={cpu != null ? `${cpu}%` : "—"} sub="last 15m" accent={cpu != null && cpu > 85 ? t.down : t.up} />
            <StatTile label="Throughput" value={total == null ? "—" : `${total}`}
                      sub={total == null ? "no counters on this device" : "Mbps in+out"}
                      accent={total == null ? t.subtle : t.accent} />
            <StatTile label="Interfaces" value={ifaces.length} sub={`${up} up`} accent={t.accent} />
          </>
        )}
        <StatTile label="Reachability" value={isUp == null ? "—" : isUp ? "100%" : "0%"}
                  sub={isUp == null ? (info.error ? "query failed" : "checking…") : isUp ? "answering SNMP" : "no response"}
                  accent={isUp == null ? t.subtle : isUp ? t.up : t.down} />
      </Flex>

      {/* Panel gated on EVIDENCE too. It was hidden entirely unless a role had been assigned,
          so the one device this panel exists for showed nothing at all. */}
      {(role === "ups" || role === "pdu" || hasUps || hasPdu) && (
        <Panel title={(role === "ups" || (hasUps && role !== "pdu")) ? "Power — UPS (RFC 1628 UPS-MIB)" : "Power — PDU (ServerTech infeed)"} tag={<Tag>live</Tag>}>
          {pwrQ.isLoading ? (
            <Text style={{ color: t.subtle }}>Loading…</Text>
          ) : hasUps ? (
            <Flex gap={12} flexWrap="wrap">
              {/* The header row above already carries power source, battery charge and runtime
                  remaining. This panel deliberately shows only what is NOT up there, so the two
                  do not restate each other — previously all three appeared twice on one screen. */}
              <StatTile label="Output load" value={`${num(pwr.uload)}%`} sub={wattsSub(pwr.uwatts, pwr.uload, " drawn")} accent={t.accent} />
              {/* upsBatteryVoltage is "0.1 Volt DC" per RFC 1628 — the raw 540 is 54.0 V.
                  Rendering it unscaled showed a 54 V bus as "540 volts". */}
              <StatTile label="Battery voltage" value={pwr.bvolt != null ? `${(Number(pwr.bvolt) / 10).toFixed(1)}` : "—"} sub="volts DC" accent={t.accent} />
              {/* The number an operator actually wants when the mains drop. */}
            </Flex>
          ) : hasPdu ? (
            <Flex gap={12} flexWrap="wrap">
              <StatTile label="Infeed load" value={`${num(pwr.pload)}`} sub="×0.01 A" accent={t.accent} />
              <StatTile label="Infeed status" value={num(pwr.pstatus) === 1 ? "normal" : "alarm"} sub="feed A" accent={num(pwr.pstatus) === 1 ? t.up : t.down} />
            </Flex>
          ) : (
            <Text style={{ color: t.subtle }}>No power data yet — the extension just activated; metrics appear within a poll cycle.</Text>
          )}
        </Panel>
      )}

      <Flex gap={16} flexWrap="wrap" alignItems="stretch">
        <div style={{ flex: "1 1 420px", minWidth: 320 }}>
          <Panel title="Interfaces" tag={<Tag>live</Tag>}>
            {ifQ.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : ifaces.length === 0 ? (
              <Text style={{ color: t.subtle }}>No interface data.</Text>
            ) : (
              <div style={{ overflowX: "auto", maxHeight: 360, overflowY: "auto" }}>
                <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 14 }}>
                  <thead>
                    <tr>{["ifIndex", "Oper", "Admin", "Speed (Mbps)", "↓ In (Mbps)", "↑ Out (Mbps)"].map((h) => <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: t.subtle, fontWeight: 600, borderBottom: `1px solid ${t.border}` }}>{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {ifaces.map((r, i) => (
                      <tr key={i}>
                        <td style={{ ...mono, padding: "7px 12px", borderBottom: `1px solid ${t.border}` }}>{r.if_index}</td>
                        <td style={{ padding: "7px 12px", borderBottom: `1px solid ${t.border}` }}><Pill status={num(r.o) === 1 ? "up" : num(r.o) === 2 ? "down" : "neutral"}>{num(r.o) === 1 ? "up" : num(r.o) === 2 ? "down" : "—"}</Pill></td>
                        <td style={{ ...mono, padding: "7px 12px", borderBottom: `1px solid ${t.border}`, color: t.subtle }}>{num(r.a) === 1 ? "up" : "down"}</td>
                        <td style={{ ...mono, padding: "7px 12px", borderBottom: `1px solid ${t.border}`, color: t.subtle }}>{r.sp ? `${num(r.sp)}` : "—"}</td>
                        <td style={{ ...mono, padding: "7px 12px", borderBottom: `1px solid ${t.border}`, color: mbps(r.inMbps) === "—" ? t.subtle : t.ink }}>{mbps(r.inMbps)}</td>
                        <td style={{ ...mono, padding: "7px 12px", borderBottom: `1px solid ${t.border}`, color: mbps(r.outMbps) === "—" ? t.subtle : t.ink }}>{mbps(r.outMbps)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
        <div style={{ flex: "1 1 380px", minWidth: 300 }}>
          <Panel title="Activity — config, syslog & traps (24h)" tag={<Tag>live</Tag>}>
            {logQ.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : logs.length === 0 ? (
              <Text style={{ color: t.subtle }}>No recent activity for this device.</Text>
            ) : (
              <Flex flexDirection="column" style={{ maxHeight: 360, overflowY: "auto" }}>
                {logs.map((r, i) => {
                  const [label, color] = badge(r.source);
                  return (
                    <Flex key={i} gap={12} alignItems="baseline" style={{ padding: "6px 0", borderBottom: `1px solid ${t.border}` }}>
                      <Text style={{ ...mono, color: t.subtle, fontSize: 12, minWidth: 100 }}>{fmt(r.timestamp)}</Text>
                      <Text style={{ ...mono, color, fontWeight: 700, fontSize: 12, minWidth: 54 }}>{label}</Text>
                      <Text style={{ ...mono, fontSize: 12 }}>{r.content}</Text>
                    </Flex>
                  );
                })}
              </Flex>
            )}
          </Panel>
        </div>
      </Flex>

      <Panel title="Dependencies — parent / child" tag={<Tag>live</Tag>}>
        {/* Provenance, not decoration. Direction on an LLDP edge is DERIVED — adjacency is
            undirected — so a flat parent/child list overstates its own certainty. Says which
            edges the customer's role assignments decided and which fell back to the collector's
            capability heuristic, and points at the fix when the heuristic is all there is. */}
        {dirSrc.collector > 0 ? (
          <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginBottom: 10 }}>
            Direction: {dirSrc.role > 0 ? `${dirSrc.role} from your role assignments, ` : ""}
            {dirSrc.collector} inferred from LLDP capability. LLDP does not say which end is
            upstream — assign roles to both devices to correct it.
          </Text>
        ) : dirSrc.role > 0 ? (
          <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginBottom: 10 }}>
            Direction from your role assignments.
          </Text>
        ) : null}
        <Flex gap={24} flexWrap="wrap">
          <div style={{ flex: "1 1 300px", minWidth: 260 }}>
            <div style={{ fontSize: 13, color: t.subtle, fontWeight: 600, letterSpacing: "0.04em", marginBottom: 8 }}>DEPENDS ON (UPSTREAM)</div>
            {parents.length === 0 ? (
              <Text style={{ color: t.subtle, fontSize: 14 }}>No upstream dependency mapped.</Text>
            ) : (
              <Flex flexDirection="column" gap={6}>
                {parents.map((p, i) => (
                  <Flex key={i} gap={8} alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 11px" }}>
                    <span style={{ color: t.accent, fontWeight: 700 }}>↑</span>
                    <span style={{ ...mono, fontSize: 14, fontWeight: 600, cursor: "pointer", color: t.accent }} onClick={() => nav(`/device/${encodeURIComponent(p.parentIp || p.parent)}`)}>{deviceLabel(p.parent, p.parentIp)}</span>
                    <span style={{ fontSize: 12, color: t.subtle }}>{p.link_type}</span>
                  </Flex>
                ))}
              </Flex>
            )}
          </div>
          <div style={{ flex: "1 1 300px", minWidth: 260 }}>
            <div style={{ fontSize: 13, color: t.subtle, fontWeight: 600, letterSpacing: "0.04em", marginBottom: 8 }}>IMPACTS IF IT FAILS (DOWNSTREAM)</div>
            {children.length === 0 ? (
              <Text style={{ color: t.subtle, fontSize: 14 }}>Nothing depends on this device.</Text>
            ) : (
              <>
                <Flex flexDirection="column" gap={6}>
                  {children.map((c, i) => (
                    <Flex key={i} gap={8} alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 11px" }}>
                      <span style={{ color: t.down, fontWeight: 700 }}>↓</span>
                      <span style={{ ...mono, fontSize: 14, fontWeight: 600, cursor: "pointer", color: t.accent }} onClick={() => nav(`/device/${encodeURIComponent(c.childIp || c.child)}`)}>{deviceLabel(c.child, c.childIp)}</span>
                      <span style={{ fontSize: 12, color: t.subtle }}>{c.link_type}</span>
                    </Flex>
                  ))}
                </Flex>
                <Text style={{ color: t.subtle, fontSize: 13, marginTop: 8, display: "block" }}>
                  If this device fails, these {children.length} lose their path — Davis pages the root cause once and suppresses them as symptoms (no alarm storm).
                </Text>
              </>
            )}
          </div>
        </Flex>
      </Panel>

      <Panel title="Compliance — ISO-27001:2022" tag={<Tag>live</Tag>}>
        {compQ.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : controls.length === 0 ? (
          <Text style={{ color: t.subtle }}>No compliance evidence for this device (config not captured).</Text>
        ) : (
          <>
            <Text style={{ color: t.subtle, fontSize: 14, marginBottom: 10, display: "block" }}>
              <span style={{ color: compPass === scored.length ? t.up : t.warn, fontWeight: 700 }}>{compPass}/{scored.length}</span> controls pass{compPlatform ? <> · rule set <b>{compPlatform}</b>{compUnverified ? <span style={{ color: t.warn }}> *</span> : null}</> : null} — evaluated on the captured running-config.{compUnverified ? <div style={{ color: t.warn, fontSize: 12.5, marginTop: 6 }}>* This rule set was written from vendor documentation and has <b>not</b> been verified against a real {compPlatform} device. Treat these results as indicative — share a sanitised config to have them validated.</div> : null}
            </Text>
            <Flex flexDirection="column">
              {controls.map((c, i) => (
                <Flex key={i} gap={12} alignItems="center" style={{ padding: "9px 4px", borderBottom: `1px solid ${t.border}` }}>
                  <span style={{ ...mono, fontSize: 13, fontWeight: 600, color: c.status === "fail" ? t.down : t.subtle, minWidth: 56 }}>{c.control}</span>
                  <span style={{ flex: 1, fontSize: 14, color: c.status === "fail" ? t.down : c.status === "not_applicable" ? t.subtle : t.ink }}>{c.name}</span>
                  <span style={{ fontSize: 12, fontWeight: 700, padding: "3px 10px", borderRadius: 20, color: c.status === "pass" ? t.up : c.status === "not_applicable" ? t.subtle : t.down, background: c.status === "pass" ? t.upBg : c.status === "not_applicable" ? t.cardSubtle : t.downBg }}>{c.status === "pass" ? "pass" : c.status === "not_applicable" ? "n/a" : "fail"}</span>
                </Flex>
              ))}
            </Flex>
          </>
        )}
      </Panel>

      {/* Retire lives HERE, not on a row in the Devices table — see components/RetireAction for why.
          Last on the page on purpose: you reach it having scrolled past this device's interfaces,
          activity, dependencies and compliance, so "am I retiring the right thing" is already
          answered by the time you arrive. */}
      {ip && ip !== "—" ? (
        <RetireAction device={{ ip, name: infoRow?.sysName || dev, label, status: up > 0 ? "up" : "down" }} />
      ) : null}

      {entity ? (
        entityLink(entity) ? (
          <a href={entityLink(entity)} target="_top" style={{ color: t.accent, fontSize: 14, textDecoration: "none" }}>
            Open <span style={{ ...mono }}>{entity}</span> in Dynatrace ↗
          </a>
        ) : (
          <Text style={{ color: t.subtle, fontSize: 13 }}>Entity <span style={{ ...mono }}>{entity}</span></Text>
        )
      ) : null}
    </Flex>
  );
};
