import { useDql } from "@dynatrace-sdk/react-hooks";
import type { MirrorData, BarRow } from "../components/charts";
import { appOf } from "../components/charts";
import { flowFactorMul, SAMPLER_ADDR, SAMPLING_RATE } from "./netflowMode";

/* ============================================================================
   NetFlow data hooks — the real flow feed (decoder -> OTLP logs -> BindPlane)
   plus SNMP interface counters (cno.if.*). Direction on the flow layer is derived
   (flows don't carry it usably): internal (RFC1918) -> external = outbound,
   external -> internal = inbound, else east-west.

   VALIDATED against the live tenant: the summarize queries (talkers / apps / convos
   / stats) and the direction derivation.
   PENDING live-verify (marked //VERIFY): makeTimeseries array shape, and the SNMP
   interface dimension keys — finalized in the deploy/verify pass.
   ============================================================================ */

// NEVER PIN THE WIRE VERSION HERE. This was `flow.type == "netflow_v9"`, which was
// true of the synthetic generator and false of every real exporter we later pointed
// at it: the UniFi UCG Ultra speaks IPFIX, so it stamps flow.type = "ipfix" and each
// panel below silently returned zero rows against a feed that was arriving correctly
// (measured 2026-08-03 — 688 records in Grail, none visible in the app).
//
// A flow record is identified by BEING a flow record, not by which protocol carried
// it. flow.type is retained on every record as PROVENANCE — worth grouping by when
// you want to know what a device is speaking — but it is deliberately not a filter,
// so v5, v9, IPFIX and a future sFlow decoder all light the same panels with no app
// change. Adding a version must never require an edit here.
const FLOW = 'isNotNull(`flow.type`)';
// derive inbound / outbound / east-west from RFC1918 membership of each endpoint
const DIR =
  'fieldsAdd sp = ipIsPrivate(toIp(`source.address`)), dp = ipIsPrivate(toIp(`destination.address`)) ' +
  '| fieldsAdd dir = if(sp and not dp, "outbound", else: if(not sp and dp, "inbound", else: "east-west"))';

const OPTS = { staleTime: 30000 } as const;
const recordsOf = (q: any): any[] => (q?.data as any)?.records ?? [];
const num = (v: any) => Number(v) || 0;

// Query window is driven by the NetFlow time picker (setNetflowWindow); the page
// re-keys the approach subtree on change so the hooks re-query with the new window.
export let CURRENT_WINDOW = "-6h";
export function setNetflowWindow(w: string) { CURRENT_WINDOW = w; }
export function winSeconds(win: string): number { const m = win.match(/(\d+)h/); return m ? parseInt(m[1], 10) * 3600 : 21600; }
// Pure helpers live in ./metrics so they are unit-testable without a browser runtime.
// Re-exported here because call sites (and the DeviceDetail page) already import them from netflow.
import { SERIES_INTERVAL_S, octetsToMbps, percentile, outerTs, IF_DOWN, counterDeltas } from "./metrics";
import type { TsPart } from "./metrics";
export { percentile, outerTs, IF_DOWN };
export type { TsPart };

/* ---- ONE broad per-conversation scan, shared by every summary panel below ----
   Talkers / apps / conversations / app-shares / egress-ASN / egress-Sankey used to each run
   their own `fetch logs | filter V9 | summarize by:{…}` — ~6 concurrent scans of the SAME
   window (staleTime only dedups IDENTICAL query strings, not overlapping scans). They now all
   derive from this single conversation-level result client-side, so TanStack dedups the one
   identical query to ONE fetch. Derivations are exact while distinct conversations <= the limit
   (always true in the lab); past that the long tail is approximate — raise the limit if needed. */
export type FlowFact = { src: string; dst: string; port: string; transport: string; dir: string; bytes: number; packets: number; flows: number; dstOrg?: string; dstAsn?: number; dstRdns?: string };
const mask24 = (ip: string): string => { const p = ip.split("."); return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : ip; };
export function useFlowFacts(): { rows: FlowFact[]; isLoading: boolean; error?: unknown } {
  const MUL = flowFactorMul(); // Sampled → per-flow × sampling.rate (manual-N fallback) inside the sum; else ""
  const q = useDql(
    // The enrichment fields are AGGREGATED, not grouped on. Grouping by them would split a
    // destination into two rows whenever some of its flows were captured before the collector's
    // lookup cache had warmed (the first flows to a new address ship unenriched by design), and
    // the byte totals would silently disagree with every other panel. takeMax ignores nulls, so
    // one enriched flow is enough to label the whole conversation.
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} | ${DIR} | summarize bytes = sum(toDouble(\`flow.io.bytes\`)${MUL}), packets = sum(toLong(\`flow.io.packets\`)${MUL}), flows = count(), dstOrg = takeMax(\`flow.dst_org\`), dstAsn = takeMax(\`flow.dst_asn\`), dstRdns = takeMax(\`flow.dst_rdns\`), by:{src = \`source.address\`, dst = \`destination.address\`, port = \`destination.port\`, transport = \`network.transport\`, dir} | sort bytes desc | limit 1000` },
    OPTS,
  );
  const rows: FlowFact[] = recordsOf(q).map((r) => ({ src: r.src, dst: r.dst, port: String(r.port), transport: r.transport, dir: r.dir, bytes: num(r.bytes), packets: num(r.packets), flows: num(r.flows), dstOrg: r.dstOrg ?? undefined, dstAsn: r.dstAsn != null ? num(r.dstAsn) : undefined, dstRdns: r.dstRdns ?? undefined }));
  return { rows, isLoading: q.isLoading, error: q.error };
}

/* ---- directional throughput series for the mirror chart (from flow bytes) ---- */
export function useFlowSeries(): { data: MirrorData; isLoading: boolean } {
  const MUL = flowFactorMul();
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} | ${DIR} | makeTimeseries bytes = sum(toDouble(\`flow.io.bytes\`)${MUL}), by:{dir}, interval:10m` },
    OPTS,
  );
  const recs = recordsOf(q);
  const seriesFor = (dir: string): number[] => {
    const r = recs.find((x) => x.dir === dir);
    const arr: any[] = Array.isArray(r?.bytes) ? r.bytes : []; //VERIFY makeTimeseries array key
    return arr.map((b) => octetsToMbps(num(b)));
  };
  const inn = seriesFor("inbound");
  const out = seriesFor("outbound");
  const len = Math.max(inn.length, out.length);
  const labels: string[] = [];
  for (let i = 0; i < len; i++) {
    const winMin = winSeconds(CURRENT_WINDOW) / 60;
    const mins = Math.round((1 - i / Math.max(1, len - 1)) * winMin);
    labels.push(i === len - 1 ? "now" : mins >= 60 ? `-${Math.floor(mins / 60)}h` : `-${mins}m`);
  }
  const pad = (a: number[]) => (a.length ? a : new Array(len).fill(0));
  return { data: { t: labels, inn: pad(inn), out: pad(out) }, isLoading: q.isLoading };
}

/* ---- top talkers by source, split by direction (derived from useFlowFacts) ---- */
export function useTalkers(limit = 6): { inbound: BarRow[]; outbound: BarRow[]; isLoading: boolean; error?: unknown } {
  const { rows, isLoading, error } = useFlowFacts();
  const pick = (dir: string): BarRow[] => {
    const agg: Record<string, number> = {};
    rows.filter((r) => r.dir === dir).forEach((r) => { agg[r.src] = (agg[r.src] || 0) + r.bytes; });
    return Object.entries(agg).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([ip, v]) => ({ name: ip, v, label: mbLabel(v), unit: mbUnit(v) }));
  };
  // when inbound is sparse (lab), fall back to east-west so the panel is never empty
  const inbound = pick("inbound");
  return { inbound: inbound.length ? inbound : pick("east-west"), outbound: pick("outbound"), isLoading, error };
}

/* ---- applications by destination port (derived from useFlowFacts) ---- */
export function useApps(limit = 7): { rows: BarRow[]; isLoading: boolean; error?: unknown } {
  const { rows: facts, isLoading, error } = useFlowFacts();
  const agg: Record<string, { port: string; transport: string; bytes: number }> = {};
  facts.forEach((r) => { const k = `${r.port}/${r.transport}`; (agg[k] = agg[k] || { port: r.port, transport: r.transport, bytes: 0 }).bytes += r.bytes; });
  const rows = Object.values(agg).sort((a, b) => b.bytes - a.bytes).slice(0, limit).map((r) => {
    const a = appOf(r.port);
    return { name: a.label, sub: r.port, v: r.bytes, label: mbLabel(r.bytes), unit: mbUnit(r.bytes), dot: a.hue, tip: `${r.port}/${r.transport} ${a.label}` } as BarRow;
  });
  return { rows, isLoading, error };
}

/* ---- top conversations (src <-> dst) ---- */
export type Convo = { src: string; dst: string; port: string; transport: string; app: string; hue: string; dir: string; bytes: number; packets?: number };
export type ConvoScope = "all" | "ns" | "ew";

/** Top conversations, optionally scoped to a traffic direction.
 *
 *  THE SCOPE EXISTS BECAUSE A SECOND EXPORTER CHANGED WHAT "TOP" MEANS. Ranking purely by bytes
 *  was right while every record came from the gateway, which only ever sees north-south. The
 *  moment a switch started exporting, east-west arrived — sampled 1-in-1024, so scaled x1024 —
 *  and a storage fabric replicating between three nodes buried every internet conversation in
 *  the table. Both are legitimately "top"; they are just answers to different questions, and one
 *  list cannot rank them against each other usefully.
 *
 *  north-south = crosses the perimeter (inbound or outbound). east-west = stays internal. */
export function useConvos(limit = 8, scope: ConvoScope = "all"): { rows: Convo[]; isLoading: boolean; error?: unknown } {
  const { rows: allFacts, isLoading, error } = useFlowFacts();
  const facts = scope === "ns" ? allFacts.filter((r) => r.dir !== "east-west")
    : scope === "ew" ? allFacts.filter((r) => r.dir === "east-west")
    : allFacts;
  const rows = facts.slice(0, limit).map((r) => {
    const a = appOf(r.port);
    return { src: r.src, dst: r.dst, port: r.port, transport: r.transport, app: a.label, hue: a.hue, dir: r.dir, bytes: r.bytes, packets: r.packets } as Convo;
  });
  return { rows, isLoading, error };
}

/* ---- flow health + headline stats ---- */
// stalenessSec is DELIBERATELY nullable, and samplingKnown exists for the same reason.
// "No records in the window" is not "0 seconds old" and not "1-in-1 sampling" — it is an
// absence, and collapsing it to a flattering number is how the Flow health panel came to
// report "Feed healthy · 100% · 0s" while exporters and flows both read 0 (seen 2026-08-03).
// Callers must branch on hasFeed before rendering any of these as a verdict.
export type FlowStats = {
  flows: number; inMbps: number; outMbps: number; ewMbps: number; talkers: number;
  exporters: number; samplingRate: number; samplingKnown: boolean;
  stalenessSec: number | null; hasFeed: boolean; versions: string[]; isLoading: boolean;
};
export function useFlowStats(): FlowStats {
  const MUL = flowFactorMul(); // Sampled → per-flow × sampling.rate on the byte sums; "" otherwise
  const q = useDql(
    {
      query:
        `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} | ${DIR} ` +
        `| summarize flows = count(), talkers = countDistinct(\`source.address\`), exporters = countDistinct(${SAMPLER_ADDR}), ` +
        `newest = takeMax(timestamp), sampling = takeMax(${SAMPLING_RATE}), versions = collectDistinct(\`flow.type\`), ` +
        `inB = sum(if(dir=="inbound", toDouble(\`flow.io.bytes\`)${MUL}, else:0)), outB = sum(if(dir=="outbound", toDouble(\`flow.io.bytes\`)${MUL}, else:0)), ewB = sum(if(dir=="east-west", toDouble(\`flow.io.bytes\`)${MUL}, else:0))`,
    },
    OPTS,
  );
  const r = recordsOf(q)[0] || {};
  const winS = winSeconds(CURRENT_WINDOW);
  // flows/talkers/exporters stay OBSERVED (feed-health counts; distinct counts can't be linearly
  // extrapolated). Only the byte VOLUMES are extrapolated — done per-flow inside the query above.
  // null, not 0 — see the FlowStats note. An empty window has no newest record, and the age
  // of a record that does not exist is unknown, not zero.
  const staleness = r.newest ? Math.max(0, Math.round((Date.now() - new Date(r.newest).getTime()) / 1000)) : null;
  const flows = num(r.flows);
  return {
    flows, talkers: num(r.talkers), exporters: num(r.exporters),
    inMbps: octetsToMbpsWin(num(r.inB), winS), outMbps: octetsToMbpsWin(num(r.outB), winS), ewMbps: octetsToMbpsWin(num(r.ewB), winS),
    // 1:1 is the correct assumption for an UNSAMPLED exporter, but it is an assumption. The UCG
    // Ultra omits flow.sampling.rate entirely, so samplingKnown lets the UI say "assumed" rather
    // than assert a rate the exporter never stated — the byte totals depend on it being right.
    samplingRate: num(r.sampling) || 1, samplingKnown: r.sampling != null,
    stalenessSec: staleness, hasFeed: flows > 0,
    versions: Array.isArray(r.versions) ? r.versions.filter(Boolean).map(String) : [],
    isLoading: q.isLoading,
  };
}

/* ---- interface inventory + throughput from the SNMP counters ----
   Feeds BOTH the Drill-down and Edge views, so a mistake here reads as "the whole fleet is
   idle" in two places at once — which is exactly what happened. */
export type IfRow = { dev: string; iface: string; ifIndex: number; speedMbps: number; oper: number; inMbps: number | null; outMbps: number | null; inP95: number | null; outP95: number | null; p95: number | null; p95Util: number | null; util: number; inn: number[]; out: number[] };
export function useIfList(limit = 200): { rows: IfRow[]; isLoading: boolean } {
  // max() PER BUCKET, THEN DIFFERENCE — the counter arrives ABSOLUTE.
  //
  // This comment previously said the opposite, and said it with confidence: that `type: count`
  // means the datasource delivers "bytes since the last poll", so summing was correct and
  // diffing was meaningless. Measured 2026-08-10, that is false. The stored values are the
  // running counter (5.09e12 and climbing); differencing them yields 6.6e8 per poll, exactly the
  // expected traffic. Summing sixty absolute readings per bucket produced 676 Gbps on a 40 Gbps
  // link, rising 5.3 Gbps an hour, with every interface pinned at 100% utilisation.
  //
  // The wrong comment is why it survived: it read as a settled decision with a validation date
  // attached, so nobody re-derived it. See counterDeltas() in metrics.ts for the evidence.
  //
  // That 2026-08-03 "validated against the Device Detail tile" note went with it. It cannot have
  // been true: Device Detail has always used max()+arrayDelta, so the two could not have agreed
  // while this hook summed. Either the tile was misread or the number was never actually compared.
  // Today they agree because they now compute the same thing.
  const q = useDql(
    // SPINE = oper_status: every polled interface reports it, while the octet counters exist on
    // only 109 of 140 here. Inner-joining them lost 31 interfaces, 9 of them up and passing traffic.
    { query: outerTs(
        { as: "oper", expr: "avg(cno.if.oper_status)" },
        [{ as: "spd",  expr: "avg(cno.if.high_speed)" },
         { as: "inb",  expr: "max(cno.if.in_octets.count)" },
         { as: "outb", expr: "max(cno.if.out_octets.count)" }],
        { dev: "sys_name", iface: "if_descr", ifidx: "if_index" }, CURRENT_WINDOW, "10m")
        + `\n | limit ${limit}` },
    OPTS,
  );
  /* THE LIMIT WAS DECLARED AND NEVER APPLIED. `useIfList(limit = 200)` took the parameter, built
     the query without it, and returned every interface on the estate. Harmless at the lab's ~185
     and not at all harmless at BDO's ~28,000 — every one of them parsed and held in the browser
     before any filtering. Found by auditing the signature against the query rather than by
     anything failing, which is the only way this class of bug ever surfaces. */
  // null (an absent metric) is NOT zero. An interface the counters never covered returns
  // mbps=null and the table prints "-" instead of a measured-looking 0.0 Mbps.
  const rate = (arr: any[]): { series: number[]; mbps: number | null; p95: number | null } => {
    if (!Array.isArray(arr)) return { series: [], mbps: null, p95: null };
    // Absolute readings -> per-bucket increases, THEN to a rate.
    const raw: (number | null)[] = counterDeltas(arr);
    // TRIM THE UNKNOWN ENDS INSTEAD OF DRAWING THEM AS ZERO.
    // Two buckets are never measurements: the FIRST (counterDeltas has no predecessor to
    // difference against) and the LAST (still filling, arrives null until it closes). Coercing
    // both to 0 pinned every sparkline to the floor at both ends, so all 189 rows drew the same
    // symmetric lens and the chart read as a decorative shape rather than as data. The zeros
    // were also the larger half of the visible amplitude, which squashed the real variation into
    // about three pixels of a 26px chart.
    let lo = 0; while (lo < raw.length && raw[lo] == null) lo++;
    let hi = raw.length - 1; while (hi >= lo && raw[hi] == null) hi--;
    if (hi < lo) return { series: [], mbps: null, p95: null };
    const known = raw.slice(lo, hi + 1);
    // Interior nulls (a device that missed a poll) stay 0 — that is a real gap, not a trim.
    const series = known.map((v) => (v == null ? 0 : Math.max(0, v) * 8 / SERIES_INTERVAL_S / 1e6));
    // THE LAST BUCKET IS THE ONE STILL FILLING, and it arrives as null until it closes. Reading
    // it as the current rate reported 0 Mbps for every interface on the fleet while the switches
    // were passing real traffic — a null coerced to 0 and then presented as a measurement. Take
    // the newest CLOSED bucket instead, and say nothing rather than say zero if there is none.
    // The trim already dropped the still-filling tail, so the last element IS the newest closed
    // bucket. (Reading the raw tail used to report 0 Mbps for the whole fleet while the switches
    // were passing traffic — a null coerced to 0 and then presented as a measurement.)
    return { series, mbps: series.length ? series[series.length - 1] : null,
             p95: percentile(series.filter((_, k) => known[k] != null), 95) };
  };
  /* NEWEST CLOSED BUCKET, for every series — not just the rates.
     rate() already does this and explains why: the last bucket is still filling and arrives null.
     oper and spd were reading `arr[arr.length - 1]` raw, so both got that null, num() turned it
     into 0, and the fleet-wide view filtered on `oper === 1`. Measured 2026-08-05: 17 devices and
     ~185 interfaces were reporting oper_status, and the Hottest-edges panel showed "1 of 1 up
     links" — the single survivor being an API-sourced SD-WAN interface whose different cadence
     happened to fill the final bucket. Its speed read "0M" for the same reason.
     The warning was already written in this file, three lines up, for the fields that were fixed. */
  const lastClosed = (v: any): number | null => {
    if (!Array.isArray(v)) return v == null ? null : num(v);
    for (let k = v.length - 1; k >= 0; k--) if (v[k] != null) return num(v[k]);
    return null;
  };
  const rows: IfRow[] = recordsOf(q).map((r) => {
    const i = rate(r.inb), o = rate(r.outb);
    const speed = Math.round(lastClosed(r.spd) ?? 0);
    const best = Math.max(i.mbps ?? 0, o.mbps ?? 0);
    const util = speed > 0 && (i.mbps != null || o.mbps != null) ? Math.min(100, (best / speed) * 100) : 0;
    // Circuit sizing uses the BUSIER DIRECTION at p95, not the sum: a carrier polls each direction
    // and bills the higher of the two, so adding them would overstate the bill.
    const p95 = i.p95 == null && o.p95 == null ? null : Math.max(i.p95 ?? 0, o.p95 ?? 0);
    const p95Util = speed > 0 && p95 != null ? Math.min(100, (p95 / speed) * 100) : null;
    return { dev: r.dev, iface: r.iface, ifIndex: num(r.ifidx), speedMbps: speed, oper: lastClosed(r.oper) ?? 0, inMbps: i.mbps, outMbps: o.mbps, inP95: i.p95, outP95: o.p95, p95, p95Util, util, inn: i.series, out: o.series };
  });
  // fastest links first (uplinks/port-channels), then by util
  rows.sort((a, b) => b.speedMbps - a.speedMbps || b.util - a.util);
  return { rows: rows.slice(0, limit), isLoading: q.isLoading };
}

/* ---- per-interface flows: conversations that ingress/egress a specific ifIndex.
   Possible only because netflow_v9_collector.py preserves INPUT/OUTPUT_SNMP that the
   OTel receiver drops — the flow carries the interface, so we filter on it directly. ---- */
export function useInterfaceFlows(ifIndex: number | null | undefined): { convos: Convo[]; talkers: BarRow[]; hasIfData: boolean; isLoading: boolean } {
  const enabled = ifIndex != null && ifIndex > 0;
  const MUL = flowFactorMul();
  const q = useDql(
    { query: enabled
      ? `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} and (toLong(\`flow.interface.input\`) == ${ifIndex} or toLong(\`flow.interface.output\`) == ${ifIndex}) | summarize bytes = sum(toDouble(\`flow.io.bytes\`)${MUL}), by:{src = \`source.address\`, dst = \`destination.address\`, port = \`destination.port\`, transport = \`network.transport\`, ingress = \`flow.interface.input\`} | sort bytes desc | limit 10`
      : `fetch logs, from:-1m | limit 0` },
    OPTS,
  );
  const recs = enabled ? recordsOf(q) : [];
  const convos: Convo[] = recs.map((r) => { const a = appOf(r.port); return { src: r.src, dst: r.dst, port: String(r.port), transport: r.transport, app: a.label, hue: a.hue, dir: num(r.ingress) === ifIndex ? "ingress" : "egress", bytes: num(r.bytes) }; });
  const talkers: BarRow[] = recs.slice(0, 6).map((r) => ({ name: r.src, sub: `→ ${r.dst}`, v: num(r.bytes), label: mbLabel(num(r.bytes)), unit: mbUnit(num(r.bytes)) }));
  return { convos, talkers, hasIfData: convos.length > 0, isLoading: q.isLoading };
}

/* ---- static IP -> ASN enrichment (how MaxMind / Team Cymru style lookups work;
   flows don't carry dst_as, so we resolve the known egress destinations here) ---- */
const ASN_MAP: { prefix: string; asn: string; name: string; hue: string }[] = [
  { prefix: "8.8.", asn: "AS15169", name: "Google", hue: "green" },
  { prefix: "142.250.", asn: "AS15169", name: "Google", hue: "green" },
  { prefix: "20.190.", asn: "AS8075", name: "Microsoft", hue: "blue" },
  { prefix: "52.96.", asn: "AS8075", name: "Microsoft", hue: "blue" },
  { prefix: "13.107.", asn: "AS8075", name: "Microsoft", hue: "blue" },
  { prefix: "52.216.", asn: "AS16509", name: "AWS", hue: "magenta" },
  { prefix: "104.18.", asn: "AS13335", name: "Cloudflare", hue: "yellow" },
  { prefix: "23.51.", asn: "AS20940", name: "Akamai", hue: "aqua" },
  { prefix: "151.101.", asn: "AS54113", name: "Fastly", hue: "orange" },
];
/** Cymru returns "AMAZON-02 - Amazon.com, Inc., US" — a handle, the org, and a country code.
 *  Only the middle part is worth showing: "Amazon.com, Inc.". Kept lossless upstream (the raw
 *  string is in Grail as flow.dst_org) — this is presentation only. */
export function prettyOrg(raw: string): string {
  let s = String(raw || "").trim();
  const dash = s.indexOf(" - ");
  if (dash > 0) s = s.slice(dash + 3).trim();        // drop the AS handle prefix
  s = s.replace(/,\s*[A-Z]{2}$/, "").trim();          // drop the trailing country code
  return s || String(raw || "");
}

// Deterministic colour for an organisation the static table has never heard of, so the same
// provider keeps the same colour between renders instead of shuffling.
const HUES = ["green", "blue", "magenta", "yellow", "aqua", "orange"];
function hueFor(key: string): string {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return HUES[h % HUES.length];
}

/** Resolution for a conversation, PREFERRING what the collector actually looked up.
 *
 *  The collector now stamps flow.dst_asn / _org / _rdns at ingest (Team Cymru + rDNS), which is
 *  real resolution rather than a guess — measured 95% coverage of public destinations. The
 *  static table below survives only as a fallback for records captured before enrichment
 *  existed, and the /24 remains the last resort so an unresolved destination is still separated
 *  and still labelled honestly rather than pooled into a fake "Other" category. */
export function asnOfFact(f: { dst: string; dstOrg?: string; dstAsn?: number; dstRdns?: string }): { asn: string; name: string; hue: string } {
  if (f.dstOrg) {
    const name = prettyOrg(f.dstOrg);
    return { asn: f.dstAsn != null ? `AS${f.dstAsn}` : "—", name, hue: hueFor(name) };
  }
  return asnOf(f.dst);
}

export function asnOf(ip: string): { asn: string; name: string; hue: string } {
  for (const e of ASN_MAP) if (ip.startsWith(e.prefix)) return { asn: e.asn, name: e.name, hue: e.hue };
  // NOT a bucket called "Other". Measured against the live feed 2026-08-03, the table above
  // matched ZERO of the top egress destinations — 185.203.219.114, 18.202.107.243, 52.204.37.47,
  // 34.240.154.243, 35.170.190.212 — so the Sankey collapsed 100% of egress into one grey bar
  // labelled "Other". That reads as a destination when it actually means "not resolved", which
  // is the same absence-as-a-value mistake as the flow-health panel.
  //
  // Falls back to the destination /24 so the chart still separates real destinations, and the
  // sub-label says "unresolved" so nobody mistakes it for an identified network. Widening the
  // prefix table is NOT the fix — AWS alone publishes hundreds of ranges and they change; this
  // needs genuine enrichment (MaxMind / Team Cymru / a Dynatrace IP-lookup), which is a data
  // source decision rather than a code change. Until then it is honest about not knowing.
  return { asn: "unresolved", name: mask24(ip), hue: "other" };
}

/* ---- egress Sankey: source /24 subnet -> destination ASN (outbound flows) ---- */
// dstMeta carries rawOrg alongside the display label: the node is keyed on the prettified name,
// but handing off to Investigate has to filter Grail on the value actually stored in
// flow.dst_org — "Amazon.com, Inc." matches nothing against "AMAZON-02 - Amazon.com, Inc., US".
export type SankeyData = { links: { src: string; dst: string; v: number }[]; srcMeta: Record<string, { label: string; sub?: string }>; dstMeta: Record<string, { label: string; sub?: string; hue?: string; rawOrg?: string }> };
export function useEgressSankey(limit = 14): { data: SankeyData; isLoading: boolean; error?: unknown } {
  const { rows, isLoading, error } = useFlowFacts();
  const linkAgg: Record<string, number> = {};
  const srcMeta: SankeyData["srcMeta"] = {}, dstMeta: SankeyData["dstMeta"] = {};
  rows.filter((r) => r.dir === "outbound").forEach((r) => {
    const sub = mask24(r.src), a = asnOfFact(r);
    linkAgg[`${sub}|${a.name}`] = (linkAgg[`${sub}|${a.name}`] || 0) + r.bytes;
    srcMeta[sub] = { label: sub, sub: "subnet" };
    dstMeta[a.name] = { label: a.name, sub: a.asn, hue: a.hue, rawOrg: r.dstOrg };
  });
  const links = Object.entries(linkAgg).map(([k, v]) => { const [src, dst] = k.split("|"); return { src, dst, v }; }).sort((a, b) => b.v - a.v).slice(0, limit);
  return { data: { links, srcMeta, dstMeta }, isLoading, error };
}

/* ---- egress by destination ASN (peering / transit view) — derived from useFlowFacts ---- */
export function useEgressAsn(limit = 6): { rows: BarRow[]; isLoading: boolean; error?: unknown } {
  const { rows: facts, isLoading, error } = useFlowFacts();
  const agg: Record<string, { name: string; asn: string; hue: string; bytes: number }> = {};
  facts.filter((r) => r.dir === "outbound").forEach((r) => { const a = asnOfFact(r); agg[a.name] = agg[a.name] || { ...a, bytes: 0 }; agg[a.name].bytes += r.bytes; });
  const rows = Object.values(agg).sort((a, b) => b.bytes - a.bytes).slice(0, limit).map((a) => ({ name: a.name, sub: a.asn, v: a.bytes, label: mbLabel(a.bytes), unit: mbUnit(a.bytes), dot: a.hue } as BarRow));
  return { rows, isLoading, error };
}

/* ---- application composition (% of bytes) split by direction, for the share bars ---- */
export type SharePart = { name: string; pct: number; port: string };
export function useAppShares(): { inbound: SharePart[]; outbound: SharePart[]; isLoading: boolean; error?: unknown } {
  const { rows, isLoading, error } = useFlowFacts();
  const build = (dir: string): SharePart[] => {
    const agg: Record<string, number> = {};
    rows.filter((r) => r.dir === dir).forEach((r) => { agg[r.port] = (agg[r.port] || 0) + r.bytes; });
    const sorted = Object.entries(agg).sort((a, b) => b[1] - a[1]);
    const total = sorted.reduce((s, [, v]) => s + v, 0) || 1;
    const top = sorted.slice(0, 4).map(([port, v]) => ({ name: appOf(port).label, port, pct: Math.round((v / total) * 100) }));
    const acc = top.reduce((s, p) => s + p.pct, 0);
    if (acc < 100 && sorted.length > 4) top.push({ name: "Other", port: "—", pct: 100 - acc });
    return top;
  };
  // inbound sparse in lab -> fall back to east-west so the panel fills
  const inbound = build("inbound");
  return { inbound: inbound.length ? inbound : build("east-west"), outbound: build("outbound"), isLoading, error };
}

// helpers — bytes shown in MB/GB in the bar labels
function mbLabel(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1);
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(0);
  return (bytes / 1e3).toFixed(0);
}
function mbUnit(bytes: number): string { return bytes >= 1e9 ? "GB" : bytes >= 1e6 ? "MB" : "KB"; }
const octetsToMbpsWin = (octets: number, winSec: number) => (octets * 8) / winSec / 1e6;

/* ============================================================================
   OUTSIDE-IN INVESTIGATION
   ----------------------------------------------------------------------------
   The troubleshooting direction operators actually use: start from a party you
   already know is involved ("something's wrong with Amazon"), and walk INWARD to
   find where in your own network it breaks. The Sankey is where that party has
   already been located, so it is the entry point.

   What flow can and cannot contribute here, stated once so the UI never oversells:
     CAN  — who internally talked to them, over which router interfaces, how much,
            and per-conversation distress signals (TCP RST, exporter resource drops).
     CANNOT — RTT, retransmissions or connection setup timing. Those are TCP-stack
            facts that only an agent on the endpoint can see; flow records are
            summaries observed in the middle of the network. Anything claiming
            otherwise from flow alone is inferring, and should say so.
   ============================================================================ */

// RST is bit 2 (value 4) of the TCP flag byte. DQL has no bitAnd, so take the low
// three bits with `mod 8` and test >= 4 — FIN(1) and SYN(2) sit below it.
const RST_TEST = "(toLong(`flow.tcp_flags`) mod 8) >= 4";

export type TraceLeg = {
  internal: string; ingress: number; egress: number; exporter: string;
  flows: number; bytes: number; packets: number; rst: number; resourceDrops: number;
};

/** Every internal host that talked to `org`, the router interfaces used, and distress counts. */
export function useOrgTrace(org: string | null): { rows: TraceLeg[]; isLoading: boolean; error?: unknown } {
  const enabled = !!org;
  const esc = (s: string) => s.replace(/["\\]/g, "\\$&");
  const q = useDql(
    { query: enabled
      ? `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} and \`flow.dst_org\` == "${esc(org!)}"
         | summarize bytes = sum(toLong(\`flow.io.bytes\`)), packets = sum(toLong(\`flow.io.packets\`)), flows = count(),
             rst = countIf(${RST_TEST}), drops = countIf(toLong(\`flow.end_reason\`) == 5),
           by:{internal = \`source.address\`, ingress = \`flow.interface.input\`, egress = \`flow.interface.output\`, exporter = ${SAMPLER_ADDR}}
         | sort bytes desc | limit 25`
      : `fetch logs, from:-1m | limit 0` },
    OPTS,
  );
  const rows: TraceLeg[] = (enabled ? recordsOf(q) : []).map((r) => ({
    internal: r.internal, ingress: num(r.ingress), egress: num(r.egress),
    // WHOSE ifIndex 26? Without the exporter, an interface number names nothing — and there are
    // already two exporters in this tenant. It travels with the leg so the diagram can say.
    exporter: String(r.exporter ?? ""),
    flows: num(r.flows), bytes: num(r.bytes), packets: num(r.packets),
    rst: num(r.rst), resourceDrops: num(r.drops),
  }));
  return { rows, isLoading: enabled && q.isLoading, error: q.error };
}

/** External parties ranked by egress volume — the pick-list, and what the Sankey shows. */
export function useEgressParties(limit = 12): { rows: { org: string; asn?: number; bytes: number; flows: number }[]; isLoading: boolean } {
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} and isNotNull(\`flow.dst_org\`)
       | summarize bytes = sum(toLong(\`flow.io.bytes\`)), flows = count(), asn = takeMax(\`flow.dst_asn\`), by:{org = \`flow.dst_org\`}
       | sort bytes desc | limit ${limit}` },
    OPTS,
  );
  const rows = recordsOf(q).map((r) => ({ org: r.org, asn: r.asn != null ? num(r.asn) : undefined, bytes: num(r.bytes), flows: num(r.flows) }));
  return { rows, isLoading: q.isLoading };
}

export type IfHealth = { dev: string; iface: string; ifIndex: number; inErr: number; outErr: number; inDisc: number; oper: number; traffic: number };

/** Interface error/discard counters — how a flow-level symptom gets localised to a port.
 *
 *  ERRORS AND DISCARDS ARE NOT THE SAME FAULT and the UI must not merge them:
 *    errors   = malformed frames (CRC/alignment) -> PHYSICAL. Cable, optic, duplex.
 *    discards = frames the device dropped ON PURPOSE -> buffer exhaustion, ACL, QoS,
 *               storm control, STP. Nothing to do with cabling.
 *  Measured on `outpost` 2026-08-03: ~70k in-discards with ZERO errors on its busiest
 *  port. Summing them into one "problems" number would have pointed a field engineer at
 *  a cable that is perfectly fine. */
export function useIfHealth(): { rows: IfHealth[]; isLoading: boolean } {
  const q = useDql(
    { query: outerTs(
        { as: "oper", expr: "avg(cno.if.oper_status)" },
        // max(), not sum() — see counterDeltas() in metrics.ts. These are running counters, so a
        // window TOTAL is (max - min), not the sum of every reading in the window.
        [{ as: "ie",    expr: "max(cno.if.in_errors.count)" },
         { as: "oe",    expr: "max(cno.if.out_errors.count)" },
         { as: "idisc", expr: "max(cno.if.in_discards.count)" },
         { as: "inb",   expr: "max(cno.if.in_octets.count)" },
         { as: "outb",  expr: "max(cno.if.out_octets.count)" }],
        { dev: "sys_name", iface: "if_descr", ifidx: "if_index" }, CURRENT_WINDOW)
       + ` | fieldsAdd inErr = arrayMax(ie) - arrayMin(ie), outErr = arrayMax(oe) - arrayMin(oe),
                      inDisc = arrayMax(idisc) - arrayMin(idisc), operv = arrayLast(oper),
                      traffic = coalesce(arrayMax(inb) - arrayMin(inb), 0) + coalesce(arrayMax(outb) - arrayMin(outb), 0)
           | fields dev, iface, ifidx, inErr, outErr, inDisc, operv, traffic` },
    OPTS,
  );
  const rows: IfHealth[] = recordsOf(q).map((r) => ({
    dev: r.dev, iface: r.iface, ifIndex: num(r.ifidx),
    inErr: num(r.inErr), outErr: num(r.outErr), inDisc: num(r.inDisc), oper: num(r.operv),
    traffic: num(r.traffic),
  // "Down" alone is not a fault. Measured on the reference fleet: 71 of 140 interfaces are oper
  // down and ALL 71 are admin UP with zero traffic — unpatched access ports, which is the normal
  // state of a switch that does not shut spare ports. Listing them would bury the 25 interfaces
  // that have something genuinely wrong.
  //
  // A port that CARRIED TRAFFIC in this window and is now down is a real outage, so that is the
  // test. It matches nothing today, which is correct — nothing is currently broken that way — and
  // it will fire when something is. The clause it replaces (`oper === 0`) could never fire at all.
  })).filter((r) => r.inErr > 0 || r.outErr > 0 || r.inDisc > 0
                 || (IF_DOWN.has(r.oper) && r.traffic > 0));
  rows.sort((a, b) => (b.inErr + b.outErr) - (a.inErr + a.outErr) || b.inDisc - a.inDisc);
  return { rows, isLoading: q.isLoading };
}

/** Distinct flow exporters — the vantage points. Path completeness is bounded by this. */
export function useExporters(): { rows: { exporter: string; flows: number; type: string }[]; isLoading: boolean } {
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW}
       | summarize flows = count(), by:{exporter = ${SAMPLER_ADDR}, type = \`flow.type\`}
       | sort flows desc | limit 20` },
    OPTS,
  );
  return { rows: recordsOf(q).map((r) => ({ exporter: String(r.exporter ?? "?"), flows: num(r.flows), type: String(r.type ?? "") })), isLoading: q.isLoading };
}

/* ---- interface-first analysis: one router, many ports ----------------------
   The other way operators enter this. A distribution router has a port per rack or
   per segment, each with its own policy, and the question is "break this router down
   by port, and tell me what each one actually carries".

   This is possible ONLY because the decoder keeps INPUT_SNMP / OUTPUT_SNMP (IPFIX IE
   10 / 14) — the stock OTel netflow receiver drops both, and without them every flow
   is anonymous with respect to the physical topology. Since each record carries BOTH,
   one exporter yields a full port-to-port matrix: not just "what crossed port 5" but
   "what entered port 5 and left by port 12", which is the rack-to-rack answer. */

export type IfMatrixCell = { exporter: string; ingress: number; egress: number; bytes: number; flows: number; talkers: number; peers: number };

export function useIfMatrix(limit = 30): { rows: IfMatrixCell[]; isLoading: boolean; error?: unknown } {
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} and isNotNull(\`flow.interface.input\`)
       | summarize bytes = sum(toLong(\`flow.io.bytes\`)), flows = count(),
           talkers = countDistinct(\`source.address\`), peers = countDistinct(\`destination.address\`),
         by:{exporter = ${SAMPLER_ADDR}, ingress = \`flow.interface.input\`, egress = \`flow.interface.output\`}
       | sort bytes desc | limit ${limit}` },
    OPTS,
  );
  const rows: IfMatrixCell[] = recordsOf(q).map((r) => ({
    exporter: String(r.exporter ?? "?"), ingress: num(r.ingress), egress: num(r.egress),
    bytes: num(r.bytes), flows: num(r.flows), talkers: num(r.talkers), peers: num(r.peers),
  }));
  return { rows, isLoading: q.isLoading, error: q.error };
}

export type IfBreakdown = {
  talkers: { name: string; bytes: number }[];
  orgs: { name: string; bytes: number }[];
  apps: { name: string; bytes: number }[];
};

/** Everything one router port carried, broken down three ways. */
export function useIfBreakdown(ifIndex: number | null): { data: IfBreakdown; isLoading: boolean } {
  const on = ifIndex != null && ifIndex > 0;
  const q = useDql(
    { query: on
      ? `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW} and (toLong(\`flow.interface.input\`) == ${ifIndex} or toLong(\`flow.interface.output\`) == ${ifIndex})
         | summarize bytes = sum(toLong(\`flow.io.bytes\`)),
           by:{src = \`source.address\`, org = \`flow.dst_org\`, port = \`destination.port\`, transport = \`network.transport\`}
         | sort bytes desc | limit 400`
      : `fetch logs, from:-1m | limit 0` },
    OPTS,
  );
  const recs = on ? recordsOf(q) : [];
  const roll = (key: (r: any) => string | undefined) => {
    const agg: Record<string, number> = {};
    recs.forEach((r) => { const k = key(r); if (k) agg[k] = (agg[k] || 0) + num(r.bytes); });
    return Object.entries(agg).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, bytes]) => ({ name, bytes }));
  };
  return {
    data: {
      talkers: roll((r) => r.src),
      orgs: roll((r) => (r.org ? prettyOrg(r.org) : undefined)),
      apps: roll((r) => (r.port ? `${r.port}/${r.transport ?? "?"}` : undefined)),
    },
    isLoading: on && q.isLoading,
  };
}

/* ---- east-west as a MESH, not a funnel ------------------------------------
   North-south converges: many hosts -> one perimeter -> external organisations, which is a
   funnel and draws well as a path. East-west has no centre — peers talk to peers, and the
   questions are who talks to whom and whether it is SYMMETRIC. Drawn as a funnel a storage
   fabric is three lines converging on nothing; drawn as a matrix, "10.0.30.10 sends six times
   what it receives" is visible instantly, which is the signature of a replication primary.

   Returns a square peer list plus directed cell totals, so the caller can render rows-send /
   columns-receive without re-deriving anything. */
export type EwMatrix = { peers: string[]; cell: Record<string, number>; sent: Record<string, number>; recv: Record<string, number>; total: number };

export function useEastWestMatrix(limit = 8): { data: EwMatrix; isLoading: boolean } {
  const MUL = flowFactorMul();
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW}
       | filter ipIsPrivate(toIp(\`source.address\`)) and ipIsPrivate(toIp(\`destination.address\`))
       | summarize bytes = sum(toDouble(\`flow.io.bytes\`)${MUL}), by:{src = \`source.address\`, dst = \`destination.address\`}
       | sort bytes desc | limit 400` },
    OPTS,
  );
  const recs = recordsOf(q);
  const sent: Record<string, number> = {}, recv: Record<string, number> = {}, cell: Record<string, number> = {};
  let total = 0;
  recs.forEach((r) => {
    const b = num(r.bytes); if (!b) return;
    cell[`${r.src}|${r.dst}`] = (cell[`${r.src}|${r.dst}`] || 0) + b;
    sent[r.src] = (sent[r.src] || 0) + b;
    recv[r.dst] = (recv[r.dst] || 0) + b;
    total += b;
  });
  // rank peers by total participation so the densest part of the mesh is what gets drawn
  const peers = Array.from(new Set([...Object.keys(sent), ...Object.keys(recv)]))
    .sort((a, b) => ((sent[b] || 0) + (recv[b] || 0)) - ((sent[a] || 0) + (recv[a] || 0)))
    .slice(0, limit);
  return { data: { peers, cell, sent, recv, total }, isLoading: q.isLoading };
}

/* ---- what each vantage point can actually observe --------------------------
   Stated as content rather than a footnote. Coverage between a router and a switch is
   COMPLEMENTARY, not redundant — measured on this estate, 100% of east-west comes from one
   exporter and 0% from the other — and a page that implies total visibility is lying by
   omission. It doubles as the argument for adding the next exporter. */
export type Coverage = { exporter: string; type: string; flows: number; ns: number; ew: number; ifaces: number };

export function useCoverage(): { rows: Coverage[]; isLoading: boolean } {
  const q = useDql(
    { query: `fetch logs, from:${CURRENT_WINDOW} | filter ${FLOW}
       | fieldsAdd ew = ipIsPrivate(toIp(\`source.address\`)) and ipIsPrivate(toIp(\`destination.address\`))
       | summarize flows = count(), ewN = countIf(ew), ifaceN = countIf(isNotNull(\`flow.interface.input\`)),
         by:{exporter = ${SAMPLER_ADDR}, type = \`flow.type\`}
       | sort flows desc | limit 12` },
    OPTS,
  );
  const rows = recordsOf(q).map((r) => {
    const flows = num(r.flows), ew = num(r.ewN);
    return { exporter: String(r.exporter ?? "?"), type: String(r.type ?? ""), flows, ew, ns: flows - ew, ifaces: num(r.ifaceN) };
  });
  return { rows, isLoading: q.isLoading };
}
