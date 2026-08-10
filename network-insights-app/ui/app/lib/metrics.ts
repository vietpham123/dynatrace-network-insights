/* ============================================================================
   Pure metric + query-shaping helpers. NO IMPORTS, deliberately.

   These live apart from netflow.ts so they can be unit-tested in plain node: netflow.ts pulls in
   @dynatrace-sdk/react-hooks, which drags a browser runtime into any test that touches it. Every
   function here is total and side-effect free — given the same input it returns the same output —
   which is exactly the property the bugs of 2026-08-03 violated at the RENDER layer rather than
   the query layer, and exactly what a test can pin down.
   ============================================================================ */

export const SERIES_INTERVAL_S = 600; // 10m buckets; keep in sync with makeTimeseries interval
export const octetsToMbps = (octets: number) => (octets * 8) / SERIES_INTERVAL_S / 1e6;

/* 95th percentile — the number a WAN circuit is actually SOLD on. Burstable carrier billing
   discards the top 5% of samples and charges the rest, so p95 is simultaneously the figure on the
   invoice and the honest answer to "is this circuit the right size".
   Mean and peak are both wrong tools here: measured across 629 real circuits on a customer SD-WAN
   fleet, p95 was 3.6x the mean (201 Mbps mean, 729 Mbps p95, 1,107 Mbps peak) — size on the
   average and you under-provision by that factor; size on the peak and one spike condemns a
   healthy circuit.
   NEAREST-RANK, not interpolation: the result is always a bucket that genuinely occurred, which is
   what a carrier measures. Returns null on an empty sample rather than 0 — no data is not no
   traffic. Callers must pass only real observations; a null bucket coerced to 0 drags p95 down. */
export function percentile(values: number[], p: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

/* ── outer-joining several metrics on the same dimensions ────────────────────
   NEVER write `timeseries { a = sum(X), b = sum(Y) }`. That form INNER-JOINS on the by-dimensions,
   so a series carrying X but not Y is dropped from the result entirely — not returned with a null.

   Measured on the reference fleet 2026-08-03: cno.if.*_octets.count exists on 109 of 140
   interfaces, so every inner join of octets against status silently lost 31 interfaces — 9 of them
   UP and passing traffic, 2 DOWN. The tables most damaged were the ones whose whole job is finding
   bad ports. Six sites in this codebase had the bug; see lib/data.ts and pages/Configuration.tsx.

   The fix is a left outer join off the widest-coverage metric as the SPINE. Every spine row
   survives, and a metric that is absent for that series arrives as null — which the caller must
   render as "no counters", never coerce to 0. DQL's lookup takes a single sourceField, hence the
   concatenated key. */
export type TsPart = { as: string; expr: string };

export function outerTs(
  spine: TsPart, joins: TsPart[], by: Record<string, string>, from: string,
  interval?: string, filter?: string,
): string {
  const byClause = Object.entries(by).map(([alias, dim]) => `${alias} = ${dim}`).join(", ");
  const keyExpr = `concat(${Object.keys(by).map((a) => `toString(${a})`).join(', "|", ')})`;
  const iv = interval ? `, interval:${interval}` : "";
  // The filter goes on EVERY leg, not just the spine — a lookup leg that scans the whole fleet to
  // serve one device is pure waste, and on a large estate it is the difference between a page that
  // loads and one that times out.
  const fl = filter ? ` | filter ${filter}` : "";
  const leg = (p: TsPart) =>
    `timeseries ${p.as} = ${p.expr}, from:${from}, by:{${byClause}}${iv}${fl} | fieldsAdd k = ${keyExpr}`;
  return joins.reduce(
    (q, j) => `${q}\n | lookup [ ${leg(j)} | fields k, ${j.as} ], sourceField:k, lookupField:k, fields:{${j.as}}`,
    leg(spine),
  );
}

/* IF-MIB ifOperStatus is an ENUM, and 0 is not one of its values: 1 up, 2 down, 3 testing,
   4 unknown, 5 dormant, 6 notPresent, 7 lowerLayerDown. Code here previously tested `oper === 0`
   to mean "down", which can never be true — the health table's down-interface detection had
   therefore never fired once. notPresent(6) is an empty SFP cage, not a fault; dormant(5) is
   normal for a standby link. Only 2 and 7 are actually broken. */
export const IF_DOWN = new Set([2, 7]);

/* ── fleet row state ─────────────────────────────────────────────────────────
   Pure, and deliberately so: this decides whether a device is SHOWN and whether it is called
   DOWN, and getting it wrong has produced every visible fault in this app so far — an erased
   fleet, a fleet that flashed and shrank, and eleven long-dead addresses rendered as red faults.
   Keeping it out of the hook means it can be tested exhaustively instead of inferred from a
   screenshot, which is how those bugs survived.

   The rule that matters: INTENT MUST BE KNOWN before its absence means anything. `intentKnown`
   is false while the configuration read is loading, if it failed, or if it came back empty —
   and in that state nothing is ever hidden or called retired, because "we could not ask" is not
   evidence of anything. The read spent this entire project silently returning zero devices (the
   platform API answers with a bare array; the code read `.items`), which is exactly the state
   this guard exists to survive. */
export type FleetState = "up" | "down" | "unmanaged" | "retired";

export function fleetRowState(p: {
  configured: boolean; live: boolean; intentKnown: boolean; acked: boolean;
}): FleetState {
  // An explicit human act always wins, and is the only thing that can hide a device that is
  // still reporting.
  if (p.acked) return "retired";
  // Intent unreadable -> fall back to pure observation. Never hide, never retire.
  if (!p.intentKnown) return p.live ? "up" : "down";
  if (p.configured) return p.live ? "up" : "down";      // silence under intent is a FAULT, at any age
  // Not configured. Reporting anyway = somebody else's device, or an API-pushed source (the
  // SD-WAN feed). Visible, but not ours to call healthy or broken.
  if (p.live) return "unmanaged";
  // Not configured AND not reporting: nobody asked for it and it is not talking. Retired.
  return "retired";
}

/* ONE CABLE, ONE EDGE — and the edge remembers WHICH SOURCES SAW IT.
   The old key was `down|up|link_type`, which is DIRECTIONAL, so the same physical cable
   arriving from two discovery sources that disagree about which end is "down" survived as two
   edges. Measured 2026-08-05, right after LLDP started working: all 8 cabled node-pairs were
   duplicated, LLDP one way and NetBox the other. It was INVISIBLE on screen — two edges between
   the same pair draw on top of each other — so nothing in the product could have shown it.
   Keying on the unordered pair fixes the duplication. Merging the sources instead of discarding
   the loser is what makes the disagreement useful:

     confirmed    seen by BOTH          the cable is real and documented
     undocumented LLDP only            it is plugged in and nobody wrote it down
     undiscovered NetBox only          documented, but the device never advertised it
                                       (an AP that does not speak LLDP, or one that is off)

   That is CMDB-versus-reality drift, which is a genuine operational question and not a lab
   trick. Direction, when the two disagree, is taken from LLDP: measured beats documented. */
export type Prov = "confirmed" | "undocumented" | "undiscovered" | "sdwan" | "power";
export function provenanceOf(srcs: Set<string>, linkType: string): Prov {
  if (linkType === "power") return "power";      // NetBox-only by nature; nothing else knows it
  if (srcs.has("api")) return "sdwan";
  const l = srcs.has("lldp"), n = srcs.has("netbox");
  return l && n ? "confirmed" : l ? "undocumented" : "undiscovered";
}

export function reconcileEdges(list: any[]): any[] {
  const byPair = new Map<string, any>();
  list.forEach((e) => {
    const a = String(e.down), b = String(e.up);
    const key = `${a < b ? a + "|" + b : b + "|" + a}|${e.link_type}`;
    const src = String(e.discovery || "netbox");
    const cur = byPair.get(key);
    if (!cur) { byPair.set(key, { ...e, sources: new Set([src]) }); return; }
    cur.sources.add(src);
    // LLDP wins the direction argument — it is what the devices actually reported.
    if (src === "lldp") { cur.down = a; cur.up = b; cur.downName = e.downName; cur.upName = e.upName; }
  });
  return Array.from(byPair.values()).map((e) => ({ ...e, prov: provenanceOf(e.sources, e.link_type) }));
}

/* ── SNMP counters arrive ABSOLUTE, not as per-poll deltas ────────────────────
   Measured 2026-08-10 on the reference tenant. `cno.if.in_octets.count` is declared `type: count`
   on ifHCInOctets, and this file previously asserted that the EF2.0 datasource therefore delivers
   "bytes since the last poll". It does not — the stored values are the running counter:

       raw datapoints   5.091e12  5.091e12  5.092e12  5.093e12
       differences        6.55e8    6.59e8    6.67e8            <- the real per-poll traffic

   Reading those with sum() over a bucket adds sixty absolute readings together, so the result
   grows with the counter rather than with traffic. It produced 676 Gbps on a 40 Gbps link,
   climbing linearly by ~5.3 Gbps every hour, and pinned every interface at 100% utilisation.
   Confirmed arithmetically: growth-per-hour divided by the counter's own rate is 60.2, which is
   exactly the polls per hour.

   It was fleet-wide, not isolated — HQ showed the same signature at a smaller constant, which is
   why it read as plausible for so long.

   Topology and DeviceDetail already do this correctly with max() + arrayDelta. This helper exists
   so the NetFlow hooks can share ONE tested implementation rather than a third opinion. */
export function counterDeltas(raw: unknown): (number | null)[] {
  if (!Array.isArray(raw)) return [];
  const out: (number | null)[] = [];
  let prev: number | null = null;
  for (const v of raw) {
    const cur = v == null ? null : Number(v);
    if (cur == null || !Number.isFinite(cur)) { out.push(null); prev = null; continue; }
    // No predecessor -> the increase is UNKNOWABLE, not zero. Emitting 0 would render a busy
    // interface as idle for the first bucket of every window, which is the same absence-as-a-value
    // mistake this codebase keeps finding.
    if (prev == null) { out.push(null); prev = cur; continue; }
    const d = cur - prev;
    prev = cur;
    // A DECREASE means the counter reset or the device rebooted. The true delta cannot be
    // recovered (we do not know how far it climbed before resetting), so report null rather than
    // inventing a number. Clamping to 0 would silently under-report a device that just rebooted.
    out.push(d < 0 ? null : d);
  }
  return out;
}
