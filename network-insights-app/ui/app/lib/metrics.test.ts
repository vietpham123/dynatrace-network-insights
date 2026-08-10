import { describe, it, expect } from "vitest";
import { percentile, outerTs, IF_DOWN, octetsToMbps, SERIES_INTERVAL_S, fleetRowState, reconcileEdges, counterDeltas} from "./metrics";

/* Every case below is a bug that actually shipped, or the invariant that would have caught it.
   The app had no test harness at all until now, which is why six inner-join defects and four
   absence-as-verdict defects reached a live tenant and were found only by hand-querying Grail. */

describe("percentile", () => {
  it("returns null on an empty sample — NOT 0", () => {
    // The whole family of bugs this suite exists for: no observations is not an observation of
    // zero. A 0 here would render as "0 Mbps p95" on an interface nobody ever measured.
    expect(percentile([], 95)).toBeNull();
  });

  it("uses nearest-rank, so the answer is always a bucket that really occurred", () => {
    // Carriers measure real samples; an interpolated value is a number nothing ever reported.
    const v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    expect(percentile(v, 95)).toBe(10);
    expect(percentile(v, 50)).toBe(5);
    expect(v).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // must not sort in place
  });

  it("discards the top 5%, so ONE spike cannot set the number", () => {
    // This is the property carriers bill on, and it is why p95 can legitimately sit BELOW the
    // mean: a single outlier drags the mean up but is excluded from p95 outright. Writing this
    // suite is what surfaced that — the first version asserted p95 >= mean and was simply wrong.
    const series = [...Array(19).fill(5), 400];
    const mean = series.reduce((a, b) => a + b, 0) / series.length; // 24.75
    expect(percentile(series, 95)).toBe(5);
    expect(percentile(series, 95)!).toBeLessThan(mean);
    expect(percentile(series, 100)).toBe(400); // the spike is still reachable
  });

  it("exceeds the mean on a genuinely bursty link — the sizing case", () => {
    // Shaped like fortress/gigabitethernet1 (mean 10.66, p95 62.78, peak 356.31 Mbps): many
    // moderately-high buckets, not one spike. Sizing this circuit on its average under-provisions
    // it roughly sixfold, which is the entire argument for the p95 column.
    const series = [1, 1, 2, 2, 3, 3, 4, 60, 65, 70, 75, 80, 90, 100, 120, 150, 200, 260, 300, 356];
    const mean = series.reduce((a, b) => a + b, 0) / series.length;
    const p95 = percentile(series, 95)!;
    expect(p95).toBeGreaterThan(mean);
    expect(p95).toBeLessThanOrEqual(Math.max(...series));
  });

  it("handles a single observation and does not go out of bounds", () => {
    expect(percentile([42], 95)).toBe(42);
    expect(percentile([42], 1)).toBe(42);
    expect(percentile([1, 2], 100)).toBe(2);
  });
});

describe("outerTs", () => {
  const BY = { dev: "sys_name", iface: "if_descr" };
  const q = outerTs(
    { as: "oper", expr: "avg(cno.if.oper_status)" },
    [{ as: "inb", expr: "sum(cno.if.in_octets.count)" }],
    BY, "-2h", "10m",
  );

  it("NEVER emits a multi-aggregate timeseries — that form inner-joins", () => {
    // The single most expensive bug in this codebase: `timeseries { a=.., b=.. }` drops any series
    // missing either metric. It cost 31 of 140 interfaces across four hooks, and blanked the
    // Configuration page's badges entirely. This assertion is the regression guard.
    expect(q).not.toMatch(/timeseries\s*\{/);
    const aggregates = q.match(/\w+\s*=\s*(?:sum|avg|max|min|count)\(/g) ?? [];
    // one per leg, never two inside one timeseries clause
    expect(q.split("timeseries").length - 1).toBe(aggregates.length);
  });

  it("left-outer-joins each metric onto the spine", () => {
    expect(q).toContain("lookup [");
    expect(q).toContain("sourceField:k");
    expect(q).toContain("fields:{inb}");
  });

  it("applies the filter to EVERY leg, not just the spine", () => {
    // A lookup leg that scans the whole fleet to serve one device is waste that turns into a
    // timeout on a real estate.
    const f = outerTs({ as: "a", expr: "avg(m1)" }, [{ as: "b", expr: "avg(m2)" }],
                      BY, "-1h", undefined, 'sys_name == "x"');
    expect(f.match(/filter sys_name == "x"/g)?.length).toBe(2);
  });

  it("builds a composite key covering every by-dimension", () => {
    // DQL's lookup takes ONE sourceField, so a multi-dimension join must concatenate. Missing a
    // dimension here would silently collapse distinct interfaces onto one another.
    expect(q).toContain('concat(toString(dev), "|", toString(iface))');
  });

  it("emits no interval clause when none is given", () => {
    expect(outerTs({ as: "a", expr: "avg(m)" }, [], BY, "-1h")).not.toContain("interval:");
  });
});

describe("IF_DOWN — IF-MIB ifOperStatus", () => {
  it("treats 2 (down) and 7 (lowerLayerDown) as down", () => {
    expect(IF_DOWN.has(2)).toBe(true);
    expect(IF_DOWN.has(7)).toBe(true);
  });

  it("does NOT contain 0 — the value the old code tested for", () => {
    // `oper === 0` was the down-check for months. IF-MIB never returns 0, so it never once fired.
    expect(IF_DOWN.has(0)).toBe(false);
  });

  it("does not treat notPresent(6), up(1) or dormant(5) as faults", () => {
    // 6 is an empty SFP cage — calling it "down" invented a fault on 28 interfaces in the lab.
    expect(IF_DOWN.has(6)).toBe(false);
    expect(IF_DOWN.has(1)).toBe(false);
    expect(IF_DOWN.has(5)).toBe(false);
  });
});

describe("octetsToMbps", () => {
  it("converts a bucket total to a rate over the bucket interval", () => {
    // These counters are per-poll DELTAS (type: count), so the bucket total IS the traffic;
    // diffing consecutive buckets — which the old code did — is meaningless on a delta metric.
    expect(octetsToMbps(SERIES_INTERVAL_S * 1e6 / 8)).toBeCloseTo(1, 6);
    expect(octetsToMbps(0)).toBe(0);
  });
});

/* fleetRowState — the rule that decides whether a device is shown at all.

   These cases are not hypothetical. Every one of them was a live defect: the eleven silent,
   unconfigured addresses that rendered as red faults; the SD-WAN feed that reports with no
   configuration and was briefly called decommissioned; and the whole fleet vanishing when the
   configuration read came back empty because the platform API answers with a bare array. */
describe("fleetRowState", () => {
  const S = (configured: boolean, live: boolean, intentKnown = true, acked = false) =>
    fleetRowState({ configured, live, intentKnown, acked });

  it("configured and reporting is up", () => {
    expect(S(true, true)).toBe("up");
  });

  it("configured and silent is DOWN — a fault at any age, never hidden", () => {
    expect(S(true, false)).toBe("down");
  });

  it("reporting without a configuration is unmanaged, not retired", () => {
    // The SD-WAN devices arrive via api_bridge with no monitoring config and are demonstrably
    // alive. Calling a talking device retired was a real bug.
    expect(S(false, true)).toBe("unmanaged");
  });

  it("unconfigured AND silent is retired", () => {
    // The 11 orphans: a decommissioned site, silent 12+ hours, still inside the 24h roster
    // window. Nobody asked for them and they are not talking.
    expect(S(false, false)).toBe("retired");
  });

  it("NEVER retires anything while intent is unknown", () => {
    // The failure that erased the fleet. With the config read broken, every device looks
    // unconfigured; if that implied retirement the whole estate would disappear at once.
    expect(S(false, false, false)).toBe("down");
    expect(S(false, true, false)).toBe("up");
  });

  it("intent-unknown never hides a device, only reports what was observed", () => {
    const states = [S(true, true, false), S(true, false, false), S(false, true, false), S(false, false, false)];
    expect(states.every((x) => x === "up" || x === "down")).toBe(true);
  });

  it("an explicit acknowledgement retires even a reporting device", () => {
    // Deliberate and reversible — the one thing allowed to hide something that is still live.
    expect(S(true, true, true, true)).toBe("retired");
    expect(S(false, false, false, true)).toBe("retired");
  });
});

/* reconcileEdges — one cable, one edge, and the edge remembers who saw it.

   The bug these lock down was INVISIBLE in the product: two edges between the same node pair
   draw on top of each other, so a duplicated link looked identical to a single one. It only
   surfaced by counting directions per pair in DQL. Anything that can be wrong without looking
   wrong belongs in a test. */
describe("reconcileEdges", () => {
  const E = (down: string, up: string, discovery: string, link_type = "data") =>
    ({ down, up, discovery, link_type });

  it("collapses the same cable seen from both ends into ONE edge", () => {
    // Exactly the measured regression: LLDP said edge->access, NetBox said access->edge.
    const out = reconcileEdges([E("a", "b", "lldp"), E("b", "a", "netbox")]);
    expect(out).toHaveLength(1);
    expect(out[0].prov).toBe("confirmed");
  });

  it("takes direction from LLDP when the sources disagree — measured beats documented", () => {
    const fromNetboxFirst = reconcileEdges([E("b", "a", "netbox"), E("a", "b", "lldp")]);
    expect(fromNetboxFirst[0].down).toBe("a");
    expect(fromNetboxFirst[0].up).toBe("b");
  });

  it("flags an LLDP-only link as undocumented — the 'I didn't know that was there' beat", () => {
    expect(reconcileEdges([E("a", "b", "lldp")])[0].prov).toBe("undocumented");
  });

  it("flags a NetBox-only data link as undiscovered — documented, never advertised", () => {
    expect(reconcileEdges([E("a", "b", "netbox")])[0].prov).toBe("undiscovered");
  });

  it("never calls a power link undiscovered — NetBox is its only possible source", () => {
    // Power cabling cannot be discovered by any protocol. Marking it "drift" would invent a
    // fault on every PDU in the estate.
    expect(reconcileEdges([E("pdu", "sw", "netbox", "power")])[0].prov).toBe("power");
  });

  it("keeps data and power between the SAME pair as separate edges", () => {
    const out = reconcileEdges([E("a", "b", "lldp"), E("a", "b", "netbox", "power")]);
    expect(out).toHaveLength(2);
  });

  it("treats a missing discovery field as netbox rather than dropping the edge", () => {
    const out = reconcileEdges([{ down: "a", up: "b", link_type: "data" }]);
    expect(out).toHaveLength(1);
    expect(out[0].prov).toBe("undiscovered");
  });

  it("is stable when the same row arrives twice (renamed device, 2h window)", () => {
    const out = reconcileEdges([E("a", "b", "lldp"), E("a", "b", "lldp")]);
    expect(out).toHaveLength(1);
  });
});

/* counterDeltas — the fix for the 676 Gbps bug.

   Every case here is drawn from the real failure: absolute counters summed as if they were
   deltas, producing 676 Gbps on a 40 Gbps link and climbing 5.3 Gbps an hour. */
describe("counterDeltas", () => {
  it("turns absolute counter readings into per-bucket increases", () => {
    // the actual measured values, scaled down
    expect(counterDeltas([1000, 1660, 2320, 2980])).toEqual([null, 660, 660, 660]);
  });

  it("reports the FIRST bucket as null, not zero", () => {
    // there is no predecessor, so the increase is unknowable. Zero would render a busy
    // interface idle for the first bucket of every window.
    expect(counterDeltas([5000, 5100])[0]).toBeNull();
  });

  it("reports a counter RESET as null rather than clamping to zero", () => {
    // a decrease means the device rebooted or the counter wrapped; the true delta cannot be
    // recovered, and 0 would hide the reboot.
    expect(counterDeltas([9000, 9500, 100, 700])).toEqual([null, 500, null, 600]);
  });

  it("propagates nulls without corrupting the following delta", () => {
    // a missing poll must not make the next bucket look like a huge burst
    expect(counterDeltas([100, null, 900, 1000])).toEqual([null, null, null, 100]);
  });

  it("never returns a negative", () => {
    const out = counterDeltas([50, 40, 30, 20]);
    expect(out.every((v) => v === null || v >= 0)).toBe(true);
  });

  it("handles a non-array input rather than throwing", () => {
    expect(counterDeltas(null)).toEqual([]);
    expect(counterDeltas(undefined)).toEqual([]);
  });

  it("a flat counter means zero traffic, which IS knowable", () => {
    // distinct from null: the device answered and the counter did not move.
    expect(counterDeltas([700, 700, 700])).toEqual([null, 0, 0]);
  });
});
