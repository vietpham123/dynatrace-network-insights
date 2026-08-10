import React from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { t, mono } from "../theme";
import { Panel, StatTile, Tag, Pill } from "../components/ui";
import { ErrorBanner } from "../components/QueryState";
import { useOrgTrace, useEgressParties, useIfHealth, useCoverage, useEastWestMatrix, useIfMatrix, useIfBreakdown, prettyOrg, CURRENT_WINDOW, winSeconds } from "../lib/netflow";
import type { IfHealth, TraceLeg } from "../lib/netflow";
import { useFleet } from "../lib/data";
import { classifyProvider, providerHue } from "../lib/providers";
import * as StratoIcons from "@dynatrace/strato-icons";

/* ============================================================================
   INVESTIGATE — outside-in fault localisation.

   Its own page rather than a fourth NetFlow tab, because it is a TASK not a view: NetFlow
   answers "what is my traffic doing", this is opened when something is already believed to be
   wrong and the question is "where".

   REBUILT to lead with a VERDICT. The first version presented seven panels at equal visual
   weight and left the reader to assemble a conclusion — Viet read it cold and could not tell
   what he was looking at, which is a design failure rather than a knowledge gap. The order is
   now finding -> figures -> who -> path -> mesh -> folded reference, and only three panels are
   open at rest.

   TWO SHAPES, DELIBERATELY. North-south is a funnel (many hosts converge on one perimeter) and
   draws as a path. East-west is a mesh with no centre, where the question is who talks to whom
   and whether it is symmetric — so it gets a matrix. Forcing both through one visual is what
   made a storage fabric render as three lines converging on nothing.
   ============================================================================ */

const fmtB = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${Math.round(n)} B`);

export const Investigate = () => {
  const [params, setParams] = useSearchParams();
  const nav = useNavigate();
  const selected = params.get("org");
  const [mode, setMode] = React.useState<"party" | "interface">("party");

  const parties = useEgressParties();
  const trace = useOrgTrace(selected);
  const health = useIfHealth();
  const coverage = useCoverage();
  const ew = useEastWestMatrix();
  const fleet = useFleet();
  const knownDevice = React.useMemo(
    () => new Set(fleet.rows.filter((d: any) => d.monitored).map((d: any) => String(d.ip))),
    [fleet.rows],
  );
  const fleetName = React.useMemo(
    () => new Map<string, string>(fleet.rows.map((d: any) => [String(d.ip), String(d.device || "")])),
    [fleet.rows],
  );

  const pick = (org: string) => {
    const next = new URLSearchParams(params);
    if (org) next.set("org", org); else next.delete("org");
    setParams(next, { replace: true });
  };

  const legs = trace.rows;
  const totalBytes = legs.reduce((s, l) => s + l.bytes, 0);
  const totalFlows = legs.reduce((s, l) => s + l.flows, 0);
  const totalRst = legs.reduce((s, l) => s + l.rst, 0);
  const totalDrops = legs.reduce((s, l) => s + l.resourceDrops, 0);
  const hosts = new Set(legs.map((l) => l.internal)).size;
  const egressIfs = Array.from(new Set(legs.map((l) => l.egress))).filter(Boolean);
  const allIfs = Array.from(new Set(legs.flatMap((l) => [l.ingress, l.egress]))).filter(Boolean).sort((a, b) => a - b);
  const rstRate = totalFlows ? (100 * totalRst) / totalFlows : 0;
  const top = legs[0];
  const exporterAddr = Array.from(new Set(legs.map((l) => l.exporter).filter(Boolean)))[0] || "";
  const exporterName = (exporterAddr && fleetName.get(exporterAddr)) || exporterAddr || "the router";

  const physical = health.rows.filter((r) => r.inErr + r.outErr > 0);
  const policy = health.rows.filter((r) => r.inErr + r.outErr === 0 && r.inDisc > 0);
  const winH = Math.round(winSeconds(CURRENT_WINDOW) / 3600);

  return (
    <Flex flexDirection="column" gap={16} padding={24}>
      <Flex justifyContent="space-between" alignItems="flex-start" flexWrap="wrap" gap={12}>
        <div>
          <Heading level={2}>Investigate</Heading>
          <Paragraph>Start from a party or an interface, follow it inward, and separate a physical fault from a policy drop.</Paragraph>
        </div>
        <Flex gap={4}>
          {(["party", "interface"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              style={{
                border: `1px solid ${mode === m ? t.accent : t.border}`,
                background: mode === m ? t.accentBg : "transparent", color: mode === m ? t.ink : t.subtle,
                borderRadius: 8, padding: "6px 13px", cursor: "pointer", fontWeight: 600, fontSize: 13,
              }}>
              {m === "party" ? "External party" : "Router interface"}
            </button>
          ))}
        </Flex>
      </Flex>

      <ErrorBanner error={trace.error} what="Flow query" />

      {mode === "interface" ? <InterfaceMode /> : (<>

        {/* THE FINDING, before any evidence. */}
        {selected && !trace.isLoading && legs.length > 0 && (
          <div style={{ borderLeft: `3px solid ${t.accent}`, background: t.accentBg, borderRadius: "0 10px 10px 0", padding: "16px 20px" }}>
            <Text style={{ fontSize: 18, lineHeight: 1.45 }}>
              <strong>{hosts} host{hosts === 1 ? "" : "s"}</strong> reached <strong>{prettyOrg(selected)}</strong> over {winH}h
              through interface <strong style={{ ...mono }}>{egressIfs.join(", ")}</strong>.{" "}
              {totalDrops > 0
                ? <span style={{ color: t.down }}>The router dropped {totalDrops} flow{totalDrops === 1 ? "" : "s"} for lack of resources.</span>
                : <>Nothing was dropped on this path.</>}
            </Text>
            <Text style={{ color: t.subtle, fontSize: 14, display: "block", marginTop: 6 }}>
              {top ? <><strong style={{ ...mono }}>{top.internal}</strong> accounts for {Math.round((100 * top.bytes) / Math.max(1, totalBytes))}% of it. </> : null}
              {health.rows.length > 0
                ? <>The {health.rows.length} unhealthy interface{health.rows.length === 1 ? "" : "s"} in the fleet {health.rows.length === 1 ? "is" : "are"} <strong>not</strong> on this path.</>
                : <>No interface in the fleet is reporting errors, discards or a down state.</>}
            </Text>
          </div>
        )}

        {selected && legs.length > 0 && (
          <Flex gap={12} flexWrap="wrap">
            <StatTile label="Internal hosts" value={hosts} sub={`reaching ${prettyOrg(selected)}`} accent={t.accent} />
            <StatTile label="Volume" value={fmtB(totalBytes)} sub={`${totalFlows.toLocaleString()} flows`} />
            <StatTile label="Interfaces" value={allIfs.length} sub={`ifIndex ${allIfs.join(", ")} on ${exporterName}`} />
            <StatTile label="TCP resets" value={totalRst.toLocaleString()} accent={t.subtle}
              sub={`${rstRate.toFixed(0)}% of flows · ${rstRate > 40 ? "high — compare, don't alarm" : "nominal"}`} />
          </Flex>
        )}

        {/* WHO */}
        <Panel title="External party" tag={<Tag>last {winH}h</Tag>}>
          {parties.isLoading ? (
            <Text style={{ color: t.subtle }}>Loading…</Text>
          ) : parties.rows.length === 0 ? (
            <Text style={{ color: t.subtle, fontSize: 14 }}>
              No resolved external parties in this window — either there is no egress traffic, or the
              collector is running with <span style={{ ...mono }}>--no-enrich</span>.
            </Text>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13.5 }}>
                <thead>
                  <tr>{["Party", "Category", "ASN", "Volume", "Flows"].map((h, i) => (
                    <th key={h} style={{ textAlign: i >= 3 ? "right" : "left", padding: "7px 11px", color: t.subtle, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em", borderBottom: `1px solid ${t.border}`, whiteSpace: "nowrap" }}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {parties.rows.map((p) => {
                    const on = selected === p.org;
                    const cls = classifyProvider(p.org, p.asn);
                    return (
                      <tr key={p.org} onClick={() => pick(on ? "" : p.org)}
                        style={{ cursor: "pointer", background: on ? t.accentBg : undefined, borderBottom: `1px solid ${t.border}` }}>
                        <td style={{ padding: "8px 11px" }}>
                          <Flex gap={8} alignItems="center">
                            <ProviderBadge org={p.org} asn={p.asn} size={24} />
                            <span style={{ fontWeight: on ? 700 : 500 }}>{prettyOrg(p.org)}</span>
                          </Flex>
                        </td>
                        <td style={{ padding: "8px 11px", color: t.subtle }}>{cls.label}</td>
                        <td style={{ ...mono, padding: "8px 11px", color: t.subtle }}>{p.asn ? `AS${p.asn}` : "—"}</td>
                        <td style={{ ...mono, padding: "8px 11px", textAlign: "right", fontWeight: 700 }}>{fmtB(p.bytes)}</td>
                        <td style={{ ...mono, padding: "8px 11px", textAlign: "right", color: t.subtle }}>{p.flows.toLocaleString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* THE PATH — a funnel, drawn as one */}
        {selected && !trace.isLoading && legs.length > 0 && (
          <Panel>
            <Flex justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={8} style={{ marginBottom: 10 }}>
              <div>
                <div style={{ ...mono, fontSize: 11, letterSpacing: "0.09em", textTransform: "uppercase", color: t.subtle, fontWeight: 700 }}>North-south path</div>
                <div style={{ fontSize: 12, color: t.subtle, marginTop: 2 }}>endpoint → entered → {exporterName} → left via → reached</div>
              </div>
              <Pill status={totalDrops > 0 ? "down" : "up"}>{totalDrops > 0 ? `${totalDrops} dropped` : "no drops"}</Pill>
            </Flex>
            <PathDiagram legs={legs} org={selected} nameFor={(a) => fleetName.get(a) || ""} />
          </Panel>
        )}

        {/* THE MESH — a matrix, because a funnel cannot show symmetry */}
        <EastWestPanel data={ew.data} isLoading={ew.isLoading} />

        {/* folded reference */}
        <Collapsible title="Interface health" tag={<Tag>SNMP</Tag>}
          badge={health.rows.length ? `${physical.length} with errors · ${policy.length} discarding` : "all clear"}>
          <HealthTable physical={physical} policy={policy} down={health.rows.filter((r) => r.oper === 0)} />
        </Collapsible>

        <Collapsible title="Coverage & limits" tag={<Tag>scope</Tag>}
          badge={`${coverage.rows.length} vantage point${coverage.rows.length === 1 ? "" : "s"}`}>
          <CoverageTable rows={coverage.rows} />
        </Collapsible>
      </>)}
    </Flex>
  );
};

/* ---- interface-first: one router, many ports -------------------------------
   The other entry point. A WAN edge router has a port per circuit, each with its own
   policy, and the operator already knows which one is unhappy.

   The MATRIX is the part a per-interface report cannot give you. Each flow record
   carries BOTH ingress and egress ifIndex, so one exporter yields every in->out pair:
   not just "what crossed port 5" but "what entered port 5 and left by port 12". On a
   WAN edge that is where the findings are — an MPLS->Internet cell is a hairpin, and
   the LAN->circuit split is what a failover has to absorb.

   An EMPTY cell is information too, but ambiguous: either nothing took that path, or
   the exporter does not report it. Measured on the UCG Ultra 2026-08-03 — it exports
   only WAN-crossing flows, so its segment-to-segment cells are structurally blank.
   The footnote says so rather than letting a reader conclude "no east-west traffic". */
function InterfaceMode() {
  const matrix = useIfMatrix();
  const [sel, setSel] = React.useState<number | null>(null);
  const bd = useIfBreakdown(sel);

  const ins = Array.from(new Set(matrix.rows.map((r) => r.ingress))).sort((a, b) => a - b);
  const outs = Array.from(new Set(matrix.rows.map((r) => r.egress))).sort((a, b) => a - b);
  const cell = (i: number, o: number) => matrix.rows.find((r) => r.ingress === i && r.egress === o);
  const perIf: Record<number, number> = {};
  matrix.rows.forEach((r) => { perIf[r.ingress] = (perIf[r.ingress] || 0) + r.bytes; perIf[r.egress] = (perIf[r.egress] || 0) + r.bytes; });
  const peak = Math.max(1, ...matrix.rows.map((r) => r.bytes));

  return (
    <>
      <Panel title="Traffic matrix — ingress → egress" tag={<Tag>per exporter</Tag>}>
        {matrix.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : matrix.rows.length === 0 ? (
          <Text style={{ color: t.subtle, fontSize: 14 }}>
            No flows carry interface indices. The decoder preserves IPFIX ingressInterface /
            egressInterface — if this is empty the exporter is not sending them, or flows are
            arriving through a receiver that drops them.
          </Text>
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", fontSize: 13.5 }}>
                <thead>
                  <tr>
                    <th style={{ padding: "8px 12px", color: t.subtle, fontSize: 12, textAlign: "left" }}>in ↓ / out →</th>
                    {outs.map((o) => (
                      <th key={o} style={{ ...mono, padding: "8px 14px", color: t.subtle, fontSize: 12.5, cursor: "pointer" }} onClick={() => setSel(sel === o ? null : o)}>{o}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ins.map((i) => (
                    <tr key={i}>
                      <td style={{ ...mono, padding: "8px 12px", color: t.subtle, cursor: "pointer", fontWeight: sel === i ? 800 : 500 }} onClick={() => setSel(sel === i ? null : i)}>{i}</td>
                      {outs.map((o) => {
                        const c = cell(i, o);
                        const shade = c ? Math.min(0.5, 0.08 + 0.42 * (c.bytes / peak)) : 0;
                        return (
                          <td key={o} title={c ? `${c.flows} flows · ${c.talkers} talkers · ${c.peers} peers` : "no flows on this path"}
                            style={{ ...mono, padding: "8px 14px", textAlign: "right", background: c ? `rgba(57,135,229,${shade})` : "transparent", color: c ? t.ink : t.subtle }}>
                            {c ? fmtB(c.bytes) : "·"}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginTop: 10 }}>
              Numbers are SNMP ifIndex. A blank cell means no flows were <em>reported</em> on that
              path — which is not the same as no traffic: an exporter that only reports
              WAN-crossing flows leaves its segment-to-segment cells permanently empty. Click any
              index to break that interface down.
            </Text>
          </>
        )}
      </Panel>

      {sel != null && (
        <Panel title={`Interface ${sel} — what it carries`} tag={<Tag>live</Tag>}>
          {bd.isLoading ? (
            <Text style={{ color: t.subtle }}>Loading…</Text>
          ) : (
            <Flex gap={24} flexWrap="wrap">
              <BreakdownList title="Top talkers" rows={bd.data.talkers} />
              <BreakdownList title="Destination organisations" rows={bd.data.orgs} />
              <BreakdownList title="Applications" rows={bd.data.apps} />
            </Flex>
          )}
          <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginTop: 10 }}>
            Total across this interface (in + out): <span style={{ ...mono }}>{fmtB(perIf[sel] || 0)}</span>.
            For circuit sizing note that carriers bill on 95th-percentile utilisation, not the
            average shown here — that is a known gap.
          </Text>
        </Panel>
      )}
    </>
  );
}

function BreakdownList({ title, rows }: { title: string; rows: { name: string; bytes: number }[] }) {
  const top = Math.max(1, ...rows.map((r) => r.bytes));
  return (
    <div style={{ flex: "1 1 260px", minWidth: 240 }}>
      <Text style={{ fontSize: 12.5, color: t.subtle, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase" }}>{title}</Text>
      {rows.length === 0 ? (
        <Text style={{ color: t.subtle, fontSize: 13, display: "block", marginTop: 6 }}>none</Text>
      ) : rows.map((r, i) => (
        <div key={i} style={{ marginTop: 7 }}>
          <Flex justifyContent="space-between" gap={8}>
            <Text style={{ ...mono, fontSize: 13, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.name}</Text>
            <Text style={{ ...mono, fontSize: 12.5, color: t.subtle, flex: "none" }}>{fmtB(r.bytes)}</Text>
          </Flex>
          <div style={{ height: 5, borderRadius: 3, background: t.cardSubtle, marginTop: 3 }}>
            <div style={{ width: `${(100 * r.bytes) / top}%`, height: "100%", borderRadius: 3, background: t.accent }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ---- the path, drawn ------------------------------------------------------
   A table of "in 26 -> out 8" is a fact, not a picture. What an operator wants is to walk
   the line: endpoint -> the port it entered -> the router -> the port it left -> who it
   reached, with width showing volume and a marker where it hurts.

   Two things the first version got wrong, both from Viet reading it cold:
     - the interface labels sat UNDER the bands and were unreadable. Labels now go above
       their node, and one node is drawn per DISTINCT interface (positioned at the mean of
       the hosts feeding it) rather than one per row, so shared ports stop repeating.
     - it had no numbers. Every segment is now labelled with its volume, and each host
       carries its share, because "which of these is the big one" is the first question
       anyone asks of a diagram like this.

   Colour is DISTRESS, and only from signals flow genuinely carries: exporter resource-drops
   (hard evidence the device could not keep up) and a reset rate elevated against this path's
   own average (comparative, never a verdict). SNMP error/discard counters are deliberately
   NOT folded in — they belong to monitored devices, and the gateway exporting these flows is
   not SNMP-polled, so colouring its ports with another device's counters would be invention. */
/** Trim to fit the node box without slicing a word in half ("Amazon.com," was the old result). */
function shortName(org: string): string {
  const n = prettyOrg(org) || classifyProvider(org).short;
  return n.length <= 16 ? n : n.slice(0, 15).replace(/[\s,.]+$/, "") + "…";
}

// A diagram is for SHAPE; the table underneath is the ledger. Past about eight rows the bands
// cross so heavily that neither is legible, and rendering all sixteen made the picture worse
// than no picture — which is what Viet was reacting to. Show the top talkers, say plainly how
// many were left out, and let the table carry completeness.
const MAX_ROWS = 8;

function PathDiagram({ legs: allLegs, org, nameFor }:
  { legs: TraceLeg[]; org: string; nameFor?: (addr: string) => string }) {
  if (!allLegs.length) return null;
  // Pick the top talkers by volume FIRST, so "top 8" keeps its meaning...
  const shown = allLegs.slice(0, MAX_ROWS);
  const hidden = allLegs.length - shown.length;
  const hiddenBytes = allLegs.slice(MAX_ROWS).reduce((s, l) => s + l.bytes, 0);

  // ...then ORDER THEM BY THE INTERFACE THEY ENTER, not by volume. Volume order and interface
  // grouping do not align, so a purely volume-sorted list makes the biggest flow dive across
  // every other band to reach its node — the diagram was mostly crossings. Grouping hosts by
  // ingress makes each interface a contiguous block, so its node sits at the centre of its own
  // hosts and the bands stop crossing. Sorting by IP achieves this incidentally (a subnet maps
  // to a VLAN interface); grouping by the interface itself is exact and survives a subnet that
  // spans two ports. Groups are ordered by their own total, and volume order is kept inside each.
  const groupTotal = new Map<number, number>();
  shown.forEach((l) => groupTotal.set(l.ingress, (groupTotal.get(l.ingress) || 0) + l.bytes));
  const legs = shown.slice().sort((a, b) =>
    (groupTotal.get(b.ingress)! - groupTotal.get(a.ingress)!) ||
    (a.ingress - b.ingress) ||
    (b.bytes - a.bytes));

  const ROW = 40, PAD_T = 26, PAD_B = 20, W = 1120;
  const H = PAD_T + PAD_B + legs.length * ROW;
  const total = allLegs.reduce((s, l) => s + l.bytes, 0) || 1;   // real total, not the visible subset
  const totalFlows = allLegs.reduce((s, l) => s + l.flows, 0) || 1;
  const avgRst = allLegs.reduce((s, l) => s + l.rst, 0) / totalFlows;

  // host labels carry "18.2 MB · 84% · 4,848 flows" — ~200px at 10.5px, so the endpoint column
  // needs that much clear space or the numbers run off the left edge of the viewBox.
  const X = { host: 236, hostDot: 248, inIf: 470, rtr: 640, outIf: 820, party: 930 };
  const y = (i: number) => PAD_T + i * ROW + ROW / 2;
  const mid = PAD_T + (legs.length * ROW) / 2;

  // width scale — capped so a dominant flow cannot swamp the labels
  const wOf = (b: number) => Math.max(2, Math.min(20, 20 * (b / total)));
  const colOf = (l: TraceLeg) => {
    if (l.resourceDrops > 0) return t.down;
    const r = l.flows ? l.rst / l.flows : 0;
    return r > avgRst * 1.5 && l.rst > 10 ? t.warn : t.accent;
  };
  // Strato icons inside the SVG via <foreignObject>. I avoided this for the destination badge,
  // where a rect and two text nodes did the job — here it buys real iconography rather than
  // ambiguous dots, which is worth the embedding. Falls back to a plain circle if an icon name
  // ever stops resolving, so the diagram degrades instead of disappearing.
  const Glyph = ({ name, x, y, s: sz = 18, color }: { name: string; x: number; y: number; s?: number; color?: string }) => {
    const C = (StratoIcons as any)[name] as React.ComponentType<any> | undefined;
    if (!C) return <circle cx={x} cy={y} r={4} fill={color || t.subtle} />;
    return (
      <foreignObject x={x - sz / 2} y={y - sz / 2} width={sz} height={sz}>
        <div style={{ width: sz, height: sz, color: color || t.subtle, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <C size="small" />
        </div>
      </foreignObject>
    );
  };

  const curve = (x1: number, y1: number, x2: number, y2: number) =>
    `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`;

  // ONE node per distinct ingress interface, at the mean row of the hosts feeding it
  const byIn = new Map<number, TraceLeg[]>();
  legs.forEach((l) => { const a = byIn.get(l.ingress) || []; a.push(l); byIn.set(l.ingress, a); });
  const inY = new Map<number, number>();
  byIn.forEach((ls, k) => inY.set(k, ls.reduce((s, l) => s + y(legs.indexOf(l)), 0) / ls.length));
  const egress = Array.from(new Set(legs.map((l) => l.egress)));
  const exporters = Array.from(new Set(allLegs.map((l) => l.exporter).filter(Boolean)));
  const exporterAddr = exporters.length === 1 ? exporters[0] : "";
  const exporterName = exporters.length > 1
    ? exporters.length + " exporters"
    : (nameFor && exporterAddr && nameFor(exporterAddr)) || "router";

  return (
    <div style={{ overflowX: "auto" }}>
      {/* height is PINNED and preserveAspectRatio is "meet", so the drawing never scales ABOVE
            1:1. With width="100%" and no height the viewBox stretched to fill the container —
            on a wide monitor a 1120x424 diagram rendered around 1600x600 with the type scaled
            up to match, which is why it looked enormous. Now extra width is empty space rather
            than magnification, and it still shrinks gracefully on a narrow screen. */}
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="xMidYMid meet"
          style={{ maxWidth: W, display: "block" }}
          role="img" aria-label={`Traffic path from internal hosts to ${org}`}>
        {[["endpoint", X.host], ["entered", X.inIf], ["left via", X.outIf], ["reached", X.party + 20]].map(([lab, x], i) => (
          <text key={i} x={x as number} y={13} textAnchor={i === 0 ? "end" : "middle"}
            style={{ fill: t.subtle, fontSize: 9.5, letterSpacing: "0.09em", textTransform: "uppercase", fontWeight: 700 }}>{lab}</text>
        ))}

        {/* host -> ingress interface */}
        {legs.map((l, i) => (
          <path key={`a${i}`} d={curve(X.hostDot, y(i), X.inIf, inY.get(l.ingress)!)}
            stroke={colOf(l)} strokeWidth={wOf(l.bytes)} fill="none" opacity={0.75} />
        ))}
        {/* ingress -> router, aggregated per interface */}
        {Array.from(byIn.entries()).map(([ifx, ls]) => {
          const b = ls.reduce((s, l) => s + l.bytes, 0);
          const worst = ls.some((l) => l.resourceDrops > 0) ? t.down : t.accent;
          return <path key={`b${ifx}`} d={curve(X.inIf, inY.get(ifx)!, X.rtr - 40, mid)} stroke={worst} strokeWidth={wOf(b)} fill="none" opacity={0.75} />;
        })}
        {/* router -> egress -> party */}
        <path d={curve(X.rtr + 40, mid, X.outIf, mid)} stroke={t.accent} strokeWidth={wOf(total)} fill="none" opacity={0.75} />
        <path d={curve(X.outIf, mid, X.party, mid)} stroke={t.accent} strokeWidth={wOf(total)} fill="none" opacity={0.75} />

        {/* endpoints */}
        {legs.map((l, i) => (
          <g key={`h${i}`}>
            <text x={X.host} y={y(i) - 2} textAnchor="end" style={{ ...mono, fill: t.ink, fontSize: 12.5 }}>{l.internal}</text>
            <text x={X.host} y={y(i) + 12} textAnchor="end" style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>
              {fmtB(l.bytes)} · {Math.round((100 * l.bytes) / total)}% · {l.flows.toLocaleString()} flows
            </text>
            <Glyph name="HostsIcon" x={X.hostDot} y={y(i)} s={16} />
          </g>
        ))}

        {/* ingress interface nodes — label ABOVE the node so no band covers it */}
        {Array.from(byIn.entries()).map(([ifx, ls]) => {
          const yy = inY.get(ifx)!, b = ls.reduce((s, l) => s + l.bytes, 0);
          const drops = ls.reduce((s, l) => s + l.resourceDrops, 0);
          return (
            <g key={`i${ifx}`}>
              <text x={X.inIf} y={yy - 15} textAnchor="middle" style={{ ...mono, fill: t.ink, fontSize: 12, fontWeight: 700 }}>if {ifx}</text>
              <circle cx={X.inIf} cy={yy} r={11} fill={t.card} stroke={drops ? t.down : t.accent} strokeWidth={2} />
              <Glyph name="ConnectorIcon" x={X.inIf} y={yy} s={13} color={drops ? t.down : t.accent} />
              <text x={X.inIf} y={yy + 22} textAnchor="middle" style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>{fmtB(b)}</text>
              {drops > 0 && <text x={X.inIf} y={yy + 34} textAnchor="middle" style={{ fill: t.down, fontSize: 10.5, fontWeight: 700 }}>⚠ {drops} dropped</text>}
            </g>
          );
        })}

        {/* router */}
        {/* NAMED, not just "router". An ifIndex belongs to a device, and with more than one
            exporter in the tenant "if 26" on its own identifies nothing. */}
        <rect x={X.rtr - 62} y={mid - 22} width={124} height={44} rx={9} fill={t.cardSubtle} stroke={t.border} strokeWidth={1.5} />
        <Glyph name="NetworkDevicesIcon" x={X.rtr - 44} y={mid - 3} s={16} />
        <text x={X.rtr - 30} y={mid - 1} style={{ fill: t.ink, fontSize: 12, fontWeight: 700 }}>{exporterName}</text>
        <text x={X.rtr - 30} y={mid + 13} style={{ ...mono, fill: t.subtle, fontSize: 10 }}>{exporterAddr || "exporter"}</text>

        {/* egress interface + party */}
        <text x={X.outIf} y={mid - 17} textAnchor="middle" style={{ ...mono, fill: t.ink, fontSize: 12, fontWeight: 700 }}>if {egress.join(", ")}</text>
        <circle cx={X.outIf} cy={mid} r={11} fill={t.card} stroke={t.accent} strokeWidth={2} />
        <Glyph name="ConnectorIcon" x={X.outIf} y={mid} s={13} color={t.accent} />
        <text x={X.outIf} y={mid + 24} textAnchor="middle" style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>{fmtB(total)}</text>

        {/* The destination reads as a BADGE, matching the party table above, so the same
            organisation is recognisable at a glance in both places. Drawn as native SVG
            (rect + initials) rather than a foreignObject wrapping the React badge — an
            <svg> that depends on HTML embedding is a rendering risk for no benefit here. */}
        <rect x={X.party} y={mid - 20} width={40} height={40} rx={11} fill={providerHue(classifyProvider(org).short)} />
        <text x={X.party + 20} y={mid + 6} textAnchor="middle" style={{ fill: "#fff", fontSize: 15, fontWeight: 800 }}>
          {classifyProvider(org).initials}
        </text>
        <text x={X.party + 50} y={mid - 2} style={{ fill: t.ink, fontSize: 12.5, fontWeight: 700 }}>{shortName(org)}</text>
        <text x={X.party + 50} y={mid + 13} style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>{fmtB(total)} · {totalFlows.toLocaleString()} flows</text>
      </svg>
      {hidden > 0 && (
        <Text style={{ color: t.subtle, fontSize: 12, display: "block", marginTop: 2 }}>
          Showing the top {MAX_ROWS} of {allLegs.length} hosts ({fmtB(hiddenBytes)} across the other{" "}
          {hidden} not drawn) — the table below lists them all.
        </Text>
      )}
      <Text style={{ color: t.subtle, fontSize: 11.5, display: "block", marginTop: 2 }}>
        Interface numbers are SNMP ifIndex on <strong>{exporterName}</strong>{exporterAddr ? " (" + exporterAddr + ")" : ""} — the
        device that exported these flows. Band width is share of volume (capped so one large flow cannot hide the labels). Red marks
        flows the router dropped for lack of resources; amber marks a reset rate well above this
        path&rsquo;s own average. Interface health from SNMP is shown separately below — the gateway
        exporting these flows is not SNMP-polled, so its ports cannot be coloured from counters.
      </Text>
    </div>
  );
}

/** Initials on a stable hue, badged with the DYNATRACE icon for the destination's category.
 *  Using Strato icons rather than bundled brand artwork keeps the visual language consistent
 *  with the rest of the product and avoids shipping someone else's trademark — and the category
 *  ("hosting / VPN" vs "CDN") is the part that actually changes what an operator does next. */
function ProviderBadge({ org, asn, size = 28 }: { org?: string; asn?: number; size?: number }) {
  const p = classifyProvider(org, asn);
  const hue = providerHue(p.short);
  const Icon = (StratoIcons as any)[p.icon] as React.ComponentType<any> | undefined;
  return (
    <span title={`${p.short} · ${p.label}`} style={{ position: "relative", display: "inline-flex", flex: "none" }}>
      <span style={{
        width: size, height: size, borderRadius: size * 0.28, background: hue, color: "#fff",
        display: "inline-flex", alignItems: "center", justifyContent: "center",
        fontSize: size * 0.38, fontWeight: 800, letterSpacing: "0.02em",
      }}>{p.initials}</span>
      {Icon ? (
        <span style={{
          position: "absolute", right: -4, bottom: -4, width: size * 0.56, height: size * 0.56,
          borderRadius: "50%", background: t.card, border: `1px solid ${t.border}`,
          display: "inline-flex", alignItems: "center", justifyContent: "center", color: t.subtle,
        }}>
          <Icon size="small" />
        </span>
      ) : null}
    </span>
  );
}

/** Sections 3 and 4 are REFERENCE, not the finding. Interface health is fleet-wide and usually
 *  not even on the path being traced; the scope panel is a standing caveat. Both matter, and
 *  both were drowning the answer by sitting open under it — the page read as a wall. Collapsed
 *  by default, with the headline count on the summary line so nothing is hidden, only folded. */
function Collapsible({ title, tag, badge, children, open: initial = false }:
  { title: string; tag?: React.ReactNode; badge?: string; children: React.ReactNode; open?: boolean }) {
  const [open, setOpen] = React.useState(initial);
  return (
    <Panel>
      <Flex justifyContent="space-between" alignItems="center" style={{ cursor: "pointer" }} onClick={() => setOpen((o) => !o)}>
        <Flex gap={8} alignItems="center">
          <span style={{ color: t.subtle, fontSize: 12, width: 12, display: "inline-block" }}>{open ? "▾" : "▸"}</span>
          <span style={{ fontSize: 12.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: t.subtle }}>{title}</span>
          {badge ? <span style={{ ...mono, fontSize: 11.5, color: t.subtle }}>{badge}</span> : null}
        </Flex>
        {tag}
      </Flex>
      {open ? <div style={{ marginTop: 12 }}>{children}</div> : null}
    </Panel>
  );
}

/** East-west drawn as a MESH. Rows send, columns receive, cell shaded by volume.
 *
 *  The asymmetry IS the finding, and it is the thing a funnel physically cannot show: a peer
 *  that sends six times what it receives is a replication primary, and drawn as converging
 *  lines that fact disappears. The diagonal is hatched rather than zeroed — a host talking to
 *  itself is not measured, which is different from measuring zero. */
function EastWestPanel({ data, isLoading }: { data: import("../lib/netflow").EwMatrix; isLoading: boolean }) {
  const { peers, cell, sent, recv, total } = data;
  if (!isLoading && peers.length < 2) return null;   // a 1x1 grid is a table with extra steps
  const peak = Math.max(1, ...Object.values(cell));
  const shade = (v: number) => `rgba(57,135,229,${Math.min(0.92, 0.1 + 0.82 * (v / peak))})`;
  const short = (ip: string) => { const p = ip.split("."); return p.length === 4 ? `.${p[3]}` : ip; };
  const lead = peers.map((p) => ({ p, s: sent[p] || 0, r: recv[p] || 0 }))
    .filter((x) => x.r > 0 && x.s / x.r >= 3).sort((a, b) => b.s - a.s)[0];

  return (
    <Panel>
      <Flex justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={8} style={{ marginBottom: 12 }}>
        <div>
          <div style={{ ...mono, fontSize: 11, letterSpacing: "0.09em", textTransform: "uppercase", color: t.subtle, fontWeight: 700 }}>East-west · peer matrix</div>
          <div style={{ fontSize: 12, color: t.subtle, marginTop: 2 }}>internal only · never crosses a router, so no gateway export can see it</div>
        </div>
        <Pill status="up">{fmtB(total)}</Pill>
      </Flex>
      {isLoading ? <Text style={{ color: t.subtle }}>Loading…</Text> : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "separate", borderSpacing: 3 }}>
              <tbody>
                <tr>
                  <td></td>
                  {peers.map((c) => <td key={c} style={{ ...mono, fontSize: 11.5, color: t.subtle, padding: "0 8px", whiteSpace: "nowrap" }}>→ {short(c)}</td>)}
                  <td style={{ ...mono, fontSize: 11.5, color: t.subtle, padding: "0 8px 0 16px" }}>sent</td>
                </tr>
                {peers.map((r) => (
                  <tr key={r}>
                    <td style={{ ...mono, fontSize: 11.5, color: t.subtle, padding: "0 8px", whiteSpace: "nowrap" }}>{r}</td>
                    {peers.map((c) => {
                      const v = cell[`${r}|${c}`] || 0;
                      const self = r === c;
                      return (
                        <td key={c}>
                          <div title={self ? "not measured" : `${r} → ${c}: ${fmtB(v)}`}
                            style={{
                              width: 82, height: 38, borderRadius: 6,
                              display: "flex", alignItems: "center", justifyContent: "center",
                              ...mono, fontSize: 11.5,
                              background: self ? t.cardSubtle : v ? shade(v) : "transparent",
                              color: self ? "transparent" : v > peak * 0.45 ? "#fff" : t.ink,
                              border: v || self ? undefined : `1px dashed ${t.border}`,
                            }}>{self ? "—" : v ? fmtB(v) : "·"}</div>
                        </td>
                      );
                    })}
                    <td style={{ ...mono, fontSize: 11.5, color: t.subtle, padding: "0 8px 0 16px", whiteSpace: "nowrap" }}>{fmtB(sent[r] || 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginTop: 11 }}>
            Rows send, columns receive; the diagonal is not measured rather than zero.
            {lead ? <> <strong style={{ color: t.ink }}>{lead.p} sends {Math.round(lead.s / Math.max(1, lead.r))}× what it receives</strong> — the signature of a replication primary.</> : null}
            {" "}Volumes are scaled by each exporter&rsquo;s stated sampling rate.
          </Text>
        </>
      )}
    </Panel>
  );
}

function HealthTable({ physical, policy, down }: { physical: IfHealth[]; policy: IfHealth[]; down: IfHealth[] }) {
  const rows = [...down.map((r) => ({ r, kind: "down" as const })), ...physical.map((r) => ({ r, kind: "phys" as const })), ...policy.map((r) => ({ r, kind: "pol" as const }))];
  if (!rows.length) return <Text style={{ color: t.subtle, fontSize: 14 }}>No interface is reporting errors, discards or a down state.</Text>;
  return (
    <>
      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13.5 }}>
          <thead><tr>{["Device", "Interface", "Errors", "Discards", "Reads as"].map((h, i) => (
            <th key={h} style={{ textAlign: i === 2 || i === 3 ? "right" : "left", padding: "7px 11px", color: t.subtle, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em", borderBottom: `1px solid ${t.border}` }}>{h}</th>
          ))}</tr></thead>
          <tbody>
            {rows.slice(0, 10).map(({ r, kind }, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${t.border}` }}>
                <td style={{ ...mono, padding: "8px 11px" }}>{r.dev}</td>
                <td style={{ ...mono, padding: "8px 11px", color: t.subtle }}>{r.iface}</td>
                <td style={{ ...mono, padding: "8px 11px", textAlign: "right", color: r.inErr + r.outErr ? t.down : t.subtle }}>{(r.inErr + r.outErr) || "—"}</td>
                <td style={{ ...mono, padding: "8px 11px", textAlign: "right", color: r.inDisc ? t.warn : t.subtle }}>{r.inDisc ? r.inDisc.toLocaleString() : "—"}</td>
                <td style={{ padding: "8px 11px" }}>
                  <Pill status={kind === "pol" ? "warn" : "down"}>{kind === "down" ? "operationally down" : kind === "phys" ? "cable / optic" : "buffers / policy"}</Pill>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginTop: 9 }}>
        Errors are physical — cable, optic, duplex. Discards are the device dropping deliberately —
        buffers, an ACL, QoS, storm control, STP. Never the same fault, so never the same number.
      </Text>
    </>
  );
}

function CoverageTable({ rows }: { rows: import("../lib/netflow").Coverage[] }) {
  if (!rows.length) return <Text style={{ color: t.subtle, fontSize: 14 }}>No flow exporters are reporting.</Text>;
  const yn = (n: number, tot: number) => n === 0 ? <Pill status="down">blind</Pill> : n === tot ? <Pill status="up">observed</Pill> : <Pill status="warn">{Math.round((100 * n) / Math.max(1, tot))}%</Pill>;
  return (
    <>
      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13.5 }}>
          <thead><tr>{["Exporter", "Protocol", "North-south", "East-west", "Per-interface", "Flows"].map((h, i) => (
            <th key={h} style={{ textAlign: i === 5 ? "right" : "left", padding: "7px 11px", color: t.subtle, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em", borderBottom: `1px solid ${t.border}` }}>{h}</th>
          ))}</tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${t.border}` }}>
                <td style={{ ...mono, padding: "8px 11px" }}>{r.exporter}</td>
                <td style={{ ...mono, padding: "8px 11px", color: t.subtle }}>{r.type}</td>
                <td style={{ padding: "8px 11px" }}>{yn(r.ns, r.flows)}</td>
                <td style={{ padding: "8px 11px" }}>{yn(r.ew, r.flows)}</td>
                <td style={{ padding: "8px 11px" }}>{r.ifaces ? <Pill status="up">yes</Pill> : <Pill status="warn">dropped by receiver</Pill>}</td>
                <td style={{ ...mono, padding: "8px 11px", textAlign: "right", color: t.subtle }}>{r.flows.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Text style={{ color: t.subtle, fontSize: 12.5, display: "block", marginTop: 9 }}>
        Coverage between a router and a switch is complementary, not redundant. Also unmapped:
        which access-switch port a host sits on, and any conversation crossing NAT — the address
        and port change there, so the two halves cannot be joined by 5-tuple.
      </Text>
    </>
  );
}
