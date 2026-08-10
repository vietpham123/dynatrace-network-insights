import React from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading } from "@dynatrace/strato-components/typography";
import { Panel, StatTile, Pill, Segmented, Tag } from "../components/ui";
import { t, mono } from "../theme";
import { MirrorChart, TalkerBars, MiniIO, ShareBar, Sankey, usePalette, fmtMbps } from "../components/charts";
import { useFlowSeries, useTalkers, useApps, useConvos, useFlowStats, useIfList, useEgressSankey, useAppShares, useEgressAsn, useInterfaceFlows, setNetflowWindow, winSeconds, CURRENT_WINDOW, IF_DOWN } from "../lib/netflow";
import type { Convo, IfRow, ConvoScope } from "../lib/netflow";
import { useTimeframe } from "../lib/timeframe";
import { useNetflowMode } from "../lib/netflowMode";
import { ErrorBanner } from "../components/QueryState";

/* Grid + table styling reproduced from the mockup's .dash / table.data, scoped to
   .nf-section. Theme tokens interpolate as CSS-var references so it stays theme-aware. */
const NF_STYLE = `
.nf-section .dash { display:grid; grid-template-columns:repeat(12,1fr); gap:16px; }
.nf-section .span4{grid-column:span 4;min-width:0} .nf-section .span6{grid-column:span 6;min-width:0}
.nf-section .span8{grid-column:span 8;min-width:0} .nf-section .span12{grid-column:span 12;min-width:0}
.nf-section .dash.eq>[class*=span]{display:flex}.nf-section .dash.eq>[class*=span]>*{flex:1;min-width:0}
.nf-section .stats4{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:16px}
.nf-section .cols3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.nf-section .rowgap+.rowgap{margin-top:16px}
.nf-section table.data{border-collapse:collapse;width:100%;font-size:14px}
.nf-section table.data th{text-align:left;padding:9px 14px;color:${t.subtle};font-weight:600;border-bottom:1px solid ${t.border};font-size:12.5px;text-transform:uppercase;letter-spacing:.04em}
.nf-section table.data td{padding:9px 14px;border-bottom:1px solid ${t.border}}
.nf-section table.data tr:last-child td{border-bottom:0}
.nf-section table.data td.num,.nf-section table.data th.num{text-align:right;font-family:${mono.fontFamily};font-variant-numeric:tabular-nums}
.nf-section table.data tbody tr:hover{background:${t.cardSubtle}}
.nf-section .panelt{text-transform:uppercase;font-size:12.5px;letter-spacing:.07em;color:${t.subtle};font-weight:700}
.nf-section .panelsub{font-size:12px;color:${t.subtle};font-weight:500;margin-top:2px}
.nf-section .hrow{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;padding:9px 0;border-bottom:1px solid ${t.border}}
.nf-section .hrow:last-child{border-bottom:0}
.nf-section .hrow small{display:block;color:${t.subtle};font-size:12px}
.nf-section .mdgrid{display:grid;grid-template-columns:340px 1fr;gap:0;border:1px solid ${t.border};border-radius:8px;overflow:hidden}
.nf-section .mlist{border-right:1px solid ${t.border}}
.nf-section .ifitem{display:grid;grid-template-columns:1fr auto;gap:3px 10px;padding:11px 14px;border-bottom:1px solid ${t.border};cursor:pointer;border-left:3px solid transparent}
.nf-section .ifitem.sel{background:${t.accentBg};border-left-color:${t.accent}}
.nf-section .ifitem:hover{background:${t.cardSubtle}}
.nf-section .iosplit{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.nf-section .iobox{background:${t.cardSubtle};border:1px solid ${t.border};border-radius:7px;padding:10px 12px}
.nf-section .meter{height:8px;border-radius:5px;background:${t.cardSubtle};overflow:hidden}
.nf-section .edgecard{background:${t.card};border:1px solid ${t.border};border-radius:8px;overflow:hidden}
.nf-section .edgecard .eh{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid ${t.border}}
.nf-section .convo{background:${t.cardSubtle};border:1px solid ${t.border};border-radius:8px;padding:12px 14px}
@media(max-width:900px){.nf-section .dash>[class*=span]{grid-column:span 12}.nf-section .cols3{grid-template-columns:1fr}.nf-section .mdgrid{grid-template-columns:1fr}.nf-section .iosplit{grid-template-columns:1fr}}
`;

function DirChip({ dir, label }: { dir: "in" | "out"; label: string }) {
  const p = usePalette();
  const c = dir === "in" ? p.dirIn : p.dirOut;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7, fontWeight: 700, fontSize: 13, color: c }}>
      <span style={{ width: 10, height: 10, borderRadius: 3, background: c }} />{label}
    </span>
  );
}

// client-side column sort, reused across NetFlow data tables
function useSort<T>(rows: T[], initial: { key: keyof T; dir: "asc" | "desc" }) {
  const [sort, setSort] = React.useState(initial);
  const sorted = React.useMemo(() => {
    const arr = [...rows];
    arr.sort((a, b) => {
      const av: any = a[sort.key], bv: any = b[sort.key];
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric: true });
      return sort.dir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [rows, sort]);
  const toggle = (key: keyof T) => setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" }));
  return { sorted, sort, toggle };
}
function SortTh<T>({ label, k, sort, toggle, num }: { label: string; k: keyof T; sort: { key: keyof T; dir: "asc" | "desc" }; toggle: (k: keyof T) => void; num?: boolean }) {
  const active = sort.key === k;
  return (
    <th className={num ? "num" : undefined} onClick={() => toggle(k)} style={{ cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }} title="Click to sort">
      {label}<span style={{ opacity: active ? 0.9 : 0.25, marginLeft: 5, fontSize: 10 }}>{active ? (sort.dir === "asc" ? "▲" : "▼") : "▲"}</span>
    </th>
  );
}

function ApproachA() {
  const p = usePalette();
  const stats = useFlowStats();
  const series = useFlowSeries();
  const talk = useTalkers();
  const apps = useApps();
  // Scope defaults to north-south: that is the traffic an operator opens this page for, and
  // east-west (sampled x1024) otherwise buries it entirely — see useConvos.
  const [convoScope, setConvoScope] = React.useState<ConvoScope>("ns");
  const convos = useConvos(12, convoScope);
  const ifs = useIfList(6);
  const asn = useEgressAsn();
  const convoSort = useSort<Convo>(convos.rows, { key: "bytes", dir: "desc" });
  const winLabel = `${Math.round(winSeconds(CURRENT_WINDOW) / 3600)}h`;
  const flowsPerMin = stats.flows / (winSeconds(CURRENT_WINDOW) / 60);

  return (
    <div style={{ padding: 20 }}>
      <ErrorBanner error={talk.error} what="Flow query" />
      {/* headline stat strip */}
      <div className="stats4 rowgap">
        <StatTile label="Flows" accent={p.dirIn} value={<>{stats.flows.toLocaleString()}</>} sub={`last ${winLabel} · ${flowsPerMin.toFixed(1)}/min`} />
        <StatTile label="Inbound" accent={p.dirIn} value={<>{stats.inMbps < 1 ? (stats.inMbps * 1000).toFixed(0) : stats.inMbps.toFixed(2)}<small style={{ fontSize: 15, color: t.subtle }}> {stats.inMbps < 1 ? "Kbps" : "Mbps"}</small></>} sub="external → internal" />
        <StatTile label="Outbound" accent={p.dirOut} value={<>{stats.outMbps < 1 ? (stats.outMbps * 1000).toFixed(0) : stats.outMbps.toFixed(2)}<small style={{ fontSize: 15, color: t.subtle }}> {stats.outMbps < 1 ? "Kbps" : "Mbps"}</small></>} sub="internal → external" />
        <StatTile label="Active talkers" value={stats.talkers} sub={`${stats.exporters} exporter${stats.exporters === 1 ? "" : "s"}`} />
      </div>

      {/* directional trend + interface list */}
      <div className="dash eq rowgap">
        <div className="span8">
          <Panel style={{ display: "flex", flexDirection: "column" }}>
            <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 12 }}>
              <div><div className="panelt">Inbound vs outbound throughput</div><div className="panelsub">derived direction · mirrored on zero · last {winLabel}</div></div>
              <Flex gap={12}><DirChip dir="in" label="↓ Inbound" /><DirChip dir="out" label="↑ Outbound" /></Flex>
            </Flex>
            {series.isLoading ? <Loading /> : <MirrorChart data={series.data} height={380} />}
          </Panel>
        </div>
        <div className="span4">
          <Panel style={{ padding: 0, display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "16px 16px 8px" }}><div className="panelt">Interfaces by utilization</div><div className="panelsub">{ifs.rows.length} fastest links · by utilization</div></div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
            {ifs.isLoading ? <div style={{ padding: 14 }}><Loading /></div> : ifs.rows.map((f, i) => {
              const uc = f.util >= 80 ? t.down : f.util >= 50 ? t.warn : t.up;
              return (
                <div key={i} style={{ padding: "11px 16px", borderTop: `1px solid ${t.border}` }}>
                  <Flex justifyContent="space-between" alignItems="baseline" gap={8}>
                    <span style={{ ...mono, fontSize: 12.5, color: t.ink, fontWeight: 600 }}>{f.dev} · {f.iface}</span>
                    <span style={{ ...mono, fontSize: 12, fontWeight: 700, color: uc }}>{f.util.toFixed(0)}%</span>
                  </Flex>
                  <div className="meter" style={{ margin: "7px 0 5px" }}><div style={{ width: `${Math.max(2, f.util)}%`, height: "100%", background: uc }} /></div>
                  <Flex justifyContent="space-between" style={{ ...mono, fontSize: 11.5 }}>
                    <span style={{ color: p.dirIn }}>↓ {fmtMbps(f.inMbps)}</span>
                    <span style={{ color: p.dirOut }}>↑ {fmtMbps(f.outMbps)}</span>
                  </Flex>
                </div>
              );
            })}
            </div>
          </Panel>
        </div>
      </div>

      {/* talkers / apps */}
      <div className="dash eq rowgap">
        <div className="span4">
          <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 12 }}><div className="panelt">Top talkers — inbound</div><DirChip dir="in" label="↓ recv" /></Flex>
            {talk.isLoading ? <Loading /> : <TalkerBars rows={talk.inbound} hue="dirIn" />}</Panel>
        </div>
        <div className="span4">
          <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 12 }}><div className="panelt">Top talkers — outbound</div><DirChip dir="out" label="↑ sent" /></Flex>
            {talk.isLoading ? <Loading /> : <TalkerBars rows={talk.outbound} hue="dirOut" />}</Panel>
        </div>
        <div className="span4">
          <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 12 }}><div className="panelt">Applications · ports</div><span style={{ ...mono, fontSize: 12, color: t.subtle }}>bytes, both dir</span></Flex>
            {apps.isLoading ? <Loading /> : <TalkerBars rows={apps.rows} perColorDot />}</Panel>
        </div>
      </div>

      {/* conversations + peering */}
      <div className="dash eq rowgap">
        <div className="span8">
          <Panel style={{ padding: 0 }}>
            <div style={{ padding: "16px 16px 0" }}><Flex justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={8}><div><div className="panelt">Top conversations — src ↔ dst</div><div className="panelsub">{convoScope === "ns" ? "north-south — crosses the perimeter" : convoScope === "ew" ? "east-west — stays internal (switch exporters only)" : "all directions — east-west is sampled, so it outranks by volume"}</div></div><Flex gap={4}>{([["ns","N-S"],["ew","E-W"],["all","All"]] as const).map(([v,lab]) => (<button key={v} onClick={() => setConvoScope(v as ConvoScope)} style={{ border: `1px solid ${convoScope===v ? t.accent : t.border}`, background: convoScope===v ? t.accentBg : "transparent", color: convoScope===v ? t.ink : t.subtle, borderRadius: 7, padding: "3px 10px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>{lab}</button>))}</Flex><span style={{ fontSize: 12.5, color: t.subtle }}>{winLabel}</span></Flex></div>
            <div style={{ overflowX: "auto", overflowY: "auto", maxHeight: 380, padding: "12px 0 4px" }}>
              {convos.isLoading ? <div style={{ padding: 16 }}><Loading /></div> : (
                <table className="data">
                  <thead><tr><SortTh<Convo> label="Source" k="src" sort={convoSort.sort} toggle={convoSort.toggle} /><th></th><SortTh<Convo> label="Destination" k="dst" sort={convoSort.sort} toggle={convoSort.toggle} /><SortTh<Convo> label="App" k="app" sort={convoSort.sort} toggle={convoSort.toggle} /><SortTh<Convo> label="Dir" k="dir" sort={convoSort.sort} toggle={convoSort.toggle} num /><SortTh<Convo> label="Packets" k="packets" sort={convoSort.sort} toggle={convoSort.toggle} num /><SortTh<Convo> label="Bytes" k="bytes" sort={convoSort.sort} toggle={convoSort.toggle} num /></tr></thead>
                  <tbody>
                    {convoSort.sorted.map((c, i) => {
                      const dc = c.dir === "outbound" ? p.dirOut : c.dir === "inbound" ? p.dirIn : t.subtle;
                      const arrow = c.dir === "outbound" ? "↑" : c.dir === "inbound" ? "↓" : "↔";
                      return (
                        <tr key={i}>
                          <td style={mono}>{c.src}</td>
                          <td style={{ color: t.subtle }}>↔</td>
                          <td style={mono}>{c.dst}</td>
                          <td><span style={{ width: 10, height: 10, borderRadius: 3, display: "inline-block", background: p.c[c.hue], marginRight: 6, verticalAlign: "middle" }} /><span style={mono}>{c.port}</span></td>
                          <td className="num" style={{ color: dc, fontWeight: 700 }}>{arrow} {c.dir === "east-west" ? "e-w" : c.dir}</td><td className="num">{(c.packets ?? 0).toLocaleString()}</td>
                          <td className="num" style={{ fontWeight: 700 }}>{fmtB(c.bytes)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
        </div>
        <div className="span4">
          <Panel><div className="panelt">Peering · destination ASN</div><div className="panelsub">internet egress · ASN and owner resolved at ingest (Team Cymru + rDNS); unresolved shown as /24</div>
            <div style={{ marginTop: 10 }}>{asn.isLoading ? <Loading /> : asn.rows.length ? <TalkerBars rows={asn.rows} perColorDot /> : <span style={{ color: t.subtle, fontSize: 13 }}>No egress traffic in window.</span>}</div></Panel>
        </div>
      </div>

      {/* flow health */}
      <div className="dash rowgap">
        <div className="span12">
          <Panel>
            <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 4 }}>
              <div><div className="panelt">Flow health & data quality</div><div className="panelsub">is the flow feed trustworthy right now? — flow-specific self-checks</div></div>
              {/* THREE states, not two. "No feed" existed as a condition but not as a verdict, so an
                  empty window fell through to the healthy branch: staleness was 0 (no newest record),
                  0 < 120, and the panel announced "Feed healthy · 100% · 0s" over zero exporters and
                  zero flows. A panel whose job is answering "is this trustworthy?" must be able to
                  say no. */}
              <Pill status={!stats.hasFeed ? "down" : (stats.stalenessSec ?? 0) < 120 ? "up" : "warn"}>
                {!stats.hasFeed ? "No feed" : (stats.stalenessSec ?? 0) < 120 ? "Feed healthy" : "Stale feed"}
              </Pill>
            </Flex>
            <div className="cols3">
              <div>
                {/* was a hardcoded <Pill status="up">100%</Pill> — a literal that reported perfect
                    decoding even with nothing decoded. Reports the protocols actually observed
                    instead, which is both true and more useful: it names what each exporter speaks. */}
                <div className="hrow"><div>Flow protocol<small>versions decoded in window</small></div>
                  {stats.versions.length
                    ? <Pill status="up">{stats.versions.join(", ")}</Pill>
                    : <span style={{ ...mono, color: t.subtle, fontWeight: 700 }}>—</span>}
                </div>
                <div className="hrow"><div>Exporters reporting<small>distinct flow.sampler.address in window</small></div><span style={{ ...mono, fontWeight: 700 }}>{stats.exporters}</span></div>
              </div>
              <div>
                <div className="hrow"><div>Sampling rate<small>{stats.samplingKnown ? "1 in N packets — byte counts ×N" : "not reported by exporter — assumed unsampled"}</small></div>
                  <span style={{ ...mono, fontWeight: 700, color: stats.samplingKnown ? undefined : t.subtle }}>
                    {stats.hasFeed ? (stats.samplingKnown ? `1:${stats.samplingRate}` : "1:1 assumed") : "—"}
                  </span>
                </div>
                <div className="hrow"><div>Total flows ({winLabel})<small>decoded flow records</small></div><span style={{ ...mono, fontWeight: 700 }}>{stats.flows.toLocaleString()}</span></div>
              </div>
              <div>
                <div className="hrow"><div>Newest record age<small>export cadence · staleness</small></div>
                  {stats.stalenessSec == null
                    ? <span style={{ ...mono, color: t.subtle, fontWeight: 700 }}>—</span>
                    : <Pill status={stats.stalenessSec < 120 ? "up" : "warn"}>{stats.stalenessSec}s</Pill>}
                </div>
                <div className="hrow"><div>Interface mapping<small>ifIndex → ifName via SNMP</small></div><Pill status="warn">field-gated</Pill></div>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

const statusOf = (u: number): "up" | "warn" | "down" => (u >= 80 ? "down" : u >= 50 ? "warn" : "up");
const speedLabel = (m: number) => (m >= 1000 ? m / 1000 + "G" : m + "M");
// bucketsAgo × the 10-minute series interval → a compact relative x-axis label for the per-interface chart.
const relLabel = (bucketsAgo: number) => { const m = bucketsAgo * 10; return m === 0 ? "now" : m >= 60 ? `-${+(m / 60).toFixed(m % 60 ? 1 : 0)}h` : `-${m}m`; };

/* Approach B — drill-down explorer: interface master list -> directional detail pane */
function ApproachB() {
  const p = usePalette();
  const ifs = useIfList();
  const [sel, setSel] = React.useState(0);
  const series = useFlowSeries();
  const shares = useAppShares();
  const talk = useTalkers(4);
  const convos = useConvos(1);
  const [devFilter, setDevFilter] = React.useState("all");
  const devices = Array.from(new Set(ifs.rows.map((r) => r.dev))).sort();
  const shownIfs = devFilter === "all" ? ifs.rows.slice(0, 30) : ifs.rows.filter((f) => f.dev === devFilter);
  const cur = shownIfs[sel] || shownIfs[0];
  const ifFlows = useInterfaceFlows(cur?.ifIndex);
  const pinned = convos.rows[0];

  return (
    <div style={{ padding: 20 }}>
      <ErrorBanner error={convos.error} what="Flow query" />
      <div className="mdgrid">
        {/* MASTER: interface list */}
        <div className="mlist" style={{ position: "relative", minHeight: 320 }}>
          <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "10px 14px", borderBottom: `1px solid ${t.border}`, flex: "none" }}>
            <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
              <span className="panelt">Interfaces</span><span style={{ ...mono, fontSize: 11.5, color: t.subtle }}>{shownIfs.length} of {ifs.rows.length}</span>
            </Flex>
            <select value={devFilter} onChange={(e) => { setDevFilter(e.target.value); setSel(0); }}
              style={{ width: "100%", background: t.cardSubtle, color: t.ink, border: `1px solid ${t.border}`, borderRadius: 6, padding: "5px 8px", fontSize: 12.5, fontFamily: mono.fontFamily }}>
              <option value="all">All devices — top 30 by link</option>
              {devices.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          {ifs.isLoading ? <div style={{ padding: 14 }}><Loading /></div> : shownIfs.map((f, i) => (
            <div key={i} className={"ifitem" + (i === sel ? " sel" : "")} onClick={() => setSel(i)}>
              <div><div style={{ ...mono, fontSize: 13, color: t.ink, fontWeight: 600 }}>{f.iface}</div><div style={{ ...mono, fontSize: 11.5, color: t.subtle }}>{f.dev} · {speedLabel(f.speedMbps)}</div></div>
              <div style={{ ...mono, fontSize: 12, fontWeight: 700, textAlign: "right", color: f.oper === 1 ? t.up : t.subtle }}>{f.oper === 1 ? "up" : "down"}</div>
              <div style={{ gridColumn: "1 / -1" }}><MiniIO inn={f.inn} out={f.out} width={296} /></div>
            </div>
          ))}
          </div>
          </div>
        </div>
        {/* DETAIL: selected interface */}
        <div style={{ padding: 18, minWidth: 0 }}>
          {cur ? (
            <>
              <Flex justifyContent="space-between" alignItems="flex-start" flexWrap="wrap" gap={12} style={{ marginBottom: 12 }}>
                <div><div style={{ ...mono, fontSize: 17, fontWeight: 700 }}>{cur.dev} · {cur.iface}</div>
                  <div style={{ fontSize: 12.5, color: t.subtle }}>{cur.speedMbps >= 1000 ? cur.speedMbps / 1000 + " Gbps" : cur.speedMbps + " Mbps"} link · oper {cur.oper === 1 ? "up" : "down"}</div></div>
                <Tag>live</Tag>
              </Flex>
              <div className="iosplit" style={{ marginBottom: 14 }}>
                <div className="iobox"><Flex justifyContent="space-between" alignItems="baseline"><DirChip dir="in" label="↓ Inbound" /><span style={{ fontSize: 12, color: t.subtle }}>{cur.util.toFixed(0)}% util</span></Flex>
                  <div style={{ fontSize: 22, fontWeight: 700, marginTop: 2 }}>{fmtMbps(cur.inMbps)}</div>
                  <div className="meter" style={{ marginTop: 8 }}><div style={{ width: `${Math.min(100, cur.util)}%`, height: "100%", background: p.dirIn }} /></div></div>
                <div className="iobox"><Flex justifyContent="space-between" alignItems="baseline"><DirChip dir="out" label="↑ Outbound" /><span style={{ fontSize: 12, color: t.subtle }}>{cur.speedMbps && cur.outMbps != null ? `${((cur.outMbps / cur.speedMbps) * 100).toFixed(0)}% util` : "no counters"}</span></Flex>
                  <div style={{ fontSize: 22, fontWeight: 700, marginTop: 2 }}>{fmtMbps(cur.outMbps)}</div>
                  <div className="meter" style={{ marginTop: 8 }}><div style={{ width: `${cur.speedMbps && cur.outMbps != null ? Math.min(100, (cur.outMbps / cur.speedMbps) * 100) : 0}%`, height: "100%", background: p.dirOut }} /></div></div>
              </div>
              <Panel style={{ marginBottom: 14 }}>
                <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
                  <div className="panelt">Flows on this interface <span style={{ color: t.subtle, fontWeight: 500, textTransform: "none" }}>· ifIndex {cur.ifIndex} · true per-interface (decoder preserves ifIndex)</span></div>
                  <Tag>live</Tag>
                </Flex>
                {ifFlows.isLoading ? <Loading /> : ifFlows.hasIfData ? (
                  <div style={{ overflowX: "auto" }}>
                    <table className="data">
                      <thead><tr><th>Source</th><th>Destination</th><th>App</th><th className="num">Dir</th><th className="num">Bytes</th></tr></thead>
                      <tbody>
                        {ifFlows.convos.map((c, i) => (
                          <tr key={i}>
                            <td style={mono}>{c.src}</td>
                            <td style={mono}>{c.dst}</td>
                            <td><span style={{ width: 10, height: 10, borderRadius: 3, display: "inline-block", background: p.c[c.hue], marginRight: 6, verticalAlign: "middle" }} /><span style={mono}>{c.port}</span></td>
                            <td className="num" style={{ color: c.dir === "ingress" ? p.dirIn : p.dirOut, fontWeight: 700 }}>{c.dir === "ingress" ? "↓ in" : "↑ out"}</td>
                            <td className="num" style={{ fontWeight: 700 }}>{fmtB(c.bytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <span style={{ color: t.subtle, fontSize: 13 }}>No flows tagged to ifIndex {cur.ifIndex} in this window.</span>}
              </Panel>
              <Panel style={{ marginBottom: 14 }}>
                <div className="panelt" style={{ marginBottom: 8 }}>Directional throughput <span style={{ color: t.subtle, fontWeight: 500, textTransform: "none" }}>· flow feed (network-wide)</span></div>
                {series.isLoading ? <Loading /> : <MirrorChart data={series.data} height={200} />}
              </Panel>
              <div className="iosplit" style={{ marginBottom: 14 }}>
                <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 10 }}><div className="panelt">What fills inbound</div><DirChip dir="in" label="↓ by app" /></Flex>
                  {!shares.isLoading && <ShareBar parts={shares.inbound} hue="dirIn" />}
                  <div style={{ marginTop: 12 }}>{!talk.isLoading && <TalkerBars rows={talk.inbound} hue="dirIn" />}</div></Panel>
                <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 10 }}><div className="panelt">What fills outbound</div><DirChip dir="out" label="↑ by app" /></Flex>
                  {!shares.isLoading && <ShareBar parts={shares.outbound} hue="dirOut" />}
                  <div style={{ marginTop: 12 }}>{!talk.isLoading && <TalkerBars rows={talk.outbound} hue="dirOut" />}</div></Panel>
              </div>
              {pinned && (
                <div className="convo">
                  <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}><span className="panelt">Top conversation — from the flow feed</span><Pill status="neutral">{fmtB(pinned.bytes)} · {pinned.dir}</Pill></Flex>
                  <Flex gap={8} alignItems="center" flexWrap="wrap" style={{ ...mono, fontSize: 13.5 }}>
                    <span style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 6, padding: "4px 9px" }}>{pinned.src}</span>
                    <span style={{ color: p.dirIn, fontWeight: 800 }}>↔</span>
                    <span style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 6, padding: "4px 9px" }}>{pinned.dst}<span style={{ color: t.subtle }}>:{pinned.port}</span></span>
                    <span style={{ width: 10, height: 10, borderRadius: 3, background: p.c[pinned.hue] }} />
                    <span style={{ fontSize: 12.5, color: t.subtle }}>{pinned.port}/{pinned.transport} {pinned.app}</span>
                  </Flex>
                </div>
              )}
            </>
          ) : <Loading />}
        </div>
      </div>
    </div>
  );
}

/* Approach C — "what's hot": fleet-wide hottest edges (top-N by utilization, carrying traffic),
   click to drill. Exhaustive per-device browsing lives in the Drill-down tab. */
function ApproachC() {
  const nav = useNavigate();
  const p = usePalette();
  const ifs = useIfList();
  const sankey = useEgressSankey();
  const asn = useEgressAsn();
  const [selIdx, setSelIdx] = React.useState<number | null>(null);
  const HOT_N = 25;
  // Fleet-wide hotspot lens. "Carrying traffic" is judged on PEAK over the window (the whole
  // series), not the latest bucket — the lab's SNMP counters are near-static, so any single
  // bucket is often 0. Pre-sort by peak load so the busiest links lead even when the latest
  // util reads 0; fall back to all up-links so the view is never empty.
  const devCount = new Set(ifs.rows.map((r) => r.dev)).size;
  const loadOf = (f: IfRow) => (f.inn.length ? Math.max(0, ...f.inn) : 0) + (f.out.length ? Math.max(0, ...f.out) : 0);
  const upRows = ifs.rows.filter((f) => f.oper === 1);
  const carrying = upRows.filter((f) => loadOf(f) > 0);
  const active = (carrying.length ? carrying : upRows).slice().sort((a, b) => loadOf(b) - loadOf(a));
  const edgeSort = useSort<IfRow>(active, { key: "util", dir: "desc" });
  const hot = edgeSort.sorted.slice(0, HOT_N);
  const pickSort = (k: keyof IfRow) => { edgeSort.toggle(k); setSelIdx(null); };
  // DEFAULT TO THE BUSIEST EDGE, not row 0. selIdx starts null and only becomes a number once
  // the operator actually clicks a row, so "Selected" means selected. Row 0 was a poor default
  // twice over: it is whatever the current sort happens to put first, and when every interface
  // reads the same utilisation the sort is a no-op, so the panel silently pinned an arbitrary
  // idle port and called it the selection.
  const busyIdx = hot.reduce((best, f, i) => (loadOf(f) > loadOf(hot[best]) ? i : best), 0);
  const cur = hot[selIdx ?? busyIdx] || hot[0];
  const ifFlows = useInterfaceFlows(cur?.ifIndex);
  const upCount = upRows.length;
  const busiest = active.length ? active.reduce((a, b) => (b.util > a.util ? b : a)) : null;
  const peakIn = cur && cur.inn.length ? Math.max(0, ...cur.inn) : 0;
  const peakOut = cur && cur.out.length ? Math.max(0, ...cur.out) : 0;
  const avgIn = cur && cur.inn.length ? cur.inn.reduce((s, v) => s + v, 0) / cur.inn.length : 0;
  const avgOut = cur && cur.out.length ? cur.out.reduce((s, v) => s + v, 0) / cur.out.length : 0;

  return (
    <div style={{ padding: 20 }}>
      <ErrorBanner error={sankey.error} what="Flow query" />
      {/* fleet edge summary */}
      <div className="stats4 rowgap">
        <StatTile label="Hot edges" value={carrying.length} sub={carrying.length ? `carrying traffic · ${devCount} devices` : `no live traffic · ${upRows.length} up links`} />
        <StatTile label="Links up" accent={p.dirIn} value={<>{upCount}<small style={{ fontSize: 15, color: t.subtle }}> / {ifs.rows.length}</small></>} sub="fleet oper status" />
        <StatTile label="Hottest edge" value={busiest ? `${busiest.util.toFixed(0)}%` : "—"} sub={busiest ? `${busiest.dev} · ${busiest.iface}` : ""} />
        {/* says whether this is the auto-pick or your pick — the tile used to read "Selected"
            over a row nobody had selected, with no hint that the table below is the control */}
        <StatTile label={selIdx == null ? "Busiest edge" : "Selected"} accent={p.dirOut}
          value={cur && (cur.inMbps != null || cur.outMbps != null) ? fmtMbps((cur.inMbps ?? 0) + (cur.outMbps ?? 0)) : "—"}
          sub={cur ? `${cur.dev} · ${cur.iface}${selIdx == null ? " · click a row to change" : ""}` : "no edges to show"} />
      </div>

      <div className="dash eq rowgap">
        {/* ALL EDGES — sortable, click to drill */}
        <div className="span8">
          <Panel style={{ padding: 0 }}>
            <div style={{ padding: "14px 16px 10px" }}>
              <Flex justifyContent="space-between" alignItems="center" gap={8}>
                <div><div className="panelt">Hottest edges — fleet-wide</div><div className="panelsub">top {Math.min(HOT_N, active.length)} of {active.length} {carrying.length ? "carrying traffic" : "up links"} · ranked by utilization · click to drill →</div></div>
                <Tag>live</Tag>
              </Flex>
            </div>
            <div style={{ overflowX: "auto", maxHeight: 400, overflowY: "auto" }}>
              {ifs.isLoading ? <div style={{ padding: 16 }}><Loading /></div> : (
                <table className="data">
                  <thead><tr>
                    <SortTh<IfRow> label="Device" k="dev" sort={edgeSort.sort} toggle={pickSort} />
                    <SortTh<IfRow> label="Interface" k="iface" sort={edgeSort.sort} toggle={pickSort} />
                    <SortTh<IfRow> label="Speed" k="speedMbps" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="Oper" k="oper" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="↓ In" k="inMbps" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="↑ Out" k="outMbps" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="Util" k="util" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="p95" k="p95" sort={edgeSort.sort} toggle={pickSort} num />
                    <SortTh<IfRow> label="p95 util" k="p95Util" sort={edgeSort.sort} toggle={pickSort} num />
                  </tr></thead>
                  <tbody>
                    {hot.map((f, i) => {
                      const uc = f.util >= 80 ? t.down : f.util >= 50 ? t.warn : t.up;
                      // p95 drives the SIZING verdict, so it gets its own thresholds: a circuit
                      // sitting above 70% at p95 is the one to upgrade, regardless of where the
                      // instantaneous reading happens to be when you look at it.
                      const pc = f.p95Util == null ? t.subtle : f.p95Util >= 70 ? t.down : f.p95Util >= 40 ? t.warn : t.up;
                      // highlight the EFFECTIVE selection, so the auto-picked busiest edge is
                      // visibly the one the detail pane is describing
                      const isSel = i === (selIdx ?? busyIdx);
                      return (
                        <tr key={i} onClick={() => setSelIdx(i)} style={{ cursor: "pointer", background: isSel ? t.accentBg : undefined }}>
                          <td style={mono}>{f.dev}</td>
                          <td style={mono}>{f.iface}</td>
                          <td className="num">{speedLabel(f.speedMbps)}</td>
                          {/* notPresent(6) is an EMPTY SFP CAGE, not a down port — calling it "down"
                              invents a fault on 28 interfaces here. See IF_DOWN in lib/netflow.ts. */}
                          <td className="num" style={{ color: f.oper === 1 ? t.up : IF_DOWN.has(f.oper) ? t.down : t.subtle, fontWeight: 700 }}>
                            {f.oper === 1 ? "up" : IF_DOWN.has(f.oper) ? "down" : f.oper === 6 ? "absent" : "—"}</td>
                          <td className="num" style={{ color: p.dirIn }}>{fmtMbps(f.inMbps)}</td>
                          <td className="num" style={{ color: p.dirOut }}>{fmtMbps(f.outMbps)}</td>
                          <td className="num" style={{ fontWeight: 700, color: uc }}>{f.util.toFixed(0)}%</td>
                          <td className="num" style={{ color: t.subtle }}>{fmtMbps(f.p95)}</td>
                          <td className="num" style={{ fontWeight: 700, color: pc }}>{f.p95Util == null ? "—" : `${f.p95Util.toFixed(0)}%`}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
        </div>

        {/* SELECTED EDGE — key data */}
        <div className="span4">
          <Panel>
            {cur ? (
              <>
                <Flex justifyContent="space-between" alignItems="flex-start" gap={12} style={{ marginBottom: 12 }}>
                  <div><div style={{ ...mono, fontSize: 16, fontWeight: 700 }}>{cur.dev} · {cur.iface}</div>
                    <div style={{ fontSize: 12.5, color: t.subtle }}>{cur.speedMbps >= 1000 ? cur.speedMbps / 1000 + " Gbps" : cur.speedMbps + " Mbps"} · oper {cur.oper === 1 ? "up" : "down"} · ifIndex {cur.ifIndex}</div></div>
                  <Pill status={statusOf(cur.util)}>{cur.util.toFixed(0)}% util</Pill>
                </Flex>
                <div className="iosplit" style={{ marginBottom: 12 }}>
                  <div className="iobox" style={{ borderLeft: `3px solid ${p.dirIn}` }}><DirChip dir="in" label="↓ Inbound" /><div style={{ fontSize: 21, fontWeight: 700, marginTop: 2 }}>{fmtMbps(cur.inMbps)}</div></div>
                  <div className="iobox" style={{ borderLeft: `3px solid ${p.dirOut}` }}><DirChip dir="out" label="↑ Outbound" /><div style={{ fontSize: 21, fontWeight: 700, marginTop: 2 }}>{fmtMbps(cur.outMbps)}</div></div>
                </div>
                <div style={{ marginBottom: 14 }}>
                  <MirrorChart data={{ t: cur.inn.map((_, i, a) => relLabel(a.length - 1 - i)), inn: cur.inn, out: cur.out }} height={150} />
                  <Flex justifyContent="space-between" style={{ ...mono, fontSize: 11.5, color: t.subtle, marginTop: 6 }}>
                    <span>peak <span style={{ color: p.dirIn, fontWeight: 700 }}>↓ {fmtMbps(peakIn)}</span></span>
                    <span>avg <span style={{ color: p.dirIn, fontWeight: 700 }}>↓ {fmtMbps(avgIn)}</span></span>
                  </Flex>
                  <Flex justifyContent="space-between" style={{ ...mono, fontSize: 11.5, color: t.subtle, marginTop: 3 }}>
                    <span>peak <span style={{ color: p.dirOut, fontWeight: 700 }}>↑ {fmtMbps(peakOut)}</span></span>
                    <span>avg <span style={{ color: p.dirOut, fontWeight: 700 }}>↑ {fmtMbps(avgOut)}</span></span>
                  </Flex>
                </div>
                <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
                  <div className="panelt">Flows on this edge <span style={{ color: t.subtle, fontWeight: 500, textTransform: "none" }}>· true per-interface</span></div>
                  <Tag>live</Tag>
                </Flex>
                {ifFlows.isLoading ? <Loading /> : ifFlows.hasIfData ? (
                  <div style={{ overflowX: "auto" }}>
                    <table className="data">
                      <thead><tr><th>Source</th><th>Destination</th><th>App</th><th className="num">Dir</th><th className="num">Bytes</th></tr></thead>
                      <tbody>
                        {ifFlows.convos.map((c, i) => (
                          <tr key={i}>
                            <td style={mono}>{c.src}</td><td style={mono}>{c.dst}</td>
                            <td><span style={{ width: 10, height: 10, borderRadius: 3, display: "inline-block", background: p.c[c.hue], marginRight: 6, verticalAlign: "middle" }} /><span style={mono}>{c.port}</span></td>
                            <td className="num" style={{ color: c.dir === "ingress" ? p.dirIn : p.dirOut, fontWeight: 700 }}>{c.dir === "ingress" ? "↓ in" : "↑ out"}</td>
                            <td className="num" style={{ fontWeight: 700 }}>{fmtB(c.bytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <span style={{ color: t.subtle, fontSize: 13 }}>No flows tagged to ifIndex {cur.ifIndex} in this window — flows are attributed only to the real uplinks (ifIndex 25–29).</span>}
              </>
            ) : <Loading />}
          </Panel>
        </div>
      </div>
      {/* egress sankey + ASN */}
      <div className="dash eq rowgap">
        <div className="span8">
          <Panel><Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 12 }}><div><div className="panelt">Egress flow — source subnet → destination</div><div className="panelsub">network-wide outbound · from the flow feed</div></div><Tag>live</Tag></Flex>
            {sankey.isLoading ? <Loading /> : sankey.data.links.length ? (
              /* Clicking a destination hands off to Investigate with that party preselected —
                 the chart is where the operator has already spotted the thing they want to chase,
                 so it should be the way in, not a dead end they have to re-find by hand. */
              <Sankey links={sankey.data.links} srcMeta={sankey.data.srcMeta} dstMeta={sankey.data.dstMeta}
                onSelectDst={(d) => { const m = sankey.data.dstMeta[d]; if (m?.rawOrg) nav(`/investigate?org=${encodeURIComponent(m.rawOrg)}`); }} />
            ) : <div style={{ color: t.subtle, fontSize: 13, padding: 12 }}>No egress (external) flows in window.</div>}
            <div style={{ color: t.subtle, fontSize: 12, paddingTop: 8 }}>Click a destination to trace it inward →</div></Panel>
        </div>
        <div className="span4">
          <Panel><div className="panelt">Egress by ASN</div><div className="panelsub">peering & transit · resolved at ingest; unresolved destinations fall back to /24</div>
            <div style={{ marginTop: 10 }}>{asn.isLoading ? <Loading /> : asn.rows.length ? <TalkerBars rows={asn.rows} perColorDot /> : <span style={{ color: t.subtle, fontSize: 13 }}>No egress traffic in window.</span>}</div>
            {!asn.isLoading && asn.rows.length > 0 && <div style={{ marginTop: 12, fontSize: 12.5, color: t.subtle }}>Egress concentrated in <span style={{ ...mono, color: t.ink }}>{asn.rows[0]?.sub}</span> {asn.rows[0]?.name} — a peering / local-cache candidate.</div>}</Panel>
        </div>
      </div>
    </div>
  );
}

const Loading = () => <span style={{ color: t.subtle, fontSize: 14 }}>Loading…</span>;
const fmtB = (n: number) => (n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : n >= 1e6 ? (n / 1e6).toFixed(0) + " MB" : (n / 1e3).toFixed(0) + " KB");

export const NetFlow = () => {
  const [view, setView] = React.useState("A");
  // drive the query window from the app-wide look-back picker; the keyed subtree below re-queries on change
  const { tf } = useTimeframe();
  setNetflowWindow(tf);
  // NetFlow ingest mode (set on the Configuration track): loads the persisted setting into the
  // module vars flowMult() reads, and re-keys the data subtree so volumes re-extrapolate on change.
  const { mode, rate } = useNetflowMode();
  return (
    <div className="nf-section">
      <style>{NF_STYLE}</style>
      <Flex flexDirection="column" gap={0}>
        <Flex justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={12} style={{ padding: "16px 20px", borderBottom: `1px solid ${t.border}` }}>
          <Flex flexDirection="column" gap={2}>
            <Heading level={3}>NetFlow</Heading>
            <Flex gap={8} alignItems="center" style={{ fontSize: 13, color: t.subtle }}>
              interface-level, directional flow visibility <Tag>live</Tag>
              {mode === "sampled" && (
                <span title={`Sampled export — volumes extrapolated ×${rate}`}
                  style={{ fontSize: 11.5, fontWeight: 700, padding: "2px 8px", borderRadius: 6, background: t.cardSubtle, border: `1px solid ${t.border}`, color: t.warn }}>
                  {`Sampled 1:${rate} · ×${rate}`}
                </span>
              )}
            </Flex>
          </Flex>
          <Flex gap={12} alignItems="center" flexWrap="wrap">
            <Segmented value={view} onChange={setView} options={[{ value: "A", label: "Dashboard" }, { value: "B", label: "Drill-down" }, { value: "C", label: "Edge" }]} />
          </Flex>
        </Flex>
        <div key={`${tf}:${mode}:${rate}`}>{view === "A" ? <ApproachA /> : view === "B" ? <ApproachB /> : <ApproachC />}</div>
      </Flex>
    </div>
  );
};
