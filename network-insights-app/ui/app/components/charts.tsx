import React from "react";
import { t, mono } from "../theme";

/* ============================================================================
   NetFlow chart primitives — ported faithfully from docs/mockups/netflow-mockup.html
   (renderMirror / renderBars / renderShare / miniIO / renderSankey). Structural
   colors come from the Strato theme tokens (t.*, theme-aware); the directional +
   application chart palette is reproduced from the mockup and validated with the
   dataviz skill on the app's navy surface.
   ============================================================================ */

// ---- validated chart palette (dark default / light override), keyed like the mockup ----
type Palette = {
  dirIn: string; dirOut: string; dirInSoft: string; dirOutSoft: string;
  grid: string; axis: string;
  c: Record<string, string>; // port -> hue
};
const PALETTE_DARK: Palette = {
  dirIn: "#25a0b0", dirOut: "#8b79e6",
  dirInSoft: "rgba(37,160,176,0.16)", dirOutSoft: "rgba(139,121,230,0.18)",
  grid: "#2b2b42", axis: "#3b3b52",
  c: { blue: "#3987e5", green: "#008300", magenta: "#d55181", yellow: "#c98500", aqua: "#199e70", orange: "#d95926", red: "#e66767", other: "#8a8f98" },
};
const PALETTE_LIGHT: Palette = {
  dirIn: "#2f8f9e", dirOut: "#6a5ad0",
  dirInSoft: "rgba(47,143,158,0.14)", dirOutSoft: "rgba(106,90,208,0.14)",
  grid: "#e6e6ee", axis: "#dadbe4",
  c: { blue: "#2a78d6", green: "#006b00", magenta: "#c33f70", yellow: "#9a6600", aqua: "#137a56", orange: "#c24a1f", red: "#cf4747", other: "#6c7079" },
};

export function useIsDark(): boolean {
  const [dark, setDark] = React.useState<boolean>(() => {
    try { return window.matchMedia("(prefers-color-scheme: dark)").matches; } catch { return true; }
  });
  React.useEffect(() => {
    let mq: MediaQueryList;
    try { mq = window.matchMedia("(prefers-color-scheme: dark)"); } catch { return; }
    const on = () => setDark(mq.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);
  return dark;
}
export const usePalette = (): Palette => (useIsDark() ? PALETTE_DARK : PALETTE_LIGHT);

// well-known port -> {label, hue-key}
export const PORTS: Record<string, { label: string; hue: string }> = {
  "443": { label: "HTTPS", hue: "blue" }, "8443": { label: "HTTPS-alt", hue: "yellow" },
  "3306": { label: "MySQL", hue: "orange" }, "3389": { label: "RDP", hue: "magenta" },
  "22": { label: "SSH", hue: "green" }, "445": { label: "SMB", hue: "aqua" },
  "53": { label: "DNS", hue: "red" }, "80": { label: "HTTP", hue: "blue" },
  "123": { label: "NTP", hue: "other" }, "0": { label: "ICMP", hue: "other" },
};
export const appOf = (port: string | number) => PORTS[String(port)] || { label: String(port), hue: "other" };

// ---- formatters ----
// null means the interface reports no octet counters at all — NOT that it is idle. Printing
// "0 Mbps" there states a measurement that was never taken; 9 up-and-passing-traffic interfaces
// on the reference fleet have no counters. Render an em dash and let the operator ask why.
export const fmtMbps = (v: number | null | undefined) =>
  v == null ? "—" : v >= 1000 ? (v / 1000).toFixed(2) + " Gbps" : Math.round(v) + " Mbps";
export const fmtTick = (v: number) => (v >= 1000 ? Math.round(v / 100) / 10 + "G" : Math.round(v) + "M");
export function fmtBytes(n: number): string {
  if (n >= 1e12) return (n / 1e12).toFixed(2) + " TB";
  if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(0) + " MB";
  if (n >= 1e3) return (n / 1e3).toFixed(0) + " KB";
  return Math.round(n) + " B";
}
export function niceCeil(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p, steps = [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10];
  for (const s of steps) if (m <= s) return s * p;
  return 10 * p;
}

// ---- color math (for ordinal share steps) ----
function hexToRgb(h: string) { h = h.replace("#", ""); if (h.length === 3) h = h.split("").map((c) => c + c).join(""); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; }
function rgbToHex(r: number[]) { return "#" + r.map((v) => { v = Math.max(0, Math.min(255, Math.round(v))); return v.toString(16).padStart(2, "0"); }).join(""); }
function shade(hex: string, f: number) { const c = hexToRgb(hex); if (f >= 1) return rgbToHex(c.map((v) => v + (255 - v) * (f - 1))); return rgbToHex(c.map((v) => v * f)); }
export function stepColor(hex: string, i: number, n: number) { const tt = n <= 1 ? 0.5 : i / (n - 1); return shade(hex, 1.22 - 0.6 * tt); }

/* ---- shared lightweight tooltip (per-chart, cursor-tracked) ---- */
function Tip(props: { html: React.ReactNode; x: number; y: number; show: boolean }) {
  if (!props.show) return null;
  return (
    <div style={{
      position: "fixed", zIndex: 50, pointerEvents: "none", left: props.x + 14, top: props.y + 14,
      background: t.emph, color: t.ink, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 10px",
      fontSize: 12.5, boxShadow: "0 8px 28px rgba(0,0,0,0.28)", maxWidth: 240,
    }}>{props.html}</div>
  );
}

/* ============ MIRRORED DIRECTIONAL AREA ============ */
export type MirrorData = { t: string[]; inn: number[]; out: number[] };
export function MirrorChart({ data, height = 250 }: { data: MirrorData; height?: number }) {
  const p = usePalette();
  const [hover, setHover] = React.useState<{ i: number; x: number; y: number } | null>(null);
  const svgRef = React.useRef<SVGSVGElement>(null);
  const wrapRef = React.useRef<HTMLDivElement>(null);
  // The height is LOCKED (a fixed pixel value). We measure only the WIDTH so the viewBox
  // matches the real box 1:1 (labels/marks never stretch) — and because height never feeds
  // back into layout, there is no measure→grow→measure loop.
  const [w, setW] = React.useState(820);
  React.useLayoutEffect(() => {
    const el = wrapRef.current; if (!el) return;
    const measure = () => { const cw = Math.round(el.clientWidth) || 820; setW((prev) => (prev === cw ? prev : cw)); };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const W = w, H = height, padL = 52, padR = 16, padT = 16, padB = 26;
  const n = data.inn.length || 1, plotW = W - padL - padR, plotH = H - padT - padB;
  const inMax = Math.max(1, ...data.inn), outMax = Math.max(1, ...data.out);
  const inTop = niceCeil(inMax * 1.02), outTop = niceCeil(outMax * 1.04);
  const scale = plotH / (inTop + outTop), zeroY = padT + inTop * scale;
  const X = (i: number) => padL + (n <= 1 ? 0 : (i / (n - 1)) * plotW);
  const YIN = (v: number) => zeroY - v * scale;
  const YOUT = (v: number) => zeroY + v * scale;
  const areaPath = (arr: number[], yfn: (v: number) => number) => { let d = `M ${X(0)} ${zeroY}`; arr.forEach((v, i) => (d += ` L ${X(i).toFixed(1)} ${yfn(v).toFixed(1)}`)); return d + ` L ${X(n - 1)} ${zeroY} Z`; };
  const linePath = (arr: number[], yfn: (v: number) => number) => { let d = `M ${X(0)} ${yfn(arr[0] ?? 0).toFixed(1)}`; arr.forEach((v, i) => { if (i) d += ` L ${X(i).toFixed(1)} ${yfn(v).toFixed(1)}`; }); return d; };

  const onMove = (e: React.MouseEvent) => {
    const svg = svgRef.current; if (!svg) return;
    const r = svg.getBoundingClientRect(), sx = W / r.width;
    const xv = (e.clientX - r.left) * sx;
    let i = Math.round(((xv - padL) / plotW) * (n - 1)); i = Math.max(0, Math.min(n - 1, i));
    setHover({ i, x: e.clientX, y: e.clientY });
  };
  const hi = hover?.i ?? -1;

  return (
    <div ref={wrapRef} style={{ position: "relative", width: "100%" }}>
      <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" role="img"
        aria-label="Inbound vs outbound throughput, mirrored on zero"
        onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        {/* gridlines + top tick labels */}
        {[YIN(inTop / 2), YIN(inTop), YOUT(outTop / 2), YOUT(outTop)].map((y, k) => (
          <line key={k} x1={padL} y1={y.toFixed(1)} x2={W - padR} y2={y.toFixed(1)} stroke={p.grid} strokeWidth={1} />
        ))}
        <text x={padL - 8} y={YIN(inTop) + 3} textAnchor="end" style={{ ...mono, fill: t.subtle, fontSize: 11 }}>{fmtTick(inTop)}</text>
        <text x={padL - 8} y={YOUT(outTop) + 3} textAnchor="end" style={{ ...mono, fill: t.subtle, fontSize: 11 }}>{fmtTick(outTop)}</text>
        {/* areas + lines */}
        <path d={areaPath(data.inn, YIN)} fill={p.dirInSoft} />
        <path d={areaPath(data.out, YOUT)} fill={p.dirOutSoft} />
        <path d={linePath(data.inn, YIN)} fill="none" stroke={p.dirIn} strokeWidth={2} strokeLinejoin="round" />
        <path d={linePath(data.out, YOUT)} fill="none" stroke={p.dirOut} strokeWidth={2} strokeLinejoin="round" />
        {/* zero baseline */}
        <line x1={padL} y1={zeroY} x2={W - padR} y2={zeroY} stroke={p.axis} strokeWidth={1.5} />
        <text x={padL - 8} y={zeroY + 3} textAnchor="end" style={{ ...mono, fill: t.subtle, fontSize: 11 }}>0</text>
        {/* endpoint dots + direct labels */}
        <circle cx={X(n - 1)} cy={YIN(data.inn[n - 1] ?? 0)} r={4} fill={p.dirIn} stroke={t.card} strokeWidth={2} />
        <circle cx={X(n - 1)} cy={YOUT(data.out[n - 1] ?? 0)} r={4} fill={p.dirOut} stroke={t.card} strokeWidth={2} />
        <text x={X(n - 1) - 8} y={YIN(data.inn[n - 1] ?? 0) - 8} textAnchor="end" style={{ fill: p.dirIn, fontSize: 12, fontWeight: 700 }}>↓ {fmtMbps(data.inn[n - 1] ?? 0)}</text>
        <text x={X(n - 1) - 8} y={YOUT(data.out[n - 1] ?? 0) + 16} textAnchor="end" style={{ fill: p.dirOut, fontSize: 12, fontWeight: 700 }}>↑ {fmtMbps(data.out[n - 1] ?? 0)}</text>
        {/* x ticks (start / mid) */}
        {[0, Math.floor(n / 2)].map((i) => (
          <text key={i} x={X(i)} y={H - 8} textAnchor={i === 0 ? "start" : "middle"} style={{ ...mono, fill: t.subtle, fontSize: 11 }}>{data.t[i]}</text>
        ))}
        {/* hover crosshair */}
        {hi >= 0 && (
          <g>
            <line x1={X(hi)} y1={padT} x2={X(hi)} y2={padT + plotH} stroke={t.accent} strokeWidth={1} opacity={0.6} />
            <circle cx={X(hi)} cy={YIN(data.inn[hi])} r={3.5} fill={p.dirIn} stroke={t.card} strokeWidth={2} />
            <circle cx={X(hi)} cy={YOUT(data.out[hi])} r={3.5} fill={p.dirOut} stroke={t.card} strokeWidth={2} />
          </g>
        )}
      </svg>
      <Tip show={hi >= 0} x={hover?.x ?? 0} y={hover?.y ?? 0} html={hi >= 0 ? (
        <div>
          <div style={{ ...mono, fontSize: 11.5, color: t.subtle, marginBottom: 4 }}>{data.t[hi]}</div>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}><span style={{ color: p.dirIn }}>↓ Inbound</span><span style={{ ...mono, fontWeight: 600 }}>{fmtMbps(data.inn[hi])}</span></div>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}><span style={{ color: p.dirOut }}>↑ Outbound</span><span style={{ ...mono, fontWeight: 600 }}>{fmtMbps(data.out[hi])}</span></div>
        </div>
      ) : null} />
    </div>
  );
}

/* ============ HORIZONTAL TALKER / APP BARS ============ */
export type BarRow = { name: string; sub?: string; v: number; label: string; unit?: string; dot?: string; tip?: string };
export function TalkerBars({ rows, hue = "dirIn", perColorDot = false }: { rows: BarRow[]; hue?: "dirIn" | "dirOut" | string; perColorDot?: boolean }) {
  const p = usePalette();
  const [tip, setTip] = React.useState<{ html: React.ReactNode; x: number; y: number } | null>(null);
  const max = Math.max(1, ...rows.map((r) => r.v));
  const fill = hue === "dirIn" ? p.dirIn : hue === "dirOut" ? p.dirOut : p.c[hue] || p.c.blue;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      {rows.map((r, i) => {
        const pct = Math.max(3, (r.v / max) * 100);
        const dotColor = r.dot ? p.c[r.dot] || r.dot : null;
        return (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "160px 1fr 78px", alignItems: "center", gap: 10, padding: "5px 6px", borderRadius: 6 }}
            onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, html: <div><div style={{ ...mono, fontSize: 11.5, color: t.subtle, marginBottom: 4 }}>{r.tip || r.name}</div><div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}><span style={{ color: t.subtle }}>volume</span><span style={{ ...mono, fontWeight: 600 }}>{r.label}{r.unit ? " " + r.unit : ""}</span></div></div> })}
            onMouseLeave={() => setTip(null)}>
            <div style={{ ...mono, fontSize: 12.5, color: t.ink, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={r.name}>
              {dotColor && <span style={{ width: 10, height: 10, borderRadius: 3, display: "inline-block", background: dotColor, marginRight: 6, verticalAlign: "middle" }} />}
              {r.name}{r.sub && <span style={{ color: t.subtle }}> {r.sub}</span>}
            </div>
            <div style={{ height: 14, borderRadius: 4, background: t.cardSubtle, position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: pct + "%", borderRadius: "3px 4px 4px 3px", background: perColorDot && dotColor ? dotColor : fill }} />
            </div>
            <div style={{ ...mono, textAlign: "right", fontSize: 12.5, fontWeight: 700 }}>{r.label}{r.unit && <span style={{ color: t.subtle, fontWeight: 500, fontSize: 11 }}> {r.unit}</span>}</div>
          </div>
        );
      })}
      <Tip show={!!tip} x={tip?.x ?? 0} y={tip?.y ?? 0} html={tip?.html} />
    </div>
  );
}

/* ============ MINI IN/OUT SPARKLINE ============ */
export function MiniIO({ inn, out, width = 120 }: { inn: number[]; out: number[]; width?: number }) {
  const p = usePalette();
  const W = width, H = 26, n = Math.max(inn.length, out.length) || 1, mid = H / 2;
  const mx = Math.max(1, ...inn, ...out);
  const xp = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * W);
  const yiu = (v: number) => mid - (v / mx) * (mid - 2);
  const yod = (v: number) => mid + (v / mx) * (mid - 2);
  const ln = (arr: number[], f: (v: number) => number) => { let d = `M 0 ${f(arr[0] ?? 0).toFixed(1)}`; arr.forEach((v, i) => { if (i) d += ` L ${xp(i).toFixed(1)} ${f(v).toFixed(1)}`; }); return d; };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} preserveAspectRatio="none" aria-hidden="true">
      <line x1={0} y1={mid} x2={W} y2={mid} stroke={p.axis} strokeWidth={0.75} />
      <path d={ln(inn, yiu)} fill="none" stroke={p.dirIn} strokeWidth={1.5} />
      <path d={ln(out, yod)} fill="none" stroke={p.dirOut} strokeWidth={1.5} />
    </svg>
  );
}

/* ============ COMPOSITION SHARE BAR (ordinal one-hue) ============ */
export type SharePart = { name: string; pct: number; port: string };
export function ShareBar({ parts, hue }: { parts: SharePart[]; hue: "dirIn" | "dirOut" }) {
  const p = usePalette();
  const base = hue === "dirIn" ? p.dirIn : p.dirOut;
  const n = parts.length;
  return (
    <div>
      <div style={{ display: "flex", height: 16, borderRadius: 5, overflow: "hidden", background: t.cardSubtle, gap: 2 }}>
        {parts.map((pt, i) => (
          <span key={i} title={`${pt.name} ${pt.pct}%`} style={{ width: `${pt.pct}%`, background: stepColor(base, i, n) }} />
        ))}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px 16px", marginTop: 10 }}>
        {parts.map((pt, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: t.subtle }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: stepColor(base, i, n) }} />
            <span style={{ ...mono, color: t.ink }}>{pt.port}</span> {pt.name} · {pt.pct}%
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============ SANKEY (source subnet -> destination network) ============ */
export type SankeyLink = { src: string; dst: string; v: number };
// rawOrg is the UNPRETTIFIED organisation string. The node is keyed on the display name,
// but a handoff has to filter Grail on the value actually stored in flow.dst_org.
export type NodeMeta = { label: string; sub?: string; hue?: string; rawOrg?: string };
// onSelectDst makes the destination nodes an ENTRY POINT rather than a picture: click the party
// you care about and the panels below scope to it. That is the outside-in troubleshooting move —
// "we know it involves Amazon, now show me where internally it breaks" — and the chart is where
// an operator has already located the thing they want to chase.
export function Sankey({ links, srcMeta, dstMeta, onSelectDst, selectedDst }: { links: SankeyLink[]; srcMeta: Record<string, NodeMeta>; dstMeta: Record<string, NodeMeta>; onSelectDst?: (dst: string) => void; selectedDst?: string | null }) {
  const p = usePalette();
  const W = 560, H = 300, NODE = 12, GAP = 12;
  const srcTot: Record<string, number> = {}, dstTot: Record<string, number> = {};
  links.forEach((l) => { srcTot[l.src] = (srcTot[l.src] || 0) + l.v; dstTot[l.dst] = (dstTot[l.dst] || 0) + l.v; });
  const srcs = Object.keys(srcTot).sort((a, b) => srcTot[b] - srcTot[a]);
  const dsts = Object.keys(dstTot).sort((a, b) => dstTot[b] - dstTot[a]);
  const grand = Object.values(srcTot).reduce((a, b) => a + b, 0) || 1;
  const scale = (H - GAP * (Math.max(srcs.length, dsts.length) - 1)) / grand;
  const sN: Record<string, { y0: number; h: number }> = {}; let ys = 0;
  srcs.forEach((s) => { const h = srcTot[s] * scale; sN[s] = { y0: ys, h }; ys += h + GAP; });
  const dN: Record<string, { y0: number; h: number }> = {}; let yd = 0;
  dsts.forEach((d) => { const h = dstTot[d] * scale; dN[d] = { y0: yd, h }; yd += h + GAP; });
  const sOff: Record<string, number> = {}; srcs.forEach((s) => (sOff[s] = sN[s].y0));
  const dOff: Record<string, number> = {}; dsts.forEach((d) => (dOff[d] = dN[d].y0));
  const dstIdx: Record<string, number> = {}; dsts.forEach((d, i) => (dstIdx[d] = i));
  const x0 = NODE, x1 = W - NODE, cx = W / 2;
  const order = links.slice().sort((a, b) => (a.src < b.src ? -1 : a.src > b.src ? 1 : 0) || dstTot[b.dst] - dstTot[a.dst]);
  const hueOf = (d: string) => p.c[dstMeta[d]?.hue || ""] || Object.values(p.c)[dstIdx[d] % 8];
  // de-collide labels: nudge each label to keep a minimum vertical gap from the previous
  const LBLH = 26;
  const decollide = (keys: string[], nodes: Record<string, { y0: number; h: number }>) => {
    const out: Record<string, number> = {}; let prev = -Infinity;
    keys.forEach((k) => { let y = nodes[k].y0 + nodes[k].h / 2; if (y < prev + LBLH) y = prev + LBLH; out[k] = y; prev = y; });
    return out;
  };
  const sLabelY = decollide(srcs, sN), dLabelY = decollide(dsts, dN);
  return (
    <svg viewBox={`-150 -10 ${W + 300} ${H + 20}`} width="100%" role="img" aria-label="Egress Sankey, source subnet to destination network">
      {order.map((e, i) => {
        const w = e.v * scale;
        const sy0 = sOff[e.src], sy1 = sy0 + w; sOff[e.src] = sy1;
        const dy0 = dOff[e.dst], dy1 = dy0 + w; dOff[e.dst] = dy1;
        const d = `M ${x0} ${sy0} C ${cx} ${sy0}, ${cx} ${dy0}, ${x1} ${dy0} L ${x1} ${dy1} C ${cx} ${dy1}, ${cx} ${sy1}, ${x0} ${sy1} Z`;
        return <path key={i} d={d} fill={hueOf(e.dst)} opacity={0.4} />;
      })}
      {srcs.map((s) => {
        const cy = sN[s].y0 + sN[s].h / 2, ly = sLabelY[s];
        return (
          <g key={s}>
            <rect x={0} y={sN[s].y0} width={NODE} height={Math.max(1, sN[s].h)} rx={2} style={{ fill: t.subtle }} />
            {Math.abs(ly - cy) > 2 && <line x1={0} y1={cy} x2={-6} y2={ly} stroke={t.border} strokeWidth={1} />}
            <text x={-8} y={ly - 3} textAnchor="end" style={{ ...mono, fill: t.ink, fontSize: 12, fontWeight: 600 }}>{srcMeta[s]?.label || s}</text>
            {srcMeta[s]?.sub && <text x={-8} y={ly + 11} textAnchor="end" style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>{srcMeta[s].sub}</text>}
          </g>
        );
      })}
      {dsts.map((d) => {
        const cy = dN[d].y0 + dN[d].h / 2, ly = dLabelY[d];
        const sel = selectedDst === d;
        const pick = onSelectDst ? () => onSelectDst(sel ? "" : d) : undefined;
        return (
          <g key={d} onClick={pick} style={pick ? { cursor: "pointer" } : undefined}>
            {/* a wide transparent hit area — the 12px node alone is a hostile click target */}
            {pick && <rect x={W - NODE} y={dN[d].y0 - 6} width={230} height={Math.max(14, dN[d].h) + 12} fill="transparent" />}
            <rect x={W - NODE} y={dN[d].y0} width={NODE} height={Math.max(1, dN[d].h)} rx={2} fill={hueOf(d)}
              stroke={sel ? t.ink : undefined} strokeWidth={sel ? 2 : undefined} />
            {Math.abs(ly - cy) > 2 && <line x1={W} y1={cy} x2={W + 6} y2={ly} stroke={t.border} strokeWidth={1} />}
            <text x={W + 8} y={ly - 3} style={{ fill: t.ink, fontSize: 12, fontWeight: sel ? 800 : 600, textDecoration: sel ? "underline" : undefined }}>{dstMeta[d]?.label || d}</text>
            {dstMeta[d]?.sub && <text x={W + 8} y={ly + 11} style={{ ...mono, fill: t.subtle, fontSize: 10.5 }}>{dstMeta[d].sub}</text>}
          </g>
        );
      })}
    </svg>
  );
}
