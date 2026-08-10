import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Text } from "@dynatrace/strato-components/typography";
import { t } from "../theme";
import { useNetflowMode, type NetflowMode } from "../lib/netflowMode";
import { generateCollectorYaml, collectorFilename } from "../lib/netflowCollectorConfig";

// NetFlow ingest-mode picker on the Configuration track. The app's mode MUST match how the collector
// actually exports — so this is a STAGED apply: picking a radio only previews that mode's config; the
// NetFlow views don't change until the user deploys the config and explicitly acknowledges + Applies.
const MODES: { id: NetflowMode; label: string; blurb: string }[] = [
  { id: "full", label: "Full", blurb: "Every flow. Highest fidelity, full per-interface drill-down. The default." },
  { id: "sampled", label: "Sampled", blurb: "Keep 1-in-N — for very high-rate links. Volumes extrapolated by each exporter's stamped rate (manual ×N fallback)." },
];
const labelOf = (m: NetflowMode) => MODES.find((x) => x.id === m)?.label ?? m;

export function NetflowModeSetup() {
  const { mode: applied, rate: appliedRate, loading, update } = useNetflowMode();
  const [pendMode, setPendMode] = React.useState<NetflowMode>(applied);
  const [rateInput, setRateInput] = React.useState(String(appliedRate));
  const [ack, setAck] = React.useState(false);

  // sync the staged selection to the applied setting whenever it changes (initial load, or after Apply)
  React.useEffect(() => { setPendMode(applied); setRateInput(String(appliedRate)); setAck(false); }, [applied, appliedRate]);

  const rateNum = Math.max(2, Math.round(Number(rateInput) || 100));
  const dirty = pendMode !== applied || (pendMode === "sampled" && rateNum !== appliedRate);
  const yaml = generateCollectorYaml(pendMode, rateNum);
  const fname = collectorFilename(pendMode);

  const apply = () => update({ mode: pendMode, rate: rateNum }); // effect above resets pend + ack when applied changes
  const cancel = () => { setPendMode(applied); setRateInput(String(appliedRate)); setAck(false); };

  const download = () => {
    try {
      const blob = new Blob([yaml], { type: "text/yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = fname;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* download blocked (iframe sandbox) — Copy still works */ }
  };
  const copy = () => { try { navigator.clipboard?.writeText(yaml); } catch { /* clipboard blocked */ } };

  const btn: React.CSSProperties = { borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer", border: 0 };

  return (
    <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
      <Flex justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={8} style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.07em", textTransform: "uppercase", color: t.accent }}>Collector config · ingest mode</div>
        <span style={{ fontSize: 12, color: t.subtle }}>Active: <b style={{ color: t.ink }}>{labelOf(applied)}{applied === "sampled" ? ` · 1:${appliedRate}` : ""}</b></span>
      </Flex>
      <Text style={{ color: t.subtle, fontSize: 13.5, marginBottom: 12, display: "block", maxWidth: 720 }}>
        This must match how your collector actually exports. Selecting a mode only <b style={{ color: t.ink }}>previews</b> its
        config — it doesn't change the NetFlow views until you deploy that config and <b style={{ color: t.ink }}>Apply</b>.
      </Text>

      {/* mode picker — stages a pending selection, does NOT apply */}
      <Flex gap={8} flexWrap="wrap" style={{ marginBottom: 12 }}>
        {MODES.map((mo) => {
          const sel = pendMode === mo.id;
          const active = applied === mo.id;
          return (
            <div key={mo.id} onClick={() => setPendMode(mo.id)} role="button" tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setPendMode(mo.id); } }}
              style={{ flex: "1 1 205px", minWidth: 205, cursor: "pointer", borderRadius: 10, padding: "12px 14px",
                border: `1.5px solid ${sel ? t.accent : t.border}`, background: sel ? t.accentBg : t.cardSubtle }}>
              <Flex alignItems="center" gap={8} style={{ marginBottom: 4 }}>
                <span style={{ width: 14, height: 14, borderRadius: "50%", border: `2px solid ${sel ? t.accent : t.subtle}`, background: sel ? t.accent : "transparent", flex: "none" }} />
                <span style={{ fontWeight: 700, fontSize: 14, color: t.ink }}>{mo.label}</span>
                {active && <span style={{ fontSize: 10.5, fontWeight: 700, color: t.up, border: `1px solid ${t.up}`, borderRadius: 5, padding: "0 5px" }}>ACTIVE</span>}
              </Flex>
              <div style={{ fontSize: 12, color: t.subtle, lineHeight: 1.4 }}>{mo.blurb}</div>
            </div>
          );
        })}
      </Flex>

      {/* fallback rate — only when staging sampled */}
      {pendMode === "sampled" && (
        <Flex alignItems="center" gap={8} style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 13, color: t.ink, fontWeight: 600 }}>Fallback rate — 1 in</span>
          <input type="number" min={2} value={rateInput}
            onChange={(e) => setRateInput(e.target.value)}
            style={{ width: 92, background: t.card, color: t.ink, border: `1px solid ${t.border}`, borderRadius: 6, padding: "6px 9px", fontSize: 14, fontFamily: "monospace" }} />
          <span style={{ fontSize: 12.5, color: t.subtle }}>used only for flows with no exporter-stamped rate</span>
        </Flex>
      )}

      {/* live YAML preview — reflects the STAGED mode */}
      <div style={{ border: `1px solid ${t.border}`, borderRadius: 8, overflow: "hidden", marginBottom: 12 }}>
        <Flex justifyContent="space-between" alignItems="center" style={{ padding: "6px 12px", background: t.cardSubtle, borderBottom: `1px solid ${t.border}` }}>
          <span style={{ fontFamily: "monospace", fontSize: 12, color: t.subtle }}>{fname}{dirty ? " · staged" : ""}</span>
          <button onClick={copy} style={{ ...btn, padding: "3px 10px", fontSize: 12, background: "none", color: t.accent }}>Copy</button>
        </Flex>
        <pre style={{ margin: 0, padding: "12px 14px", overflowX: "auto", maxHeight: 240, fontSize: 11.5, lineHeight: 1.5, fontFamily: "monospace", color: t.ink, background: t.card }}>{yaml}</pre>
      </div>

      <Flex gap={12} flexWrap="wrap" alignItems="center" style={{ marginBottom: dirty ? 14 : 0 }}>
        <button onClick={download} style={{ ...btn, background: t.accent, color: "#fff" }}>⤓ Download {fname}</button>
        <Text style={{ fontSize: 12, color: t.subtle, fontStyle: "italic" }}>Deploy this to your collector first, then Apply below.</Text>
      </Flex>

      {/* apply gate — appears only when the staged mode differs from what's live */}
      {dirty && (
        <div style={{ borderRadius: 10, border: `1px solid ${t.warn}`, background: t.cardSubtle, borderLeft: `3px solid ${t.warn}`, padding: "12px 14px" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: t.ink, marginBottom: 4 }}>Apply {labelOf(applied)} → {labelOf(pendMode)}?</div>
          <Text style={{ fontSize: 12.5, color: t.subtle, display: "block", marginBottom: 10 }}>
            {pendMode === "sampled"
              ? <>This makes the NetFlow views <b style={{ color: t.ink }}>multiply every volume by the sampling rate</b>. Apply only after your collector is actually sampling — otherwise volumes read inflated ×{rateNum}.</>
              : <>This <b style={{ color: t.ink }}>stops extrapolating volumes</b> (Full = every flow, no scaling). Apply only after your collector has stopped sampling.</>}
          </Text>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: t.ink, cursor: "pointer", marginBottom: 12 }}>
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>I've updated the collector to <b style={{ color: t.ink }}>{labelOf(pendMode)}</b> mode</span>
          </label>
          <Flex gap={8} alignItems="center">
            <button onClick={apply} disabled={!ack || loading}
              style={{ ...btn, background: ack ? t.warn : t.cardSubtle, color: ack ? "#fff" : t.subtle, cursor: ack ? "pointer" : "not-allowed" }}>Apply {labelOf(pendMode)}</button>
            <button onClick={cancel} style={{ ...btn, background: "none", color: t.subtle, border: `1px solid ${t.border}` }}>Cancel</button>
          </Flex>
        </div>
      )}
    </div>
  );
}
