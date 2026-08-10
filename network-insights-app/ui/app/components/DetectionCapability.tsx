import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text } from "@dynatrace/strato-components/typography";
import { t } from "../theme";
import { Panel, Tag } from "./ui";
import { DETECTOR_DEFS } from "../lib/detectors";
import { createDetectors } from "../lib/provision";

// Per-signature UI copy. The unified Network RCA workflow now owns ALL state detection (device,
// interface up/down, power), so those detectors were retired. Only the error-rate signal remains —
// a thing a state model can't see.
const META: Record<string, { blurb: string; hint: string; defaultOn: boolean }> = {
  "bad-link": {
    blurb: "Dirty optic / CRC error storm — a healthy, up interface degrading before it fully fails.",
    hint: "The one signal a state model can't see (errors, not up/down). Needs the extension emitting cno.if.in_errors.count.",
    defaultOn: false,
  },
};

export function DetectionCapability() {
  const [sel, setSel] = React.useState<Set<string>>(
    new Set(DETECTOR_DEFS.filter((d) => META[d.signature]?.defaultOn).map((d) => d.signature)),
  );
  const [busy, setBusy] = React.useState(false);
  const [result, setResult] = React.useState<{ tone: "ok" | "err"; msg: string } | null>(null);

  const toggle = (s: string) =>
    setSel((prev) => { const n = new Set(prev); if (n.has(s)) n.delete(s); else n.add(s); return n; });
  const chosen = DETECTOR_DEFS.filter((d) => sel.has(d.signature));

  const install = async () => {
    if (!chosen.length) return;
    setBusy(true); setResult(null);
    const r = await createDetectors(chosen.map((d) => d.payload));
    setBusy(false);
    if (!r.ok) { setResult({ tone: "err", msg: r.error || "Install failed." }); return; }
    const parts: string[] = [];
    if (r.created) parts.push(`created ${r.created} (${(r.createdTitles || []).map((x) => x.replace("CNO - ", "")).join(", ")})`);
    if (r.skipped) parts.push(`${r.skipped} already present`);
    setResult({ tone: "ok", msg: parts.join(" · ") || "Nothing to do." });
  };

  const btn: React.CSSProperties = { borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer", border: 0 };

  return (
    <Panel>
      <Flex flexDirection="column" gap={16}>
        <Flex gap={12} alignItems="flex-start" justifyContent="space-between">
          <Flex gap={12} alignItems="flex-start">
            <span style={{ width: 44, height: 44, borderRadius: 11, display: "grid", placeItems: "center", background: t.accent, color: "#fff", fontSize: 22, flex: "none" }}>◈</span>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: t.accent }}>Detection · granularity</div>
              <Heading level={3}>Alert detectors</Heading>
            </div>
          </Flex>
          <Tag kind="ext">optional</Tag>
        </Flex>

        <Text style={{ color: t.subtle, fontSize: 14, maxWidth: 680 }}>
          The unified <b style={{ color: t.ink }}>Network RCA</b> workflow now handles all state — device, site, power,
          and interface up/down — so those detectors are retired. What remains is the one signal a state model can't
          see: interface <b style={{ color: t.ink }}>error rate</b>. <b style={{ color: t.ink }}>Optional</b>.
        </Text>

        <Flex flexDirection="column" gap={8}>
          {DETECTOR_DEFS.map((d) => {
            const m = META[d.signature] || { blurb: "", hint: "", defaultOn: false };
            const on = sel.has(d.signature);
            return (
              <button key={d.signature} onClick={() => toggle(d.signature)}
                style={{ textAlign: "left", display: "flex", gap: 12, alignItems: "flex-start", background: on ? t.emph : t.cardSubtle, border: `1px solid ${on ? t.accent : t.border}`, borderRadius: 8, padding: "11px 14px", cursor: "pointer" }}>
                <span style={{ width: 18, height: 18, borderRadius: 5, border: `2px solid ${on ? t.accent : t.subtle}`, background: on ? t.accent : "transparent", color: "#fff", fontSize: 12, fontWeight: 700, display: "grid", placeItems: "center", flex: "none", marginTop: 1 }}>{on ? "✓" : ""}</span>
                <div style={{ flex: 1 }}>
                  <Flex gap={8} alignItems="baseline">
                    <span style={{ fontWeight: 650, fontSize: 14, color: t.ink }}>{d.title.replace("CNO - ", "")}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: t.accent, background: t.accentBg, borderRadius: 5, padding: "1px 6px" }}>{d.signature}</span>
                  </Flex>
                  <div style={{ fontSize: 13, color: t.subtle, marginTop: 3 }}>{m.blurb}</div>
                  <div style={{ fontSize: 12, color: t.subtle, marginTop: 3, fontStyle: "italic" }}>{m.hint}</div>
                </div>
              </button>
            );
          })}
        </Flex>

        <Flex gap={12} alignItems="center" flexWrap="wrap">
          <button disabled={busy || !chosen.length} onClick={install}
            style={{ ...btn, background: chosen.length ? t.accent : t.cardSubtle, color: chosen.length ? "#fff" : t.subtle, cursor: chosen.length && !busy ? "pointer" : "not-allowed" }}>
            {busy ? "Installing…" : `Install selected (${chosen.length})`}
          </button>
          {result ? <span style={{ fontSize: 13, color: result.tone === "ok" ? t.up : t.down }}>{result.tone === "ok" ? "✓ " : "✕ "}{result.msg}</span> : null}
        </Flex>

        <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 14 }}>
          <Text style={{ fontSize: 13, color: t.subtle }}>
            <b style={{ color: t.ink }}>Detectors vs the workflow.</b> The workflow owns state RCA (device / interface /
            power), consolidated and root-caused. Detectors remain only for signals a state model can't see — metric
            thresholds (errors), Davis baselines, sub-minute speed. Run the workflow alone; add this for error visibility.
          </Text>
        </div>
      </Flex>
    </Panel>
  );
}
