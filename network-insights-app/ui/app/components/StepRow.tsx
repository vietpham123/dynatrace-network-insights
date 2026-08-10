import React, { useState } from "react";
import { t, mono } from "../theme";

// Shared guided-step row — used by the Configuration tracks AND the Root-cause panel so both
// walk through with the identical expandable "What · How · Done right" design + who-does-it tag.
export type Who = "you" | "netbox" | "auto" | "verify";

// THREE ALTITUDES, NOT ONE LIST. These cards used to flatten "do this now", "here is the evidence
// that this matters", and "here is the day-2 operation" into a single flat sequence — so someone
// installing an ActiveGate for the first time read an API path for an upgrade they would not
// perform for six months, and a measurement from a specific UPS on a specific date, mid-procedure.
//
// The evidence is what makes this guidance credible and none of it is cut. It moves one level
// down: `what`/`how`/`cmd`/`verify` is the execution path, `why` is the reasoning behind it, and
// `phase: "day2"` lifts an operation out of first-run entirely.
export type Detail = { what?: string; how?: string; why?: string; cmd?: string; verify?: string; who: Who };
export type Step = { text: string; key?: boolean; phase?: "day0" | "day2"; d?: Detail };

const WHO: Record<Who, [string, string]> = {
  you: [t.accent, "You do this"],
  netbox: [t.warn, "In NetBox"],
  auto: [t.up, "We automate"],
  verify: [t.subtle, "Verify"],
};

export function WhoTag({ who }: { who: Who }) {
  const [c, label] = WHO[who];
  return <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase", color: c, border: `1px solid ${c}`, borderRadius: 5, padding: "1px 6px", whiteSpace: "nowrap", flex: "none" }}>{label}</span>;
}

export function StepRow(props: { step: Step; n: number }) {
  const { step: s, n } = props;
  const [open, setOpen] = useState(false);
  const [whyOpen, setWhyOpen] = useState(false);
  const d = s.d;
  const expandable = !!d;
  return (
    <div style={{ background: t.cardSubtle, border: `1px solid ${s.key ? t.accent : t.border}`, borderRadius: 8, overflow: "hidden" }}>
      <button
        onClick={() => expandable && setOpen((o) => !o)}
        style={{ width: "100%", textAlign: "left", background: "none", border: 0, cursor: expandable ? "pointer" : "default", padding: "10px 14px", display: "flex", gap: 10, alignItems: "center" }}
      >
        <span style={{ minWidth: 22, height: 22, borderRadius: "50%", background: s.key ? t.accent : t.accentBg, color: s.key ? "#fff" : t.accent, fontSize: 12, fontWeight: 700, display: "grid", placeItems: "center", flex: "none" }}>{n}</span>
        <span style={{ flex: 1, fontSize: 14, fontWeight: s.key ? 650 : 400, color: t.ink }}>{s.text}</span>
        {d ? <WhoTag who={d.who} /> : null}
        {expandable ? <span style={{ color: t.subtle, fontSize: 16, transform: open ? "rotate(90deg)" : "none", transition: "transform .12s", flex: "none" }}>›</span> : null}
      </button>
      {open && d ? (
        <div style={{ padding: "0 14px 14px 46px", display: "flex", flexDirection: "column", gap: 8 }}>
          {d.what ? <div style={{ fontSize: 13, color: t.ink }}><span style={{ fontWeight: 700, color: t.subtle }}>What&nbsp;·&nbsp;</span>{d.what}</div> : null}
          {d.how ? <div style={{ fontSize: 13, color: t.ink }}><span style={{ fontWeight: 700, color: t.subtle }}>How&nbsp;·&nbsp;</span>{d.how}</div> : null}
          {d.cmd ? <pre style={{ ...mono, fontSize: 12, background: t.emph, border: `1px solid ${t.border}`, borderRadius: 6, padding: "10px 12px", margin: 0, overflowX: "auto", color: t.ink, whiteSpace: "pre" }}>{d.cmd}</pre> : null}
          {d.verify ? <div style={{ fontSize: 13, color: t.up }}><span style={{ fontWeight: 700 }}>✓ Done right&nbsp;·&nbsp;</span>{d.verify}</div> : null}
          {/* Second-level disclosure on purpose. Someone executing the step should not have to read
              past a measurement to reach the command, but the measurement is why the step is worded
              the way it is — so it stays one click away rather than being cut or inlined. */}
          {d.why ? (
            <div>
              <button
                onClick={() => setWhyOpen((o) => !o)}
                style={{ background: "none", border: 0, padding: 0, cursor: "pointer", color: t.subtle, fontSize: 12.5, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 5 }}
              >
                <span style={{ transform: whyOpen ? "rotate(90deg)" : "none", transition: "transform .12s" }}>›</span>
                Why this matters
              </button>
              {whyOpen ? (
                <div style={{ fontSize: 12.5, color: t.subtle, lineHeight: 1.55, marginTop: 6, paddingLeft: 11, borderLeft: `2px solid ${t.border}` }}>{d.why}</div>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
