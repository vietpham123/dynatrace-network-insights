import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Text } from "@dynatrace/strato-components/typography";
import { getEnvironmentUrl } from "@dynatrace-sdk/app-environment";
import { t } from "../theme";
import { StepRow, Step } from "./StepRow";
import { NETBOX_APPLY_WORKFLOW } from "../lib/netboxApplyWorkflow";

// Baseline workflow shipped on the NetBox track: NetBox -> Dynatrace provisioning. Download-to-import
// (the app can't install workflows). Only the SAFE, one-way direction is shipped; the reverse
// (write-back into NetBox) is advanced and deliberately not bundled.
const STEPS: Step[] = [
  {
    text: "Download the workflow", d: { who: "you",
      what: "A ready-made NetBox->Dynatrace provisioning workflow (2 tasks, disabled by default) — no need to author it yourself.",
      how: "Click ⤓ Download workflow JSON below." },
  },
  {
    text: "Import it into the Workflows app", key: true, d: { who: "you",
      what: "Dynatrace reserves programmatic workflow install for first-party apps, so you import the JSON once.",
      how: "Workflows app → Import → upload the JSON you just downloaded.",
      verify: "It appears as \"CNO - Apply to Dynatrace (reconcile from NetBox intent)\", disabled." },
  },
  {
    text: "Enable once the bridge is landing data", key: true, d: { who: "you",
      what: "It reconciles against the declared roster in Grail (cno.inv.device) — so the on-prem NetBox→Grail bridge must be running first.",
      how: "When cno.inv.* is flowing, enable the schedule (or run it on demand).",
      verify: "A run makes Dynatrace's monitoring match the NetBox roster — it WRITES DYNATRACE ONLY, never NetBox." },
  },
];

export function NetboxApplyDownload() {
  const download = () => {
    try {
      const blob = new Blob([JSON.stringify(NETBOX_APPLY_WORKFLOW, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "cno-apply-to-dynatrace.json";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* download blocked (iframe sandbox) — fall back to the Workflows link */ }
  };
  const link = (() => { try { return getEnvironmentUrl().replace(/\/$/, "") + "/ui/apps/dynatrace.automations"; } catch { return ""; } })();
  const btn: React.CSSProperties = { textDecoration: "none", borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer", border: 0 };
  const mono: React.CSSProperties = { fontFamily: "monospace", color: t.ink, fontSize: "0.92em" };

  return (
    <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.07em", textTransform: "uppercase", color: t.accent, marginBottom: 6 }}>Baseline workflow · download-to-import</div>
      <Text style={{ color: t.subtle, fontSize: 13.5, marginBottom: 10, display: "block", maxWidth: 680 }}>
        A ready-made <b style={{ color: t.ink }}>NetBox → Dynatrace</b> provisioning workflow: it reads your declared device
        roster and makes Dynatrace's monitoring match, so you don't author it yourself. It <b style={{ color: t.ink }}>writes
        Dynatrace only</b> — it never touches NetBox.
      </Text>
      <div style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 12px", marginBottom: 12 }}>
        <Text style={{ fontSize: 12.5, color: t.subtle }}>
          <b style={{ color: t.ink }}>Prereq 1:</b> the <span style={{ color: t.ink }}>NetBox→Grail</span> source must be
          landing <span style={mono}>cno.inv.*</span> — the workflow reconciles against that declared roster.
          <br />
          <b style={{ color: t.ink }}>Prereq 2:</b> your tenant needs an <b style={{ color: t.ink }}>enabled PRIVATE synthetic
          location</b> — an ActiveGate running the synthetic module. This workflow creates ICMP reachability monitors, which
          can only run from one. It resolves a location at run time and, if none exists, reports why and{" "}
          <b style={{ color: t.ink }}>skips</b> the creates rather than provisioning monitors against a location that isn&apos;t there.
        </Text>
      </div>
      <Flex flexDirection="column" gap={8}>
        {STEPS.map((s, i) => <StepRow key={i} step={s} n={i + 1} />)}
      </Flex>
      <Flex gap={12} flexWrap="wrap" alignItems="center" style={{ marginTop: 12 }}>
        <button onClick={download} style={{ ...btn, background: t.accent, color: "#fff" }}>⤓ Download workflow JSON</button>
        {link ? <a href={link} target="_top" rel="noreferrer" style={{ ...btn, background: "none", color: t.accent, border: `1px solid ${t.border}` }}>Open Workflows app →</a> : null}
      </Flex>
      <Text style={{ fontSize: 12, color: t.subtle, marginTop: 12, display: "block", fontStyle: "italic" }}>
        The reverse direction — pushing Dynatrace's discovered state back into NetBox — is a separate, advanced workflow that
        writes your CMDB; not bundled here by default.
      </Text>
    </div>
  );
}
