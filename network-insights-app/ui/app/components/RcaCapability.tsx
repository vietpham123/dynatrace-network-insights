import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text } from "@dynatrace/strato-components/typography";
import { getEnvironmentUrl } from "@dynatrace-sdk/app-environment";
import { useNavigate } from "react-router-dom";
import { t } from "../theme";
import { Panel, Tag } from "./ui";
import { StepRow, Step } from "./StepRow";
import { NETWORK_RCA_WORKFLOW } from "../lib/networkRcaWorkflow";

// The unified reasoner. ONE scheduled workflow does complete deterministic network RCA — whole-device
// & power-domain outages AND partial interface failures — in a single 3-min poll. It replaces the two
// earlier workflows (device dependency-suppression + interface degradation). The app can't install
// workflows (automation:workflows:write is first-party-only), so it ships bundled as a download to import.
const BULLETS = [
  "Device down → traverses the NetBox dependency graph to the true root (incl. power-domain faults Davis can't observe) and suppresses downstream symptoms.",
  "Interface degradation → consolidates admin-ENABLED ports down on a still-reachable device into one card; disabled/unused ports are excluded, so no false positives.",
  "One 3-min poll evaluates both lanes; a down device routes to the device lane, a reachable one with bad ports to the interface lane — never both. Stable-title dedup renews one problem per fault (no storms).",
];

const STEPS: Step[] = [
  {
    text: "Download the workflow", d: { who: "you",
      what: "The reasoner ships bundled inside this app — no separate file to hand around. The button below gives you the exact definition (6 tasks, disabled by default).",
      how: "Click ⤓ Download workflow JSON below." },
  },
  {
    text: "Import it into the Workflows app", key: true, d: { who: "you",
      what: "Dynatrace reserves programmatic workflow install for first-party apps, so a custom app can't create it for you — you import the JSON once. This is the only manual step.",
      how: "Open the Workflows app → Import, and upload the JSON you just downloaded.",
      verify: "It appears as \"CNO - Network RCA\" with 6 tasks and a 3-minute schedule." },
  },
  {
    text: "Enable + authorize on first run", d: { who: "you",
      what: "It imports DISABLED so it costs nothing until you're ready (workflows bill per run). Dynatrace also requires a one-time owner authorization the first time it runs — this is also what lets the Davis CoPilot narrative call succeed.",
      how: "Toggle the schedule on; the first execution prompts you to authorize it (interactive, one-time).",
      verify: "Executions flip to Success every 3 min — they error at 0s until the authorization is granted." },
  },
  {
    text: "Root-caused problems land in Alerts", key: true, d: { who: "verify",
      verify: "A device/PDU failure posts ONE root-caused problem with downstream devices suppressed; enabled ports going down on a reachable device post ONE consolidated \"Interface degradation\" card. Both carry the Davis-CoPilot narrative and appear in this app's Alerts view and in Dynatrace Problems." },
  },
];

function workflowsLink(): string {
  try { return getEnvironmentUrl().replace(/\/$/, "") + "/ui/apps/dynatrace.automations"; } catch { return ""; }
}

export function RcaCapability() {
  const link = workflowsLink();
  const nav = useNavigate();

  const download = () => {
    try {
      const blob = new Blob([JSON.stringify(NETWORK_RCA_WORKFLOW, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cno-network-rca.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* download blocked (iframe sandbox) — fall back to the Workflows link */ }
  };

  const btn: React.CSSProperties = { textDecoration: "none", borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer", border: 0 };

  return (
    <Panel>
      <Flex flexDirection="column" gap={16}>
        <Flex gap={12} alignItems="flex-start" justifyContent="space-between">
          <Flex gap={12} alignItems="flex-start">
            <span style={{ width: 44, height: 44, borderRadius: 11, display: "grid", placeItems: "center", background: t.accent, color: "#fff", fontSize: 22, flex: "none" }}>◎</span>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: t.accent }}>Capability · the reasoner</div>
              <Heading level={3}>Network RCA</Heading>
            </div>
          </Flex>
          <Tag>workflow</Tag>
        </Flex>

        <Text style={{ color: t.subtle, fontSize: 14, maxWidth: 680 }}>
          One deterministic Dynatrace Workflow that root-causes the whole network — device &amp; power-domain
          outages <b style={{ color: t.ink }}>and</b> partial interface failures — each into a single problem.
          A single classify pass routes every device to the right lane. It ships bundled; you import it once.
        </Text>
        <Flex flexDirection="column" gap={6}>
          {BULLETS.map((b, i) => (
            <Flex key={i} gap={8} alignItems="baseline">
              <span style={{ color: t.accent, fontWeight: 700 }}>›</span>
              <Text style={{ fontSize: 13.5 }}>{b}</Text>
            </Flex>
          ))}
        </Flex>

        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.07em", textTransform: "uppercase", color: t.subtle, marginTop: 2 }}>Install &amp; configure</div>
        <Flex flexDirection="column" gap={8}>
          {STEPS.map((s, i) => <StepRow key={i} step={s} n={i + 1} />)}
        </Flex>

        <Flex gap={12} flexWrap="wrap" alignItems="center">
          <button onClick={download} style={{ ...btn, background: t.accent, color: "#fff" }}>⤓ Download workflow JSON</button>
          {link ? (
            <a href={link} target="_top" rel="noreferrer" style={{ ...btn, background: "none", color: t.accent, border: `1px solid ${t.border}` }}>Open Workflows app →</a>
          ) : null}
        </Flex>

        <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 14 }}>
          <Text style={{ fontSize: 13, color: t.subtle }}>
            <b style={{ color: t.ink }}>How alerting fits.</b> This deterministic reasoner replaces the up/down detectors — it consolidates and root-causes state instead of firing raw alerts. Keep <b style={{ color: t.ink }}>metric</b> detectors (errors, utilization, latency) and Davis baselines for the signals a state model can't see. Live problems land in{" "}
            <button onClick={() => nav("/alerts")} style={{ background: "none", border: 0, color: t.accent, fontWeight: 600, cursor: "pointer", padding: 0, fontSize: 13 }}>Alerts</button>.
          </Text>
        </div>
      </Flex>
    </Panel>
  );
}
