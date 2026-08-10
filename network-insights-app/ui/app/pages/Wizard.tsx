import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { functions } from "@dynatrace-sdk/app-utils";
import { t } from "../theme";
import { Panel, Tag } from "../components/ui";
import { CredentialPicker, type SnmpV3Fields } from "../components/CredentialPicker";

// ── Catalog: capability-scoped, progressive disclosure ──────────────────────
// The wizard asks what OUTCOMES you want, then only shows the steps that serve
// them. Every "monitor" leaf ends in the proven `provision` write.

type OutcomeId = "monitor" | "config" | "reconcile" | "alert" | "flow";
const OUTCOMES: { id: OutcomeId; title: string; desc: string; icon: string }[] = [
  { id: "monitor", title: "Monitor devices", desc: "Health & availability via SNMP or API", icon: "▤" },
  { id: "flow", title: "Traffic & flow", desc: "Top talkers & conversations via NetFlow / sFlow", icon: "⇋" },
  { id: "alert", title: "Alerting & root cause", desc: "Root-cause correlation across the fleet", icon: "◆" },
  { id: "reconcile", title: "Reconcile inventory", desc: "Keep NetBox / ServiceNow / SolarWinds in sync", icon: "⇄" },
  { id: "config", title: "Config & compliance", desc: "Back up configs, prove ISO / change control", icon: "◨" },
];

type Method = "snmp" | "api";
const DEVICE_TYPES: { id: string; label: string; ext: string; method: Method }[] = [
  { id: "cisco-switch", label: "Cisco switches / routers", ext: "com.dynatrace.extension.snmp-generic-device", method: "snmp" },
  { id: "generic-snmp", label: "Generic SNMP devices", ext: "com.dynatrace.extension.snmp-generic-device", method: "snmp" },
  { id: "palo-alto", label: "Palo Alto firewalls", ext: "com.dynatrace.extension.palo-alto-generic", method: "snmp" },
  { id: "power", label: "UPS / PDU", ext: "com.dynatrace.extension.snmp-generic-device", method: "snmp" },
  { id: "cisco-sdwan", label: "Cisco SD-WAN (vManage API)", ext: "com.dynatrace.extension.cisco-sdwan", method: "api" },
];
const extLabel = (n: string) => n.replace("com.dynatrace.extension.", "").replace("custom:", "");

// ── little UI helpers ───────────────────────────────────────────────────────
function SelectCard(props: { on: boolean; onClick: () => void; title: string; desc?: string; icon?: string }) {
  return (
    <button
      onClick={props.onClick}
      style={{
        textAlign: "left", cursor: "pointer", borderRadius: 10, padding: 16, flex: "1 1 240px", minWidth: 220,
        background: props.on ? t.emph : t.cardSubtle,
        border: `1.5px solid ${props.on ? t.accent : t.border}`,
        color: t.ink, display: "flex", gap: 12, alignItems: "flex-start",
      }}
    >
      {props.icon ? <span style={{ fontSize: 20, opacity: 0.85, lineHeight: 1.2 }}>{props.icon}</span> : null}
      <span>
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontWeight: 700, fontSize: 15 }}>{props.title}</span>
          <span style={{ width: 16, height: 16, borderRadius: 5, border: `1.5px solid ${props.on ? t.accent : t.subtle}`, background: props.on ? t.accent : "transparent", color: "#fff", fontSize: 12, lineHeight: "13px", textAlign: "center" }}>{props.on ? "✓" : ""}</span>
        </span>
        {props.desc ? <span style={{ display: "block", color: t.subtle, fontSize: 13, marginTop: 4 }}>{props.desc}</span> : null}
      </span>
    </button>
  );
}

const primaryBtn = (on: boolean): React.CSSProperties => ({ background: on ? t.accent : t.cardSubtle, color: on ? "#fff" : t.subtle, border: 0, borderRadius: 8, padding: "10px 18px", fontSize: 15, fontWeight: 600, cursor: on ? "pointer" : "not-allowed" });
const ghostBtn: React.CSSProperties = { background: "none", color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 18px", fontSize: 15, cursor: "pointer" };
const inputStyle: React.CSSProperties = { background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 11px", color: t.ink, fontSize: 15, width: "100%" };
const fieldLabel: React.CSSProperties = { fontSize: 13, color: t.subtle, marginBottom: 5, display: "block", fontWeight: 600 };
// The SNMP credential is chosen in the discovery step via <CredentialPicker> — a vault entry,
// a v2c community, or SNMPv3 (user + security level + auth/priv) — resolved server-side by the
// `provision` function's discoAuth().

const SOR_NOTE: Record<string, string> = {
  none: "No system of record — autodiscovery is your source of truth. Reconciliation compares what's monitored against what discovery finds, flagging found-but-not-monitored gaps. This is the default for a SolarWinds displacement.",
  netbox: "NetBox is usually private, so the app writes an intent that an on-prem executor applies. Reconciliation compares Dynatrace-observed devices against NetBox's intended inventory and flags drift both ways.",
  servicenow: "Connect via the ServiceNow API. Reconciliation compares CMDB CIs against monitored devices — CIs not monitored, and devices missing from the CMDB.",
  solarwinds: "During migration, seed inventory from the SolarWinds API, then reconcile against what Dynatrace observes as you cut over and decommission SolarWinds.",
};

// Why a customer would ADOPT each system of record — the value-proposition, so the wizard
// helps them decide, not just wire it up. Framed against the new baseline: topology now
// self-assembles from LLDP, so a CMDB is optional ENRICHMENT — this is what it buys you.
const SOR_BENEFITS: Record<string, string> = {
  none: "Zero to deploy or keep in sync — autodiscovery is your truth. The trade-off: no intended-state to compare against, so reconciliation surfaces found-but-not-monitored gaps, not a 'this should exist but doesn't' signal.",
  netbox: "You don't need NetBox for topology — that self-assembles from LLDP. NetBox earns its place as the intended-state overlay: the authoritative record of what should be there (IPAM, VLANs, rack / site / role) plus the physical and power cabling LLDP can't see (patch panels, PDU / UPS power chains). That unlocks true drift detection — observed vs intended — and tags every device with location and ownership. Optional, but the payoff is a single source of truth and two-way reconciliation.",
  servicenow: "If the CMDB is already your enterprise system of record, reconciling against it keeps ITSM and monitoring on the same CIs — change tickets, ownership, and impact analysis all line up with what's actually monitored.",
  solarwinds: "Only for the migration window: seed from SolarWinds so you don't hand-key inventory, reconcile as you cut over, then decommission it once Dynatrace + discovery own the truth.",
};

const SOR_STEPS: Record<string, string[]> = {
  none: [
    "Run autodiscovery on your subnets (Monitor → Discover a subnet).",
    "The app compares what's monitored against what discovery finds.",
    "Review found-but-not-monitored gaps in Devices and promote them to full polling.",
  ],
  netbox: [
    "Deploy the on-prem executor (apply_netbox.py) on a host that can reach NetBox.",
    "Give it NETBOX_URL + an API token — credentials never leave your network.",
    "The emit_inventory bridge lands the NetBox roster in Grail (cno.inv.device).",
    "Reconcile compares Dynatrace-observed vs NetBox-intended and writes drift as bizevents.",
    "Approve per device, or let the two-button workflow apply the changes automatically.",
  ],
  servicenow: [
    "Create a ServiceNow API user with read access to the CMDB.",
    "Pick the CI class (e.g. cmdb_ci_ip_switch) and a query filter for your network gear.",
    "Bridge the CIs into Grail on a schedule.",
    "Reconcile CIs vs monitored devices — CIs not monitored, and devices missing from the CMDB.",
  ],
  solarwinds: [
    "Enable the SolarWinds Information Service (SWIS) API + a read-only account.",
    "Export Orion.Nodes (IP, name, vendor) as the seed inventory.",
    "Bridge nodes into Grail during migration.",
    "Reconcile SW nodes vs Dynatrace as you cut over, then decommission SolarWinds.",
  ],
};

export const Wizard = () => {
  const nav = useNavigate();
  const [outcomes, setOutcomes] = useState<Set<OutcomeId>>(new Set(["monitor", "alert"]));
  const [types, setTypes] = useState<Set<string>>(new Set(["cisco-switch"]));
  const [method, setMethod] = useState<"discover" | "manual">("discover");
  const [installed, setInstalled] = useState<string[] | null>(null);
  const [detectors, setDetectors] = useState<{ objectId: string; name: string; model: string; enabled: boolean }[] | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [step, setStep] = useState(0);

  async function toggleDetector(objectId: string, next: boolean) {
    setTogglingId(objectId);
    try {
      const r = await functions.call("provision", { data: { action: "toggleDetector", objectId, enabled: next } });
      const b: any = await r.json();
      if (b?.ok) setDetectors((ds) => (ds || []).map((d) => (d.objectId === objectId ? { ...d, enabled: next } : d)));
    } catch { /* ignore */ }
    setTogglingId(null);
  }
  const [subnet, setSubnet] = useState("");
  const [cred, setCred] = useState("");
  // SNMP version + v3 params for autodiscovery. discoAuth() server-side already supports v3
  // and the Credential Vault; this step used to force a raw v2c community, which made it the
  // one onboarding path that bypassed the vault entirely.
  const [snmp, setSnmp] = useState<{ snmpVersion: "v2c" | "v3"; v3?: SnmpV3Fields }>({ snmpVersion: "v2c" });
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState<{ ok: boolean; msg: string } | null>(null);

  async function runDiscover() {
    setApplying(true); setApplied(null);
    try {
      const r = await functions.call("provision", { data: { action: "discover", subnet, profileId: cred, label: "wizard", snmpVersion: snmp.snmpVersion, v3: snmp.v3 } });
      const b: any = await r.json();
      setApplied(b?.ok
        ? { ok: true, msg: `Autodiscovery is now scanning ${subnet} via the ActiveGate. Devices answering SNMP appear in Devices within a few minutes.` }
        : { ok: false, msg: b?.error || "Failed to start discovery." });
    } catch (e: any) { setApplied({ ok: false, msg: e?.message || String(e) }); }
    setApplying(false);
  }

  // fetch installed extensions once — powers the "advise, don't assume" step
  useEffect(() => {
    let live = true;
    functions.call("provision", { data: { action: "catalog" } })
      .then((r) => r.json())
      .then((b: any) => { if (live) setInstalled(b?.installed ?? []); })
      .catch(() => { if (live) setInstalled([]); });
    functions.call("provision", { data: { action: "anomalyDetectors" } })
      .then((r) => r.json())
      .then((b: any) => { if (live) setDetectors(b?.detectors ?? []); })
      .catch(() => { if (live) setDetectors([]); });
    return () => { live = false; };
  }, []);

  const monitor = outcomes.has("monitor");
  const flow = outcomes.has("flow");
  const alerting = outcomes.has("alert");
  const reconcile = outcomes.has("reconcile");
  const config = outcomes.has("config");
  const [sor, setSor] = useState("none");
  // steps are gated on the chosen outcomes (progressive disclosure)
  const steps: { key: string; label: string }[] = [
    { key: "outcomes", label: "Outcomes" },
    ...(monitor ? [{ key: "devices", label: "Devices" }, { key: "prereqs", label: "Prerequisites" }, { key: "collect", label: "Collection" }] : []),
    ...(flow ? [{ key: "flow", label: "Flow" }] : []),
    ...(alerting ? [{ key: "alerting", label: "Alerting" }] : []),
    ...(reconcile ? [{ key: "reconcile", label: "Reconcile" }] : []),
    ...(config ? [{ key: "config", label: "Config" }] : []),
    { key: "review", label: "Review" },
  ];
  const cur = steps[Math.min(step, steps.length - 1)].key;

  const toggle = <T,>(set: Set<T>, v: T) => { const n = new Set(set); n.has(v) ? n.delete(v) : n.add(v); return n; };
  const chosenTypes = DEVICE_TYPES.filter((d) => types.has(d.id));
  const neededExts = Array.from(new Set(chosenTypes.map((d) => d.ext)));
  const hasSnmp = chosenTypes.some((d) => d.method === "snmp");
  const hasApi = chosenTypes.some((d) => d.method === "api");

  const canNext =
    (cur === "outcomes" && outcomes.size > 0) ||
    (cur === "devices" && types.size > 0) ||
    cur === "prereqs" || cur === "collect" || cur === "flow" || cur === "alerting" || cur === "reconcile" || cur === "config" || cur === "review";

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 980 }}>
      <div>
        <Heading level={2}>Set up monitoring</Heading>
        <Paragraph>A guided setup — answer a few questions and we configure only what you need.</Paragraph>
      </div>

      {/* stepper */}
      <Flex gap={8} flexWrap="wrap" alignItems="center">
        {steps.map((s, i) => (
          <React.Fragment key={s.key}>
            <Flex gap={8} alignItems="center">
              <span style={{ width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, background: i === step ? t.accent : i < step ? t.accentBg : t.cardSubtle, color: i === step ? "#fff" : i < step ? t.accent : t.subtle, border: `1px solid ${i <= step ? t.accent : t.border}` }}>{i < step ? "✓" : i + 1}</span>
              <Text style={{ fontSize: 14, fontWeight: i === step ? 700 : 500, color: i === step ? t.ink : t.subtle }}>{s.label}</Text>
            </Flex>
            {i < steps.length - 1 ? <span style={{ color: t.subtle }}>→</span> : null}
          </React.Fragment>
        ))}
      </Flex>

      <Panel>
        {/* ── Outcomes ── */}
        {cur === "outcomes" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>What do you want to set up?</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Pick your outcomes — the wizard only asks about the parts you choose.</Text>
            <Flex gap={12} flexWrap="wrap">
              {OUTCOMES.map((o) => <SelectCard key={o.id} on={outcomes.has(o.id)} onClick={() => setOutcomes((s) => toggle(s, o.id))} title={o.title} desc={o.desc} icon={o.icon} />)}
            </Flex>
          </Flex>
        )}

        {/* ── Devices ── */}
        {cur === "devices" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>What are you monitoring?</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>We map each type to the right Dynatrace extension.</Text>
            <Flex gap={12} flexWrap="wrap">
              {DEVICE_TYPES.map((d) => <SelectCard key={d.id} on={types.has(d.id)} onClick={() => setTypes((s) => toggle(s, d.id))} title={d.label} desc={`${d.method.toUpperCase()} · ${extLabel(d.ext)}`} />)}
            </Flex>
          </Flex>
        )}

        {/* ── Prerequisites (live extension advice) ── */}
        {cur === "prereqs" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Extensions you'll need</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Checked live against your tenant — install anything missing from the Hub.</Text>
            {installed === null ? (
              <Text style={{ color: t.subtle }}>Checking installed extensions…</Text>
            ) : (
              <Flex flexDirection="column" gap={8}>
                {neededExts.map((ext) => {
                  const ok = installed.includes(ext);
                  return (
                    <Flex key={ext} justifyContent="space-between" alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${ok ? t.up : t.warn}`, borderRadius: 8, padding: "12px 14px" }}>
                      <span style={{ fontWeight: 600, fontSize: 14 }}>{extLabel(ext)}</span>
                      {ok
                        ? <span style={{ fontSize: 13, fontWeight: 700, color: t.up }}>✓ installed</span>
                        : <span style={{ fontSize: 13, fontWeight: 700, color: t.warn }}>⚠ install from Hub</span>}
                    </Flex>
                  );
                })}
              </Flex>
            )}
          </Flex>
        )}

        {/* ── Collection ── */}
        {cur === "collect" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>How should we find your devices?</Text>
            {hasSnmp && (
              <>
                <Flex gap={12} flexWrap="wrap">
                  <SelectCard on={method === "discover"} onClick={() => setMethod("discover")} title="Discover a subnet" desc="Point autodiscovery at an IP range — Dynatrace finds the devices. Best when you don't have an inventory list." icon="⌕" />
                  <SelectCard on={method === "manual"} onClick={() => setMethod("manual")} title="Add specific devices" desc="Enter devices one at a time (name + IP + credential)." icon="＋" />
                </Flex>
                {method === "discover" && (
                  <Flex gap={12} flexWrap="wrap" style={{ marginTop: 4 }}>
                    <div style={{ flex: "1 1 240px", minWidth: 200 }}>
                      <label style={fieldLabel}>Subnet to scan (CIDR)</label>
                      <input style={inputStyle} value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="10.0.0.0/24" />
                    </div>
                    <div style={{ flex: "1 1 200px", minWidth: 180 }}>
                      <label style={fieldLabel}>SNMP credential</label>
                      <CredentialPicker value={cred} onChange={setCred} allowCommunity allowV3 onSnmpChange={setSnmp} style={inputStyle} />
                    </div>
                  </Flex>
                )}
              </>
            )}
            {hasApi && (
              <Flex flexDirection="column" gap={8} style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: 14 }}>
                <Text style={{ fontSize: 14, color: t.subtle }}>API sources (Cisco SD-WAN, Meraki, Catalyst Center) connect to the controller's API — provide the controller URL + a vault token, and the on-prem executor polls it into the fleet.</Text>
                <button onClick={() => nav("/configuration")} style={ghostBtn}>Set up API sources →</button>
              </Flex>
            )}
            {!hasSnmp && !hasApi && <Text style={{ color: t.subtle }}>Pick at least one device type first.</Text>}
          </Flex>
        )}

        {/* ── Traffic & flow ── */}
        {cur === "flow" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Traffic & flow monitoring</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>The conversation layer — top talkers, who-talks-to-whom, bandwidth by network. SNMP counters can't show this; it comes from a NetFlow / sFlow / IPFIX feed off your switches, through a collector.</Text>
            <Flex flexDirection="column" gap={8}>
              {[
                "Enable NetFlow v9 / IPFIX (or sFlow) export on your switches & routers, pointed at a collector.",
                "Deploy a collector — BindPlane or an OpenTelemetry Collector — to receive the flow export.",
                "Forward to Dynatrace: as metrics (aggregated → cheap top-talkers / Sankey) or logs (raw → per-conversation drill-down).",
                "The NetFlow view renders it live — no app change.",
              ].map((s, i) => (
                <Flex key={i} gap={8} alignItems="baseline" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 14px" }}>
                  <span style={{ color: t.accent, fontWeight: 700, minWidth: 16 }}>{i + 1}</span>
                  <Text style={{ fontSize: 14 }}>{s}</Text>
                </Flex>
              ))}
            </Flex>
            <button onClick={() => nav("/netflow")} style={ghostBtn}>View NetFlow →</button>
          </Flex>
        )}

        {/* ── Alerting / anomaly detection ── */}
        {cur === "alerting" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Anomaly detection & root cause</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Davis watches your network metrics for anomalies — no static thresholds to babysit — and they're consolidated into one root-caused problem. Here's what's watching your network — turn any detector on or off:</Text>
            {detectors === null ? (
              <Text style={{ color: t.subtle }}>Loading detectors…</Text>
            ) : detectors.length === 0 ? (
              <Text style={{ color: t.subtle }}>No network anomaly detectors found.</Text>
            ) : (
              <Flex flexDirection="column" gap={8}>
                {detectors.map((d, i) => {
                  const known = d.model === "AUTO_ADAPTIVE_THRESHOLD" || d.model === "STATIC_THRESHOLD";
                  const auto = d.model === "AUTO_ADAPTIVE_THRESHOLD";
                  return (
                    <Flex key={i} justifyContent="space-between" alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 14px" }}>
                      <span style={{ fontSize: 14, fontWeight: 600 }}>{d.name}</span>
                      <Flex gap={8} alignItems="center">
                        {known ? <span style={{ fontSize: 12, fontWeight: 700, color: auto ? t.accent : t.subtle, background: auto ? t.accentBg : "transparent", border: `1px solid ${auto ? t.accent : t.border}`, borderRadius: 5, padding: "1px 7px" }}>{auto ? "auto-baseline" : "static"}</span> : null}
                        <button onClick={() => toggleDetector(d.objectId, !d.enabled)} disabled={togglingId === d.objectId} style={{ cursor: togglingId === d.objectId ? "wait" : "pointer", fontSize: 12, fontWeight: 700, border: `1px solid ${d.enabled ? t.up : t.border}`, background: d.enabled ? t.upBg : "transparent", color: d.enabled ? t.up : t.subtle, borderRadius: 12, padding: "3px 12px", minWidth: 62 }}>
                          {togglingId === d.objectId ? "…" : d.enabled ? "● on" : "turn on"}
                        </button>
                      </Flex>
                    </Flex>
                  );
                })}
              </Flex>
            )}
            <Text style={{ color: t.subtle, fontSize: 13 }}>Auto-baseline detectors learn what's normal per metric and device (Davis) — the behavior SolarWinds' static thresholds can't match. Static ones fire on fixed limits.</Text>
          </Flex>
        )}

        {/* ── Reconcile inventory ── */}
        {cur === "reconcile" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Where does your inventory live?</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Reconciliation keeps Dynatrace and your system of record in agreement — or runs source-of-truth-free on autodiscovery.</Text>
            <Flex gap={12} flexWrap="wrap">
              {[
                { id: "none", label: "No system of record", desc: "Autodiscovery is the source of truth (SolarWinds-displacement default)" },
                { id: "netbox", label: "NetBox", desc: "Private CMDB — reconcile via the on-prem executor" },
                { id: "servicenow", label: "ServiceNow", desc: "Reconcile CMDB CIs vs monitored devices" },
                { id: "solarwinds", label: "SolarWinds", desc: "Seed inventory during migration" },
              ].map((o) => <SelectCard key={o.id} on={sor === o.id} onClick={() => setSor(o.id)} title={o.label} desc={o.desc} />)}
            </Flex>
            <div style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: 14 }}>
              <Text style={{ fontSize: 14, color: t.subtle }}>{SOR_NOTE[sor]}</Text>
            </div>
            <div style={{ background: t.emph, border: `1px solid ${t.accent}`, borderRadius: 8, padding: 14 }}>
              <Text style={{ fontSize: 13, fontWeight: 700, color: t.accent, display: "block", marginBottom: 5 }}>{sor === "none" ? "The trade-off" : "Why adopt it — the payoff"}</Text>
              <Text style={{ fontSize: 14, color: t.ink }}>{SOR_BENEFITS[sor]}</Text>
            </div>
            <Text style={{ fontWeight: 650, fontSize: 14, marginTop: 4 }}>How to set it up</Text>
            <Flex flexDirection="column" gap={8}>
              {SOR_STEPS[sor].map((s, i) => (
                <Flex key={i} gap={8} alignItems="baseline" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 14px" }}>
                  <span style={{ color: t.accent, fontWeight: 700, minWidth: 16 }}>{i + 1}</span>
                  <Text style={{ fontSize: 14 }}>{s}</Text>
                </Flex>
              ))}
            </Flex>
          </Flex>
        )}

        {/* ── Config & compliance ── */}
        {cur === "config" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Config backup & compliance</Text>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Device configs are archived to Git (Oxidized) — the SolarWinds NCM replacement. Dynatrace reads & correlates changes but never writes device config; ISO-27001 rules evaluate the captured config.</Text>
            <Flex flexDirection="column" gap={8}>
              {["Oxidized polls devices → commits configs to Git", "Config-change events stream into Grail (who changed what, when)", "War-room diff on any change; ISO controls evaluated on the captured config"].map((s, i) => (
                <Flex key={i} gap={8} alignItems="baseline" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 14px" }}>
                  <span style={{ color: t.accent, fontWeight: 700 }}>{i + 1}</span>
                  <Text style={{ fontSize: 14 }}>{s}</Text>
                </Flex>
              ))}
            </Flex>
            <button onClick={() => nav("/config")} style={ghostBtn}>View Config & Changes →</button>
          </Flex>
        )}

        {/* ── Review ── */}
        {cur === "review" && (
          <Flex flexDirection="column" gap={16}>
            <Text style={{ fontWeight: 650, fontSize: 16 }}>Review</Text>
            <ReviewRow label="Outcomes" value={Array.from(outcomes).map((o) => OUTCOMES.find((x) => x.id === o)?.title).join(" · ")} />
            {monitor && <ReviewRow label="Device types" value={chosenTypes.map((d) => d.label).join(" · ") || "—"} />}
            {monitor && <ReviewRow label="Extensions" value={neededExts.map(extLabel).join(" · ")} />}
            {monitor && <ReviewRow label="Collection" value={hasSnmp ? (method === "discover" ? "Autodiscovery (subnet scan)" : "Add specific devices") : hasApi ? "API (controller)" : "—"} />}
            {flow && <ReviewRow label="Traffic & flow" value="NetFlow / sFlow feed → Sankey + top talkers" />}
            {alerting && <ReviewRow label="Alerting" value={`${detectors?.length ?? 0} network detectors · root-cause correlation`} />}
            {reconcile && <ReviewRow label="Reconcile" value={sor === "none" ? "Autodiscovery (no external system of record)" : sor.charAt(0).toUpperCase() + sor.slice(1)} />}
            {config && <ReviewRow label="Config & compliance" value="Oxidized + Git · ISO-27001" />}

            <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
              {monitor && hasSnmp && method === "manual" ? (
                <>
                  <Text style={{ color: t.subtle, fontSize: 14, marginBottom: 12, display: "block" }}>Ready to onboard devices — this drops you into the live Add-device flow.</Text>
                  <button onClick={() => nav("/configure")} style={primaryBtn(true)}>Go to onboarding →</button>
                </>
              ) : monitor && hasSnmp && method === "discover" ? (
                <>
                  <Text style={{ color: t.subtle, fontSize: 14, marginBottom: 12, display: "block" }}>
                    Autodiscovery will scan <span style={{ color: t.ink, fontWeight: 600 }}>{subnet || "(enter a subnet)"}</span> via the ActiveGate using {snmp.snmpVersion === "v3" ? "SNMPv3" : "SNMPv2c"} <span style={{ color: t.ink, fontWeight: 600 }}>{cred || snmp.v3?.userName || "(set one)"}</span>. Devices answering SNMP are discovered automatically.
                  </Text>
                  {applied ? (
                    <div style={{ borderRadius: 8, padding: "12px 14px", marginBottom: 12, background: applied.ok ? t.upBg : t.downBg, border: `1px solid ${applied.ok ? t.up : t.down}`, color: applied.ok ? t.up : t.down, fontSize: 14 }}>{applied.ok ? "✓ " : "✕ "}{applied.msg}</div>
                  ) : null}
                  {applied?.ok ? (
                    <button onClick={() => nav("/devices")} style={primaryBtn(true)}>View Devices →</button>
                  ) : (
                    <button onClick={runDiscover} disabled={applying} style={primaryBtn(!applying)}>{applying ? "Starting…" : "Start autodiscovery"}</button>
                  )}
                </>
              ) : monitor && hasApi ? (
                <>
                  <Text style={{ color: t.subtle, fontSize: 14, marginBottom: 12, display: "block" }}>Ready to onboard your API controller — this drops you into the live API onboarding in the Configuration hub.</Text>
                  <button onClick={() => nav("/configuration")} style={primaryBtn(true)}>Go to API onboarding →</button>
                </>
              ) : (
                <button onClick={() => nav("/")} style={primaryBtn(true)}>Back to Overview →</button>
              )}
            </div>
          </Flex>
        )}
      </Panel>

      {/* nav */}
      <Flex justifyContent="space-between">
        <button onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0} style={{ ...ghostBtn, opacity: step === 0 ? 0.4 : 1, cursor: step === 0 ? "not-allowed" : "pointer" }}>← Back</button>
        {cur !== "review" ? (
          <button onClick={() => canNext && setStep((s) => s + 1)} style={primaryBtn(canNext)}>Next →</button>
        ) : <span />}
      </Flex>
    </Flex>
  );
};

function ReviewRow(props: { label: string; value: string }) {
  return (
    <Flex gap={16} style={{ padding: "8px 0", borderBottom: `1px solid ${t.border}` }}>
      <Text style={{ color: t.subtle, fontSize: 14, minWidth: 130 }}>{props.label}</Text>
      <Text style={{ fontSize: 14, fontWeight: 600 }}>{props.value}</Text>
    </Flex>
  );
}
