import React, { useState, useEffect } from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t, mono } from "../theme";
import { Panel, Pill, StatTile, Tag, Segmented, QueryErr } from "../components/ui";
import { listAgGroups } from "../lib/provision";
import { CredentialPicker } from "../components/CredentialPicker";

// Live API-sourced devices — landed by the on-prem executor (api_bridge) polling the controller API.
// This is the proof the source is real: the same fleet metric (cno.if.oper_status) tagged source="…-api".
const LIVE_Q = `timeseries st=avg(cno.if.oper_status), by:{sys_name, \`device.address\`}, filter:{source=="sdwan-api"}, from:-10m
| fieldsAdd up=if(arrayAvg(st)>=0.5,1,else:0)
| fields sys_name, ip=\`device.address\`, up | sort sys_name asc`;

const extLabel = (n: string) => n.replace("com.dynatrace.extension.", "");

type Platform = { id: string; label: string; ext: string; urlHint: string; devLabel: string };
const PLATFORMS: Platform[] = [
  { id: "vmanage", label: "Cisco SD-WAN (vManage)", ext: "com.dynatrace.extension.cisco-sdwan", urlHint: "https://vmanage.example.com:8443", devLabel: "vEdge / cEdge routers" },
  { id: "meraki", label: "Cisco Meraki Dashboard", ext: "com.dynatrace.extension.cisco-meraki", urlHint: "https://api.meraki.com/api/v1", devLabel: "MX / MS / MR devices" },
  { id: "catalyst", label: "Catalyst Center (DNA-C)", ext: "com.dynatrace.extension.cisco-dnac", urlHint: "https://dnac.example.com", devLabel: "Catalyst switches / APs" },
  { id: "custom", label: "Other controller (custom extension)…", ext: "", urlHint: "https://controller.example.com", devLabel: "the devices it manages" },
];

const inputStyle: React.CSSProperties = { background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "8px 11px", color: t.ink, fontSize: 15, width: "100%" };
const labelStyle: React.CSSProperties = { fontSize: 13, color: t.subtle, marginBottom: 5, display: "block", fontWeight: 600 };

function Field(props: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div style={{ width: "100%" }}>
      <label style={labelStyle}>{props.label}</label>
      {props.children}
      {props.hint ? <div style={{ fontSize: 12, color: t.subtle, marginTop: 4 }}>{props.hint}</div> : null}
    </div>
  );
}

export const ConfigureApi = ({ embedded }: { embedded?: boolean } = {}) => {
  const liveQ = useDql({ query: LIVE_Q });
  const devices: any[] = (liveQ.data as any)?.records ?? [];

  const [agGroups, setAgGroups] = useState<{ scope: string; group: string }[]>([]);
  const [agScope, setAgScope] = useState("");
  useEffect(() => { listAgGroups().then(({ groups, current }) => { setAgGroups(groups); setAgScope((s) => s || current || groups[0]?.scope || ""); }); }, []);

  const [showAdd, setShowAdd] = useState(false);
  const [stage, setStage] = useState<"form" | "preview">("form");
  const [staged, setStaged] = useState<string | null>(null);

  // A7 — this screen used to have a "Stage source" button that set a success message reading
  // "…is ready. The on-prem executor polls the controller…" and made NO backend call at all.
  // Nothing was provisioned; the operator was told otherwise.
  //
  // It is not fixed by silently making it write, either: every vendor controller extension has a
  // different activation schema and we have no real vManage/Meraki to verify against, so an
  // untested write path would be a worse defect than the honest one. Instead this now follows the
  // pattern the app already uses for things it cannot install (workflows, extensions): it hands
  // you the exact monitoring configuration to apply in the Extensions app.
  const apiMonitoringConfig = () => ({
    scope: agScope || "ag_group-<your-group>",
    value: {
      enabled: true,
      description: `CNO API source — ${isCustom ? ext : plat.label}`,
      activationContext: "REMOTE",
      // Controller URL + a Credential Vault id. The exact property NAMES are defined by the
      // chosen extension's own activation schema — check it before applying:
      //   GET /api/v2/extensions/<extension>/<version>/schema
      url: f.url.trim(),
      credentialVaultId: f.vaultId.trim(),
      pollIntervalMinutes: Number(f.interval),
      ...(f.scope.trim() ? { siteScope: f.scope.trim() } : {}),
    },
  });

  const configText = () => JSON.stringify([apiMonitoringConfig()], null, 2);

  const copyConfig = async () => {
    try {
      await navigator.clipboard.writeText(configText());
      setStaged(`Configuration copied. Apply it in the Extensions app: open ${isCustom ? ext : plat.ext || plat.label}, add a monitoring configuration, and paste this. Nothing has been written to your tenant yet — verify the property names against that extension's schema first, since they differ per vendor.`);
    } catch {
      setStaged("Couldn't reach the clipboard from the app frame — use ⤓ Download JSON instead.");
    }
  };

  const downloadConfig = () => {
    try {
      const blob = new Blob([configText()], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `cno-api-source-${isCustom ? "custom" : plat.id}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setStaged("Configuration downloaded. Apply it in the Extensions app as a monitoring configuration — nothing has been written to your tenant yet.");
    } catch {
      setStaged("Download was blocked by the app frame — use ⧉ Copy monitoring config instead.");
    }
  };
  const [f, setF] = useState({ platform: "vmanage", url: "", vaultId: "", scope: "", interval: "5", customExt: "" });
  const set = (k: string, v: string) => setF((s) => ({ ...s, [k]: v }));
  const plat = PLATFORMS.find((p) => p.id === f.platform)!;
  const isCustom = f.platform === "custom";
  const ext = isCustom ? f.customExt.trim() : plat.ext;
  const valid = /^https?:\/\/.+/.test(f.url.trim()) && /^CREDENTIALS_VAULT-/i.test(f.vaultId.trim()) && (!isCustom || ext.length > 0);
  const reset = () => { setShowAdd(false); setStage("form"); setF({ platform: "vmanage", url: "", vaultId: "", scope: "", interval: "5", customExt: "" }); };

  return (
    <Flex flexDirection="column" gap={16} padding={embedded ? 0 : 24} style={{ maxWidth: embedded ? undefined : 1100 }}>
      {!embedded && (
        <div>
          <Heading level={2}>API source</Heading>
          <Paragraph>Onboard controller-based gear (SD-WAN, Meraki, Catalyst Center) via its API — one endpoint reports every device it manages.</Paragraph>
        </div>
      )}

      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Live API devices" value={devices.length} sub="from the controller" accent={t.up} />
        <StatTile label="Reachable" value={devices.filter((d) => Number(d.up) >= 1).length} sub="reporting now" accent={t.up} />
        <StatTile label="Platform" value={f.platform === "meraki" ? "Meraki" : f.platform === "catalyst" ? "Catalyst" : "vManage"} sub="controller API" accent={t.accent} />
        <StatTile label="Executor" value="on-prem" sub="polls the controller API" accent={t.accent} />
      </Flex>

      {staged ? (
        <div style={{ borderRadius: 8, padding: "12px 14px", background: t.accentBg, border: `1px solid ${t.accent}`, color: t.accent, fontSize: 14 }}>• {staged}</div>
      ) : null}

      {/* ── Add API source ── */}
      <Panel title="Onboard an API source" tag={showAdd ? <Tag kind="road">wizard</Tag> : undefined}
        style={showAdd ? undefined : { display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        {!showAdd ? (
          <>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Connect a controller and let the on-prem executor poll its device inventory into the fleet.</Text>
            <button onClick={() => { setStaged(null); setShowAdd(true); }} style={{ background: t.accent, color: "#fff", border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer" }}>+ Add API source</button>
          </>
        ) : stage === "form" ? (
          <Flex flexDirection="column" gap={12} style={{ maxWidth: 460 }}>
            <Field label="Platform / controller" hint="each controller has its own API → one extension per platform. Pick a bundled one, or choose custom to point at any installed API extension.">
              <select style={{ ...inputStyle, appearance: "auto" }} value={f.platform} onChange={(e) => set("platform", e.target.value)}>
                {PLATFORMS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
              {isCustom ? <input style={{ ...inputStyle, marginTop: 8, ...mono, fontSize: 13 }} value={f.customExt} placeholder="com.dynatrace.extension.your-controller" onChange={(e) => set("customExt", e.target.value)} /> : null}
            </Field>
            <Flex gap={16} flexWrap="wrap">
              <Field label="Controller URL" hint={`base API URL — reports all ${plat.devLabel}`}><input style={inputStyle} value={f.url} placeholder={plat.urlHint} onChange={(e) => set("url", e.target.value)} /></Field>
              <Field label="API token" hint="pick a read-only API token from your Credential Vault — referenced by id, the app never reads the secret"><CredentialPicker value={f.vaultId} onChange={(v) => set("vaultId", v)} style={inputStyle} /></Field>
            </Flex>
            <Flex gap={16} flexWrap="wrap">
              <Field label="ActiveGate group" hint="which AG runs the extension">
                {agGroups.length ? (
                  <select style={{ ...inputStyle, appearance: "auto" }} value={agScope} onChange={(e) => setAgScope(e.target.value)}>
                    {agGroups.map((g) => <option key={g.scope} value={g.scope}>{g.group}</option>)}
                  </select>
                ) : <input style={inputStyle} value={agScope} placeholder="ag_group-…" onChange={(e) => setAgScope(e.target.value)} />}
              </Field>
              <Field label="Scope (sites / fabrics)" hint="limit which sites to onboard — blank = all"><input style={inputStyle} value={f.scope} placeholder="all sites" onChange={(e) => set("scope", e.target.value)} /></Field>
              <Field label="Poll interval"><Segmented options={[{ value: "5", label: "5 min" }, { value: "15", label: "15 min" }]} value={f.interval} onChange={(v) => set("interval", v)} /></Field>
            </Flex>
            <Flex gap={12}>
              <button disabled={!valid} onClick={() => setStage("preview")} style={{ background: valid ? t.accent : t.cardSubtle, color: valid ? "#fff" : t.subtle, border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: valid ? "pointer" : "not-allowed" }}>Review connection</button>
              <button onClick={reset} style={{ background: "none", color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, cursor: "pointer" }}>Cancel</button>
            </Flex>
          </Flex>
        ) : (
          <Flex flexDirection="column" gap={16}>
            <div style={{ border: `1px solid ${t.border}`, borderRadius: 8, padding: 14, background: t.cardSubtle }}>
              <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
                <span style={{ fontWeight: 700, fontSize: 14 }}>Monitoring configuration to apply</span><Tag kind="ext">you apply this</Tag>
              </Flex>
              <div style={{ ...mono, fontSize: 12.5, color: t.subtle, lineHeight: 1.7 }}>
                <div>extension <span style={{ color: t.ink }}>{ext ? extLabel(ext) : "(enter extension id)"}</span></div>
                <div>controller <span style={{ color: t.up }}>{f.url.trim()}</span></div>
                <div>credential <span style={{ color: t.ink }}>{f.vaultId.trim()}</span> <span style={{ color: t.subtle }}>(referenced by id)</span></div>
                <div>AG group <span style={{ color: t.ink }}>{agGroups.find((g) => g.scope === agScope)?.group || agScope || "auto"}</span></div>
                <div>scope <span style={{ color: t.ink }}>{f.scope.trim() || "all sites"}</span> · interval <span style={{ color: t.ink }}>{f.interval} min</span></div>
                <div style={{ marginTop: 6, color: t.ink }}>→ devices land tagged <span style={{ color: t.accent }}>source=api</span>; entities auto-create from cno.if.*</div>
              </div>
            </div>
            <Flex gap={12} flexWrap="wrap" alignItems="center">
              <button onClick={() => { void copyConfig(); }} style={{ background: t.accent, color: "#fff", border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer" }}>⧉ Copy monitoring config</button>
              <button onClick={() => { downloadConfig(); }} style={{ background: "none", color: t.accent, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer" }}>⤓ Download JSON</button>
              <button onClick={() => setStage("form")} style={{ background: "none", color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, cursor: "pointer" }}>← Back</button>
            </Flex>
          </Flex>
        )}
      </Panel>

      {/* ── Live API-sourced devices (the proof) ── */}
      <Panel title="Live API-sourced devices" tag={<Tag>live</Tag>} style={{ padding: 0 }}>
        <div style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}` }}>
          <Text style={{ fontSize: 13, color: t.subtle }}>Landed by the on-prem executor polling the controller's API — the API analog of SNMP polling. Point it at your SD-WAN vManage, Meraki, or Catalyst Center and the devices land here.</Text>
        </div>
        {liveQ.error ? (
          <div style={{ padding: 16 }}><QueryErr label="API devices" /></div>
        ) : liveQ.isLoading ? (
          <Text style={{ color: t.subtle, padding: 16, display: "block" }}>Loading…</Text>
        ) : devices.length === 0 ? (
          <Text style={{ color: t.subtle, padding: 16, display: "block" }}>No API-sourced devices yet — stage a source above and the executor lands them here.</Text>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 15 }}>
              <thead><tr>{["Device", "System IP", "Reachability"].map((h) => <th key={h} style={{ textAlign: "left", padding: "11px 16px", color: t.subtle, fontWeight: 600, borderBottom: `1px solid ${t.border}` }}>{h}</th>)}</tr></thead>
              <tbody>
                {devices.map((d, i) => (
                  <tr key={i}>
                    <td style={{ ...mono, padding: "10px 16px", borderBottom: `1px solid ${t.border}`, fontWeight: 600 }}>{d.sys_name}</td>
                    <td style={{ ...mono, padding: "10px 16px", borderBottom: `1px solid ${t.border}`, color: t.subtle }}>{d.ip}</td>
                    <td style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}` }}><Pill status={Number(d.up) >= 1 ? "up" : "down"}>{Number(d.up) >= 1 ? "reachable" : "unreachable"}</Pill></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </Flex>
  );
};
