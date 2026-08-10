import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t, mono } from "../theme";
import { Panel, Pill, StatTile, Tag, Segmented, SitePicker } from "../components/ui";
import { addDevicePolling, listAgGroups, FEATURE_SETS_FOR_ROLE, type FeatureSet } from "../lib/provision";
import { CredentialPicker, type SnmpV3Fields } from "../components/CredentialPicker";
import { useFleet } from "../lib/data";
import { useSites } from "../lib/sites";
import { useRoles, roleFor, roleGroupOf, type Role } from "../lib/roles";

// Inventory of record from NetBox (bridged to Grail by emit_inventory). role + netbox.id live here.
const INV_Q = `timeseries v=count(cno.inv.device), by:{\`device.name\`, \`device.role\`, \`device.address\`, \`netbox.id\`}, from:-2h
| fieldsAdd live=arraySum(v) | filter live>0
| fields device=\`device.name\`, role=\`device.role\`, ip=\`device.address\`, nbid=\`netbox.id\``;


// Role drives BOTH the NetBox record and — since SNMP extension 0.0.14 — which OID groups the
// monitoring configuration actually polls (FEATURE_SETS_FOR_ROLE). It is no longer cosmetic.
//
// `power` was one option covering both UPS and PDU, which could not be mapped to a feature set:
// `UPS power` and `PDU power` are deliberately separate sets (merging them was measured to
// return noSuchName and ZERO values on a real UPS). lib/roles.ts already distinguishes ups/pdu,
// so the option is split to match rather than collapsing a distinction the backend needs.
const ROLE_OPTS = [
  { value: "core", label: "Core" },
  { value: "access", label: "Access" },
  { value: "wan-edge", label: "WAN" },
  { value: "ap", label: "AP" },
  { value: "ups", label: "UPS" },
  { value: "pdu", label: "PDU" },
];

// SNMP credentials are picked from the Credential Vault via <CredentialPicker> — auto-listed by id
// (the app never reads the secret), with a v2c-community fallback.

const inputStyle: React.CSSProperties = {
  background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8,
  padding: "8px 11px", color: t.ink, fontSize: 15, width: "100%",
};
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

const EXT = "custom:cno.network.interfaces";
type Result = { tone: "ok" | "staged" | "err"; msg: string } | null;

export const Configure = ({ embedded }: { embedded?: boolean } = {}) => {
  const nav = useNavigate();
  const fleetQ = useFleet();
  const invQ = useDql({ query: INV_Q });

  const fleet = fleetQ.rows;
  const inv: any[] = (invQ.data as any)?.records ?? [];
  const invByIp: Record<string, any> = {};
  inv.forEach((r) => { if (r.ip) invByIp[String(r.ip)] = r; });

  const { sites: knownSites, assign } = useSites();
  const { map: roleMap, assignRole } = useRoles();

  // merge: every polled device + its NetBox record (if any).
  //
  // NO RETIRE FILTER HERE, and none is needed. This reads useFleet, and retiring or hiding a
  // device removes it from useFleet at the source — so it leaves this table for free. The old
  // local `retiredIps` optimistic-hide went with the duplicate retire button: once the filter
  // lives in one place, every consumer inherits it, which is the whole argument for putting it
  // there rather than teaching each page to filter for itself.
  const rows = fleet
    .map((f) => {
      const rec = invByIp[String(f.ip)];
      return { device: f.device, ip: f.ip, role: rec?.role || roleGroupOf(roleFor(roleMap, f.ip, f.device)), nbid: rec?.nbid, inNetbox: !!rec };
    });

  const [showAdd, setShowAdd] = useState(false);
  const [stage, setStage] = useState<"form" | "preview">("form");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);

  const [f, setF] = useState({ name: "", ip: "", role: "access", vaultId: "", interval: "1", site: "" });
  const set = (k: string, v: string) => setF((s) => ({ ...s, [k]: v }));

  // ActiveGate group to poll from — picked by the operator (no longer assumed)
  // SNMP version + v3 params, set by <CredentialPicker>. Defaults to v2c so existing
  // v2c onboarding is unchanged; v3 is opt-in from the picker.
  const [snmp, setSnmp] = useState<{ snmpVersion: "v2c" | "v3"; v3?: SnmpV3Fields }>({ snmpVersion: "v2c" });
  const [agGroups, setAgGroups] = useState<{ scope: string; group: string }[]>([]);
  const [agScope, setAgScope] = useState("");
  useEffect(() => { listAgGroups().then(({ groups, current }) => { setAgGroups(groups); setAgScope((s) => s || current || groups[0]?.scope || ""); }); }, []);
  const credIsVault = /^CREDENTIALS_VAULT-/i.test(f.vaultId.trim()); // vault id vs an inline community/user
  // v3 with inline credentials needs a user name; a vault entry supplies it instead.
  const v3Ready = snmp.snmpVersion !== "v3" || credIsVault || !!snmp.v3?.userName?.trim();
  const valid = f.name.trim() && /^\d{1,3}(\.\d{1,3}){3}$/.test(f.ip.trim()) && f.site.trim() && f.vaultId.trim().length > 0 && v3Ready;

  // Which OID groups this device will actually be polled for (SNMP extension ≥0.0.14).
  // Derived from the Role the operator picked — which the wizard used to collect, echo back in
  // the preview, and then throw away, so a device selected as "Power" was onboarded as a switch.
  const featureSets: FeatureSet[] = FEATURE_SETS_FOR_ROLE[f.role] ?? ["Interfaces"];
  const isPower = f.role === "ups" || f.role === "pdu";

  const reset = () => { setShowAdd(false); setStage("form"); setResult(null); setBusy(false); setF({ name: "", ip: "", role: "access", vaultId: "", interval: "1", site: "" }); };

  async function applyDynatrace() {
    setBusy(true); setResult(null);
    const credentialId = f.vaultId.trim(); // a vault id (CREDENTIALS_VAULT-…) or a v2c community — credAuth auto-detects
    const r = await addDevicePolling({ extension: EXT, name: f.name.trim(), ip: f.ip.trim(), credentialId, intervalMin: Number(f.interval), scope: agScope, snmpVersion: snmp.snmpVersion, v3: snmp.v3, featureSets });
    setBusy(false);
    if (!r.ok) { setResult({ tone: "err", msg: r.error || "Failed to add endpoint." }); return; }
    if (r.staged) { setResult({ tone: "staged", msg: `Reviewed & staged — ${f.name.trim()} is ready to apply. The live extension-config write is wired in the next step (B1); it will start polling ${f.ip.trim()} within ~1 min.` }); return; }
    if (f.site.trim()) assign(f.ip.trim(), f.site.trim(), f.name.trim());
    // PERSIST THE ROLE THE OPERATOR JUST CHOSE. The site was saved here and the role was not, so
    // every newly onboarded device arrived on the Devices page with no explicit role, fell back
    // to hostname inference, and rendered as a GUESS — even though the operator had picked one
    // two fields above. The role was being read (it selects the feature sets) and then discarded.
    assignRole(f.ip.trim(), f.role as Role);
    // Name what is actually being polled. "Added, polling starts shortly" was true and useless:
    // it read identically whether the device got interface metrics, power metrics, or (on the
    // wrong role) an ERROR config collecting nothing but uptime.
    setResult({ tone: "ok", msg: `Endpoint added to ${EXT}, polling ${featureSets.join(" + ")}. First data within ~1 min.${isPower ? " Interfaces is deliberately OFF for power gear — a UPS/PDU management card that cannot answer GetBulk would otherwise put the whole configuration in ERROR." : " Cisco device? Add “Cisco device health” to this configuration for CPU and memory."}` });
    fleetQ.refresh();
  }

  const credLabel = f.vaultId.trim() || "credential";

  return (
    <Flex flexDirection="column" gap={16} padding={embedded ? 0 : 24} style={{ maxWidth: embedded ? undefined : 1100 }}>
      {!embedded && (
        <div>
          <Heading level={2}>Configure</Heading>
          <Paragraph>Onboard and tune monitoring — the two-button model. Retiring a device lives on Fleet, where the filters are. Dynatrace starts polling directly; NetBox (inventory of record) is updated through the on-prem executor.</Paragraph>
        </div>
      )}

      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Polled" value={rows.length} sub="answering SNMP" accent={t.up} />
        <StatTile label="In NetBox" value={rows.filter((r) => r.inNetbox).length} sub="inventory of record" accent={t.accent} />
        <StatTile label="Sites" value={knownSites.length} sub={knownSites.join(" · ") || "none assigned yet"} accent={t.accent} />
        <StatTile label="Collector" value="SNMP v2c" sub={EXT.replace("custom:", "")} accent={t.accent} />
      </Flex>

      {result ? (
        (() => {
          const c = result.tone === "ok" ? t.up : result.tone === "staged" ? t.accent : t.down;
          const bg = result.tone === "ok" ? t.upBg : result.tone === "staged" ? t.accentBg : t.downBg;
          const mark = result.tone === "ok" ? "✓ " : result.tone === "staged" ? "• " : "✕ ";
          return <div style={{ borderRadius: 8, padding: "12px 14px", background: bg, border: `1px solid ${c}`, color: c, fontSize: 14 }}>{mark}{result.msg}</div>;
        })()
      ) : null}

      {/* ── Add device ─────────────────────────────────────────── */}
      <Panel
        title="Onboard a device"
        tag={showAdd ? <Tag kind="road">wizard</Tag> : undefined}
        style={showAdd ? undefined : { display: "flex", justifyContent: "space-between", alignItems: "center" }}
      >
        {!showAdd ? (
          <>
            <Text style={{ color: t.subtle, fontSize: 14 }}>Add a device to SNMP polling and to the inventory of record.</Text>
            <button onClick={() => { setResult(null); setShowAdd(true); }} style={{ background: t.accent, color: "#fff", border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: "pointer" }}>+ Add device</button>
          </>
        ) : stage === "form" ? (
          <Flex flexDirection="column" gap={12} style={{ maxWidth: 460 }}>
            <Flex gap={16} flexWrap="wrap">
              <Field label="Device name" hint="SNMP sysName — how the device is identified"><input style={inputStyle} value={f.name} placeholder="LAB02-9300-01" onChange={(e) => set("name", e.target.value)} /></Field>
              <Field label="Management IP" hint="the polled address (entity id key)"><input style={inputStyle} value={f.ip} placeholder="10.20.30.11" onChange={(e) => set("ip", e.target.value)} /></Field>
            </Flex>
            <Field label="Role"><Segmented options={ROLE_OPTS} value={f.role} onChange={(v) => set("role", v)} /></Field>
            <Flex gap={16} flexWrap="wrap">
              <Field label="Site" hint="Required — pick an existing site or add a new one">
                <SitePicker value={f.site} sites={knownSites} onChange={(v) => set("site", v)} style={inputStyle} />
              </Field>
              <Field label="SNMP credential" hint="pick from your Credential Vault (by id — the app never reads the secret) or enter a v2c community">
                <CredentialPicker value={f.vaultId} onChange={(v) => set("vaultId", v)} allowCommunity allowV3 onSnmpChange={setSnmp} style={inputStyle} />
              </Field>
              <Field label="ActiveGate group" hint="which AG polls this device">
                {agGroups.length ? (
                  <select style={{ ...inputStyle, appearance: "auto" }} value={agScope} onChange={(e) => setAgScope(e.target.value)}>
                    {agGroups.map((g) => <option key={g.scope} value={g.scope}>{g.group}</option>)}
                  </select>
                ) : (
                  <input style={inputStyle} value={agScope} placeholder="ag_group-…" onChange={(e) => setAgScope(e.target.value)} />
                )}
              </Field>
              <Field label="Poll interval" hint="Fixed fleet-wide by the SNMP extension — Dynatrace doesn't support per-device SNMP intervals."><div style={{ padding: "9px 2px", fontSize: 15, color: t.ink, fontWeight: 600 }}>1&nbsp;min <span style={{ fontWeight: 400, fontSize: 13, color: t.subtle }}>· extension default, fleet-wide</span></div></Field>
            </Flex>
            <Flex gap={12}>
              <button disabled={!valid} onClick={() => { setResult(null); setStage("preview"); }} style={{ background: valid ? t.accent : t.cardSubtle, color: valid ? "#fff" : t.subtle, border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: valid ? "pointer" : "not-allowed" }}>Review changes</button>
              <button onClick={reset} style={{ background: "none", color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, cursor: "pointer" }}>Cancel</button>
            </Flex>
          </Flex>
        ) : (
          // ── preview: the two outcomes, reviewable before anything is written ──
          <Flex flexDirection="column" gap={16}>
            <Flex gap={16} flexWrap="wrap" alignItems="stretch">
              <div style={{ flex: "1 1 320px", minWidth: 280, border: `1px solid ${t.border}`, borderRadius: 8, padding: 14, background: t.cardSubtle }}>
                <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>① Dynatrace — start polling</span><Tag>live</Tag>
                </Flex>
                <div style={{ ...mono, fontSize: 12.5, color: t.subtle, lineHeight: 1.7 }}>
                  <div>extension <span style={{ color: t.ink }}>{EXT}</span></div>
                  <div>+ endpoint <span style={{ color: t.up }}>{f.ip.trim()}</span></div>
                  <div>{credIsVault ? "credential" : "community"} <span style={{ color: t.ink }}>{credLabel}</span></div>
                  <div>AG group <span style={{ color: t.ink }}>{agGroups.find((g) => g.scope === agScope)?.group || agScope || "auto"}</span></div>
                  <div>interval <span style={{ color: t.ink }}>per extension (1 min)</span></div>
                  {/* Show what will actually be POLLED. Without this the operator cannot tell a
                      correctly-classified device from one about to be onboarded as the wrong class. */}
                  <div>polling <span style={{ color: t.up }}>{featureSets.join(" + ")}</span></div>
                  {isPower ? (
                    <div style={{ color: t.warn }}>Interfaces OFF — correct for power gear (a card that cannot answer GetBulk would put the whole config in ERROR)</div>
                  ) : (
                    <div style={{ color: t.subtle }}>Cisco? add “Cisco device health” after creation for CPU/memory</div>
                  )}
                  <div style={{ marginTop: 6, color: t.ink }}>→ network:device <span style={{ color: t.accent }}>network_device_{f.ip.trim()}</span> auto-created</div>
                </div>
              </div>
              <div style={{ flex: "1 1 320px", minWidth: 280, border: `1px solid ${t.border}`, borderRadius: 8, padding: 14, background: t.cardSubtle }}>
                <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>② NetBox — inventory of record</span><Tag kind="ext">on-prem</Tag>
                </Flex>
                <div style={{ ...mono, fontSize: 12.5, color: t.subtle, lineHeight: 1.7 }}>
                  <div>+ device <span style={{ color: t.up }}>{f.name.trim()}</span></div>
                  <div>role <span style={{ color: t.ink }}>{f.role}</span></div>
                  <div>site <span style={{ color: t.ink }}>{f.site.trim() || "Unassigned"}</span></div>
                  <div>mgmt_ip <span style={{ color: t.ink }}>{f.ip.trim()}</span></div>
                  <div style={{ marginTop: 6 }}>applied by the on-prem executor (NetBox is private)</div>
                </div>
              </div>
            </Flex>
            <Flex gap={12} flexWrap="wrap" alignItems="center">
              <button disabled={busy} onClick={applyDynatrace} style={{ background: t.accent, color: "#fff", border: 0, borderRadius: 8, padding: "9px 16px", fontSize: 15, fontWeight: 600, cursor: busy ? "wait" : "pointer" }}>{busy ? "Applying…" : "Apply to Dynatrace"}</button>
              <button disabled title="Wired in Phase B2 (on-prem executor)" style={{ background: t.cardSubtle, color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, cursor: "not-allowed" }}>Update NetBox</button>
              <button onClick={() => setStage("form")} style={{ background: "none", color: t.subtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 15, cursor: "pointer" }}>← Back</button>
              {result && result.tone !== "err" ? <button onClick={reset} style={{ background: "none", color: t.accent, border: 0, fontSize: 15, cursor: "pointer" }}>Done</button> : null}
            </Flex>
          </Flex>
        )}
      </Panel>

      {/* ── Inventory ──────────────────────────────────────────── */}
      <Panel title="Onboarded devices" tag={<Tag>provisioning + CMDB</Tag>} style={{ padding: 0 }}>
        {fleetQ.isLoading ? (
          <Text style={{ color: t.subtle, padding: 16, display: "block" }}>Loading…</Text>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 15 }}>
              <thead>
                <tr>{["Device", "Mgmt IP", "Role", "NetBox", "Polling", ""].map((h) => <th key={h} style={{ textAlign: "left", padding: "11px 16px", color: t.subtle, fontWeight: 600, borderBottom: `1px solid ${t.border}` }}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i}>
                    <td style={{ ...mono, padding: "10px 16px", borderBottom: `1px solid ${t.border}`, fontWeight: 600 }}>{r.device}</td>
                    <td style={{ ...mono, padding: "10px 16px", borderBottom: `1px solid ${t.border}`, color: t.subtle }}>{r.ip}</td>
                    <td style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}`, color: t.subtle }}>{r.role}</td>
                    <td style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}` }}>{r.inNetbox ? <span style={{ ...mono, fontSize: 13, color: t.subtle }}>#{r.nbid}</span> : <span style={{ fontSize: 13, color: t.warn }}>not recorded</span>}</td>
                    <td style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}` }}><Pill status="up">polling</Pill></td>
                    <td style={{ padding: "10px 16px", borderBottom: `1px solid ${t.border}`, textAlign: "right" }}>
                      {/* RETIRE LIVES IN EXACTLY ONE PLACE — Fleet. There used to be a second
                          implementation here, and it had already drifted: no acknowledgement, no
                          hide/retire distinction, and a "staged … live in B1" message describing
                          a phase that shipped long ago. Two implementations of a destructive
                          action means maintaining parity forever and discovering you have not
                          the first time somebody uses the stale one. This page onboards; Fleet
                          owns the lifecycle, and it is the page with the filters you need to
                          find a device anyway. */}
                      <button onClick={() => nav(`/devices?q=${encodeURIComponent(String(r.ip))}`)}
                              title="Retire is on the Fleet page, which has the search and filters to find a device"
                              style={{ background: "none", color: t.accent, border: `1px solid ${t.border}`, borderRadius: 6, padding: "5px 11px", fontSize: 13, cursor: "pointer" }}>
                        Manage on Fleet →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* ── Configuration options ──────────────────────────────── */}
      <Panel title="Configuration">
        <Flex gap={16} flexWrap="wrap">
          <div style={{ flex: "1 1 260px", minWidth: 240 }}>
            <div style={labelStyle}>SNMP credential</div>
            <Flex flexDirection="column" gap={6}>
              <Flex justifyContent="space-between" alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 11px" }}>
                <span style={{ fontSize: 14 }}>Credential Vault (by id)</span>
                <span style={{ ...mono, fontSize: 11, color: t.accent }}>secure · auto-listed</span>
              </Flex>
              <Flex justifyContent="space-between" alignItems="center" style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 11px" }}>
                <span style={{ fontSize: 14 }}>v2c community string</span>
                <span style={{ ...mono, fontSize: 11, color: t.subtle }}>fallback</span>
              </Flex>
            </Flex>
          </div>
          <div style={{ flex: "1 1 200px", minWidth: 180 }}>
            <div style={labelStyle}>Poll interval</div>
            <div style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 7, padding: "8px 11px", fontSize: 14 }}>1 min · set in extension.yaml</div>
          </div>
          <div style={{ flex: "1 1 200px", minWidth: 180 }}>
            <div style={labelStyle}>Sites</div>
            <Flex gap={6} flexWrap="wrap">{knownSites.length ? knownSites.map((s) => <span key={s} style={{ background: t.emph, color: t.accent, borderRadius: 7, padding: "8px 11px", fontSize: 14, fontWeight: 600 }}>{s}</span>) : <span style={{ color: t.subtle, fontSize: 14 }}>No sites assigned yet — assign devices to sites in the Devices page.</span>}</Flex>
          </div>
        </Flex>
      </Panel>
    </Flex>
  );
};
