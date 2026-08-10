import React, { useEffect, useState } from "react";
import { t, mono } from "../theme";
import { listCredentials, type VaultCred } from "../lib/provision";

// Auto-populating credential input. Lists Credential Vault entries (metadata only — id/name/type,
// never the secret) so the operator picks by name instead of memorizing CREDENTIALS_VAULT-… ids.
// Degrades gracefully: if the app isn't granted the credentials-read scope (or the vault is empty),
// it falls back to manual id entry so onboarding never breaks. `allowCommunity` adds a v2c-community
// option (SNMP); `allowV3` adds the SNMPv3 modes.
//
// Emits the credential itself via onChange (a vault id, or a v2c community string) and — when
// allowV3 is set — the SNMP version + v3 parameters via onSnmpChange. Callers that only speak v2c
// (e.g. the API source) can ignore both new props entirely.
//
// The v3 field set mirrors the datasource schema's PRECONDITIONS: auth_* only applies at
// AUTH_PRIV/AUTH_NO_PRIV, priv_* only at AUTH_PRIV. Rendering them conditionally means the UI
// cannot submit a combination the config API would reject.

export type SecurityLevel = "AUTH_PRIV" | "AUTH_NO_PRIV" | "NO_AUTH_NO_PRIV";
export type SnmpV3Fields = {
  userName?: string;
  securityLevel?: SecurityLevel;
  authProtocol?: string;
  authPassword?: string;
  privProtocol?: string;
  privPassword?: string;
};

const AUTH_PROTOCOLS = ["SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"];
const PRIV_PROTOCOLS = ["AES", "AES192", "AES256", "AES192C", "AES256C", "DES"];
const LEVELS: { v: SecurityLevel; label: string }[] = [
  { v: "AUTH_PRIV", label: "authPriv — authenticated + encrypted (recommended)" },
  { v: "AUTH_NO_PRIV", label: "authNoPriv — authenticated, not encrypted" },
  { v: "NO_AUTH_NO_PRIV", label: "noAuthNoPriv — neither" },
];

type Mode = "vault" | "community" | "manual" | "v3-vault" | "v3-manual";

export function CredentialPicker({
  value, onChange, allowCommunity, allowV3, onSnmpChange, style,
}: {
  value: string;
  onChange: (v: string) => void;
  allowCommunity?: boolean;
  allowV3?: boolean;
  onSnmpChange?: (s: { snmpVersion: "v2c" | "v3"; v3?: SnmpV3Fields }) => void;
  style?: React.CSSProperties;
}) {
  const [creds, setCreds] = useState<VaultCred[] | null>(null); // null = loading
  const [failed, setFailed] = useState(false);
  const [mode, setMode] = useState<Mode>("vault");
  const [v3, setV3] = useState<SnmpV3Fields>({ securityLevel: "AUTH_PRIV", authProtocol: "SHA", privProtocol: "AES" });

  useEffect(() => {
    let live = true;
    listCredentials().then((r) => {
      if (!live) return;
      setCreds(r.credentials);
      if (!r.ok || r.credentials.length === 0) {
        setFailed(!r.ok);
        setMode(allowCommunity ? "community" : "manual");
      }
    });
    return () => { live = false; };
  }, [allowCommunity]);

  const isV3 = mode === "v3-vault" || mode === "v3-manual";
  const setV3Field = (k: keyof SnmpV3Fields, val: string) => {
    const next = { ...v3, [k]: val };
    setV3(next);
    onSnmpChange?.({ snmpVersion: "v3", v3: next });
  };
  const pickMode = (m: Mode) => {
    setMode(m);
    onChange("");
    const v3mode = m === "v3-vault" || m === "v3-manual";
    onSnmpChange?.(v3mode ? { snmpVersion: "v3", v3 } : { snmpVersion: "v2c" });
  };

  const selStyle: React.CSSProperties = { ...style, appearance: "auto" };
  const inpStyle: React.CSSProperties = { ...style, ...mono, fontSize: 13 };
  const hasVault = !!creds && creds.length > 0;
  const row: React.CSSProperties = { marginTop: 8 };

  if (creds === null) {
    return <input style={inpStyle} value={value} placeholder="loading vault credentials…" readOnly />;
  }

  return (
    <div>
      <select style={selStyle} value={mode} onChange={(e) => pickMode(e.target.value as Mode)}>
        {hasVault && <option value="vault">v2c · pick from Credential Vault</option>}
        {allowCommunity && <option value="community">v2c · community string</option>}
        <option value="manual">v2c · enter vault id manually</option>
        {allowV3 && hasVault && <option value="v3-vault">SNMPv3 · pick from Credential Vault</option>}
        {allowV3 && <option value="v3-manual">SNMPv3 · enter credentials</option>}
      </select>

      {(mode === "vault" || mode === "v3-vault") && hasVault && (
        <select style={{ ...selStyle, ...row }} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">— select a credential —</option>
          {creds.map((c) => (
            <option key={c.id} value={c.id}>{c.name} · {String(c.type || "").toLowerCase().replace(/_/g, " ")}</option>
          ))}
        </select>
      )}
      {mode === "community" && (
        <input style={{ ...inpStyle, ...row }} value={value} placeholder="e.g. public" onChange={(e) => onChange(e.target.value)} />
      )}
      {mode === "manual" && (
        <input style={{ ...inpStyle, ...row }} value={value} placeholder="CREDENTIALS_VAULT-XXXXXXXXXXXXXXXX" onChange={(e) => onChange(e.target.value)} />
      )}

      {mode === "v3-manual" && (
        <>
          <input style={{ ...inpStyle, ...row }} value={v3.userName || ""} placeholder="SNMPv3 user name"
                 onChange={(e) => setV3Field("userName", e.target.value)} />
          <select style={{ ...selStyle, ...row }} value={v3.securityLevel} onChange={(e) => setV3Field("securityLevel", e.target.value)}>
            {LEVELS.map((l) => <option key={l.v} value={l.v}>{l.label}</option>)}
          </select>
          {/* auth_* apply only at AUTH_PRIV / AUTH_NO_PRIV — schema precondition */}
          {(v3.securityLevel === "AUTH_PRIV" || v3.securityLevel === "AUTH_NO_PRIV") && (
            <>
              <select style={{ ...selStyle, ...row }} value={v3.authProtocol} onChange={(e) => setV3Field("authProtocol", e.target.value)}>
                {AUTH_PROTOCOLS.map((a) => <option key={a} value={a}>auth: {a}</option>)}
              </select>
              <input style={{ ...inpStyle, ...row }} type="password" value={v3.authPassword || ""} placeholder="authentication passphrase"
                     onChange={(e) => setV3Field("authPassword", e.target.value)} />
            </>
          )}
          {/* priv_* apply only at AUTH_PRIV — schema precondition */}
          {v3.securityLevel === "AUTH_PRIV" && (
            <>
              <select style={{ ...selStyle, ...row }} value={v3.privProtocol} onChange={(e) => setV3Field("privProtocol", e.target.value)}>
                {PRIV_PROTOCOLS.map((a) => <option key={a} value={a}>priv: {a}</option>)}
              </select>
              <input style={{ ...inpStyle, ...row }} type="password" value={v3.privPassword || ""} placeholder="privacy passphrase"
                     onChange={(e) => setV3Field("privPassword", e.target.value)} />
            </>
          )}
          <div style={{ fontSize: 12, color: t.subtle, marginTop: 6 }}>
            Passphrases are sent to the provisioning function and stored by Dynatrace with the monitoring
            configuration. A Credential Vault entry (the option above) is the more secure choice.
          </div>
        </>
      )}

      {isV3 && mode === "v3-vault" && (
        <div style={{ fontSize: 12, color: t.subtle, marginTop: 6 }}>
          The vault entry supplies the v3 user and passphrases — the app references it by id and never reads it.
        </div>
      )}

      {failed && (
        <div style={{ fontSize: 12, color: t.subtle, marginTop: 4 }}>
          Couldn't list the vault (the app may need the credentials-read scope) — enter the id manually.
        </div>
      )}
    </div>
  );
}
