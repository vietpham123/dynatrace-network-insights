import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Text } from "@dynatrace/strato-components/typography";
import { t } from "../theme";
import { EXTENSION_BUNDLES, type ExtBundle } from "../lib/extensionBundles";

// Reusable "download the extension source, build + sign it yourself, upload it" block. Shared by every
// card that ships an Extensions-2.0 package. Source + self-sign (the customer's cert) — the app never
// signs anything, so there is nothing of ours to trust. Kind-aware build steps: Python = dt-sdk,
// declarative = dt-cli (they package/sign differently — see the module READMEs).

const BUILD: Record<ExtBundle["kind"], { tool: string; cmds: string[] }> = {
  python: {
    tool: "dt-sdk",
    cmds: ["pip install dt-extensions-sdk", "dt-sdk gencerts        # once — your developer cert", "dt-sdk build           # → dist/*.zip, signed"],
  },
  declarative: {
    tool: "dt-cli",
    cmds: ["pip install dt-cli", "dt ext gencerts        # once — your developer cert", "dt ext assemble --source extension --output ext.zip", "dt ext sign --src ext.zip --output bundle.zip --key <dev_fused.pem>"],
  },
};

export function ExtensionDownload({ bundleKeys, intro }: { bundleKeys: string[]; intro?: string }) {
  const bundles = bundleKeys.map((k) => EXTENSION_BUNDLES[k]).filter(Boolean) as ExtBundle[];
  const kinds = Array.from(new Set(bundles.map((b) => b.kind)));

  const download = (b: ExtBundle) => {
    try {
      // data URI avoids Uint8Array/Blob typing + works from the sandboxed iframe; zips are a few KB
      const a = document.createElement("a");
      a.href = `data:application/zip;base64,${b.b64}`;
      a.download = b.file;
      document.body.appendChild(a); a.click(); a.remove();
    } catch { /* download blocked (iframe sandbox) */ }
  };

  const btn: React.CSSProperties = { borderRadius: 8, padding: "8px 14px", fontSize: 14, fontWeight: 600, cursor: "pointer", border: 0 };
  const mono: React.CSSProperties = { fontFamily: "monospace", fontSize: "0.92em", color: t.ink };

  if (!bundles.length) return null;
  return (
    <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.07em", textTransform: "uppercase", color: t.accent, marginBottom: 6 }}>Extension · download-to-build (you sign)</div>
      <Text style={{ color: t.subtle, fontSize: 13.5, marginBottom: 12, display: "block", maxWidth: 720 }}>
        {intro || "Deploy this on your ActiveGate. You get the source, build + sign it with your own certificate, and upload it — the app never signs anything, so there's nothing of ours for you to trust."}
      </Text>

      {/* download rows */}
      <Flex flexDirection="column" gap={8} style={{ marginBottom: 14 }}>
        {bundles.map((b) => (
          <Flex key={b.name} justifyContent="space-between" alignItems="center" gap={12} flexWrap="wrap"
            style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "10px 12px" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 13.5, color: t.ink }}>{b.display}</div>
              <div style={{ ...mono, color: t.subtle, fontSize: 12 }}>{b.name} · {b.kind}</div>
            </div>
            <button onClick={() => download(b)} style={{ ...btn, background: t.accent, color: "#fff" }}>⤓ {b.file}</button>
          </Flex>
        ))}
      </Flex>

      {/* build → sign, per kind present */}
      <div style={{ fontSize: 12.5, color: t.subtle, marginBottom: 6, fontWeight: 700 }}>Build → sign → upload</div>
      {kinds.map((k) => (
        <div key={k} style={{ marginBottom: 10 }}>
          {kinds.length > 1 && <div style={{ fontSize: 12, color: t.subtle, marginBottom: 4 }}>{k === "python" ? "Python" : "Declarative"} extension — <span style={mono}>{BUILD[k].tool}</span></div>}
          <pre style={{ margin: 0, padding: "10px 12px", overflowX: "auto", background: t.card, border: `1px solid ${t.border}`, borderRadius: 8, fontSize: 11.5, lineHeight: 1.6, ...mono }}>{BUILD[k].cmds.join("\n")}</pre>
        </div>
      ))}
      {/* Two gotchas that cost real time during a clean install — surfaced here rather than
          buried in a README, because this is the screen you are on when you hit them. */}
      <div style={{ marginTop: 12, padding: "10px 12px", borderRadius: 8, border: `1px solid ${t.warn}`, background: t.cardSubtle }}>
        <div style={{ fontSize: 12.5, fontWeight: 700, color: t.warn, marginBottom: 4 }}>A clean build does not mean a deployable extension</div>
        <Text style={{ fontSize: 12, color: t.subtle, display: "block", maxWidth: 720 }}>
          The build tools do <b style={{ color: t.ink }}>not</b> validate activation-schema semantics — they will build
          and even <i>sign</i> an artifact the tenant then rejects on upload. If you edit a schema, three rules they
          won't check for you: an ActiveGate-hosted Python extension's datasource key must be
          <span style={mono}> pythonRemote</span> (not <span style={mono}>python</span>); a
          <b style={{ color: t.ink }}> non-nullable</b> property <b style={{ color: t.ink }}>must</b> carry a default;
          a <b style={{ color: t.ink }}>nullable</b> property must <b style={{ color: t.ink }}>not</b>. The upload is the test.
        </Text>
      </div>

      <div style={{ marginTop: 10, padding: "10px 12px", borderRadius: 8, border: `1px solid ${t.border}`, background: t.cardSubtle }}>
        <div style={{ fontSize: 12.5, fontWeight: 700, color: t.ink, marginBottom: 4 }}>Your signing CA is needed in two places</div>
        <Text style={{ fontSize: 12, color: t.subtle, display: "block", maxWidth: 720 }}>
          <b style={{ color: t.ink }}>1 · Tenant</b> — upload the CA's <b style={{ color: t.ink }}>public</b> cert to the
          Credential vault (type <i>certificate</i>, scope <i>extension</i>). This permits the <b style={{ color: t.ink }}>upload</b>.
          <br />
          <b style={{ color: t.ink }}>2 · ActiveGate</b> — the AG must also trust it, to permit <b style={{ color: t.ink }}>execution</b>.
          It is meant to sync this from the tenant; if it hasn't, place the CA in
          <span style={mono}> /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/</span> and restart the AG.
          <br />
          Symptom when 2 is missing: <span style={mono}>Cannot extract extension … checking signature failed</span>,
          and the monitoring configuration sits at <span style={mono}>UNKNOWN</span> with no other error.
        </Text>
      </div>

      <Text style={{ fontSize: 12, color: t.subtle, marginTop: 10, display: "block", maxWidth: 720 }}>
        Then upload the built <span style={mono}>.zip</span>, activate it, and add a monitoring configuration scoped to
        your AG group. Note the AG needs an <b style={{ color: t.ink }}>explicit</b> group
        (<span style={mono}>agctl group set &lt;name&gt;</span> + restart) — a fresh AG reports its group as bare
        <span style={mono}> default</span>, which does not match a config scoped <span style={mono}>ag_group-default</span>,
        and it fails silently. Each download's README has the exact config fields + the "retire the cron" step.
      </Text>
    </div>
  );
}
