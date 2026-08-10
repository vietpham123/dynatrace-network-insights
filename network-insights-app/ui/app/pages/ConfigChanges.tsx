import React, { useState } from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { useTimeframe } from "../lib/timeframe";
import { t, mono } from "../theme";
import { useFleet, fleetLogScope } from "../lib/data";
import { Panel, StatTile, Tag, Segmented, QueryErr } from "../components/ui";

// Live queries against the Grail data landed by the custom:cno.network.compliance extension.
// (These used to be fed by the lab's scripts/config_capture.py bridge; the extension replaced it,
//  and one of these queries was never updated to match — see driftDql.)
const changeDql = (tf: string, scope: string) => `fetch logs, from:${tf}
| filter log.source == "network.config" and isNotNull(\`config.diff\`) and \`config.diff\` != ""
${scope}
| sort timestamp desc
| fields dev = \`host.name\`, user = \`config.user\`, action = \`config.action\`, diff = \`config.diff\`, drift = \`config.drift_from_golden\`
| limit 15`;

// Standing drift: the latest running-vs-golden verdict per device.
//
// This filtered on `config.action == "on-demand check-now"` and therefore ALWAYS RETURNED NOTHING.
// That string came from the retired scripts/config_capture.py bridge; the extension that replaced
// it emits `config.action == "scheduled check"` (__main__.py, the drift record), so the two never
// matched. Measured 2026-08-02: real drift was live in Grail — "DRIFTED from golden" at WARN with
// the diff attached — while this panel rendered empty.
//
// That is the worst possible failure for this panel: an empty drift table reads as "nothing has
// drifted", not "this query is broken". Same false-all-clear class as §A0 and the missing-golden-ref
// bug. So the filter is now on the PRESENCE OF A DRIFT VERDICT rather than on how the check was
// triggered — scheduled or on-demand are both legitimate sources of a standing verdict, and any
// future trigger keeps working without another silent break here.
const driftDql = (tf: string, scope: string) => `fetch logs, from:${tf}
| filter log.source == "network.config" and isNotNull(\`config.drift_from_golden\`)
${scope}
| dedup {\`host.name\`}, sort:{timestamp desc}
| fields dev = \`host.name\`, addr = \`device.address\`, drift = \`config.drift_from_golden\`, diff = \`config.diff\`, refreshed = \`config.archive.refreshed\`, age = \`config.archive.age_seconds\`
| sort dev asc`;

// The extension can serve a device's config out of a LOCAL MIRROR of a remote Git archive that
// it could not refresh this cycle (see modules/oxidized-extension, remote mode). The drift
// verdict is then real but describes the archive as of `age` seconds ago, so a device that has
// drifted SINCE is still carrying drift="no". Rendering that as "on intended config" would
// paint green over an unknown present state — the same false all-clear the extension itself
// was hardened against four times. The contract the extension publishes is:
// config.archive.refreshed == "no" means UNKNOWN, never healthy. Absent (records written
// before remote mode shipped) is treated as fresh, because there was no mirror to be stale.
// Local-path deployments emit "yes" explicitly — they read the archive directly, so there is
// no cached copy that could be behind.
// Typed rather than `any` — these four fields are exactly what driftDql selects, and the
// whole bug below was a wrong assumption about what values `drift` can hold.
type DriftRow = { dev?: string; addr?: string; drift?: string; diff?: string;
                  refreshed?: string; age?: string };

const isStale = (r: DriftRow) => r.refreshed === "no";

// The SECOND way a row can be unknown, and the one that was rendering GREEN. The extension
// emits config.drift_from_golden as "yes" | "no" | "unknown", and "unknown" means drift was
// NOT EVALUATED — the golden ref did not resolve, which is the DEFAULT state of every archive
// until someone tags a baseline, and also what --prune-tags correctly produces once the tag is
// deleted upstream. Measured 2026-08-02 against a real archive with no golden tag: every
// device emitted drift="unknown" with refreshed="yes", and this function returned "ok" for all
// of them — a "✓ on intended" pill and a count in "On intended config", for devices with no
// intended config to compare against.
//
// So ONLY an explicit "no" is a clean bill of health. Anything else is unknown. __main__.py
// already argues this exact point where it SUPPRESSES drift for a bad capture ("an 'unknown'
// would render as healthy"); this is the golden-ref path it did not cover.
const hasBaseline = (r: DriftRow) => r.drift === "yes" || r.drift === "no";
const driftState = (r: DriftRow) =>
  r.drift === "yes" ? "drifted" : !hasBaseline(r) || isStale(r) ? "unknown" : "ok";

// latest pass/fail per (device, control), with the control's plain-English name
const complianceDql = (tf: string, scope: string) => `fetch logs, from:${tf}
| filter log.source == "network.compliance"
${scope}
| dedup {\`host.name\`, \`compliance.control\`}, sort:{timestamp desc}
| filter isNotNull(\`compliance.control\`)
| fields dev = \`host.name\`, addr = \`device.address\`, control = \`compliance.control\`, name = \`compliance.control_name\`, status = \`compliance.status\`, platform = \`compliance.platform_label\`, verified = \`compliance.verified\``;

// ISO-27001:2022 control → functional family (for the filter chips)
const FAMILY: Record<string, string> = {
  "A.5.15": "Access", "A.5.37": "Ops",
  "A.8.5": "Auth", "A.8.8": "Auth",
  "A.8.9": "Config", "A.8.32": "Config",
  "A.8.15": "Logging", "A.8.16": "Logging",
  "A.8.20": "Network", "A.8.21": "Network", "A.8.22": "Network",
  "A.8.24": "Crypto", "A.8.26": "Crypto",
};
const familyOf = (c: string) => FAMILY[c] || "Other";

const pill = (fg: string, bg: string): React.CSSProperties => ({ fontSize: 12, fontWeight: 700, padding: "3px 10px", borderRadius: 20, color: fg, background: bg, whiteSpace: "nowrap" });
const chip = (on: boolean): React.CSSProperties => ({ fontSize: 13, fontWeight: 600, padding: "5px 13px", borderRadius: 20, cursor: "pointer", border: `1px solid ${on ? t.accent : t.border}`, color: on ? t.accent : t.subtle, background: on ? t.accentBg : t.cardSubtle });

export const ConfigChanges = () => {
  const { tf } = useTimeframe();
  // log-backed views must be scoped to the monitored fleet (see fleetLogScope)
  const fleet = useFleet();
  const scope = fleetLogScope(fleet.rows);
  const changes = useDql({ query: changeDql(tf, scope) });
  const compliance = useDql({ query: complianceDql(tf, scope) });
  const drift = useDql({ query: driftDql(tf, scope) });

  const changeRows: any[] = (changes.data as any)?.records ?? [];
  const compRows: any[] = (compliance.data as any)?.records ?? [];
  const driftRows: DriftRow[] = ((drift.data as any)?.records ?? []) as DriftRow[];

  // per-control: name + which devices fail
  const byControl: Record<string, { control: string; name: string; fails: { dev: string; addr: string }[]; total: number }> = {};
  compRows.forEach((r) => {
    const b = (byControl[r.control] = byControl[r.control] || { control: r.control, name: r.name, fails: [], total: 0 });
    b.total++;
    if (r.status === "fail") b.fails.push({ dev: r.dev, addr: r.addr });
  });
  const controlList = Object.values(byControl).sort((a, b) => a.control.localeCompare(b.control));
  const families = ["All", ...Array.from(new Set(controlList.map((c) => familyOf(c.control)))).sort()];

  const [fam, setFam] = useState("All");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [expandedDrift, setExpandedDrift] = useState<string | null>(null);
  const [tab, setTab] = useState("drift");
  const shown = controlList.filter((c) => fam === "All" || familyOf(c.control) === fam);

  // COVERAGE, not just outcome. A control is only "clean across fleet" if every assessed device
  // was actually EVALUATED for it and none failed.
  //
  // Control sets are PLATFORM-SCOPED and differ in size: cisco-ios declares 12, nokia/frr 10,
  // juniper/arista 9, netgear and panos 6 — because a control is only checkable if the platform
  // expresses it in its running-config. On a mixed fleet that means a control like A.8.5 (AAA) is
  // evaluated on the Cisco and never on the Netgear.
  //
  // The old test was `c.fails.length === 0`, which counted such a control as "clean across fleet"
  // on the strength of the one device that reported it, while every device that was never assessed
  // for it stayed invisible. Absence of a finding read as compliance — the same failure class as
  // the empty drift panel and the missing golden ref. It also perversely rewards the WEAKER
  // platform: a Netgear scoring 6/6 outranks a Cisco at 10/12 purely because four controls were
  // never checked on it.
  //
  // assessedDevices is the denominator: every device that produced ANY compliance record.
  const assessedDevices = new Set(compRows.map((r) => r.dev)).size;
  const fullyCovered = (c: { total: number }) => c.total >= assessedDevices;
  const passingControls = controlList.filter((c) => c.fails.length === 0 && fullyCovered(c)).length;
  const failingControls = controlList.filter((c) => c.fails.length > 0).length;
  // Neither clean nor failing: nobody failed it, but not every device was checked.
  const partialControls = controlList.length - passingControls - failingControls;
  const devicesAtRisk = new Set(compRows.filter((r) => r.status === "fail").map((r) => r.dev)).size;
  const checks = compRows.length, passChecks = compRows.filter((r) => r.status === "pass").length;
  const pct = checks ? Math.round((100 * passChecks) / checks) : 0;
  const drifted = new Set(changeRows.filter((r) => r.drift === "yes").map((r) => r.dev)).size;

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1120 }}>
      <div>
        <Heading level={2}>Config &amp; Compliance</Heading>
        <Paragraph>Event-triggered capture + diff + ISO-27001:2022 evaluation — live from Grail. Rules run on the captured config; Dynatrace reads &amp; correlates, never writes device config.</Paragraph>
      </div>

      <Segmented options={[{ value: "drift", label: "Config Drift" }, { value: "compliance", label: "ISO-27001" }, { value: "changes", label: "Change Feed" }]} value={tab} onChange={setTab} />

      {/* ── Drift — running vs intended (custom:cno.network.compliance, per poll) ── */}
      {tab === "drift" && (
      <Panel title="Config drift — running vs intended" tag={<Tag>live</Tag>}>
        {drift.error ? (
          <QueryErr label="drift checks" />
        ) : drift.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : driftRows.length === 0 ? (
          // Empty here means "no drift VERDICT was produced", which is a coverage gap, not a clean
          // bill of health — so say what is missing and how to fix it rather than leaving a blank
          // panel that reads as "nothing has drifted".
          <Text style={{ color: t.subtle }}>
            No drift verdicts in this window. Drift needs the <b>custom:cno.network.compliance</b> extension
            running <i>and</i> a golden baseline tagged in the config archive
            (<code>git -C &lt;archive&gt; tag -f golden HEAD</code>). Without the tag the extension skips drift
            entirely — see <b>OXIDIZED-SETUP.md §8</b>.
          </Text>
        ) : (
          <>
            <Flex gap={12} flexWrap="wrap" style={{ marginBottom: 16 }}>
              {/* "Config-managed" counts devices that actually HAVE a baseline — i.e. a real
                  yes/no verdict. Counting driftRows.length claimed a golden baseline for
                  every device even when the golden ref did not resolve for any of them. */}
              <StatTile label="Config-managed" value={driftRows.filter(hasBaseline).length} sub="devices with a golden baseline" accent={t.accent} />
              <StatTile label="On intended config" value={driftRows.filter((r) => driftState(r) === "ok").length} sub="match golden" accent={t.up} />
              <StatTile label="Drifted" value={driftRows.filter((r) => r.drift === "yes").length} sub="running ≠ intended" accent={driftRows.some((r) => r.drift === "yes") ? t.warn : t.up} />
              {/* Gated on the STATE, not on staleness: a missing golden ref produces unknown
                  rows with refreshed="yes", so some(isStale) hid the tile in exactly the case
                  the tile exists for. */}
              {driftRows.some((r) => driftState(r) === "unknown") ? (
                <StatTile label="Unknown" value={driftRows.filter((r) => driftState(r) === "unknown").length} sub="not checked against a baseline" accent={t.subtle} />
              ) : null}
            </Flex>
            <Flex flexDirection="column">
              {driftRows.map((r) => {
                const isDrift = r.drift === "yes";
                const state = driftState(r);
                const isExp = expandedDrift === r.dev;
                return (
                  <div key={r.dev}>
                    <Flex gap={12} alignItems="center" style={{ padding: "10px 4px", borderBottom: `1px solid ${t.border}` }}>
                      <span style={{ ...mono, fontSize: 14, fontWeight: 600, minWidth: 150 }}>{r.dev}</span>
                      <span style={{ ...mono, fontSize: 12.5, color: t.subtle, flex: 1, minWidth: 96 }}>{r.addr}</span>
                      {isDrift ? (
                        <button onClick={() => setExpandedDrift(isExp ? null : r.dev ?? null)} style={{ ...pill(t.warn, t.warnBg), border: 0, cursor: "pointer" }}>⚠ drifted {isExp ? "▴" : "▾"}</button>
                      ) : state === "unknown" ? (
                        // Name the ACTUAL cause. "archive stale" was wrong — and actively
                        // misleading — for the missing-baseline case, which is the common one.
                        !hasBaseline(r) ? (
                          <span style={pill(t.subtle, t.cardSubtle)} title="the golden baseline ref did not resolve in the archive, so drift was not evaluated for this device">? unknown — no baseline</span>
                        ) : (
                          <span style={pill(t.subtle, t.cardSubtle)} title={`config archive last refreshed ${r.age}s ago`}>? unknown — archive stale</span>
                        )
                      ) : (
                        <span style={pill(t.up, t.upBg)}>✓ on intended</span>
                      )}
                    </Flex>
                    {isExp && isDrift ? (
                      <div style={{ background: t.cardSubtle, borderRadius: 8, margin: "2px 0 8px", border: `1px solid ${t.border}`, padding: "8px 12px" }}>
                        <div style={{ fontSize: 12, color: t.subtle, marginBottom: 6 }}>running config differs from the golden / intended baseline:</div>
                        <div style={{ ...mono, fontSize: 14, whiteSpace: "pre-wrap" }}>
                          {String(r.diff).split("\n").map((line: string, k: number) => (
                            <div key={k} style={{ color: line.startsWith("+") ? t.up : line.startsWith("-") ? t.down : t.subtle }}>{line}</div>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </Flex>
          </>
        )}
      </Panel>
      )}

      {/* ── Compliance (Option C: summary → filters → control list) ── */}
      {tab === "compliance" && (
      <Panel title="ISO-27001:2022 compliance" tag={<Tag>live</Tag>}>
        {compliance.error ? (
          <QueryErr label="compliance" />
        ) : compliance.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : compRows.length === 0 ? (
          <Text style={{ color: t.subtle }}>No compliance evidence in the last 24h.</Text>
        ) : (
          <>
            <Flex gap={12} flexWrap="wrap" style={{ marginBottom: 16 }}>
              <StatTile label="Compliant" value={`${pct}%`} sub={`${passChecks}/${checks} checks`} accent={pct >= 90 ? t.up : pct >= 70 ? t.warn : t.down} />
              <StatTile label="Controls passing" value={passingControls} sub={`clean on all ${assessedDevices} assessed`} accent={t.up} />
              <StatTile label="Controls failing" value={failingControls} sub="≥1 device fails" accent={failingControls ? t.down : t.up} />
              {partialControls ? (
                <StatTile label="Partial coverage" value={partialControls} sub="not checked on every device" accent={t.subtle} />
              ) : null}
              <StatTile label="Devices at risk" value={devicesAtRisk} sub="have a failing control" accent={devicesAtRisk ? t.warn : t.up} />
            </Flex>

            <Flex gap={8} flexWrap="wrap" style={{ marginBottom: 12 }}>
              {families.map((f) => <button key={f} onClick={() => setFam(f)} style={chip(fam === f)}>{f}</button>)}
            </Flex>

            <Flex flexDirection="column">
              {shown.map((c) => {
                const fc = c.fails.length;
                const isExp = expanded === c.control;
                return (
                  <div key={c.control}>
                    <Flex gap={12} alignItems="center" style={{ padding: "10px 4px", borderBottom: `1px solid ${t.border}` }}>
                      <span style={{ ...mono, fontSize: 14, fontWeight: 600, color: t.accent, minWidth: 56 }}>{c.control}</span>
                      <span style={{ flex: 1, fontSize: 14, minWidth: 160 }}>{c.name}</span>
                      <span style={{ fontSize: 12, color: t.subtle, minWidth: 64, textAlign: "center" }}>{familyOf(c.control)}</span>
                      {fc === 0 && !fullyCovered(c) ? (
                        // Nobody failed it, but it was not evaluated on every assessed device —
                        // the platform does not express this control. Saying "pass" here would
                        // credit a device for a check that never ran.
                        <span style={pill(t.subtle, t.cardSubtle)} title={`evaluated on ${c.total} of ${assessedDevices} devices`}>
                          {c.total}/{assessedDevices} checked
                        </span>
                      ) : fc === 0 ? (
                        <span style={pill(t.up, t.upBg)}>pass</span>
                      ) : (
                        <button onClick={() => setExpanded(isExp ? null : c.control)} style={{ ...pill(t.down, t.downBg), border: 0, cursor: "pointer", ...(fc === 1 ? mono : {}) }}>
                          {fc === 1 ? `✕ ${c.fails[0].dev}` : `✕ ${fc} devices`} {isExp ? "▴" : "▾"}
                        </button>
                      )}
                    </Flex>
                    {isExp && fc >= 1 ? (
                      <div style={{ background: t.cardSubtle, borderRadius: 8, margin: "2px 0 8px", border: `1px solid ${t.border}` }}>
                        {c.fails.map((f) => (
                          <Flex key={f.dev} gap={12} alignItems="baseline" flexWrap="wrap" style={{ padding: "8px 14px", borderBottom: `1px solid ${t.border}` }}>
                            <span style={{ ...mono, fontWeight: 600, color: t.down, minWidth: 150 }}>{f.dev}</span>
                            <span style={{ ...mono, color: t.subtle, fontSize: 12.5, minWidth: 96 }}>{f.addr}</span>
                            <span style={{ color: t.subtle, fontSize: 13 }}>does not meet — {c.name}</span>
                          </Flex>
                        ))}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </Flex>
          </>
        )}
      </Panel>
      )}

      {/* ── Change feed with the diff ── */}
      {tab === "changes" && (
      <>
      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Changes (24h)" value={changeRows.length} sub="who / when / what" accent={t.accent} />
        <StatTile label="Drifted" value={drifted} sub="off golden baseline" accent={drifted ? t.warn : t.up} />
      </Flex>

      <Panel title="Change feed — with the diff" tag={<Tag>live</Tag>}>
        {changes.error ? (
          <QueryErr label="changes" />
        ) : changes.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : changeRows.length === 0 ? (
          <Text style={{ color: t.subtle }}>No config changes in the last 24h.</Text>
        ) : (
          <Flex flexDirection="column" gap={12}>
            {changeRows.map((r, i) => (
              <div key={i} style={{ borderLeft: `3px solid ${r.drift === "yes" ? t.warn : t.up}`, paddingLeft: 12 }}>
                <Text style={{ fontWeight: 600 }}>{r.action}</Text>
                {/* WHO made the change is NOT knowable from a git archive — Oxidized commits the config, not
                      the operator who typed it, so config.user is null on every record (measured: 1,499
                      network.config records over 30 days, zero with a user). Rendering it produced
                      "outpost ·  · matches golden" — an empty slot that reads as "nobody", which is a
                      stronger claim than "unknown" and a false one. Shown only when a source actually
                      supplies it; the honest way to fill it is a syslog join, which is a design change. */}
                <div style={{ ...mono, fontSize: 14, color: t.subtle, margin: "2px 0 6px" }}>
                  {r.dev}
                  {r.user ? ` · ${r.user}` : ""}
                  {" · "}{r.drift === "yes" ? "drifted from golden" : "matches golden"}
                </div>
                <div style={{ ...mono, fontSize: 14, background: t.cardSubtle, borderRadius: 6, padding: "6px 10px", whiteSpace: "pre-wrap" }}>
                  {String(r.diff).split("\n").map((line: string, k: number) => (
                    <div key={k} style={{ color: line.startsWith("+") ? t.up : line.startsWith("-") ? t.down : t.subtle }}>{line}</div>
                  ))}
                </div>
              </div>
            ))}
          </Flex>
        )}
      </Panel>
      </>
      )}
    </Flex>
  );
};
