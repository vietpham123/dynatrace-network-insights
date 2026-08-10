import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { t, mono } from "../theme";
import { Panel, Pill, StatTile, Tag, Segmented, SitePicker } from "../components/ui";
import { useFleet } from "../lib/data";
import { useDeviceLifecycle, ARCHIVE_AFTER_DAYS, useAcknowledgedDevices } from "../lib/lifecycle";
import { retireDevicePolling, refreshConfigured } from "../lib/provision";
import { useSites, siteOf } from "../lib/sites";

import { useRoles, roleFor, roleGroupOf, roleIsInferred, ROLES, ROLE_LABEL, type Role } from "../lib/roles";

const STATUS_OPTS = [
  { value: "all", label: "All" },
  { value: "up", label: "Up" },
  { value: "down", label: "Down" },
  { value: "unmonitored", label: "Not monitored" },
  // NOT a filter on `rows` — an ACKNOWLEDGED device is dropped by useFleet at the source, so it
  // cannot appear here however the filters are set. Selecting this swaps the whole table for a
  // separate one sourced from useDeviceLifecycle, giving a retired device exactly one place it
  // can be seen. Note the trigger is the acknowledgement, not the absence of a config: an
  // unconfigured device that is still reporting stays in the fleet as "not monitored".
  { value: "retired", label: "Retired" },
];
const ROLE_OPTS = [
  { value: "all", label: "All roles" },
  { value: "core", label: "Core" },
  { value: "access", label: "Access" },
  { value: "wan-edge", label: "WAN" },
  { value: "ap", label: "AP" },
  { value: "power", label: "Power" },
  { value: "console", label: "Console" },
];

// Inline site editor for a Devices row — click to type/pick a site (autocompletes from
// existing ones via the shared <datalist>). Blank clears the assignment.
// Role is CUSTOMER-OWNED (lib/roles.ts), keyed on the management address. An inferred value is
// shown in muted italics with a "guess" affordance so an operator can tell it apart from something
// they actually set — on a real fleet almost every hostname guess lands on "other".
function RoleCell({ addr, role, guessed, onAssign }:
  { addr: string; role: Role; guessed: boolean; onAssign: (addr: string, r: Role | "") => void }) {
  const [editing, setEditing] = React.useState(false);
  if (editing) {
    return (
      <select
        autoFocus
        // A GUESSED ROLE MUST START UNSELECTED. With value={role} the guess was already the
        // selected option, so choosing that same role fired NO change event and nothing saved —
        // the operator had to pick a wrong role first to force a change, then pick the right one.
        // Unselected makes every choice a real change, including confirming the guess.
        value={guessed ? "" : role}
        onChange={(e) => { if (!e.target.value) return; onAssign(addr, e.target.value as Role); setEditing(false); }}
        onBlur={() => setEditing(false)}
        style={{ background: t.cardSubtle, border: `1px solid ${t.accent}`, borderRadius: 6, color: t.ink, padding: "3px 7px", fontSize: 13, appearance: "auto" }}
      >
        {guessed && <option value="" disabled>— guessed {ROLE_LABEL[role]}, confirm or change —</option>}
        {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
      </select>
    );
  }
  // Three states, mirroring SiteCell so the column reads as actionable rather than as data:
  //   unset + nothing inferable -> "+ set role"  (the common case on a real fleet, since a
  //                                hostname with no convention infers to "other")
  //   unset but inferred        -> the guess, marked, with an explicit "change"
  //   assigned                  -> the value plainly, with "change"
  const unknown = guessed && role === "other";
  if (unknown) {
    return (
      <span onClick={() => setEditing(true)} title="No role set — click to choose one"
        style={{ cursor: "pointer", fontWeight: 600, color: t.subtle, borderBottom: `1px dashed ${t.border}`, paddingBottom: 1 }}>
        + set role
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", alignItems: "baseline", gap: 8 }}>
      <span style={{ fontWeight: 600, color: guessed ? t.subtle : t.ink, fontStyle: guessed ? "italic" : "normal" }}>
        {ROLE_LABEL[role]}{guessed ? " ·guess" : ""}
      </span>
      <span onClick={() => setEditing(true)} title={guessed ? "Guessed from the hostname — click to set the real role" : "Change role"}
        style={{ cursor: "pointer", fontSize: 12, color: t.accent }}>change</span>
    </span>
  );
}

function SiteCell({ addr, legacyName, site, sites, onAssign }:
  { addr: string; legacyName?: string; site: string; sites: string[]; onAssign: (addr: string, s: string, legacyName?: string) => void }) {
  const assigned = site !== "Unassigned";
  const [editing, setEditing] = React.useState(false);
  const [val, setVal] = React.useState(assigned ? site : "");
  React.useEffect(() => { setVal(assigned ? site : ""); }, [site, assigned]);
  const commit = (v: string) => { setEditing(false); const tv = v.trim(); if (tv !== (assigned ? site : "")) onAssign(addr, tv, legacyName); };
  if (!editing) {
    // Onboarded devices carry a site already → show it read-only with an explicit "change"
    // affordance (rack moves / renames still need a fix path). Stragglers with no site → assign.
    return assigned ? (
      <span style={{ display: "inline-flex", alignItems: "baseline", gap: 8 }}>
        <span style={{ fontWeight: 600, color: t.ink }}>{site}</span>
        <span onClick={() => setEditing(true)} title="Change site" style={{ cursor: "pointer", fontSize: 12, color: t.accent }}>change</span>
      </span>
    ) : (
      <span onClick={() => setEditing(true)} title="Assign a site"
        style={{ cursor: "pointer", fontWeight: 600, color: t.subtle, borderBottom: `1px dashed ${t.border}`, paddingBottom: 1 }}>
        + assign
      </span>
    );
  }
  return <SitePicker value={val} sites={sites} onChange={setVal} onCommit={commit} autoFocus style={{ width: 150, borderColor: t.accent, padding: "3px 7px" }} />;
}

type Row = { device: string; ip: string; label: string; status: "up" | "down" | "unmonitored"; role: string; roleExact: Role; roleGuessed: boolean; site: string };
type SortKey = "status" | "device" | "ip" | "site" | "role";
const COLS: { key: SortKey; label: string }[] = [
  { key: "status", label: "Status" },
  { key: "device", label: "Device" },
  { key: "ip", label: "Mgmt IP" },
  { key: "site", label: "Site" },
  { key: "role", label: "Role" },
];

export const Devices = () => {
  const nav = useNavigate();
  const q = useFleet();
  const { map, sites: knownSites, assign } = useSites();
  const { map: roleMap, assignRole } = useRoles();
  const rows: Row[] = q.rows.map((r) => ({ device: r.device, ip: r.ip, label: r.label, status: !r.monitored ? "unmonitored" : r.up ? "up" : "down",
    role: roleGroupOf(roleFor(roleMap, r.ip, r.device)), roleExact: roleFor(roleMap, r.ip, r.device),
    roleGuessed: roleIsInferred(roleMap, r.ip), site: siteOf(map, r.ip, r.device) }));

  const [status, setStatus] = useState("all");
  const [role, setRole] = useState("all");
  const [site, setSite] = useState("all");
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("status");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  // BULK ASSIGN. Site scoping is the whole scale strategy — Topology, Overview and the Fleet
  // filters are all per-site — and it only works if devices HAVE a site. Assigning one row at a
  // time made that a chore at four devices and a non-starter at forty, so "Unassigned" quietly
  // became the largest site. Selection is by management address, the same key sites.ts and
  // roles.ts store against.
  const [sel, setSel] = useState<Set<string>>(new Set());
  // RETIRE, FROM THE PAGE THAT CAN FIND THINGS. Until now the only route was deleting a
  // monitoring configuration by API and then acknowledging what had already happened — which
  // means a customer could not retire anything at all. Fleet is the right home for it because
  // retiring is a find-then-act task and this is the only page with search, site, role and
  // status filters; Configuration has a flat list.
  const { acknowledge } = useAcknowledgedDevices();
  const [retiring, setRetiring] = useState<Row | null>(null);
  const [retireBusy, setRetireBusy] = useState(false);
  const [retireMsg, setRetireMsg] = useState<{ tone: "ok" | "err"; msg: string } | null>(null);

  async function doRetire(r: Row) {
    setRetireBusy(true);
    const res = await retireDevicePolling({ ip: r.ip, name: r.device });
    setRetireBusy(false);
    setRetiring(null);
    if (!res.ok && !res.removed?.length) {
      setRetireMsg({ tone: "err", msg: res.error || `Could not retire ${r.label}.` });
      return;
    }
    // Acknowledge REGARDLESS of how much intent came off. The configurations are gone or
    // shrinking, the entity cannot be deleted at all (405), and leaving the row on the live
    // fleet after the operator affirmed the retirement is the behaviour this whole feature
    // exists to remove. Reversible from the Retired tab.
    acknowledge(r.ip);
    refreshConfigured();   // intent just changed on the tenant; the 60s cache would hide it
    const n = res.removed?.length ?? 0;
    setRetireMsg(res.partial
      ? { tone: "err", msg: `${r.label}: withdrawn from ${n} configuration${n === 1 ? "" : "s"}, but ${res.failed?.length} could not be updated — it may still be polled. See Retired.` }
      : { tone: "ok", msg: `${r.label} retired — withdrawn from ${n} configuration${n === 1 ? "" : "s"}. It is on the Retired tab and can be restored from there.` });
    q.refresh();
  }
  const toggleSel = (ip: string) => setSel((p) => { const n = new Set(p); n.has(ip) ? n.delete(ip) : n.add(ip); return n; });

  const siteList = Array.from(new Set(rows.map((r) => r.site))).sort();
  const SITE_OPTS = [{ value: "all", label: "All sites" }, ...siteList.map((s) => ({ value: s, label: s }))];

  const filtered = rows.filter(
    (r) =>
      (status === "all" || r.status === status) &&
      (role === "all" || r.role === role) &&
      (site === "all" || r.site === site) &&
      (!search || r.label.toLowerCase().includes(search) || r.device.toLowerCase().includes(search) || String(r.ip).includes(search)),
  );

  // down sorts first when ascending, so an outage surfaces at the top of the table
  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    const val = (r: Row, k: SortKey) => (k === "status" ? (r.status === "down" ? 0 : r.status === "unmonitored" ? 1 : 2) : String((r as any)[k]).toLowerCase());
    return [...filtered].sort((a, b) => {
      const va = val(a, sortKey), vb = val(b, sortKey);
      return (va < vb ? -1 : va > vb ? 1 : 0) * dir;
    });
  }, [filtered, sortKey, sortDir]);

  const upCount = rows.filter((r) => r.status === "up").length;
  // Count only devices we actually poll. An LLDP-discovered device we do not monitor is not
  // "down" — subtracting it from the total would report a healthy network as failing.
  const monCount = rows.filter((r) => r.status !== "unmonitored").length;
  const downCount = monCount - upCount;
  const unmonCount = rows.length - monCount;
  const roleCount = new Set(rows.map((r) => r.role)).size;

  const setSort = (k: SortKey) => {
    if (k === sortKey) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(k); setSortDir("asc"); }
  };

  const cell: React.CSSProperties = { padding: "10px 16px", borderBottom: `1px solid ${t.border}` };

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1000 }}>
      <div>
        <Heading level={2}>Devices</Heading>
        <Paragraph>Live fleet from SNMP. Status is real reachability — a device answering in the last 5 minutes is up, otherwise down.</Paragraph>
      </div>

      <LifecyclePanel onViewRetired={() => setStatus("retired")} />

      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Devices" value={rows.length} sub="in the fleet" accent={t.accent} />
        <StatTile label="Sites" value={siteList.length} sub={siteList.join(" · ")} accent={t.accent} />
        <StatTile label="Reachable" value={`${upCount}/${monCount}`} sub={downCount > 0 ? `${downCount} down${unmonCount ? ` · ${unmonCount} not monitored` : ""}` : unmonCount ? `all up · ${unmonCount} not monitored` : "all up"} accent={downCount > 0 ? t.down : t.up} />
        <StatTile label="Roles" value={roleCount} sub="core · access · wan · ap · power" accent={t.accent} />
      </Flex>

      <Flex gap={12} alignItems="center" flexWrap="wrap">
        <Segmented options={STATUS_OPTS} value={status} onChange={setStatus} />
        {status !== "retired" && siteList.length > 1 ? <Segmented options={SITE_OPTS} value={site} onChange={setSite} /> : null}
        {status !== "retired" && <Segmented options={ROLE_OPTS} value={role} onChange={setRole} />}
        {status !== "retired" && (
          <input
            placeholder="Search name or IP…"
            value={search}
            onChange={(e) => setSearch(e.target.value.toLowerCase().trim())}
            style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "7px 11px", color: t.ink, fontSize: 15, minWidth: 180 }}
          />
        )}
        {status !== "retired" && (
          <Text style={{ color: t.subtle, fontSize: 14 }}>
            {sorted.length} of {rows.length}
          </Text>
        )}
      </Flex>

      {status === "retired" ? (
        <RetiredTable />
      ) : (
      <>
      {retireMsg ? (
        <div style={{ border: `1px solid ${retireMsg.tone === "ok" ? t.up : t.down}44`,
                      background: t.cardSubtle, borderRadius: 8, padding: "8px 12px", fontSize: 13 }}>
          <Flex gap={8} style={{ alignItems: "center", flexWrap: "wrap" }}>
            <Text style={{ color: retireMsg.tone === "ok" ? t.up : t.down, fontWeight: 600 }}>
              {retireMsg.tone === "ok" ? "Retired" : "Partly retired"}
            </Text>
            <Text style={{ color: t.subtle }}>{retireMsg.msg}</Text>
            <button onClick={() => setRetireMsg(null)}
                    style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", fontSize: 13 }}>dismiss</button>
          </Flex>
        </div>
      ) : null}
      {retiring ? (
        <RetireConfirm row={retiring} busy={retireBusy}
                       onCancel={() => setRetiring(null)} onConfirm={() => void doRetire(retiring)} />
      ) : null}
      <IntentNote intent={(q as any).intent} sources={(q as any).sources} />
      <BulkBar
        selected={sel} sites={knownSites}
        onSite={(site) => { sel.forEach((ip) => assign(ip, site)); setSel(new Set()); }}
        onRole={(r) => { sel.forEach((ip) => assignRole(ip, r)); setSel(new Set()); }}
        onClear={() => setSel(new Set())}
      />
      <Panel title="Fleet" tag={<Tag>live</Tag>} style={{ padding: 0 }}>
        {q.isLoading ? (
          <Text style={{ color: t.subtle, padding: 16, display: "block" }}>Loading…</Text>
        ) : q.error ? (
          <Text style={{ color: t.down, padding: 16, display: "block" }}>Query error: {String((q.error as any)?.message ?? q.error)}</Text>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 15 }}>
              <thead>
                <tr>
                  <th style={{ ...cell, width: 30, textAlign: "left" }}>
                    <input
                      type="checkbox"
                      aria-label="Select all shown"
                      // Selects only what is CURRENTLY FILTERED, never the whole fleet — the
                      // filters are how you scope a bulk change, so honouring them is the safety.
                      checked={sorted.length > 0 && sorted.every((r) => sel.has(r.ip))}
                      onChange={(e) => setSel(e.target.checked ? new Set(sorted.map((r) => r.ip)) : new Set())}
                      style={{ cursor: "pointer" }}
                    />
                  </th>
                  {COLS.map((c) => {
                    const active = sortKey === c.key;
                    return (
                      <th
                        key={c.key}
                        onClick={() => setSort(c.key)}
                        title={`Sort by ${c.label}`}
                        style={{ textAlign: "left", padding: "11px 16px", color: active ? t.ink : t.subtle, fontWeight: 600, borderBottom: `1px solid ${t.border}`, cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }}
                      >
                        {c.label}
                        <span style={{ marginLeft: 6, opacity: active ? 0.9 : 0.28, fontSize: 11 }}>{active ? (sortDir === "asc" ? "▲" : "▼") : "↕"}</span>
                      </th>
                    );
                  })}
                  <th style={{ ...cell, width: 60 }} />
                </tr>
              </thead>
              <tbody>
                {sorted.map((r, i) => (
                  <tr key={i} onClick={() => nav(`/device/${encodeURIComponent(r.ip || r.device)}`)} style={{ cursor: "pointer", opacity: r.status === "up" ? 1 : 0.72 }}>
                    <td style={{ ...cell, width: 30 }} onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={sel.has(r.ip)} onChange={() => toggleSel(r.ip)}
                             aria-label={`Select ${r.label}`} style={{ cursor: "pointer" }} />
                    </td>
                    <td style={cell}>
                      {/* "not monitored" was rendered with DOWN styling — red dot, red text — so a
                          neighbour LLDP found but nobody asked us to poll looked like a failure.
                          Pill already has a neutral variant; the row text was right all along and
                          only the colour lied. (Measured 2026-08-03: `transformers` 192.168.1.1.) */}
                      <Pill status={r.status === "up" ? "up" : r.status === "unmonitored" ? "neutral" : "down"}>
                        {r.status === "unmonitored" ? "not monitored" : r.status}
                      </Pill>
                    </td>
                    <td style={{ ...mono, ...cell, fontWeight: 600 }}>{r.label}</td>
                    <td style={{ ...mono, ...cell, color: t.subtle }}>{r.ip}</td>
                    <td style={cell} onClick={(e) => e.stopPropagation()}><SiteCell addr={r.ip} legacyName={r.device} site={r.site} sites={knownSites} onAssign={assign} /></td>
                    <td style={cell} onClick={(e) => e.stopPropagation()}><RoleCell addr={r.ip} role={r.roleExact} guessed={r.roleGuessed} onAssign={assignRole} /></td>
                    <td style={{ ...cell, textAlign: "right" }} onClick={(e) => e.stopPropagation()}>
                      {/* TWO ACTIONS, because they are two different intents and conflating them
                          makes every reversible act carry an irreversible cost.
                            hide   — acknowledge only. Off Fleet/Overview/Topology, STILL POLLED,
                                     undone in one click. This is the clutter/demo/re-cabling case.
                            retire — withdraws the monitoring configuration. Stops collection and
                                     frees the licence, and cannot be undone with a click because
                                     re-onboarding needs a credential the app does not retain. */}
                      <Flex gap={6} style={{ justifyContent: "flex-end" }}>
                        <button onClick={() => acknowledge(r.ip)} title={`Hide ${r.label} from the live views — still polled, undo any time from Retired`}
                                style={{ background: "none", border: 0, color: t.subtle, cursor: "pointer",
                                         fontSize: 12.5, padding: "2px 4px" }}>
                          hide
                        </button>
                        <button onClick={() => setRetiring(r)} title={`Retire ${r.label} — stops polling`}
                                style={{ background: "none", border: 0, color: t.subtle, cursor: "pointer",
                                         fontSize: 12.5, padding: "2px 4px" }}>
                          retire
                        </button>
                      </Flex>
                    </td>
                  </tr>
                ))}
                {sorted.length === 0 && (
                  <tr>
                    <td colSpan={COLS.length + 2} style={{ textAlign: "center", color: t.subtle, padding: 22 }}>
                      No devices match this filter
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      </>
      )}
    </Flex>
  );
};



/* Bulk site/role assignment. Listed in the architecture proposal as a blocker, and it is a real
   one rather than a convenience: every scale mechanism in this app — Topology's per-site canvas,
   Overview's site strip, the Fleet site filter — keys off a site the operator has to set by hand,
   one row at a time. At four Branch-A devices that is tedious; at the ~30-device target it is the
   reason everything ends up in "Unassigned", which is the one bucket none of those mechanisms can
   help with. Applies to the CURRENT SELECTION only, and the select-all honours the active
   filters, so "all access switches at Branch-A" is a filter plus two clicks. */
function BulkBar({ selected, sites, onSite, onRole, onClear }: {
  selected: Set<string>; sites: string[];
  onSite: (s: string) => void; onRole: (r: Role) => void; onClear: () => void;
}) {
  const [site, setSite] = React.useState("");
  if (!selected.size) return null;
  return (
    <div style={{ border: `1px solid ${t.accent}55`, background: t.cardSubtle, borderRadius: 8,
                  padding: "8px 12px" }}>
      <Flex gap={8} style={{ alignItems: "center", flexWrap: "wrap" }}>
        <Text style={{ fontWeight: 700 }}>{selected.size} selected</Text>
        <SitePicker
          value={site} sites={sites} onChange={setSite}
          onCommit={(v) => { const tv = v.trim(); if (tv) { onSite(tv); setSite(""); } }}
          style={{ width: 170, padding: "3px 7px" }}
        />
        <Text style={{ color: t.subtle, fontSize: 13 }}>set site (Enter)</Text>
        <span style={{ color: t.border }}>|</span>
        <select
          defaultValue=""
          onChange={(e) => { if (e.target.value) { onRole(e.target.value as Role); e.target.value = ""; } }}
          style={{ background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 6,
                   color: t.ink, padding: "3px 7px", fontSize: 13, appearance: "auto" }}
        >
          <option value="" disabled>set role…</option>
          {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
        </select>
        <button onClick={onClear}
                style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", fontSize: 13 }}>
          clear
        </button>
      </Flex>
    </div>
  );
}


/* TWO STEPS, ON PURPOSE. Retirement hides a device from Fleet, Overview and Topology, and the
   inferred version of this — "no configuration, so assume retired" — is what erased the entire
   fleet earlier today. What makes hiding trustworthy is that a human affirmed it: an explicit
   action, then a confirmation naming the device and stating what will happen. Reversible from the
   Retired tab, and it says so, because an operator who believes an action is permanent will not
   take it and will leave the clutter instead. */
function RetireConfirm({ row, busy, onCancel, onConfirm }:
  { row: { label: string; ip: string; status: string }; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  return (
    <div style={{ border: `1px solid ${t.warn}55`, background: t.warnBg, borderRadius: 8, padding: "12px 14px" }}>
      <Flex flexDirection="column" gap={8}>
        <Text style={{ fontWeight: 700, color: t.warn }}>Retire {row.label}?</Text>
        <Text style={{ fontSize: 13, color: t.subtle }}>
          This removes {row.ip} from every monitoring configuration that polls it, so Dynatrace
          stops collecting from the device. It then appears only under <b>Retired</b> — not on
          Fleet, Overview or Topology.
          {row.status === "up" ? " This device is currently UP and reporting." : ""}
        </Text>
        <Text style={{ fontSize: 12.5, color: t.subtle }}>
          Historical data is kept, and the device entity remains in Dynatrace — entities cannot be
          deleted. You can restore it from the Retired tab.
        </Text>
        <Flex gap={8} style={{ marginTop: 2 }}>
          <button onClick={onConfirm} disabled={busy}
                  style={{ background: t.warn, color: "#fff", border: 0, borderRadius: 6,
                           padding: "6px 14px", fontSize: 13, fontWeight: 600,
                           cursor: busy ? "wait" : "pointer", opacity: busy ? 0.6 : 1 }}>
            {busy ? "Retiring…" : "Yes, retire it"}
          </button>
          <button onClick={onCancel} disabled={busy}
                  style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 6,
                           color: t.ink, padding: "6px 14px", fontSize: 13, cursor: "pointer" }}>
            Cancel
          </button>
        </Flex>
      </Flex>
    </div>
  );
}

/* ── what the app actually read from the extension configurations ────────────
   This is a DIAGNOSTIC, and it exists because the read it reports on cannot be observed any
   other way. It goes to /platform/extensions/v2/..., which rejects both an Api-Token and a
   platform token (403, tried both) — so when the app and the tenant disagree about which devices
   are configured, the browser is the only place that disagreement is visible. Without this the
   only symptom is a fleet full of grey "not monitored" rows and no way to tell whether the
   configurations are missing or merely unread. Shows the counts inline and the addresses behind
   a toggle; loud only when a read actually failed. */
function IntentNote({ intent, sources }: { intent: any; sources?: any }) {
  const [open, setOpen] = React.useState(false);
  if (!intent) return null;
  const configured: string[] = intent.configured ?? [];
  const unconfigured: string[] = intent.unconfigured ?? [];
  const skipped: string[] = intent.skipped ?? [];
  const broken = skipped.filter((sk) => sk.includes("("));   // "(…)" carries the error text
  const down: string[] = sources?.down ?? [];
  const bad = intent.failed || broken.length > 0;
  // Silent only when there is genuinely nothing to explain: everything reporting is configured
  // and nothing is being called down.
  if (!bad && !unconfigured.length && !down.length) return null;

  const tone = bad ? t.warn : t.subtle;
  return (
    <div style={{ border: `1px solid ${tone}33`, background: bad ? t.warnBg : "transparent",
                  borderRadius: 8, padding: "8px 12px", fontSize: 13, color: t.subtle }}>
      <Flex gap={8} style={{ alignItems: "center", flexWrap: "wrap" }}>
        <Text style={{ color: tone, fontWeight: 600 }}>
          {intent.failed ? "Monitoring configurations could not be read"
            : broken.length ? `${broken.length} extension${broken.length > 1 ? "s" : ""} could not be read`
            : unconfigured.length
              ? `${unconfigured.length} device${unconfigured.length > 1 ? "s" : ""} reporting without a configuration`
              : `${down.length} device${down.length > 1 ? "s" : ""} not seen in the last 5 minutes`}
        </Text>
        <Text>
          roster {sources?.rosterCount ?? "?"} · answering now {sources?.liveCount ?? "?"} · configured {configured.length}
          {intent.scanned != null ? ` (from ${intent.scanned} extension${intent.scanned === 1 ? "" : "s"})` : ""}
        </Text>
        <button onClick={() => setOpen((v) => !v)}
                style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", fontSize: 13, padding: 0 }}>
          {open ? "hide" : "details"}
        </button>
      </Flex>
      {open ? (
        <Flex gap={24} style={{ marginTop: 8, flexWrap: "wrap", alignItems: "flex-start" }}>
          <IpList title={`Called down — in the 24h roster, silent for 5m (${down.length})`} ips={down} />
          <IpList title={`Read as configured (${configured.length})`} ips={configured} />
          <IpList title={`Reporting, not in any config (${unconfigured.length})`} ips={unconfigured} />
          {skipped.length ? (
            <div>
              <Text style={{ fontWeight: 600, color: broken.length ? t.warn : t.subtle }}>
                Extensions returning no config list ({skipped.length})
              </Text>
              <div style={{ ...mono, fontSize: 12, marginTop: 2 }}>
                {skipped.map((sk) => <div key={sk}>{sk}</div>)}
              </div>
            </div>
          ) : null}
        </Flex>
      ) : null}
    </div>
  );
}

function IpList({ title, ips }: { title: string; ips: string[] }) {
  return (
    <div>
      <Text style={{ fontWeight: 600 }}>{title}</Text>
      <div style={{ ...mono, fontSize: 12, marginTop: 2 }}>
        {ips.length ? ips.map((ip) => <div key={ip}>{ip}</div>) : <div>—</div>}
      </div>
    </div>
  );
}

/* ── device lifecycle: intent vs observation ────────────────────────────────
   See lib/lifecycle.ts for why this exists. The short version: metric silence means DOWN or
   RETIRED or BROKEN POLLING and they are indistinguishable from the metric alone, so the app
   reads INTENT — a monitoring configuration — and crosses it with observation.

   The rule that matters: a CONFIGURED device that has gone quiet is a fault at any age and is
   never hidden. Only removing the configuration retires a device, and that is an act somebody
   performed rather than a timeout this code inferred. */
function LifecyclePanel({ onViewRetired }: { onViewRetired: () => void }) {
  const { rows, isLoading, intentUnavailable } = useDeviceLifecycle();
  if (isLoading) return null;

  const count = (s: string) => rows.filter((r) => r.state === s).length;
  const down = rows.filter((r) => r.state === "down");
  const retiredCount = count("decommissioned"); // archived ones are counted inside useDeviceLifecycle's own bucketing on the Retired tab, not here

  const chip = (label: string, v: number, colour: string, hint: string) => (
    <span title={hint} style={{ display: "inline-flex", alignItems: "center", gap: 7, border: `1px solid ${colour}`,
      borderRadius: 20, padding: "4px 11px", fontSize: 12.5, color: colour, fontWeight: v ? 700 : 400 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: colour }} />{label} {v}
    </span>
  );

  return (
    <Panel title="Lifecycle" tag={<Tag>intent vs observation</Tag>}>
      {intentUnavailable ? (
        // Never invent intent. If the configuration list cannot be read, saying "nothing is
        // configured" would reclassify the whole fleet as decommissioned — the exact false
        // negative this panel exists to prevent.
        <Text style={{ color: t.warn, fontSize: 13 }}>
          Could not read the monitoring configurations, so retired and down cannot be told apart.
          Showing reachability only — nothing here is classified as retired.
        </Text>
      ) : (
        <>
          <Flex gap={8} flexWrap="wrap" style={{ marginBottom: 10 }}>
            {chip("up", count("up"), t.up, "configured and reporting")}
            {chip("down", count("down"), t.down, "configured but silent — a fault at any age, never hidden")}
            {chip("unmanaged", count("unmanaged"), t.warn, "reporting data, but no monitoring configuration asks for it — an API-pushed source, or a config this app cannot see")}
            {chip("discovered", count("discovered"), t.subtle, "seen via LLDP, nobody polls it")}
          </Flex>
          {down.length > 0 && (
            <Text style={{ fontSize: 13, color: t.down, display: "block", marginBottom: 6 }}>
              <strong>{down.length} configured {down.length === 1 ? "device is" : "devices are"} not answering.</strong>{" "}
              Somebody asked for {down.length === 1 ? "it" : "them"} to be polled, so this is a fault — not a retirement.
            </Text>
          )}
          {retiredCount > 0 && (
            // NOT the device list — that lives in exactly one place, the Retired tab (see
            // RetiredTable below). This page shows a count and a door, never the names, so a
            // retired device cannot be "seen" incidentally while looking at the live fleet.
            <Text style={{ fontSize: 12.5, color: t.subtle, display: "block" }}>
              {retiredCount} device{retiredCount === 1 ? "" : "s"} no longer {retiredCount === 1 ? "has" : "have"} a monitoring configuration.{" "}
              <button onClick={onViewRetired} style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", padding: 0, fontSize: 12.5 }}>
                Review under Retired →
              </button>
            </Text>
          )}
        </>
      )}
    </Panel>
  );
}

/* ── the ONE place a retired device can be seen ───────────────────────────────
   Reached only via the "Retired" status option — never rendered inline on the main Devices
   view, never counted in Overview, never drawn on Topology (see useAcknowledgedDevices' use
   there). Acknowledging here does not delete anything — the platform will not let us (DELETE
   /api/v2/entities returns 405) — it only moves a row into the archived, collapsed count. */
function RetiredTable() {
  const { archived, rows, isLoading, acknowledge, unacknowledge } = useDeviceLifecycle();
  const nav = useNavigate();
  const [showArchived, setShowArchived] = React.useState(false);
  const decomm = rows.filter((r) => r.state === "decommissioned");
  /* HIDDEN IS NOT RETIRED, and the restore path differs, so the tab must not present them as one
     thing. A hidden device still has a configuration and is still being polled — un-hiding is
     instant. A retired device had its intent withdrawn; "restoring" it is re-onboarding, which
     needs a credential this app never keeps. An undo button that silently fails to bring polling
     back would be worse than no button: the device reappears, reports nothing, and is classified
     retired again on the next render. */
  const hidden = archived.filter((r) => r.configured);
  if (isLoading) return <Text style={{ color: t.subtle, padding: 16, display: "block" }}>Loading…</Text>;

  return (
    <Panel title="Retired" tag={<Tag>no configuration · history only</Tag>}>
      {decomm.length === 0 && archived.length === 0 ? (
        <Text style={{ color: t.subtle, fontSize: 14 }}>Nothing retired right now.</Text>
      ) : (
        <>
          {decomm.length > 0 && (
            <Flex flexDirection="column" gap={4} style={{ marginBottom: archived.length ? 14 : 0 }}>
              <Text style={{ fontSize: 12.5, color: t.subtle }}>
                No configuration asks for these — only observed history remains:
              </Text>
              {decomm.map((r) => (
                <Flex key={r.ip} alignItems="center" gap={8}>
                  <Text style={{ fontSize: 13, color: t.ink, ...mono }}>
                    {r.name || r.ip}{r.lastSeenDaysAgo != null ? ` — seen within ${r.lastSeenDaysAgo}d` : ""}
                  </Text>
                  <button onClick={() => nav(`/setup?ip=${encodeURIComponent(r.ip)}&name=${encodeURIComponent(r.name || "")}`)}
                    title="Re-onboard this device. Not an undo — retiring withdrew the monitoring configuration, and re-creating it needs a credential the app does not store."
                    style={{ background: "none", border: `1px solid ${t.accent}66`, borderRadius: 6, color: t.accent, cursor: "pointer", padding: "1px 8px", fontSize: 12 }}>
                    restore →
                  </button>
                  <button onClick={() => acknowledge(r.ip)}
                    title="Confirm this is retired on purpose — moves it into the archived count. It cannot be deleted from the platform, so this does not remove it, only stops it being listed here."
                    style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 6, color: t.subtle, cursor: "pointer", padding: "1px 8px", fontSize: 12 }}>
                    acknowledge
                  </button>
                </Flex>
              ))}
            </Flex>
          )}
          {hidden.length > 0 && (
            <Flex flexDirection="column" gap={4} style={{ marginBottom: 14 }}>
              <Text style={{ fontSize: 12.5, color: t.subtle }}>
                Hidden, but still configured and still being polled — collection never stopped:
              </Text>
              {hidden.map((r) => (
                <Flex key={r.ip} alignItems="center" gap={8}>
                  <Text style={{ fontSize: 13, color: t.ink, ...mono }}>{r.name || r.ip}</Text>
                  <button onClick={() => unacknowledge(r.ip)}
                    title="Put it back on the live views. Instant — nothing was ever withdrawn."
                    style={{ background: "none", border: `1px solid ${t.accent}66`, borderRadius: 6, color: t.accent, cursor: "pointer", padding: "1px 8px", fontSize: 12 }}>
                    unhide
                  </button>
                </Flex>
              ))}
            </Flex>
          )}
          {archived.length > 0 && (
            /* A COUNT, never a silent hide. These cannot be deleted from the platform, so the
               honest move is to still name them on request rather than pretend they are gone. */
            <Text style={{ fontSize: 12.5, color: t.subtle, display: "block" }}>
              {archived.length} archived (acknowledged, or nothing seen for over {ARCHIVE_AFTER_DAYS} days).{" "}
              <button onClick={() => setShowArchived(!showArchived)}
                style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", padding: 0, fontSize: 12.5 }}>
                {showArchived ? "hide" : "show"}
              </button>
              {showArchived && (
                <Flex flexDirection="column" gap={4} style={{ marginTop: 6 }}>
                  {archived.map((r) => (
                    <Flex key={r.ip} alignItems="center" gap={8}>
                      <span style={mono}>{r.name || r.ip}</span>
                      {r.acknowledged && (
                        <button onClick={() => unacknowledge(r.ip)}
                          title="Undo — this will reappear above instead of in the archived count"
                          style={{ background: "none", border: 0, color: t.accent, cursor: "pointer", padding: 0, fontSize: 11.5 }}>
                          unacknowledge
                        </button>
                      )}
                    </Flex>
                  ))}
                </Flex>
              )}
            </Text>
          )}
        </>
      )}
    </Panel>
  );
}
