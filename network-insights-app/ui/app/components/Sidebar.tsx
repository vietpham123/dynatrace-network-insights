import React from "react";
import { NavLink } from "react-router-dom";
import { getAppVersion } from "@dynatrace-sdk/app-environment";
import { t } from "../theme";
import { useDavis } from "../lib/data";

const groups: { label: string; items: { to: string; label: string; icon: string; end?: boolean }[] }[] = [
  {
    label: "Monitor",
    items: [
      { to: "/", label: "Overview", icon: "▦", end: true },
      { to: "/devices", label: "Devices", icon: "▤" },
      { to: "/topology", label: "Topology", icon: "⧉" },
      { to: "/netflow", label: "NetFlow", icon: "⇄" },
      { to: "/investigate", label: "Investigate", icon: "⌖" },
      { to: "/alerts", label: "Alerts", icon: "◆" },
    ],
  },
  {
    label: "Operate",
    items: [
      { to: "/config", label: "Config & Compliance", icon: "◨" },
      { to: "/events", label: "Events", icon: "◈" },
      { to: "/data", label: "Explore Data", icon: "⌕" },
    ],
  },
  {
    label: "Provision",
    items: [
      { to: "/configuration", label: "Configuration", icon: "⊕" },
    ],
  },
];

const STORE_KEY = "cno.nav.collapsed";

export const Sidebar = () => {
  let version = "";
  try { version = getAppVersion(); } catch { /* runtime not available */ }
  // live active-alert count for the Alerts badge (shares the cached Davis query)
  const { rows: problems } = useDavis();
  const activeAlerts = problems.filter((p: any) => p.status === "ACTIVE").length;

  // collapse state — persists across reloads so the user's real-estate choice sticks
  const [collapsed, setCollapsed] = React.useState<boolean>(() => {
    try { return localStorage.getItem(STORE_KEY) === "1"; } catch { return false; }
  });
  const toggle = () =>
    setCollapsed((c) => {
      const next = !c;
      try { localStorage.setItem(STORE_KEY, next ? "1" : "0"); } catch { /* ignore */ }
      return next;
    });

  return (
    <nav
      style={{
        width: collapsed ? 56 : 214,
        flex: "none",
        alignSelf: "flex-start",
        position: "sticky",
        top: 0,
        borderRight: `1px solid ${t.border}`,
        background: t.card,
        padding: 8,
        height: "calc(100vh - 52px)",
        overflowY: "auto",
        display: "flex",
        flexDirection: "column",
        transition: "width 0.15s ease",
      }}
    >
      {/* collapse toggle — reclaim horizontal real estate */}
      <button
        onClick={toggle}
        title={collapsed ? "Expand navigation" : "Collapse navigation"}
        aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
        style={{
          alignSelf: collapsed ? "center" : "flex-end",
          border: `1px solid ${t.border}`,
          background: t.cardSubtle,
          color: t.subtle,
          cursor: "pointer",
          borderRadius: 7,
          width: 28,
          height: 28,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 14,
          lineHeight: 1,
          marginBottom: 4,
        }}
      >
        {collapsed ? "»" : "«"}
      </button>

      {groups.map((g, gi) => (
        <div key={g.label}>
          {collapsed ? (
            gi > 0 ? <div style={{ height: 1, background: t.border, margin: "10px 8px 6px" }} /> : <div style={{ height: 8 }} />
          ) : (
            <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.09em", color: t.subtle, padding: "14px 10px 6px", fontWeight: 600 }}>
              {g.label}
            </div>
          )}
          {g.items.map((it) => (
            <NavLink
              key={it.to}
              to={it.to}
              end={it.end}
              title={collapsed ? it.label : undefined}
              style={({ isActive }) => ({
                display: "flex",
                alignItems: "center",
                gap: collapsed ? 0 : 11,
                justifyContent: collapsed ? "center" : "flex-start",
                padding: collapsed ? "9px 0" : "9px 11px",
                borderRadius: 8,
                textDecoration: "none",
                fontSize: 14,
                fontWeight: 600,
                color: isActive ? t.ink : t.subtle,
                background: isActive ? t.emph : "transparent",
                position: "relative",
              })}
            >
              <span style={{ width: 17, textAlign: "center", fontSize: 15, opacity: 0.85 }}>{it.icon}</span>
              {!collapsed && <span>{it.label}</span>}
              {it.to === "/alerts" && activeAlerts > 0 ? (
                collapsed ? (
                  <span style={{ position: "absolute", top: 3, right: 6, background: t.down, color: "#fff", fontSize: 9, fontWeight: 700, minWidth: 14, height: 14, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 3px" }}>{activeAlerts}</span>
                ) : (
                  <span style={{ marginLeft: "auto", background: t.down, color: "#fff", fontSize: 11, fontWeight: 700, minWidth: 18, height: 18, borderRadius: 9, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 5px" }}>{activeAlerts}</span>
                )
              ) : null}
            </NavLink>
          ))}
        </div>
      ))}

      {!collapsed && (
        <div style={{ marginTop: "auto", padding: "12px 11px 6px", borderTop: `1px solid ${t.border}`, color: t.subtle, fontSize: 12 }}>
          Network Insights{version && version !== "dt.missing.app.version" ? ` · v${version}` : ""}
        </div>
      )}
    </nav>
  );
};
