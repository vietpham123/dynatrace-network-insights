import React, { createContext, useContext, useState } from "react";
import { useLocation } from "react-router-dom";
import { t } from "../theme";

// App-wide look-back window for the historical/log views (NetFlow, Config, Events, Alerts,
// Overview summary). Defaults to a tight 2h so query scan cost (Grail bills per GiB scanned)
// stays low unless the operator deliberately widens it. The live operational status queries
// (fleet reachability, RCA) keep their own fixed windows and ignore this.
export const TF_OPTIONS = [
  { value: "-30m", label: "Last 30 min" },
  { value: "-1h", label: "Last 1 hour" },
  { value: "-2h", label: "Last 2 hours" },
  { value: "-6h", label: "Last 6 hours" },
  { value: "-12h", label: "Last 12 hours" },
  { value: "-24h", label: "Last 24 hours" },
  { value: "-3d", label: "Last 3 days" },
  { value: "-7d", label: "Last 7 days" },
  { value: "-30d", label: "Last 30 days" },
];

const TfCtx = createContext<{ tf: string; setTf: (v: string) => void }>({ tf: "-2h", setTf: () => {} });

export const TimeframeProvider = ({ children }: { children: React.ReactNode }) => {
  const [tf, setTf] = useState("-2h");
  return <TfCtx.Provider value={{ tf, setTf }}>{children}</TfCtx.Provider>;
};

export const useTimeframe = () => useContext(TfCtx);

// Routes that DO honour the look-back. Everything else hides the control rather than showing
// an inert one.
//
// This is not new policy — the note at the top of this file already said the live operational
// views "keep their own fixed windows and ignore this". The bar simply rendered globally in
// App.tsx regardless, so on 7 of 12 pages an operator could change it and nothing happened.
// A visible control that does nothing is worse than no control: it makes the reader distrust
// the numbers on the page.
//
// Two reasons a page is absent from this list, and they are different:
//   * LIVE views (Devices, Topology) are "right now" by definition — reachability is a 5-minute
//     window and the topology is current state. They carry a LIVE tag saying so.
//   * SETUP views (Configuration, Wizard, Configure, Data) have no time dimension at all.
const TF_ROUTES = [
  "/",            // Overview
  "/netflow",
  "/config",      // Config changes
  "/alerts",
  "/events",
  "/device/",     // Device detail — its log + compliance panels are historical
];

const honoursTimeframe = (path: string) =>
  TF_ROUTES.some((r) => (r === "/" ? path === "/" : path.startsWith(r)));

// Small right-aligned selector, rendered only on the routes that actually use it.
export const TimeframeBar = () => {
  const { tf, setTf } = useTimeframe();
  const { pathname } = useLocation();
  if (!honoursTimeframe(pathname)) return null;
  return (
    <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 8, padding: "12px 24px 0" }}>
      <span style={{ fontSize: 12, fontWeight: 600, color: t.subtle }}>Look-back</span>
      <select
        value={tf}
        onChange={(e) => setTf(e.target.value)}
        style={{ font: "inherit", fontSize: 13, fontWeight: 600, color: t.ink, background: t.cardSubtle, border: `1px solid ${t.border}`, borderRadius: 8, padding: "6px 10px", cursor: "pointer" }}
      >
        {TF_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
};
