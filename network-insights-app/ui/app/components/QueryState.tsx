import React from "react";
import { t } from "../theme";

/* Shared query-state surfaces so a Grail/Davis FAILURE never renders as a false "all clear" — the
   worst failure mode for a NOC tool (an operator reads "no traffic / no problems" when the query
   actually errored). Use QueryState to wrap a panel's body, or ErrorBanner to flag an error above
   content that still renders. (Devices/Alerts/Events/Overview already handle this inline.) */

function errText(error: unknown): string {
  const m = (error as any)?.message || (error as any)?.details?.message || String(error || "");
  return m.length > 180 ? m.slice(0, 180) + "…" : m;
}

export function ErrorBanner({ error, what = "Query" }: { error: unknown; what?: string }) {
  if (!error) return null;
  return (
    <div style={{
      display: "flex", gap: 8, alignItems: "baseline", margin: "0 0 12px", padding: "9px 12px",
      borderRadius: 8, border: `1px solid ${t.down}`, background: t.cardSubtle,
    }}>
      <span style={{ color: t.down, fontWeight: 800, fontSize: 13 }}>⚠ {what} failed</span>
      <span style={{ color: t.subtle, fontSize: 12.5 }}>
        — this is <b style={{ color: t.ink }}>not</b> "no data." {errText(error)}
      </span>
    </div>
  );
}

export function QueryState(props: {
  loading?: boolean; error?: unknown; empty?: boolean; emptyText?: string; children: React.ReactNode;
}) {
  if (props.error) return <ErrorBanner error={props.error} />;
  if (props.loading) return <span style={{ color: t.subtle, fontSize: 14 }}>Loading…</span>;
  if (props.empty) return <span style={{ color: t.subtle, fontSize: 14 }}>{props.emptyText || "No data in the selected window."}</span>;
  return <>{props.children}</>;
}
