import { t } from "../theme";

// Shared formatting helpers — these were copy-pasted verbatim across Overview / Events /
// DeviceDetail (a new log.source added in one would show raw in the others).

// Grail timestamp -> "MM-DD HH:MM:SS" (drops the year + sub-second for the compact feeds).
export function fmt(ts: any): string {
  try {
    return new Date(ts).toISOString().replace("T", " ").slice(5, 19);
  } catch {
    return String(ts);
  }
}

// A log source -> [short label, color] for the trap / syslog / config paging feeds.
export function badge(source: string): [string, string] {
  if (source === "snmptraps") return ["TRAP", t.down];
  if (source === "network.config") return ["CONFIG", t.accent];
  return ["SYSLOG", t.warn];
}
