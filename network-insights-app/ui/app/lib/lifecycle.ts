import React from "react";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { stateClient } from "@dynatrace-sdk/client-state";
import { useConfiguredDevices } from "./provision";

/* ============================================================================
   DEVICE LIFECYCLE — intent vs observation

   Absence of metrics means four different things and they are indistinguishable from the metric
   alone: the device is DOWN, it was RETIRED, polling BROKE, or it was never onboarded.

   The tempting rule — "silent for 30 days means retired, stop showing it" — resolves that
   ambiguity the wrong way. A device genuinely down for 31 days gets silently reclassified as
   retired and vanishes: a real outage erased by a cleanup rule. That is the same
   absence-as-a-verdict mistake this codebase has made repeatedly, and it is worse here because
   the thing being hidden is a fault.

   A MONITORING CONFIGURATION IS A STATEMENT OF INTENT. Somebody asked for this device to be
   polled, and that is separable from whether it answers. Cross-referencing the two resolves all
   four cases without guessing:

       configured + reporting     -> up
       configured + silent        -> DOWN. A fault at ANY age. Never hidden.
       NOT configured + REPORTING -> unmanaged. It is sending data that nothing asked for —
                                     an API-pushed source, or a config we cannot see. Caught by
                                     testing against live data: the SD-WAN devices arrive via
                                     api_bridge with no monitoring configuration, and an earlier
                                     draft of this file called four actively-reporting devices
                                     "decommissioned". A device that is talking is never retired.
       not configured + history   -> decommissioned. Retirement is the REMOVAL of intent, an act
                                     somebody performed, not a timeout this code inferred.
       not configured + never     -> discovered only (an LLDP neighbour nobody polls)

   AGE DECIDES PROMINENCE, NEVER CLASSIFICATION. A decommissioned device stays listed with its
   last-seen date while it is recent (this is the hardware-refresh view), then collapses behind a
   COUNT. Never a silent hide — a count is not clutter, a disappearance is a lie.
   ============================================================================ */

export type LifecycleState = "up" | "down" | "unmanaged" | "decommissioned" | "discovered";

export type LifecycleRow = {
  ip: string;
  name: string;
  state: LifecycleState;
  configured: boolean;
  lastSeenDaysAgo: number | null;   // null = never seen, or still reporting
  extension?: string;
  acknowledged: boolean;
};

/** Decommissioned devices older than this collapse behind a count. Presentation only —
 *  it never changes whether something is a fault. */
export const ARCHIVE_AFTER_DAYS = 30;

/* ── acknowledging a decommissioned device ────────────────────────────────────
   The platform gives us no way to delete a CUSTOM_DEVICE entity (DELETE /api/v2/entities
   returns 405) and orphaned entities never expire — so a decommissioned device is permanent
   whether we like it or not. What an operator CAN do is say "I've seen this, stop showing it
   at the top" — which is exactly what the age-based archive already does automatically, just
   sooner and on purpose.
   Acknowledging never deletes or reclassifies anything: it only moves a decommissioned row
   into the same archived-count bucket the age rule produces, so it stays reachable behind
   "show" rather than disappearing. Stored the same way site/role assignments are (app-state,
   keyed on the management address — see sites.ts for why address, not name). */
const ACK_KEY = "cno.lifecycle-ack";
type AckMap = Record<string, true>;

async function readAcks(): Promise<AckMap> {
  try {
    const s = await stateClient.getAppState({ key: ACK_KEY });
    const v = (s as { value?: string } | undefined)?.value;
    return v ? (JSON.parse(v) as AckMap) : {};
  } catch { return {}; }
}
async function writeAcks(m: AckMap): Promise<void> {
  await stateClient.setAppState({ key: ACK_KEY, body: { value: JSON.stringify(m), validUntilTime: "now+90d" } });
}

export function useAcknowledgedDevices() {
  const [acked, setAcked] = React.useState<AckMap>({});
  React.useEffect(() => { void readAcks().then(setAcked); }, []);
  const acknowledge = React.useCallback((ip: string) => {
    setAcked((prev) => {
      const next = { ...prev, [ip]: true as const };
      void writeAcks(next);
      return next;
    });
  }, []);
  const unacknowledge = React.useCallback((ip: string) => {
    setAcked((prev) => {
      const next = { ...prev }; delete next[ip];
      void writeAcks(next);
      return next;
    });
  }, []);
  return { acked, acknowledge, unacknowledge };
}

const LIVE_Q = `timeseries n = count(cno.if.oper_status), from:-10m, by:{ip = \`device.address\`, dev = sys_name}
  | fieldsAdd n = arraySum(n) | filter n > 0 | fields ip, dev`;

/* LAST SEEN, AS BANDS RATHER THAN AN EXACT DATE.
   DQL has arraySize/arrayLast/arrayIndexOf but NO arrayLastIndex, arrayFirstIndex or arraySlice
   (all three probed against the live tenant), so there is no clean way to find the position of
   the last non-null bucket. Bands are the honest alternative: four windows appended, and the
   NARROWEST window a device appears in is how recently it reported. That is exactly the
   granularity the design needs — recent enough to list, or old enough to archive — and it uses
   only constructs verified to exist.
   APPEND, never a multi-aggregate timeseries: that form inner-joins and one empty window would
   erase the rest. */
const BANDS = [1, 7, 30, 90];
const LAST_SEEN_Q = BANDS.map((d, i) => {
  const leg = `timeseries n = count(cno.if.oper_status), from:-${d}d, by:{ip = \`device.address\`, dev = sys_name}`
    + ` | fieldsAdd s = arraySum(n) | filter s > 0 | fields ip, dev, band = ${d}`;
  return i === 0 ? leg : `| append [ ${leg} ]`;
}).join(" ") + " | summarize c = count(), by:{ip, dev, band}";

export function useDeviceLifecycle(): {
  rows: LifecycleRow[];
  archived: LifecycleRow[];
  isLoading: boolean;
  intentUnavailable: boolean;
  acknowledge: (ip: string) => void;
  unacknowledge: (ip: string) => void;
} {
  const live = useDql({ query: LIVE_Q });
  const hist = useDql({ query: LAST_SEEN_Q });
  // Shared with useFleet() (lib/data.ts) via useConfiguredDevices — see the note on that hook
  // for why the two must never fetch or compute "is this configured" independently.
  const { devices: cfg, ips: configuredSet, isLoading: cfgLoading, failed: cfgFailed } = useConfiguredDevices();
  const { acked, acknowledge, unacknowledge } = useAcknowledgedDevices();

  const liveRows: any[] = (live.data as any)?.records ?? [];
  const histRows: any[] = (hist.data as any)?.records ?? [];

  const liveSet = new Set(liveRows.map((r) => String(r.ip)));
  const nameOf: Record<string, string> = {};
  const narrowest: Record<string, number> = {};
  histRows.forEach((r) => {
    const ip = String(r.ip); const b = Number(r.band);
    if (!ip || !b) return;
    if (r.dev) nameOf[ip] = String(r.dev);
    narrowest[ip] = narrowest[ip] ? Math.min(narrowest[ip], b) : b;
  });
  liveRows.forEach((r) => { if (r.ip && r.dev) nameOf[String(r.ip)] = String(r.dev); });

  const extOf: Record<string, string> = {};
  cfg.forEach((c) => { extOf[c.ip] = c.extension; });

  // If intent could not be read we must NOT invent it. Treating an unreadable config list as
  // "nothing is configured" would reclassify the ENTIRE fleet as decommissioned — the loudest
  // possible false negative from a feature whose whole purpose is to avoid one. Fall back to
  // pure observation and say so.
  //
  // "Unavailable" includes STILL LOADING and SUCCEEDED-BUT-EMPTY, not just an outright error.
  // An empty list is not evidence that nothing is configured: configuredDevices() reads
  // b.items from /platform/extensions/v2/..., and a shape mismatch there returns ok:true with
  // zero devices — identical, from here, to a genuinely empty fleet. On a tenant with roster
  // data the read problem is the likelier explanation, and guessing wrong marks every device
  // retired. Mirrors intentUsable in lib/data.ts; keep the two in step.
  const intentUnavailable = cfgFailed || cfgLoading || configuredSet.size === 0;

  const all = new Set<string>([...liveSet, ...Object.keys(narrowest), ...configuredSet]);
  const rows: LifecycleRow[] = [];
  all.forEach((ip) => {
    const reporting = liveSet.has(ip);
    const configured = configuredSet.has(ip);
    const seenBand = narrowest[ip] ?? null;
    let state: LifecycleState;
    if (intentUnavailable) state = reporting ? "up" : "down";
    else if (configured) state = reporting ? "up" : "down";
    // REPORTING ALWAYS WINS over any retirement verdict. Silence is the only evidence that can
    // support "decommissioned", so a device still sending data cannot be one whatever the
    // configurations say.
    else if (reporting) state = "unmanaged";
    else state = seenBand != null ? "decommissioned" : "discovered";
    rows.push({
      ip, name: nameOf[ip] || "", state, configured,
      lastSeenDaysAgo: reporting ? null : seenBand,
      extension: extOf[ip],
      acknowledged: !!acked[ip],
    });
  });

  // Archiving is a DISPLAY decision and applies only to decommissioned devices. A down device is
  // never archived, however long it has been down — and an acknowledgement on a device that is
  // no longer decommissioned (e.g. it came back and is reporting again) does nothing, because
  // `state` already overrides it below.
  const isArchived = (r: LifecycleRow) =>
    r.state === "decommissioned" &&
    (r.acknowledged || r.lastSeenDaysAgo == null || r.lastSeenDaysAgo > ARCHIVE_AFTER_DAYS);
  const archived = rows.filter(isArchived);
  const visible = rows.filter((r) => !isArchived(r));
  const order: Record<LifecycleState, number> = { down: 0, unmanaged: 1, up: 2, discovered: 3, decommissioned: 4 };
  visible.sort((a, b) => order[a.state] - order[b.state] || a.ip.localeCompare(b.ip));

  return {
    rows: visible, archived,
    isLoading: live.isLoading || hist.isLoading || cfgLoading,
    intentUnavailable, acknowledge, unacknowledge,
  };
}
