import React from "react";
import { stateClient } from "@dynatrace-sdk/client-state";

/* ============================================================================
   NetFlow ingest MODE — the customer's choice of how much flow they export/keep.
   Persisted as one app-scoped state blob (same mechanism as the site map in sites.ts).
   ONE setting drives two things:
     1. the collector config the app hands you  — full or sampled
        (the standalone copies live in Desktop/netflow-collector-configs)
     2. how the NetFlow queries read the data:
          • Full → the data as-is (no scaling)
          • Sampled → multiply volumes by the rate to extrapolate 1-in-N back to true
   ============================================================================ */

export type NetflowMode = "full" | "sampled";
export type NetflowSetting = { mode: NetflowMode; rate: number };
const KEY = "cno.netflow-mode";
const DEFAULT: NetflowSetting = { mode: "full", rate: 100 };
const isMode = (m: any): m is NetflowMode => m === "full" || m === "sampled";

/* Module-level current setting the data hooks read SYNCHRONOUSLY (mirrors CURRENT_WINDOW in
   netflow.ts). Loaded from app-state on mount by useNetflowMode; the view re-keys its data
   subtree on mode+rate so the hooks re-query when it changes. */
export let CURRENT_MODE: NetflowMode = DEFAULT.mode;
export let CURRENT_RATE = DEFAULT.rate;
export function setNetflowModeVars(s: NetflowSetting) { CURRENT_MODE = s.mode; CURRENT_RATE = s.rate > 0 ? s.rate : 1; }

/* Per-flow extrapolation SPLICED INTO the query (sum(bytes * <factor>)) — more accurate than a
   post-hoc ×N because it scales EACH flow by its own exporter-stamped rate, so mixed fleet rates
   (core 1:1000, access 1:100) are each correct.

   A STATED RATE IS NOW HONOURED IN BOTH MODES, which it was not before, and the old behaviour
   under-reported by three orders of magnitude the moment a second exporter appeared. sFlow is
   ALWAYS sampled — outpost runs 1-in-1024, the lowest that switch permits — and it stamps that
   rate on every record. "Full" previously returned "" and did no scaling at all, so those bytes
   were counted raw: 1024x too low. Meanwhile "Sampled" would have applied the manual N to the
   UNSAMPLED IPFIX records as well, inflating them by the same order. Neither mode was right for
   a mixed estate, and a mixed estate is now the normal case.

   So: a record that STATES its rate is always scaled by it. The manual N remains a fallback for
   exporters that sample but do not say so, and only in Sampled mode — an unsampled exporter in
   Full mode still yields a factor of 1, byte-for-byte raw.

   BOTH SPELLINGS ARE READ. Our decoder emits flow.sampling.rate (dotted); BindPlane's native
   sflow receiver emits flow.sampling_rate (underscore). Reading only one silently ignores half
   the fleet, which is exactly the bug this comment exists to prevent recurring. */
const RATE = 'coalesce(toDouble(`flow.sampling.rate`), toDouble(`flow.sampling_rate`))';

export function flowFactorMul(): string {
  const fallback = CURRENT_MODE === "sampled" ? (CURRENT_RATE > 0 ? Math.round(CURRENT_RATE) : 1) : 1;
  return ` * if(${RATE} > 1, ${RATE}, else: ${fallback})`;
}

/** The exporter address, whichever spelling the source used. */
export const SAMPLER_ADDR = 'coalesce(`flow.sampler.address`, `flow.sampler_address`)';
/** The stated sampling rate, whichever spelling the source used. */
export const SAMPLING_RATE = RATE;

async function readSetting(): Promise<{ s: NetflowSetting; validUntil: string | null }> {
  try {
    const st = await stateClient.getAppState({ key: KEY });
    const p = st?.value ? (JSON.parse(st.value) as Partial<NetflowSetting>) : {};
    const mode = isMode(p.mode) ? p.mode : DEFAULT.mode;
    const rate = Number(p.rate) > 0 ? Number(p.rate) : DEFAULT.rate;
    return { s: { mode, rate }, validUntil: (st as any)?.validUntilTime ?? null };
  } catch {
    return { s: { ...DEFAULT }, validUntil: null }; // NotFound on first use → default
  }
}
async function writeSetting(s: NetflowSetting): Promise<void> {
  await stateClient.setAppState({ key: KEY, body: { value: JSON.stringify(s), validUntilTime: "now+90d" } });
}

/* Load + expose the NetFlow mode setting, with a setter. Sets the module vars on load so the data
   hooks see the persisted mode; callers re-key their data subtree on {mode,rate} to re-query.
   Keep-alive re-stamps the ≤90d TTL when within 30d of lapsing (same rationale as sites.ts). */
export function useNetflowMode() {
  const [setting, setSetting] = React.useState<NetflowSetting>({ ...DEFAULT });
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(() => {
    setLoading(true);
    readSetting().then(({ s, validUntil }) => {
      setNetflowModeVars(s);
      setSetting(s);
      setLoading(false);
      const remaining = validUntil ? new Date(validUntil).getTime() - Date.now() : -1;
      if (remaining < 30 * 24 * 3600 * 1000) writeSetting(s).catch(() => { /* best-effort refresh */ });
    });
  }, []);
  React.useEffect(() => { load(); }, [load]);

  // Optimistic: set module vars + local state immediately, persist, revert to server truth on failure.
  const update = React.useCallback(async (next: NetflowSetting) => {
    const s: NetflowSetting = { mode: next.mode, rate: next.rate > 0 ? next.rate : 1 };
    setNetflowModeVars(s);
    setSetting(s);
    try { await writeSetting(s); } catch { load(); }
  }, [load]);

  return { mode: setting.mode, rate: setting.rate, loading, update };
}
