import React from "react";
import { stateClient } from "@dynatrace-sdk/client-state";

// App-owned device→site map — the customer's grouping, NOT inferred from hostnames, so it
// works for any device and any naming convention. Stored as one app-scoped state blob
// (shared across the app's users on this tenant). App-state persists on a rolling window
// (max 90d), refreshed on every write; a permanent store (documents/app-settings) is a
// straightforward later swap if a customer needs indefinite retention with no edits.
const KEY = "cno.site-map";
// KEY IS THE MANAGEMENT ADDRESS, not the device name.
// This was originally keyed on sys_name, which collides: a real Netgear GSM7248V2 in the lab
// reports no sysName (SNMP returns the literal "n/a"), and switches routinely ship that way —
// so every unnamed device shared ONE site assignment, and a renamed device silently lost its
// site. device.address is unique by construction (it is what the extension builds entity ids
// from), so it is the stable key.
//
// MIGRATION: maps written before this change are keyed by name. Reads therefore fall back to
// the name (see siteOf), and a write re-keys that device onto its address and drops the stale
// entry. Nothing is lost and no one-shot migration job is needed — assignments move across as
// they are touched, and untouched legacy entries keep resolving in the meantime.
export type SiteMap = Record<string, string>; // device.address (legacy: sys_name) -> site

async function readState(): Promise<{ map: SiteMap; validUntil: string | null }> {
  try {
    const s = await stateClient.getAppState({ key: KEY });
    const st = s as { value?: string; validUntilTime?: string } | undefined;
    return { map: st?.value ? (JSON.parse(st.value) as SiteMap) : {}, validUntil: st?.validUntilTime ?? null };
  } catch {
    return { map: {}, validUntil: null }; // NotFound on first use → empty map
  }
}

async function writeMap(map: SiteMap): Promise<void> {
  await stateClient.setAppState({ key: KEY, body: { value: JSON.stringify(map), validUntilTime: "now+90d" } });
}

// Keep-alive: app-state has a ≤90-day TTL. On load we re-stamp it to now+90d whenever it's
// within 30 days of lapsing, so any app open inside a 90-day window keeps the map effectively
// permanent — at zero cost (a state write isn't billed, no standing workflow). If the app goes
// a full 90 days totally untouched the map lapses, but by then the tool is abandoned and its
// sites are moot. (Falls back to refreshing every load if the TTL isn't returned.)
async function keepAlive(map: SiteMap, validUntil: string | null): Promise<void> {
  if (!Object.keys(map).length) return;
  const remaining = validUntil ? new Date(validUntil).getTime() - Date.now() : -1;
  if (remaining < 30 * 24 * 3600 * 1000) {
    try { await writeMap(map); } catch { /* best-effort refresh */ }
  }
}

// The device→site map plus a setter and the list of known sites (for autocomplete).
export function useSites() {
  const [map, setMap] = React.useState<SiteMap>({});
  const [loading, setLoading] = React.useState(true);
  const mapRef = React.useRef<SiteMap>({});
  mapRef.current = map;

  const load = React.useCallback(() => {
    setLoading(true);
    void readState().then(({ map: m, validUntil }) => {
      setMap(m);
      setLoading(false);
      void keepAlive(m, validUntil); // re-stamp the TTL on load so the map stays effectively permanent
    });
  }, []);
  React.useEffect(() => { load(); }, [load]);

  // Assign (or clear, when site is blank) a device's site. Keyed on the management ADDRESS.
  // `legacyName` lets a write clean up the pre-migration name-keyed entry for the same device.
  // Optimistic; reverts to server truth if the write fails. Reads the latest map from a ref so
  // rapid edits don't clobber.
  const assign = React.useCallback(async (addr: string, site: string, legacyName?: string) => {
    const next = { ...mapRef.current };
    const v = site.trim();
    if (v) next[addr] = v; else delete next[addr];
    // drop the stale name-keyed entry so a device can't carry two conflicting sites
    if (legacyName && legacyName !== addr && next[legacyName] !== undefined) delete next[legacyName];
    mapRef.current = next;
    setMap(next);
    try { await writeMap(next); } catch { load(); }
  }, [load]);

  const sites = Array.from(new Set(Object.values(map))).filter(Boolean).sort();
  return { map, sites, loading, assign, refresh: load };
}

// A device's site: the customer's assignment, else "Unassigned" (never fabricated).
// Looks up by management ADDRESS first, then falls back to the device name so assignments
// written before the re-key still resolve (see the MIGRATION note at the top).
export function siteOf(map: SiteMap, addr: string, legacyName?: string): string {
  return (addr && map[addr]) || (legacyName && map[legacyName]) || "Unassigned";
}
