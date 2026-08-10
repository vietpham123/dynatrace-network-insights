// Provisioning seam — the app's two-button write path (now LIVE).
//
// ① Apply-to-Dynatrace (start polling): calls the `provision` app function, which
//    POSTs a single-device monitoring configuration to the SNMP extension
//    (Extensions 2.0). The AG group starts polling within ~1 min and the
//    network:device entity is created once cno.if.* arrives. Verified payload.
//
// ② Update-NetBox (inventory of record): NetBox is private, so that path still goes
//    through the on-prem executor (Phase B2) — not wired here.

import { useState, useEffect } from 'react';
import { functions } from '@dynatrace-sdk/app-utils';

export type ProvisionResult = { ok: boolean; staged?: boolean; error?: string; objectId?: string };

/** SNMPv3 parameters. Only meaningful when snmpVersion === 'v3' and the credential is NOT a
 *  vault id (a vault entry carries the user + passphrases itself). Field names here are the
 *  app's own; provision.function.ts maps them to each extension's schema spelling. */
export type SnmpV3Fields = {
  userName?: string;
  securityLevel?: 'AUTH_PRIV' | 'AUTH_NO_PRIV' | 'NO_AUTH_NO_PRIV';
  authProtocol?: string;
  authPassword?: string;
  privProtocol?: string;
  privPassword?: string;
};

/** SNMP extension feature sets (≥0.0.14). These strings are an API contract — they must match
 *  the `featureSet:` declarations in modules/snmp-interfaces-extension/extension/extension.yaml
 *  byte for byte, and renaming one orphans every monitoring config that selected it. */
export type FeatureSet =
  | 'Interfaces'
  | 'Cisco device health'
  | 'UPS power'
  | 'UPS battery voltage'
  | 'PDU power'
  | 'LLDP topology';

export type AddDeviceInput = {
  extension: string;
  name: string;
  ip: string;
  credentialId: string; // used as the server-side SNMP profile id
  intervalMin: number;   // interval is defined by the extension, not the config; informational
  scope?: string;        // the ActiveGate group to poll from (operator's pick)
  snmpVersion?: 'v2c' | 'v3'; // defaults to v2c server-side
  v3?: SnmpV3Fields;
  /** Which OID groups this device should be polled for (SNMP extension ≥0.0.14). Omit to accept
   *  the server-side default of ['Interfaces'], which is WRONG for a UPS or PDU — see
   *  addDevicePolling. On ≤0.0.13 the server ignores this (the groups are always-on there). */
  featureSets?: FeatureSet[];
};

/** Device class → the feature sets that class should actually be polled for.
 *
 *  This is the mapping that stops the app re-creating the §P3 defect it exists to fix: a UPS
 *  onboarded with `Interfaces` gets a 15 s GetBulk timeout every minute, lands its whole
 *  configuration in ERROR, and collects no power data at all — while the operator watches a
 *  "Power" role they selected being silently ignored.
 *
 *  `Cisco device health` is not in any entry: vendor is orthogonal to role and the wizard does
 *  not ask for it. Callers that know the device is Cisco should append it. */
export const FEATURE_SETS_FOR_ROLE: Record<string, FeatureSet[]> = {
  core: ['Interfaces'],
  access: ['Interfaces'],
  'wan-edge': ['Interfaces'],
  ap: ['Interfaces'],
  // ⚠️ NO `Interfaces` — see above. And NOT `UPS battery voltage`: on an all-or-nothing agent
  // an unimplemented upsBatteryVoltage returns noSuchName for the WHOLE request and takes every
  // other power metric down with it, so it is opt-in per confirmed device only.
  ups: ['UPS power'],
  pdu: ['PDU power'],
};

/** ActiveGate groups available to poll — for the onboarding picker. `current` is the
 *  group the app's extension already polls from (the recommended default). */
export async function listAgGroups(): Promise<{ groups: { scope: string; group: string }[]; current: string }> {
  try {
    const res = await functions.call("provision", { data: { action: "agGroups" } });
    const b: any = await res.json();
    return { groups: b?.groups ?? [], current: b?.current ?? "" };
  } catch { return { groups: [], current: "" }; }
}

/** A Credential Vault entry — metadata only (no secret). */
export type VaultCred = { id: string; name: string; type: string; scope: string };

/** List Credential Vault entries so the onboarding pickers auto-populate. Metadata only — the app
 *  references credentials by id and never reads the secret. Returns ok:false + empty list if the app
 *  isn't granted the credentials-read scope, so callers fall back to manual id entry. */
export async function listCredentials(): Promise<{ ok: boolean; credentials: VaultCred[] }> {
  try {
    const res = await functions.call("provision", { data: { action: "credentials" } });
    const b: any = await res.json();
    return b?.ok ? { ok: true, credentials: b.credentials ?? [] } : { ok: false, credentials: [] };
  } catch { return { ok: false, credentials: [] }; }
}

async function callProvision(data: Record<string, unknown>): Promise<ProvisionResult> {
  try {
    const res = await functions.call('provision', { data });
    const b: any = await res.json();
    return b?.ok ? { ok: true, objectId: b.objectId } : { ok: false, error: b?.error || 'provision failed' };
  } catch (e: any) {
    return { ok: false, error: e?.message || String(e) };
  }
}

/**
 * Add a device to SNMP polling by creating a single-device monitoring config.
 *
 * PASS `featureSets` — derive it from the device class with FEATURE_SETS_FOR_ROLE. If it is
 * omitted the backend falls back to `['Interfaces']`, i.e. it onboards the device AS A
 * SWITCH/ROUTER. That is right for the common case and WRONG for a UPS or PDU: enabling
 * `Interfaces` on a UPS management card causes a 15 s GetBulk timeout every minute, puts the
 * whole configuration in ERROR and collects no power data at all (measured on a CyberPower
 * OR2200LCDRTXL2U, 2026-08-03).
 *
 * This used to be a documented-but-unfixable limitation: the JSDoc said "the backend already
 * accepts a featureSets override" while AddDeviceInput had no such field and this function
 * forwarded none, so the override had no reachable caller and the Role the operator picked in
 * Configure was silently discarded. Both are now wired.
 */
export function addDevicePolling(p: AddDeviceInput): Promise<ProvisionResult> {
  return callProvision({
    action: 'add', name: p.name, ip: p.ip, profileId: p.credentialId, scope: p.scope,
    snmpVersion: p.snmpVersion, v3: p.v3,
    ...(p.featureSets?.length ? { featureSets: p.featureSets } : {}),
  });
}

/** Remove a device from polling — delete its single-device monitoring config. */
/** Every device somebody asked us to poll — the INTENT side of the lifecycle.
 *  See the note on configuredDevices() in api/provision.function.ts for why intent, not age,
 *  is what separates "retired" from "broken". */
/** `scanned`/`skipped` are DIAGNOSTICS, not decoration, and dropping them on the floor is what
 *  made the "fleet is short by three devices" hunt take an afternoon. The function reads
 *  /platform/extensions/v2/... which needs a Bearer token, so it cannot be reproduced from a
 *  shell with an Api-Token — the app is the ONLY place that read is observable. Returning just
 *  {ok, devices} made a partial read (some extensions listed, others erroring) look exactly like
 *  a complete one, so a short fleet had no explanation anywhere in the product. */
export type ConfiguredDiag = { scanned?: number; skipped?: string[] };

export async function listConfiguredDevices(): Promise<{ ok: boolean; devices: ConfiguredDevice[] } & ConfiguredDiag> {
  try {
    const res = await functions.call("provision", { data: { action: "configuredDevices" } });
    const b: any = await res.json();
    return { ok: !!b?.ok, devices: b?.devices ?? [], scanned: b?.scanned, skipped: b?.skipped ?? [] };
  } catch (e: any) {
    return { ok: false, devices: [], skipped: [`call failed: ${String(e?.message || e).slice(0, 120)}`] };
  }
}
export type ConfiguredDevice = { ip: string; extension: string; configId: string; description: string };

/** THE ONE PLACE "is this device configured" gets asked. Both useFleet() (lib/data.ts) and
 *  useDeviceLifecycle() (lib/lifecycle.ts) need this, and it must be the SAME answer in both —
 *  a device that useFleet calls "monitored" and useDeviceLifecycle calls "decommissioned" is a
 *  contradiction the two halves of the app would show side by side.
 *
 *  Historical bug this exists to prevent: useFleet's roster query looks back 24h, so it marked
 *  any device that had reported ANY metric in the last day as monitored:true regardless of
 *  whether a monitoring configuration still existed. A device retired minutes earlier — its
 *  config deleted, its simulator no longer answering — still showed up as a live "down" fault
 *  for a full day after every teardown, not just once historically. Cross-referencing against
 *  the actual configuration list (this hook) instead of "reported recently" fixes it for every
 *  future retirement, not just the one that was visible when the bug was found. */
/* ONE CALL, SHARED. This is the slowest thing the app does — an app-function round trip that
   itself fans out to every network extension — and EVERY consumer blocks its first paint on it.
   It was a plain useState/useEffect per component, so useFleet and useDeviceLifecycle each fired
   their own, and a page using both paid for two full scans. useDql is deduped by TanStack Query;
   this hand-rolled hook had none of that, which is why the app felt slow after the extension
   catalog fix took the fan-out from 6 extensions to 11.

   Module-level cache plus in-flight sharing: concurrent callers await the SAME promise, and
   later mounts reuse the result for TTL. refreshConfigured() drops it, for after a write. */
type ConfiguredPayload = { ok: boolean; devices: ConfiguredDevice[] } & ConfiguredDiag;
const CONFIGURED_TTL_MS = 60_000;
let _cfgCache: { at: number; value: ConfiguredPayload } | null = null;
let _cfgInflight: Promise<ConfiguredPayload> | null = null;

function fetchConfiguredShared(): Promise<ConfiguredPayload> {
  const fresh = _cfgCache && Date.now() - _cfgCache.at < CONFIGURED_TTL_MS;
  if (fresh) return Promise.resolve(_cfgCache!.value);
  if (_cfgInflight) return _cfgInflight;
  _cfgInflight = listConfiguredDevices()
    .then((v) => { _cfgCache = { at: Date.now(), value: v }; return v; })
    .finally(() => { _cfgInflight = null; });
  return _cfgInflight;
}

/** Drop the cache — call after anything that changes monitoring configurations (add, retire). */
export function refreshConfigured(): void { _cfgCache = null; }

export function useConfiguredDevices(): {
  devices: ConfiguredDevice[]; ips: Set<string>; isLoading: boolean; failed: boolean; diag: ConfiguredDiag;
} {
  // Seed synchronously from the shared cache so a second consumer on the same page does not
  // re-enter the loading state and re-block the paint.
  const seeded = _cfgCache && Date.now() - _cfgCache.at < CONFIGURED_TTL_MS ? _cfgCache.value : null;
  const [devices, setDevices] = useState<ConfiguredDevice[] | null>(seeded ? seeded.devices : null);
  const [failed, setFailed] = useState(seeded ? !seeded.ok : false);
  const [diag, setDiag] = useState<ConfiguredDiag>(seeded ? { scanned: seeded.scanned, skipped: seeded.skipped } : {});
  useEffect(() => {
    let cancelled = false;
    fetchConfiguredShared()
      .then((r) => {
        if (cancelled) return;
        setDevices(r.devices); setFailed(!r.ok);
        setDiag({ scanned: r.scanned, skipped: r.skipped });
      })
      .catch((e) => {
        if (cancelled) return;
        setFailed(true); setDiag({ skipped: [String(e?.message || e).slice(0, 120)] });
      });
    return () => { cancelled = true; };
  }, []);
  const list = devices ?? [];
  return { devices: list, ips: new Set(list.map((d) => d.ip)), isLoading: devices === null && !failed, failed, diag };
}

export type RetireResult = ProvisionResult & {
  removed?: { extension: string; how: "deleted" | "removed"; configId: string }[];
  failed?: { extension: string; error: string }[];
  partial?: boolean;
};

/** Withdraw the intent to poll, from every extension that holds this device. `extension` is no
 *  longer used — retire is fleet-wide by definition, and passing one made it possible to retire a
 *  device from its metrics while leaving it configured for LLDP, which is not a state anybody
 *  wants. Kept in the signature so existing callers compile. */
export async function retireDevicePolling(p: { extension?: string; ip: string; name: string }): Promise<RetireResult> {
  // NOT callProvision: that flattens the body to {ok, objectId} and would drop `removed`,
  // `failed` and `partial`. A retire that withdrew intent from one extension and failed on
  // another must be able to say so — reporting "done" after a partial withdrawal leaves a device
  // half-configured and still polling, which is the worst of both states.
  try {
    const res = await functions.call('provision', { data: { action: 'retire', ip: p.ip, name: p.name } });
    const b: any = await res.json();
    return { ok: !!b?.ok, error: b?.error, removed: b?.removed, failed: b?.failed, partial: !!b?.partial };
  } catch (e: any) {
    return { ok: false, error: e?.message || String(e) };
  }
}

export type CreateDetectorsResult = { ok: boolean; created?: number; createdTitles?: string[]; skipped?: number; skippedTitles?: string[]; failed?: { title?: string; code?: number; error?: any }[]; error?: string };

/** Create the selected anomaly detectors (opt-in). The app CAN create these — davis.anomaly-detectors
 *  is a settings object, covered by settings:objects:write (unlike workflows). Idempotent: existing
 *  titles are skipped server-side. */
export async function createDetectors(detectors: any[]): Promise<CreateDetectorsResult> {
  try {
    const res = await functions.call('provision', { data: { action: 'createDetectors', detectors } });
    type FailedDetector = { title?: string; code?: number; error?: string };
    type CreateDetectorsResponse = {
      ok?: boolean; created?: number; createdTitles?: string[];
      skipped?: number; skippedTitles?: string[];
      failed?: FailedDetector[]; error?: string; body?: unknown;
    };
    const b = (await res.json()) as CreateDetectorsResponse;
    if (b?.ok) return { ok: true, created: b.created ?? 0, createdTitles: b.createdTitles ?? [], skipped: b.skipped ?? 0, skippedTitles: b.skippedTitles ?? [] };
    // Settings v2 can reject individual detectors inside a 2xx response. Name them rather
    // than dumping the raw envelope — "3 created" while 2 silently failed is the mode we
    // are fixing, so the message has to say WHICH ones and why.
    const failed: FailedDetector[] = Array.isArray(b?.failed) ? b.failed : [];
    if (failed.length) {
      const detail = failed.map((f) => `${f.title ?? '(untitled)'}${f.code ? ` [${f.code}]` : ''}${f.error ? `: ${String(f.error).slice(0, 80)}` : ''}`).join(' · ');
      return {
        ok: false,
        created: b?.created ?? 0,
        createdTitles: b?.createdTitles ?? [],
        failed,
        error: `${failed.length} of ${failed.length + (b?.created ?? 0)} detector(s) rejected — ${detail}`,
      };
    }
    return { ok: false, error: b?.error || (b?.body ? String(JSON.stringify(b.body)).slice(0, 180) : 'create failed') };
  } catch (e: any) {
    return { ok: false, error: e?.message || String(e) };
  }
}
