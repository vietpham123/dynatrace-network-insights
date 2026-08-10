import React from "react";
import { stateClient } from "@dynatrace-sdk/client-state";

// Device role. CUSTOMER-OWNED, keyed on the management address — the same model as
// lib/sites.ts, and for the same reason.
//
// This used to be pure hostname inference (`sdwan`/`9300`/`access`/`pdu`…), which only ever
// worked because the lab's devices were named to match. On a real fleet every device falls
// through to "other", and three things degrade AT ONCE — role display, topology direction and
// RCA fault classification — which reads to a customer as "this product doesn't understand my
// network". Verified against real gear: containerlab nodes named swi-fra-01 / rtr-lon-01, and a
// Netgear switch whose sysName is literally "n/a", all infer to "other".
//
// Inference is retained ONLY as a first-guess seed for the assignment UI. It is never the source
// of truth, and callers should show provenance so an operator can tell an assignment from a guess.

export type Role = "wan-edge" | "core" | "access" | "ap" | "console" | "pdu" | "ups" | "other";

export const ROLES: Role[] = ["wan-edge", "core", "access", "ap", "console", "pdu", "ups", "other"];

export const ROLE_LABEL: Record<Role, string> = {
  "wan-edge": "WAN edge", core: "Core", access: "Access", ap: "Access point",
  console: "Console server", pdu: "PDU", ups: "UPS", other: "Other",
};

/** Hostname heuristic — a SUGGESTION for the assignment UI, never truth. Returns "other"
 *  whenever the name carries no recognisable convention, which is the common case on a real fleet. */
export function inferRole(n: string): Role {
  const s = (n || "").toLowerCase();
  if (s.includes("sdwan") || s.includes("8200")) return "wan-edge";
  if (s.includes("9300") || s.includes("core") || s.includes("spine")) return "core";
  if (s.includes("access") || s.includes("leaf")) return "access";
  if (s.includes("ap-") || s.startsWith("ap")) return "ap";
  if (s.includes("console")) return "console";
  if (s.includes("pdu")) return "pdu";
  if (s.includes("ups")) return "ups";
  return "other";
}

// ── customer-owned assignments ───────────────────────────────────────────────
const KEY = "cno.role-map";
export type RoleMap = Record<string, Role>; // device.address -> role

async function readState(): Promise<{ map: RoleMap; validUntil: string | null }> {
  try {
    const s = await stateClient.getAppState({ key: KEY });
    const st = s as { value?: string; validUntilTime?: string } | undefined;
    return { map: st?.value ? (JSON.parse(st.value) as RoleMap) : {}, validUntil: st?.validUntilTime ?? null };
  } catch {
    return { map: {}, validUntil: null }; // NotFound on first use → empty map
  }
}

async function writeMap(map: RoleMap): Promise<void> {
  await stateClient.setAppState({ key: KEY, body: { value: JSON.stringify(map), validUntilTime: "now+90d" } });
}

// Same keep-alive as sites: app-state has a ≤90d TTL, re-stamped whenever it is within 30 days
// of lapsing, so any app open inside the window keeps assignments effectively permanent.
async function keepAlive(map: RoleMap, validUntil: string | null): Promise<void> {
  if (!Object.keys(map).length) return;
  const remaining = validUntil ? new Date(validUntil).getTime() - Date.now() : -1;
  if (remaining < 30 * 24 * 3600 * 1000) {
    try { await writeMap(map); } catch { /* best-effort refresh */ }
  }
}

export function useRoles() {
  const [map, setMap] = React.useState<RoleMap>({});
  const [loading, setLoading] = React.useState(true);
  const mapRef = React.useRef<RoleMap>({});
  mapRef.current = map;

  const load = React.useCallback(() => {
    setLoading(true);
    void readState().then(({ map: m, validUntil }) => { setMap(m); setLoading(false); void keepAlive(m, validUntil); });
  }, []);
  React.useEffect(() => { load(); }, [load]);

  /** Assign (or clear, when role is blank) a device's role, keyed on the management address.
   *  Optimistic; reverts to server truth if the write fails. */
  const assignRole = React.useCallback(async (addr: string, role: Role | "") => {
    const next = { ...mapRef.current };
    if (role) next[addr] = role; else delete next[addr];
    mapRef.current = next;
    setMap(next);
    try { await writeMap(next); } catch { load(); }
  }, [load]);

  return { map, loading, assignRole, refresh: load };
}

/** The role to USE: the customer's assignment, else the hostname guess. */
export function roleFor(map: RoleMap, addr: string, name?: string): Role {
  return (addr && map[addr]) || inferRole(name || addr);
}

/** True when the role shown is a guess rather than something the customer set — callers should
 *  mark these visually so an operator knows what to trust. */
export function roleIsInferred(map: RoleMap, addr: string): boolean {
  return !(addr && map[addr]);
}

// ── topology direction ───────────────────────────────────────────────────────
// Higher rank sits further upstream. Power roles are deliberately absent: a UPS feeds a device,
// but that is a POWER edge drawn separately, never a data-path parent.
const DIR_RANK: Partial<Record<Role, number>> = {
  "wan-edge": 5, core: 4, access: 3, ap: 2, console: 1,
};

/**
 * Orient a DATA edge using the customer's role assignments.
 *
 *   -1  `a` is downstream of `b`  (b is the parent)
 *    1  `b` is downstream of `a`  (a is the parent)
 *    0  undecidable — the caller MUST keep whatever direction the collector stored
 *
 * WHY THIS EXISTS. LLDP adjacency is undirected — it says two devices are neighbours, never
 * which one is uphill — so the controlplane extension derives direction from the advertised
 * capability bitmap (router > bridge > AP) and tie-breaks on the chassis key. Measured on real
 * gear 2026-08-03: the Netgear GS752TP access switch advertises lldpLocSysCapEnabled = 0x2800 =
 * bridge + router, EXACTLY as the UCG Ultra gateway does. Both rank equal, the tie fell to an
 * arbitrary chassis-id sort, and the WAN gateway was recorded as depending on an access switch.
 * The Topology page already placed the gateway on the top tier from its assigned role while the
 * Device Detail page listed it as a child — the same estate contradicting itself on two screens.
 *
 * DECIDES ONLY ON EXPLICIT ASSIGNMENTS. Both ends must be customer-assigned and rank differently.
 * Hostname inference is not consulted, because trading a measured (if imperfect) LLDP signal for
 * a guess drawn from a device's NAME is a downgrade — the exact inference this module exists to
 * stop being the source of truth. Unassigned or equal-ranked pairs keep the collector's answer.
 */
export function orientByRole(map: RoleMap, aAddr: string, bAddr: string): -1 | 0 | 1 {
  if (!aAddr || !bAddr || aAddr === bAddr) return 0;
  const ra = map[aAddr], rb = map[bAddr];
  if (!ra || !rb) return 0;
  const na = DIR_RANK[ra], nb = DIR_RANK[rb];
  if (na == null || nb == null || na === nb) return 0;
  return na < nb ? -1 : 1;
}

/** Fleet-filter grouping — pdu + ups collapse into one user-facing "power" bucket. */
export function roleGroupOf(role: Role): string {
  return role === "pdu" || role === "ups" ? "power" : role;
}

/** Short topology glyph for a role. */
export const glyph = (r: string): string =>
  r === "wan-edge" ? "WAN" : r === "core" ? "CORE" : r === "access" ? "ACC" : r === "ap" ? "AP" : r === "pdu" ? "PDU" : r === "ups" ? "UPS" : r === "console" ? "CON" : "DEV";
