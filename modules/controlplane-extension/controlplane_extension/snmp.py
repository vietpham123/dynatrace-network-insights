"""
SNMP transport for the LLDP walk.

Deliberately thin: it walks the LLDP-MIB columns we need and hands back RAW BYTES. All
interpretation lives in codec.py, which is pure and unit-tested — this module does I/O and
nothing else.

pysnmp 7.x is asyncio-only (the synchronous hlapi was removed), so everything here is a
coroutine and __main__.py drives it with asyncio.run() inside the SDK's synchronous query().
"""
import asyncio

from .codec import parse_man_addr_index
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget,
    UsmUserData, bulk_walk_cmd, get_cmd, walk_cmd, usmAesCfb128Protocol, usmAesCfb192Protocol,
    usmAesCfb256Protocol, usmDESPrivProtocol, usmHMAC192SHA256AuthProtocol,
    usmHMAC384SHA512AuthProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmNoAuthProtocol, usmNoPrivProtocol,
)

# ── LLDP-MIB (IEEE 802.1AB) ───────────────────────────────────────────────────────────────
SYS_NAME = "1.3.6.1.2.1.1.5.0"

# lldpLocalSystemData — this device's own identity. The other half of the topology join.
LOC_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
LOC_SYS_NAME = "1.0.8802.1.1.2.1.3.3.0"
# This device's OWN capabilities. Needed so edge direction can be computed symmetrically:
# both ends must rank the same pair the same way or we emit a bidirectional edge.
LOC_CAP_ENABLED = "1.0.8802.1.1.2.1.3.6.0"

# lldpLocPortTable — indexed by lldpLocPortNum, which is how a remote entry names its port.
LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"
LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"

# lldpRemTable — indexed by (lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex).
REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
REM_PORT_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
REM_CAP_ENABLED = "1.0.8802.1.1.2.1.4.1.1.12"

# lldpRemManAddrTable — the neighbour's MANAGEMENT ADDRESS. Walked for the OID INDEX, not the
# value: the address itself is part of the index (see codec.parse_man_addr_index). Confirmed
# populated on real Netgear hardware where lldpRemSysName was empty. Any column in the table
# works since we only want the index; ifSubtype is the cheapest.
REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.3"

REM_COLUMNS = {
    "chassis_subtype": REM_CHASSIS_SUBTYPE, "chassis_id": REM_CHASSIS_ID,
    "port_subtype": REM_PORT_SUBTYPE, "port_id": REM_PORT_ID, "port_desc": REM_PORT_DESC,
    "sys_name": REM_SYS_NAME, "cap_enabled": REM_CAP_ENABLED,
}

_AUTH = {
    "md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol, "sha512": usmHMAC384SHA512AuthProtocol,
}
_PRIV = {
    "des": usmDESPrivProtocol, "aes": usmAesCfb128Protocol,
    "aes192": usmAesCfb192Protocol, "aes256": usmAesCfb256Protocol,
}


# ── GetBulk vs GetNext ────────────────────────────────────────────────────────────────────
# GetBulk is an SNMPv2 PDU and NOT every agent implements it. Measured on a CyberPower
# OR2200LCDRTXL2U (RMCARD) 2026-08-01:
#
#   GETNEXT  ups battery subtree ->  6 varbinds in     68 ms
#   GETBULK  ups battery subtree ->  0 varbinds in 10,220 ms   (hard timeout, every time)
#
# Single GETs answer in 30 ms, so the device is healthy and fast — it simply has no GetBulk.
# The Dynatrace DECLARATIVE SNMP datasource only ever issues GetBulk and exposes no option to
# change that, so this whole class of device is unmonitorable by any declarative extension,
# Dynatrace's own included. It is reachable from here because pysnmp lets us choose the PDU.
#
# Detected per device rather than configured, because an operator should not have to know
# which of their devices implement a 1996 PDU. The probe is deliberately cheap: one small
# GetBulk against the system subtree with a short timeout. A device that fails it is walked
# with GetNext for the rest of the process; the verdict is cached because paying a 10-second
# timeout per column per cycle would be worse than the problem.
_WALK_MODE: dict = {}          # host -> "getbulk" | "getnext"
SYSTEM_SUBTREE = "1.3.6.1.2.1.1"


class SnmpError(Exception):
    """A device-level failure. Carried per-device so one bad device cannot fail the run —
    the declarative extension turned the whole monitoring configuration ERROR when a single
    switch timed out on a single OID group (see §L7)."""


def build_auth(cfg: dict):
    """CommunityData for v2c, UsmUserData for v3.

    Field names mirror the app's provisioning payload so an operator sees the same words in
    the extension config and in the app.
    """
    if (cfg.get("version") or "v2c").lower() == "v3":
        lvl = (cfg.get("securityLevel") or "noAuthNoPriv").lower()
        user = cfg.get("userName") or ""
        if lvl == "noauthnopriv":
            return UsmUserData(user, authProtocol=usmNoAuthProtocol,
                               privProtocol=usmNoPrivProtocol)
        auth = _AUTH.get((cfg.get("authProtocol") or "sha").lower(), usmHMACSHAAuthProtocol)
        if lvl == "authnopriv":
            return UsmUserData(user, authKey=cfg.get("authPassword"), authProtocol=auth,
                               privProtocol=usmNoPrivProtocol)
        priv = _PRIV.get((cfg.get("privProtocol") or "aes").lower(), usmAesCfb128Protocol)
        return UsmUserData(user, authKey=cfg.get("authPassword"),
                           privKey=cfg.get("privPassword"), authProtocol=auth,
                           privProtocol=priv)
    return CommunityData(cfg.get("community") or "public", mpModel=1)  # mpModel 1 == v2c


def _octets(value):
    """Raw bytes out of a pysnmp value. This single call is what the declarative datasource
    never gets to make — it only ever sees the stringified form."""
    try:
        return value.asOctets()
    except AttributeError:
        return str(value).encode("utf-8", "replace")


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_error(value) -> bool:
    """noSuchObject / noSuchInstance / endOfMibView come back as values, not exceptions."""
    return value is None or value.__class__.__name__ in (
        "NoSuchObject", "NoSuchInstance", "EndOfMibView")


PROBE_TIMEOUT_SECS = 2

async def detect_walk_mode(engine, auth, ctx, host: str, port: int) -> str:
    """Decide once per host whether GetBulk works. Cached for the process lifetime.

    Uses its OWN short-timeout transport rather than the caller's. A GetBulk-less agent answers
    the probe by saying nothing, so the probe costs exactly one timeout — and with the caller's
    normal settings (5s x 2 retries) that measured 8.1 SECONDS per device. Once per process is
    tolerable for two devices and is 13 minutes of startup for a hundred. Capped at
    PROBE_TIMEOUT_SECS with no retry: we are asking "does this PDU work at all", not trying to
    get data, so one lost packet costing a re-probe next cycle is the right trade.

    A negative verdict is NOT cached, so a transient blip cannot permanently demote a capable
    device to the slower PDU.
    """
    cached = _WALK_MODE.get(host)
    if cached:
        return cached
    try:
        probe_target = await UdpTransportTarget.create(
            (host, port), timeout=PROBE_TIMEOUT_SECS, retries=0)
        async for err_ind, err_stat, _i, var_binds in bulk_walk_cmd(
            engine, auth, probe_target, ctx, 0, 3,
            ObjectType(ObjectIdentity(SYSTEM_SUBTREE)),
            lexicographicMode=False, lookupMib=False,
        ):
            if err_ind or err_stat:
                break
            if var_binds:
                _WALK_MODE[host] = "getbulk"
                return "getbulk"
            break
    except Exception:
        pass
    return "getnext"     # deliberately not cached — see docstring


async def _walk_column(engine, auth, target, ctx, base: str, max_reps: int,
                       mode: str = "getbulk") -> dict:
    """Walk one column; returns {index_suffix: raw_value}.

    lexicographicMode=False stops at the end of the subtree instead of running off into the
    rest of the MIB. lookupMib=False skips MIB resolution — we address by numeric OID, so
    loading MIBs would be pure overhead and an extra failure mode on an ActiveGate.

    `mode` selects the PDU: GetBulk where the agent supports it, GetNext where it does not.
    """
    out = {}
    if mode == "getnext":
        stream = walk_cmd(engine, auth, target, ctx,
                          ObjectType(ObjectIdentity(base)),
                          lexicographicMode=False, lookupMib=False)
    else:
        stream = bulk_walk_cmd(engine, auth, target, ctx, 0, max_reps,
                               ObjectType(ObjectIdentity(base)),
                               lexicographicMode=False, lookupMib=False)
    async for err_ind, err_stat, err_idx, var_binds in stream:
        if err_ind:
            raise SnmpError(str(err_ind))
        if err_stat:
            # noSuchName means "this agent does not implement that OID" — an ANSWER, not a
            # failure. GetBulk reports it per-varbind (endOfMibView / noSuchObject, handled by
            # _is_error), but on a GetNext walk it arrives as a PDU-level error, so the naive
            # `raise` here took the whole device down.
            #
            # Found on the CyberPower UPS: it implements no LLDP tables, so walking them
            # returned noSuchName and the device failed entirely — losing the UPS data it DOES
            # serve. A device that does not implement a MIB has zero rows for it; that is all.
            if "nosuchname" in str(err_stat).replace(" ", "").lower():
                return out
            raise SnmpError(f"{err_stat.prettyPrint()} at index {err_idx}")
        for oid, value in var_binds:
            s = str(oid)
            if not s.startswith(base + "."):
                continue
            if _is_error(value):
                continue
            out[s[len(base) + 1:]] = value
    return out


async def _get_scalars(engine, auth, target, ctx, oids: list) -> dict:
    """One GET for the scalar identity OIDs, degrading to per-OID GETs when the agent is
    all-or-nothing about them.

    A v2c agent reports an unimplemented OID per-varbind (noSuchObject) and still answers the
    rest. Plenty of agents do NOT: they reject the WHOLE PDU with noSuchName the moment one
    varbind is unknown — v1 semantics, which some v2c implementations keep.

    Measured on the CyberPower UPS: it implements none of the LLDP scalars, so a single GET
    bundling sysName + four LLDP OIDs was rejected outright and we lost sysName too — a device
    that answers perfectly well returned nothing at all.

    So: try the batch (one round trip, the common case), and only on noSuchName fall back to
    asking one at a time. The slow path costs N round trips and is only taken by agents that
    force it.
    """
    def _no_such_name(e) -> bool:
        return "nosuchname" in str(e).replace(" ", "").lower()

    err_ind, err_stat, _, var_binds = await get_cmd(
        engine, auth, target, ctx,
        *[ObjectType(ObjectIdentity(o)) for o in oids], lookupMib=False,
    )
    if err_ind:
        raise SnmpError(str(err_ind))
    if not err_stat:
        return {str(oid): val for oid, val in var_binds if not _is_error(val)}
    if not _no_such_name(err_stat):
        raise SnmpError(err_stat.prettyPrint())

    out = {}
    for o in oids:
        ei, es, _x, vbs = await get_cmd(
            engine, auth, target, ctx, ObjectType(ObjectIdentity(o)), lookupMib=False)
        if ei or es:
            continue                      # this one is simply not implemented
        for oid, val in vbs:
            if not _is_error(val):
                out[str(oid)] = val
    return out


async def collect_device(host: str, port: int, cfg: dict, timeout: int = 5, retries: int = 2,
                         max_reps: int = 10, want_lldp: bool = True,
                         want_routing: bool = False) -> dict:
    """Walk one device. Returns raw bytes throughout — codec.py does the interpreting.

    max_reps defaults to 10 rather than the usual 25+. The lab's older GSM7248V2 returns
    DEVICE_CONNECTION_ERROR / GetBulk timeout to the declarative datasource on exactly these
    LLDP scalars (§L7, root cause still unestablished), so a gentler default is the safer
    starting point on mixed-age estates. It is configurable for anyone who wants it faster.
    """
    engine = SnmpEngine()
    auth = build_auth(cfg)
    ctx = ContextData()
    target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=retries)
    # Probe once, then use the PDU this agent actually implements.
    mode = await detect_walk_mode(engine, auth, ctx, host, port)

    scalars = await _get_scalars(
        engine, auth, target, ctx,
        [SYS_NAME, LOC_CHASSIS_SUBTYPE, LOC_CHASSIS_ID, LOC_SYS_NAME, LOC_CAP_ENABLED],
    )

    local_ports = {}
    remote = {}
    man_addr = {}
    routing = {"bgp": {}, "ospf": {}, "bgp_supported": False, "ospf_supported": False}

    # Routing shares this device's session — one SNMP setup, both capabilities.
    if want_routing:
        from .routing import collect_routing
        routing = await collect_routing(engine, auth, target, ctx, max_reps, mode)

    if not want_lldp:
        return {
            "host": host,
            "sys_name": scalars.get(SYS_NAME),
            "loc_chassis_subtype": _as_int(scalars.get(LOC_CHASSIS_SUBTYPE)),
            "loc_chassis_id": _octets(scalars[LOC_CHASSIS_ID]) if LOC_CHASSIS_ID in scalars else b"",
            "loc_sys_name": scalars.get(LOC_SYS_NAME),
            "loc_caps": _octets(scalars[LOC_CAP_ENABLED]) if LOC_CAP_ENABLED in scalars else b"",
            "local_ports": {}, "remote": {}, "man_addr": {}, "routing": routing,
            "walk_mode": mode,
        }

    for name, base in (("port_subtype", LOC_PORT_ID_SUBTYPE), ("port_id", LOC_PORT_ID),
                       ("port_desc", LOC_PORT_DESC)):
        for idx, val in (await _walk_column(engine, auth, target, ctx, base, max_reps, mode)).items():
            local_ports.setdefault(idx, {})[name] = val

    for name, base in REM_COLUMNS.items():
        for idx, val in (await _walk_column(engine, auth, target, ctx, base, max_reps, mode)).items():
            remote.setdefault(idx, {})[name] = val

    # Management addresses, keyed back onto the lldpRemTable index. Best-effort: a device that
    # does not implement this table still yields perfectly good topology.
    try:
        for idx in (await _walk_column(engine, auth, target, ctx, REM_MAN_ADDR, max_reps, mode)):
            key, addr = parse_man_addr_index(idx)
            if key and addr:
                man_addr.setdefault(key, addr)
    except SnmpError:
        pass

    return {
        "host": host,
        "sys_name": scalars.get(SYS_NAME),
        "loc_chassis_subtype": _as_int(scalars.get(LOC_CHASSIS_SUBTYPE)),
        "loc_chassis_id": _octets(scalars[LOC_CHASSIS_ID]) if LOC_CHASSIS_ID in scalars else b"",
        "loc_sys_name": scalars.get(LOC_SYS_NAME),
        "loc_caps": _octets(scalars[LOC_CAP_ENABLED]) if LOC_CAP_ENABLED in scalars else b"",
        "local_ports": local_ports,
        "remote": remote,
        "man_addr": man_addr,
        "routing": routing,
        "walk_mode": mode,
    }


def local_port_num(rem_index: str) -> str:
    """lldpRemTable is indexed (timeMark, localPortNum, remIndex) — the middle component is
    how a neighbour entry names the local port it was heard on, and is the key into
    lldpLocPortTable."""
    parts = rem_index.split(".")
    return parts[1] if len(parts) >= 2 else ""


__all__ = [
    "SnmpError", "build_auth", "collect_device", "local_port_num", "_octets", "_as_int",
    "asyncio",
]
