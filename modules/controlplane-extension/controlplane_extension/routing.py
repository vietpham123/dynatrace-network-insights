"""
Routing adjacency collection — BGP4-MIB and OSPF-MIB.

WHY THIS MATTERS OPERATIONALLY. Everything else this app collects is data plane: is the
interface up, is it passing bits. Routing state is a different layer, and the gap between them
is where the expensive outages live — an eBGP session to the carrier can drop while the
interface stays perfectly `up`, counters still ticking, the device green in the fleet view,
and traffic blackholing. `ifTable` structurally cannot see that.

It also retires an inference hack: the RCA workflow currently decides a fault is
"wan-isolation" with the regex /sdwan|8200/ against the HOSTNAME. A down eBGP session on an
edge device IS WAN isolation, whatever the device happens to be called.

Same split as the rest of this module: I/O only in here, all interpretation in codec.py.
"""
from .codec import decode_ip
from .snmp import SnmpError, _as_int, _octets, _walk_column

# ── BGP4-MIB (1.3.6.1.2.1.15) ─────────────────────────────────────────────────────────────
BGP_LOCAL_AS = "1.3.6.1.2.1.15.2.0"
# bgpPeerTable — INDEXED BY THE PEER ADDRESS, but every field we need is also a proper column,
# so no index parsing is required here (unlike lldpRemManAddrTable).
BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2"
BGP_PEER_ADMIN = "1.3.6.1.2.1.15.3.1.3"
BGP_PEER_REMOTE_ADDR = "1.3.6.1.2.1.15.3.1.7"
BGP_PEER_REMOTE_AS = "1.3.6.1.2.1.15.3.1.9"
# CORRECTED 2026-08-01. These were .24 and .25, which are WRONG:
#   .24 is bgpPeerInUpdateElapsedTime  (not a flap counter)
#   .25 does not exist in bgpPeerEntry at all
# The real columns per BGP4-MIB / RFC 4273:
BGP_PEER_FSM_TRANSITIONS = "1.3.6.1.2.1.15.3.1.15"  # bgpPeerFsmEstablishedTransitions - flaps
BGP_PEER_FSM_TIME = "1.3.6.1.2.1.15.3.1.16"         # bgpPeerFsmEstablishedTime - secs in state

BGP_COLUMNS = {
    "state": BGP_PEER_STATE, "admin": BGP_PEER_ADMIN, "remote_addr": BGP_PEER_REMOTE_ADDR,
    "remote_as": BGP_PEER_REMOTE_AS, "transitions": BGP_PEER_FSM_TRANSITIONS,
    "uptime": BGP_PEER_FSM_TIME,
}

# ── OSPF-MIB (1.3.6.1.2.1.14) ─────────────────────────────────────────────────────────────
OSPF_ROUTER_ID = "1.3.6.1.2.1.14.1.1.0"
OSPF_NBR_RTR_ID = "1.3.6.1.2.1.14.10.1.3"
OSPF_NBR_STATE = "1.3.6.1.2.1.14.10.1.6"
OSPF_NBR_EVENTS = "1.3.6.1.2.1.14.10.1.7"   # adjacency change counter

OSPF_COLUMNS = {"rtr_id": OSPF_NBR_RTR_ID, "state": OSPF_NBR_STATE, "events": OSPF_NBR_EVENTS}


async def collect_routing(engine, auth, target, ctx, max_reps: int = 10,
                          mode: str = "getbulk") -> dict:
    """Walk BGP peers and OSPF neighbours. Returns raw values; codec.py interprets.

    BEST EFFORT BY DESIGN. A switch does not implement BGP4-MIB and an access layer does not
    run OSPF — those walks return nothing, which is not an error and must not fail the device.
    Anything that raises is swallowed per-protocol so one unsupported MIB cannot cost us the
    other, or cost us LLDP.
    """
    out = {"bgp": {}, "ospf": {}, "bgp_supported": False, "ospf_supported": False}

    try:
        for name, base in BGP_COLUMNS.items():
            for idx, val in (await _walk_column(engine, auth, target, ctx, base, max_reps, mode)).items():
                out["bgp"].setdefault(idx, {})[name] = val
        out["bgp_supported"] = bool(out["bgp"])
    except SnmpError:
        pass

    try:
        for name, base in OSPF_COLUMNS.items():
            for idx, val in (await _walk_column(engine, auth, target, ctx, base, max_reps, mode)).items():
                out["ospf"].setdefault(idx, {})[name] = val
        out["ospf_supported"] = bool(out["ospf"])
    except SnmpError:
        pass

    return out


def peer_address(cols: dict, index: str) -> str:
    """Peer identity, preferring the column and falling back to the table index.

    bgpPeerRemoteAddr is an SNMP IpAddress — four raw bytes — which is exactly the value the
    declarative datasource would have mangled. If an agent leaves the column empty the index
    still carries the address in dotted form (the table is indexed by it), so we recover it.
    """
    raw = cols.get("remote_addr")
    if raw is not None:
        addr = decode_ip(_octets(raw))
        if addr and addr.count(".") == 3:
            return addr
    return index if index.count(".") == 3 else ""


def ospf_neighbour_id(cols: dict, index: str) -> str:
    """ospfNbrRtrId, same IpAddress shape. The ospfNbrTable index is
    <ospfNbrIpAddr>.<ospfNbrAddressLessIndex>, so the first four components are the address."""
    raw = cols.get("rtr_id")
    if raw is not None:
        rid = decode_ip(_octets(raw))
        if rid and rid.count(".") == 3:
            return rid
    parts = index.split(".")
    return ".".join(parts[:4]) if len(parts) >= 4 else ""


__all__ = ["collect_routing", "peer_address", "ospf_neighbour_id", "_as_int"]
