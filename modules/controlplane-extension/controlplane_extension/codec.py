"""
LLDP TLV decoding — the entire reason this extension exists.

The declarative SNMP datasource decodes binary OCTET STRINGs as UTF-8 and DROPS invalid
bytes. Measured on real hardware 2026-08-01:

    lldpRemChassisId  20 4E 7F 4E C3 E6  (a MAC)      ->  ' N\x7fN'   (2 of 6 bytes gone)
    lldpRemSysCapEnabled  20 00  (Bridge)             ->  ' '
    lldpRemSysCapEnabled  28 00  (Bridge+Router)      ->  '('

That is lossy, not merely ugly. Three distinct MACs sharing an OUI collapse to one string,
and same-vendor fleets differ precisely in the trailing bytes that get dropped — so the
"mangled but deterministic, use it as an opaque key" shortcut would silently merge distinct
devices into one topology node. See docs/ENTERPRISE-READINESS.md §L.

Everything here is pure: bytes in, str/dict out. No SNMP, no I/O, no Dynatrace SDK — so it is
unit-testable against the exact byte sequences we captured from real gear, which is what
tests/test_codec.py does.

Reference: IEEE 802.1AB (LLDP-MIB).
"""

# ── ID subtypes (IEEE 802.1AB) ────────────────────────────────────────────────────────────
# The subtype tells you how to read the bytes. THIS is what the declarative datasource has no
# access to, and why it cannot get this right: it sees only the value column, never the
# subtype column, so it cannot know whether it is holding text or a raw MAC.

CHASSIS_SUBTYPE = {
    1: "chassisComponent", 2: "interfaceAlias", 3: "portComponent", 4: "macAddress",
    5: "networkAddress", 6: "interfaceName", 7: "local",
}
PORT_SUBTYPE = {
    1: "interfaceAlias", 2: "portComponent", 3: "macAddress", 4: "networkAddress",
    5: "interfaceName", 6: "agentCircuitId", 7: "local",
}

# Subtypes whose value is RAW BYTES rather than text.
_MAC_SUBTYPES = {4}          # chassis: macAddress
_MAC_PORT_SUBTYPES = {3}     # port:    macAddress
_ADDR_SUBTYPES = {5}         # chassis: networkAddress
_ADDR_PORT_SUBTYPES = {4}    # port:    networkAddress

# IANA address family numbers, as used in the networkAddress TLV's first octet.
_AF_IPV4, _AF_IPV6 = 1, 2


def _mac(b: bytes) -> str:
    """aa:bb:cc:dd:ee:ff — lowercase, the form every NOS and every operator writes."""
    return ":".join(f"{x:02x}" for x in b)


def _network_address(b: bytes) -> str:
    """networkAddress TLV: one IANA address-family octet, then the address itself."""
    if not b:
        return ""
    fam, rest = b[0], b[1:]
    if fam == _AF_IPV4 and len(rest) == 4:
        return ".".join(str(x) for x in rest)
    if fam == _AF_IPV6 and len(rest) == 16:
        parts = [f"{rest[i]<<8 | rest[i+1]:x}" for i in range(0, 16, 2)]
        return ":".join(parts)
    return _hex(rest)  # unknown family — keep the bytes rather than invent a reading


def _hex(b: bytes) -> str:
    """Last resort for bytes we cannot type. LOSSLESS, which is the whole point — an operator
    can still eyeball it and it still joins correctly."""
    return "0x" + b.hex() if b else ""


def _printable(b: bytes) -> str:
    """Text-ish subtypes. Devices do ship trailing NULs and stray control bytes here, so strip
    them — but if what remains is not sensible text, fall back to hex rather than emit
    mojibake. This is the case the declarative datasource gets wrong."""
    s = b.decode("utf-8", "replace").replace("�", "").strip("\x00").strip()
    if s and all(ch.isprintable() for ch in s):
        return s
    return _hex(b)


def decode_chassis_id(subtype, raw: bytes) -> str:
    """Render lldpRemChassisId / lldpLocChassisId according to its subtype.

    This is the topology JOIN KEY: device A's view of neighbour B must produce the exact same
    string as device B's view of itself. Both go through this function, so they do.
    """
    if raw is None:
        return ""
    st = _as_int(subtype)
    if st in _MAC_SUBTYPES:
        # The subtype DECLARES these bytes binary, so they never go through text decoding —
        # not even when they happen to form valid UTF-8. Caught by test: DE AD decodes
        # cleanly to U+07AD ('ޭ'), which is printable and utterly wrong.
        return _mac(raw) if len(raw) == 6 else _hex(raw)
    if st in _ADDR_SUBTYPES:
        return _network_address(raw)
    return _printable(raw)


def decode_port_id(subtype, raw: bytes) -> str:
    """Render lldpRemPortId / lldpLocPortId according to its subtype."""
    if raw is None:
        return ""
    st = _as_int(subtype)
    if st in _MAC_PORT_SUBTYPES:  # declared binary — see decode_chassis_id
        return _mac(raw) if len(raw) == 6 else _hex(raw)
    if st in _ADDR_PORT_SUBTYPES:
        return _network_address(raw)
    return _printable(raw)


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ── system capabilities bitmap ────────────────────────────────────────────────────────────
# Two octets. Bit 0 is the MOST significant bit of the FIRST octet — a detail that is easy to
# get backwards, so it is pinned by tests using bytes captured from real hardware.
#
#   20 00 -> 0b00100000 -> bit 2       -> bridge
#   28 00 -> 0b00101000 -> bits 2,4    -> bridge + router

CAPABILITIES = [
    "other", "repeater", "bridge", "wlanAccessPoint", "router", "telephone",
    "docsisCableDevice", "stationOnly", "cVLANComponent", "sVLANComponent",
    "twoPortMACRelay",
]

# What makes a neighbour part of the NETWORK rather than something attached to it.
_INFRA = {"repeater", "bridge", "router", "wlanAccessPoint", "docsisCableDevice",
          "cVLANComponent", "sVLANComponent", "twoPortMACRelay"}
# What positively identifies a neighbour as an endpoint. These WIN over infra markers: an IP
# phone almost always advertises bridge+telephone because it has a pass-through switch, and a
# laptop dock can advertise bridge too. Treating "bridge" as decisive would pull every desk
# phone into the topology — the exact noise we are excluding.
_ENDPOINT = {"telephone", "stationOnly"}


def decode_capabilities(raw: bytes) -> list:
    """Bitmap -> capability names, most-significant-bit-first within each octet."""
    if not raw:
        return []
    out = []
    for i, name in enumerate(CAPABILITIES):
        octet, bit = divmod(i, 8)
        if octet < len(raw) and raw[octet] & (0x80 >> bit):
            out.append(name)
    return out


def classify(raw_caps: bytes) -> str:
    """'endpoint' | 'infrastructure' | 'unknown'.

    'unknown' is deliberate and is NOT merged into either bucket: plenty of gear ships the
    capability TLV empty or omits it. The exclusion policy below only ever drops what we can
    POSITIVELY identify as an endpoint, so a switch that advertises nothing is never silently
    hidden from an operator. Under-filtering is recoverable; a missing switch is not.
    """
    caps = set(decode_capabilities(raw_caps))
    if not caps or caps == {"other"}:
        return "unknown"
    if caps & _ENDPOINT:
        return "endpoint"
    if caps & _INFRA:
        return "infrastructure"
    return "unknown"


def parse_man_addr_index(suffix: str):
    """lldpRemManAddrTable — pull the neighbour's MANAGEMENT IP out of the OID index.

    This is the capability the declarative datasource could not have. The address is not a
    column value at all; it lives inside the index:

        lldpRemManAddrEntry index =
            lldpRemTimeMark . lldpRemLocalPortNum . lldpRemIndex
            . lldpRemManAddrSubtype . lldpRemManAddrLen . <address octets>

    Real example walked from a Netgear GS752TP: index '0.47.7.1.4.10.0.10.3' -> the neighbour
    heard on local port 47 manages at 10.0.10.3. A declarative datasource only ever sees the
    column value, so it cannot reach this. Python walks the OIDs and can.

    Returns (rem_key, address) where rem_key matches the lldpRemTable index, so the address
    can be joined onto the neighbour it belongs to. ('', '') when the index is unparseable.

    NOTE this address is an ATTRIBUTE, not the topology join key. Joining topology on IP
    inherits the overlapping-IP problem (DR pairs, K8s meshes legitimately reuse ranges) —
    chassis id stays the key. This is here because it is genuinely useful to an operator and
    it lines up with device.address for the managed fleet.
    """
    parts = suffix.split(".")
    if len(parts) < 6:
        return "", ""
    rem_key = ".".join(parts[:3])
    try:
        subtype, length = int(parts[3]), int(parts[4])
    except ValueError:
        return rem_key, ""
    octets = parts[5:5 + length]
    if len(octets) != length:
        return rem_key, ""
    try:
        vals = [int(o) for o in octets]
    except ValueError:
        return rem_key, ""
    if subtype == _AF_IPV4 and length == 4:
        return rem_key, ".".join(str(v) for v in vals)
    if subtype == _AF_IPV6 and length == 16:
        return rem_key, ":".join(f"{vals[i] << 8 | vals[i + 1]:x}" for i in range(0, 16, 2))
    return rem_key, _hex(bytes(vals))


def should_emit(raw_caps: bytes, exclude_endpoints: bool = True) -> bool:
    """The cost/noise control, defaulted ON.

    Network teams manage endpoints with dedicated tooling (CrowdStrike, Zscaler); endpoints
    are where LLDP volume concentrates (a 48-port access switch can carry 40+ of them) and
    they crowd every topology view. Excluding them by default is the right posture — but see
    classify(): 'unknown' is kept, so this reduces noise without ever hiding infrastructure.
    """
    if not exclude_endpoints:
        return True
    return classify(raw_caps) != "endpoint"


# ── edge direction ────────────────────────────────────────────────────────────────────────
# cno.dep.uses is DIRECTED (device -> upstream) and the RCA suppression walk depends on that
# direction. LLDP adjacency is undirected, so a direction has to be derived.
#
# The old LLDP path derived it FROM THE HOSTNAME, which is exactly the inference we removed in
# B1a — it only worked because lab devices were named to match. We now decode the capability
# bitmap correctly (that is the whole point of this extension), so direction comes from what
# the devices ACTUALLY ADVERTISE about themselves instead of what they happen to be called.
#
# This is a HEURISTIC, not ground truth. It is honest about that: a router is more likely to
# sit above a switch, which is above an AP. Where an operator knows better, the app's
# customer-owned roles remain the authority.
CAP_RANK = {"router": 4, "bridge": 3, "wlanAccessPoint": 2, "repeater": 2}


def direction_rank(raw_caps: bytes) -> int:
    """Highest-ranked advertised capability. 1 when nothing useful is advertised."""
    return max((CAP_RANK.get(c, 1) for c in decode_capabilities(raw_caps)), default=1)


def gateway_hint(addr: str) -> int:
    """1 when the address is the first host of its /24 — the conventional gateway slot.

    A TIE-BREAK ONLY, and convention rather than fact. It exists because the capability rank
    above genuinely ties on real hardware: measured 2026-08-03, the Netgear GS752TP access
    switch `fortress` advertises lldpLocSysCapEnabled = 0x2800 (bridge + router), which is
    byte-identical to what the UCG Ultra gateway advertises. Both rank 4, so the decision fell
    through to a chassis-id sort — a value with NO relationship to network hierarchy — and
    recorded the WAN gateway as depending on an access switch.

    Comparing x.y.z.1 against x.y.z.2 carries at least some signal where a chassis id carries
    none. It is still a guess, and it is the LAST thing consulted before the arbitrary sort.
    """
    parts = str(addr or "").split(".")
    if len(parts) != 4:
        return 0  # IPv6 / chassis-id / anything unparseable — no opinion
    try:
        return 1 if int(parts[3]) == 1 and all(0 <= int(p) <= 255 for p in parts) else 0
    except ValueError:
        return 0


def orient(local_caps: bytes, local_key: str, remote_caps: bytes, remote_key: str,
           local_addr: str = "", remote_addr: str = "") -> bool:
    """True when the LOCAL device is the downstream end of this link.

    Mirrors the NetBox extension's rule — "lower rank depends on higher, tie-break by sort" —
    so the two topology sources agree on direction rather than fighting each other.

    SYMMETRY MATTERS. Both ends of a link are polled independently, and each computes this
    from the same (rank, gateway_hint, key) triples, so both arrive at the SAME direction and
    emit the SAME edge. Without that, A->B and B->A would both be emitted, and a bidirectional
    edge breaks the RCA workflow's downstream-suppression walk. Every component below is drawn
    from data BOTH ends can see — the two capability bitmaps, the two management addresses and
    the two chassis keys — which is what preserves that property. Never add a term that only
    one end can evaluate (local routing table, ipForwarding, interface counts), however much
    better a signal it looks: it would make the two ends disagree.

    Ordering: capability rank, then the gateway-address convention, then the arbitrary sort as
    a final deterministic fallback. None of this outranks a customer's own role assignment —
    the app applies those at render time (lib/roles.ts orientByRole), because assignments live
    in app state that an ActiveGate extension cannot read.
    """
    return ((direction_rank(local_caps), gateway_hint(local_addr), local_key)
            <= (direction_rank(remote_caps), gateway_hint(remote_addr), remote_key))


# ── routing adjacency (BGP4-MIB / OSPF-MIB) ───────────────────────────────────────────────
# The peer IDENTITY in both MIBs is an SNMP IpAddress: [APPLICATION 0] IMPLICIT OCTET STRING
# (SIZE(4)) — four RAW bytes, not text. 10.0.10.3 is 0A 00 0A 03, three of which are control
# characters. This is the same class of value the declarative datasource destroys on LLDP, and
# it is why routing lives in this extension rather than a declarative group: the peer STATE is
# an integer and would survive, but a session state with no identifiable peer is not actionable.

def decode_ip(raw) -> str:
    """SNMP IpAddress (exactly 4 bytes) -> dotted quad. Anything else stays LOSSLESS as hex
    rather than being guessed at or text-decoded."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw  # some agents/stacks hand this back already rendered
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        return ":".join(f"{raw[i] << 8 | raw[i+1]:x}" for i in range(0, 16, 2))
    return _hex(bytes(raw))


# bgpPeerState (BGP4-MIB 1.3.6.1.2.1.15.3.1.2)
BGP_STATE = {1: "idle", 2: "connect", 3: "active", 4: "opensent", 5: "openconfirm",
             6: "established"}
BGP_ESTABLISHED = 6

# ospfNbrState (OSPF-MIB 1.3.6.1.2.1.14.10.1.6). Only FULL means the adjacency is usable;
# twoWay is normal and healthy on a broadcast segment for non-DR/BDR routers, so it is NOT
# an error — see ospf_is_healthy().
OSPF_STATE = {1: "down", 2: "attempt", 3: "init", 4: "twoWay", 5: "exchangeStart",
              6: "exchange", 7: "loading", 8: "full"}
OSPF_FULL = 8
OSPF_TWO_WAY = 4


def bgp_state_label(v) -> str:
    return BGP_STATE.get(_as_int(v), f"unknown({_as_int(v)})")


def bgp_is_established(v) -> bool:
    return _as_int(v) == BGP_ESTABLISHED


def ospf_state_label(v) -> str:
    return OSPF_STATE.get(_as_int(v), f"unknown({_as_int(v)})")


def ospf_is_healthy(v) -> bool:
    """FULL, or twoWay.

    twoWay is deliberately counted healthy. On a broadcast segment every router forms a FULL
    adjacency only with the DR and BDR; with everyone else it settles at twoWay by design.
    Alerting on 'not full' would page for normal OSPF behaviour on every LAN — exactly the
    alert storm this project exists to avoid.
    """
    return _as_int(v) in (OSPF_FULL, OSPF_TWO_WAY)


# ── LLDP coverage: ports that are UP but report no neighbour ──────────────────────────────
# The silent failure this exists to expose: a port is up, something real is attached, and the
# topology shows nothing — with no error anywhere. Observed on the lab GS752TP, where an
# LLDP-capable access point on port g1 never appeared because the switch had no LLDP record
# for that port. The neighbour table said 3 and the operator had no way to know it should
# have said 4.
#
# We already collect both halves, so the gap is computable and therefore reportable.

# IF-MIB ifType. Only real ETHERNET ports can have an LLDP neighbour; counting anything else
# inflates the gap with things that can never have one. This filter is not cosmetic — the lab
# switch reports 13 interfaces "up" of which only 4 are physical; the other 9 are LAG/virtual
# and would have produced a fictional gap of 9.
IFTYPE_ETHERNET = 6
IFTYPE_LAG = 161


def coverage(ports_up, ports_with_neighbor):
    """(up, with_neighbour) -> {'up','covered','gap','gap_ports'} keyed on PORT NAME.

    Joined on NAME, not index, on purpose: LLDP maintains its own port numbering
    (lldpLocPortNum) which is not guaranteed to equal ifIndex. Both sides render a name —
    ifName and lldpLocPortId — so the name is the only key that is reliably comparable.
    """
    # str(None) is the truthy string "None", so filter the value BEFORE stringifying.
    up = {str(p).strip() for p in ports_up if p is not None and str(p).strip()}
    seen = {str(p).strip() for p in ports_with_neighbor if p is not None and str(p).strip()}
    gap = sorted(up - seen)
    return {"up": len(up), "covered": len(up & seen), "gap": len(gap), "gap_ports": gap}
