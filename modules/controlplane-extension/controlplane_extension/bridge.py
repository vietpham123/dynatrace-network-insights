"""
Switch port mapping — which physical port is a given host plugged into.

WHY THIS EXISTS. Flow data names the ROUTER interface a conversation crossed, and LLDP names
the device adjacency, but neither can say that 10.0.10.100 hangs off `outpost` port 4. That
last hop is the one a network team is asked about constantly ("find me this device"), and it
is the missing link between the topology graph and the traffic matrix. Commercial NMS tools
sell it as a "switch port mapper"; it is three SNMP tables and a join.

    ipNetToMediaPhysAddress   IP  -> MAC          (an L3 device's ARP cache)
    dot1qTpFdbPort            MAC -> bridge port  (the switch's forwarding database)
    dot1dBasePortIfIndex      bridge port -> ifIndex

THE JOIN USUALLY SPANS DEVICES, which is the part that catches people out. A pure L2 switch
has a forwarding database but no ARP entries for hosts — the ARP cache lives on whatever does
routing for that subnet. So ARP is collected from every device that has one and pooled, while
the FDB is per-switch. Insisting both come from the same box would return nothing on exactly
the estates this is for.

WHY IT IS NOT IN THE DECLARATIVE EXTENSION. The FDB index carries the MAC as six raw
sub-identifiers inside the OID, and the ARP index carries ifIndex plus a dotted quad. That is
the same binary-in-the-index decoding the declarative datasource mangles, which is why this
extension exists at all (see codec.py). Everything here decodes from the numeric index by hand.
"""

# Q-BRIDGE-MIB: index is fdbId . 6 MAC octets  -> value is the bridge port number
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
# BRIDGE-MIB (older, not VLAN-aware): index is 6 MAC octets -> bridge port
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
# BRIDGE-MIB: bridge port -> ifIndex. Bridge ports are NOT ifIndexes; assuming they are is the
# classic error, and on many platforms they genuinely differ.
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
# IP-MIB ARP cache: index is ifIndex . a.b.c.d -> value is the MAC
IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1.2"


def _parts(index: str):
    try:
        return [int(x) for x in str(index).strip(".").split(".") if x != ""]
    except ValueError:
        return []


def mac_from_fdb_index(index: str):
    """MAC from a dot1q (fdbId + 6) or dot1d (6) forwarding-database index.

    Returns the canonical lower-case colon form, or None when the index is not a shape we
    recognise — never a guess. A wrong MAC here would attach a host to the wrong port, which is
    worse than reporting nothing.
    """
    p = _parts(index)
    if len(p) == 7:
        p = p[1:]                      # drop the leading fdbId / VLAN id
    if len(p) != 6 or any(o < 0 or o > 255 for o in p):
        return None
    return ":".join(f"{o:02x}" for o in p)


def ip_from_arp_index(index: str):
    """(ifIndex, dotted-quad) from an ipNetToMedia index, or None."""
    p = _parts(index)
    if len(p) != 5 or any(o < 0 or o > 255 for o in p[1:]):
        return None
    return p[0], ".".join(str(o) for o in p[1:])


def mac_from_octets(raw) -> str:
    """A MAC held as a VALUE (the ARP table) rather than in an index."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        s = raw.strip()
        return s.lower() if ":" in s else ""
    b = bytes(raw)
    return ":".join(f"{o:02x}" for o in b) if len(b) == 6 else ""


def port_to_ifindex(base_port_rows: dict) -> dict:
    """{bridge port -> ifIndex} from dot1dBasePortIfIndex."""
    out = {}
    for idx, val in (base_port_rows or {}).items():
        p = _parts(idx)
        try:
            ifx = int(val)
        except (TypeError, ValueError):
            continue
        if len(p) == 1 and ifx > 0:
            out[p[0]] = ifx
    return out


def mac_to_ifindex(fdb_rows: dict, base_map: dict) -> dict:
    """{MAC -> ifIndex} for one switch.

    A bridge port with no dot1dBasePortIfIndex entry is DROPPED rather than passed through as
    though the bridge port were an ifIndex. They coincide on some platforms and not on others,
    and silently emitting the wrong number is how a port mapper loses trust.
    """
    out = {}
    for idx, val in (fdb_rows or {}).items():
        mac = mac_from_fdb_index(idx)
        if not mac:
            continue
        try:
            bport = int(val)
        except (TypeError, ValueError):
            continue
        ifx = (base_map or {}).get(bport)
        if ifx:
            out[mac] = ifx
    return out


def arp_to_ip(arp_rows: dict) -> dict:
    """{MAC -> IP} from one device's ARP cache.

    Last write wins on a duplicate MAC, which is correct for the common case (a host with one
    address) and harmless for the rare one — the port attribution is keyed on the MAC either way.
    """
    out = {}
    for idx, val in (arp_rows or {}).items():
        parsed = ip_from_arp_index(idx)
        mac = mac_from_octets(val)
        if parsed and mac:
            out[mac] = parsed[1]
    return out


# Uplinks carry the MAC of everything beyond them. A port showing dozens of MACs is a trunk, not
# a host port, and reporting "these 40 devices are plugged into port 49" is actively misleading.
UPLINK_MAC_THRESHOLD = 8


def host_ports(mac_ifx: dict, mac_ip: dict, device: str, address: str,
               threshold: int = UPLINK_MAC_THRESHOLD) -> list:
    """Join into per-host records, excluding uplink ports.

    Returns [{mac, ifIndex, ip, device, address}]. `ip` is "" when no ARP cache in the pool
    resolved that MAC — the port attribution is still true and useful, so the record is kept
    rather than dropped, and the empty address says plainly that this MAC was not matched.
    """
    per_port = {}
    for mac, ifx in (mac_ifx or {}).items():
        per_port.setdefault(ifx, []).append(mac)
    out = []
    for ifx, macs in per_port.items():
        if len(macs) >= threshold:
            continue                    # a trunk/uplink, not an access port
        for mac in macs:
            out.append({
                "mac": mac,
                "ifIndex": ifx,
                "ip": (mac_ip or {}).get(mac, ""),
                "device": device,
                "address": address,
            })
    out.sort(key=lambda r: (r["ifIndex"], r["mac"]))
    return out


async def collect_bridge(walk_column, engine, auth, target, ctx, max_reps, mode) -> dict:
    """Walk the three tables. Absent tables come back empty, never as an error.

    A device with no BRIDGE-MIB is not a fault — routers, UPSs and access points legitimately
    have none — so each walk is guarded independently and a failure on one leaves the others
    usable.
    """
    async def safe(base):
        try:
            return await walk_column(engine, auth, target, ctx, base, max_reps, mode)
        except Exception:               # noqa: BLE001 — an absent table must not fail the poll
            return {}

    q = await safe(DOT1Q_FDB_PORT)
    fdb = q or await safe(DOT1D_FDB_PORT)      # prefer VLAN-aware; fall back to the older table
    return {
        "fdb": fdb,
        "base_ports": await safe(DOT1D_BASE_PORT_IFINDEX),
        "arp": await safe(IP_NET_TO_MEDIA),
        "vlan_aware": bool(q),
    }
