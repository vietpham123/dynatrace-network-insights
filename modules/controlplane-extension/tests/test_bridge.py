"""
Switch port mapper — the join, pinned.

Every assertion here is a way the mapping can be silently WRONG rather than absent. A port
mapper that reports nothing is obviously broken and gets fixed; one that confidently attaches a
host to the wrong port sends an engineer to unplug the wrong cable.
"""
import pytest

from controlplane_extension.bridge import (
    mac_from_fdb_index, ip_from_arp_index, mac_from_octets, port_to_ifindex,
    mac_to_ifindex, arp_to_ip, host_ports,
)

MAC_A = "20:4e:7f:4e:c3:e6"
MAC_B = "58:d6:1f:23:21:af"


class TestIndexDecoding:
    def test_dot1q_index_drops_the_leading_vlan_id(self):
        # fdbId=1, then the six MAC octets
        assert mac_from_fdb_index("1.32.78.127.78.195.230") == MAC_A

    def test_dot1d_index_is_the_bare_mac(self):
        assert mac_from_fdb_index("32.78.127.78.195.230") == MAC_A

    def test_a_shape_we_do_not_recognise_returns_None_not_a_guess(self):
        for bad in ("", "1.2.3", "1.2.3.4.5.6.7.8", "abc", "1.2.3.4.5"):
            assert mac_from_fdb_index(bad) is None, bad

    def test_an_out_of_range_octet_is_rejected(self):
        assert mac_from_fdb_index("1.32.78.127.78.195.999") is None

    def test_arp_index_splits_ifindex_from_address(self):
        assert ip_from_arp_index("12.10.0.10.100") == (12, "10.0.10.100")

    def test_arp_index_of_the_wrong_shape_is_rejected(self):
        assert ip_from_arp_index("10.0.10.100") is None      # missing ifIndex
        assert ip_from_arp_index("12.10.0.10.100.7") is None

    def test_mac_value_decoding(self):
        assert mac_from_octets(bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE6])) == MAC_A
        assert mac_from_octets(b"\xde\xad") == ""            # wrong length -> nothing
        assert mac_from_octets(None) == ""
        assert mac_from_octets("58:D6:1F:23:21:AF") == MAC_B  # already rendered


class TestTheJoin:
    def test_bridge_port_is_translated_through_dot1dBasePortIfIndex(self):
        """Bridge port 4 is NOT necessarily ifIndex 4 — the whole reason that table is walked."""
        base = port_to_ifindex({"4": 104, "49": 149})
        assert base == {4: 104, 49: 149}
        got = mac_to_ifindex({"1.32.78.127.78.195.230": 4}, base)
        assert got == {MAC_A: 104}, "bridge port was used as an ifIndex"

    def test_a_mac_on_a_port_with_no_ifindex_mapping_is_DROPPED(self):
        """Passing the bridge port through as though it were an ifIndex is the failure this
        guards. Silence beats a plausible wrong number."""
        assert mac_to_ifindex({"1.32.78.127.78.195.230": 7}, {4: 104}) == {}

    def test_unparseable_rows_are_skipped_not_fatal(self):
        base = port_to_ifindex({"4": 104, "bad": "x", "5": None})
        assert base == {4: 104}
        assert mac_to_ifindex({"garbage": 4, "1.32.78.127.78.195.230": "x"}, base) == {}

    def test_arp_builds_mac_to_ip(self):
        rows = {"12.10.0.10.100": bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE6])}
        assert arp_to_ip(rows) == {MAC_A: "10.0.10.100"}


class TestUplinkSuppression:
    def test_a_port_carrying_many_macs_is_treated_as_an_uplink(self):
        """Everything beyond a trunk appears on it. Reporting 40 hosts as 'plugged into port 49'
        is worse than reporting nothing for that port."""
        macs = {f"00:00:00:00:00:{i:02x}": 49 for i in range(12)}
        assert host_ports(macs, {}, "outpost", "10.0.10.3") == []

    def test_access_ports_survive(self):
        got = host_ports({MAC_A: 104, MAC_B: 105}, {MAC_A: "10.0.10.100"}, "outpost", "10.0.10.3")
        assert [r["ifIndex"] for r in got] == [104, 105]
        assert got[0]["ip"] == "10.0.10.100"

    def test_a_mac_with_no_arp_match_is_KEPT_with_an_empty_address(self):
        """The port attribution is true even when no ARP cache resolved the MAC. Dropping it
        would hide a real device; faking an address would be worse."""
        got = host_ports({MAC_B: 105}, {}, "outpost", "10.0.10.3")
        assert len(got) == 1
        assert got[0]["mac"] == MAC_B and got[0]["ip"] == ""

    def test_the_threshold_is_tunable(self):
        macs = {f"00:00:00:00:00:{i:02x}": 3 for i in range(4)}
        assert host_ports(macs, {}, "d", "a", threshold=99) != []
        assert host_ports(macs, {}, "d", "a", threshold=2) == []


class TestEndToEnd:
    def test_a_realistic_two_port_switch(self):
        """ARP comes from a DIFFERENT device than the FDB — the normal enterprise case, since a
        pure L2 switch has no ARP entries for hosts."""
        fdb = {"1.32.78.127.78.195.230": 4, "1.88.214.31.35.33.175": 5}
        base = port_to_ifindex({"4": 104, "5": 105})
        arp_from_the_router = arp_to_ip({
            "12.10.0.10.100": bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE6]),
            "12.10.0.10.28": bytes([0x58, 0xD6, 0x1F, 0x23, 0x21, 0xAF]),
        })
        rows = host_ports(mac_to_ifindex(fdb, base), arp_from_the_router, "outpost", "10.0.10.3")
        assert rows == [
            {"mac": MAC_A, "ifIndex": 104, "ip": "10.0.10.100", "device": "outpost", "address": "10.0.10.3"},
            {"mac": MAC_B, "ifIndex": 105, "ip": "10.0.10.28", "device": "outpost", "address": "10.0.10.3"},
        ]

    def test_a_device_with_no_bridge_mib_yields_nothing_quietly(self):
        """Routers, UPSs and APs have no forwarding database. Not a fault."""
        assert host_ports(mac_to_ifindex({}, {}), {}, "ups-1", "10.0.10.146") == []
