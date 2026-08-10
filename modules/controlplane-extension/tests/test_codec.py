"""
Tests for the LLDP decoder, built around the EXACT bytes captured from real hardware on
2026-08-01 (docs/ENTERPRISE-READINESS.md §L).

This file exists to pin a defect we shipped and measured, not to exercise the happy path. The
declarative SNMP datasource turned those same bytes into ' N\x7fN', ' ' and '(' — every
assertion below is a thing that was demonstrably broken in production data.
"""
import pytest

from controlplane_extension.codec import (
    CAPABILITIES, classify, decode_capabilities, decode_chassis_id, decode_port_id,
    bgp_is_established, bgp_state_label, decode_ip, direction_rank, gateway_hint, orient,
    coverage, ospf_is_healthy, ospf_state_label, parse_man_addr_index, should_emit,
)

# Captured from the lab, switch "Starscream", 2026-08-01.
NEIGHBOUR_MAC = bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE6])  # became ' N\x7fN'
CAP_BRIDGE = bytes([0x20, 0x00])                             # became ' '
CAP_BRIDGE_ROUTER = bytes([0x28, 0x00])                      # became '('


class TestTheRegressionWeMeasured:
    """The three values the declarative datasource destroyed."""

    def test_neighbour_mac_survives_as_a_real_mac(self):
        # was: ' N\x7fN'  (2 of 6 bytes silently dropped)
        assert decode_chassis_id(4, NEIGHBOUR_MAC) == "20:4e:7f:4e:c3:e6"

    def test_bridge_capability_survives(self):
        # was: ' '
        assert decode_capabilities(CAP_BRIDGE) == ["bridge"]

    def test_bridge_router_capability_survives(self):
        # was: '('
        assert decode_capabilities(CAP_BRIDGE_ROUTER) == ["bridge", "router"]

    def test_distinct_macs_no_longer_collide(self):
        """The reason the 'mangled but deterministic' shortcut was rejected.

        Under UTF-8-with-drop these three collapsed to ONE string. They differ in the
        trailing bytes — exactly where same-vendor fleet MACs differ — so the old scheme
        would have merged three switches into one topology node.
        """
        macs = [
            bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE6]),
            bytes([0x20, 0x4E, 0x7F, 0x4E, 0xC3, 0xE7]),
            bytes([0x20, 0x4E, 0x7F, 0x4E, 0xFF, 0xFE]),
        ]
        # prove the old behaviour really did collide, so this test documents the bug
        assert len({m.decode("utf-8", "ignore") for m in macs}) == 1
        # and that we now keep them distinct
        assert len({decode_chassis_id(4, m) for m in macs}) == 3


class TestChassisId:
    def test_mac_subtype(self):
        assert decode_chassis_id(4, bytes.fromhex("58d61f2321af")) == "58:d6:1f:23:21:af"

    def test_local_subtype_is_text(self):
        # the endpoint that came through clean even on the broken path
        assert decode_chassis_id(7, b"VP-GAMING-PC") == "VP-GAMING-PC"

    def test_already_printable_mac_is_left_alone(self):
        assert decode_chassis_id(6, b"58:d6:1f:23:21:af") == "58:d6:1f:23:21:af"

    def test_network_address_ipv4(self):
        assert decode_chassis_id(5, bytes([1, 10, 0, 10, 3])) == "10.0.10.3"

    def test_network_address_ipv6(self):
        raw = bytes([2]) + bytes.fromhex("20010db8000000000000000000000001")
        assert decode_chassis_id(5, raw) == "2001:db8:0:0:0:0:0:1"

    def test_mac_subtype_with_wrong_length_falls_back_to_hex_not_garbage(self):
        # a 6-byte reading is asserted, not assumed; anything else stays LOSSLESS
        assert decode_chassis_id(4, bytes([0xDE, 0xAD])) == "0xdead"

    def test_binary_under_a_text_subtype_falls_back_to_hex(self):
        """A lying subtype must not produce mojibake — hex is wrong-looking but recoverable."""
        assert decode_chassis_id(7, NEIGHBOUR_MAC) == "0x204e7f4ec3e6"

    def test_trailing_nulls_are_stripped(self):
        assert decode_chassis_id(7, b"switch-01\x00\x00") == "switch-01"

    @pytest.mark.parametrize("bad", [None, b""])
    def test_empty_input(self, bad):
        assert decode_chassis_id(4, bad) == ""


class TestPortId:
    def test_interface_name_survives(self):
        # the one field that came through clean on the broken path
        assert decode_port_id(5, b"0/48") == "0/48"

    def test_mac_port_id(self):
        # was: 'X_#!' — a port-id advertised as raw MAC bytes
        assert decode_port_id(3, bytes.fromhex("58d61f2321af")) == "58:d6:1f:23:21:af"

    def test_port_component_binary_is_hex_not_mojibake(self):
        assert decode_port_id(2, bytes([0x00, 0x01])) == "0x0001"


class TestCapabilityBitmap:
    def test_bit_order_is_msb_first(self):
        """Easy to get backwards; pinned against hardware-captured bytes."""
        assert decode_capabilities(bytes([0x80, 0x00])) == ["other"]
        assert decode_capabilities(bytes([0x40, 0x00])) == ["repeater"]
        assert decode_capabilities(bytes([0x20, 0x00])) == ["bridge"]
        assert decode_capabilities(bytes([0x01, 0x00])) == ["stationOnly"]

    def test_second_octet(self):
        assert decode_capabilities(bytes([0x00, 0x80])) == ["cVLANComponent"]
        assert decode_capabilities(bytes([0x00, 0x20])) == ["twoPortMACRelay"]

    def test_every_capability_is_reachable(self):
        seen = set()
        for i in range(len(CAPABILITIES)):
            octet, bit = divmod(i, 8)
            raw = bytearray(2)
            raw[octet] = 0x80 >> bit
            seen.update(decode_capabilities(bytes(raw)))
        assert seen == set(CAPABILITIES)

    def test_empty_bitmap(self):
        assert decode_capabilities(b"") == []
        assert decode_capabilities(bytes([0x00, 0x00])) == []


class TestClassification:
    def test_switch_is_infrastructure(self):
        assert classify(CAP_BRIDGE) == "infrastructure"

    def test_router_is_infrastructure(self):
        assert classify(CAP_BRIDGE_ROUTER) == "infrastructure"

    def test_access_point_is_infrastructure(self):
        assert classify(bytes([0x10, 0x00])) == "infrastructure"

    def test_workstation_is_an_endpoint(self):
        assert classify(bytes([0x01, 0x00])) == "endpoint"

    def test_ip_phone_is_an_endpoint_even_though_it_bridges(self):
        """Phones advertise bridge+telephone because of the pass-through switch. Treating
        'bridge' as decisive would drag every desk phone into the topology."""
        raw = bytes([0x20 | 0x04, 0x00])  # bridge + telephone
        assert set(decode_capabilities(raw)) == {"bridge", "telephone"}
        assert classify(raw) == "endpoint"

    def test_absent_capabilities_are_unknown_not_guessed(self):
        assert classify(b"") == "unknown"
        assert classify(bytes([0x00, 0x00])) == "unknown"

    def test_other_alone_is_unknown(self):
        assert classify(bytes([0x80, 0x00])) == "unknown"


class TestExclusionPolicy:
    def test_endpoints_excluded_by_default(self):
        assert should_emit(bytes([0x01, 0x00])) is False

    def test_infrastructure_always_kept(self):
        assert should_emit(CAP_BRIDGE) is True

    def test_unknown_is_KEPT_so_a_switch_is_never_silently_hidden(self):
        """The conservative half of the default. Under-filtering is recoverable; a missing
        switch in a topology view is not."""
        assert should_emit(b"") is True
        assert should_emit(bytes([0x00, 0x00])) is True

    def test_opting_out_keeps_everything(self):
        assert should_emit(bytes([0x01, 0x00]), exclude_endpoints=False) is True


class TestBinarySubtypesNeverTextDecode:
    """Regression: DE AD is VALID UTF-8 (U+07AD 'ޭ') and passes an isprintable() check, so a
    printability test alone is not enough. When the subtype declares binary, the bytes must
    never reach text decoding at all."""

    def test_short_mac_chassis_is_hex_not_valid_looking_utf8(self):
        assert decode_chassis_id(4, bytes([0xDE, 0xAD])) == "0xdead"

    def test_short_mac_port_is_hex(self):
        assert decode_port_id(3, bytes([0xDE, 0xAD])) == "0xdead"

    def test_long_mac_is_hex_rather_than_truncated(self):
        assert decode_chassis_id(4, bytes.fromhex("58d61f2321afaf")) == "0x58d61f2321afaf"


class TestManagementAddressFromOidIndex:
    """lldpRemManAddrTable puts the address INSIDE the index, which is precisely why the
    declarative datasource cannot reach it. Fixture is a real index walked from a Netgear
    GS752TP: local port 47, neighbour managing at 10.0.10.3."""

    def test_real_hardware_ipv4_index(self):
        assert parse_man_addr_index("0.47.7.1.4.10.0.10.3") == ("0.47.7", "10.0.10.3")

    def test_key_matches_the_lldp_rem_table_index(self):
        """The first three components must line up with lldpRemTable so the address can be
        joined onto the right neighbour."""
        key, _ = parse_man_addr_index("0.47.7.1.4.10.0.10.3")
        assert key == "0.47.7"

    def test_ipv6(self):
        addr = ".".join(str(b) for b in bytes.fromhex("20010db8000000000000000000000001"))
        key, got = parse_man_addr_index(f"0.3.1.2.16.{addr}")
        assert (key, got) == ("0.3.1", "2001:db8:0:0:0:0:0:1")

    def test_declared_length_must_match_the_octets_present(self):
        assert parse_man_addr_index("0.47.7.1.4.10.0.10") == ("0.47.7", "")

    def test_unknown_family_is_kept_as_hex_not_invented(self):
        _, got = parse_man_addr_index("0.1.1.99.2.1.2")
        assert got == "0x0102"

    def test_truncated_index(self):
        assert parse_man_addr_index("0.47") == ("", "")


class TestEdgeDirection:
    """Direction must be derived from ADVERTISED CAPABILITY, not the hostname (B1a), and it
    must be symmetric — both ends of a link have to agree or the RCA suppression walk sees a
    bidirectional edge."""

    ROUTER = bytes([0x28, 0x00])   # bridge + router
    SWITCH = bytes([0x20, 0x00])   # bridge
    AP = bytes([0x10, 0x00])       # wlanAccessPoint
    NONE = b""

    def test_switch_is_downstream_of_router(self):
        assert orient(self.SWITCH, "sw", self.ROUTER, "rtr") is True

    def test_router_is_not_downstream_of_switch(self):
        assert orient(self.ROUTER, "rtr", self.SWITCH, "sw") is False

    def test_ap_is_downstream_of_switch(self):
        assert orient(self.AP, "ap", self.SWITCH, "sw") is True

    def test_unadvertised_is_downstream_of_a_switch(self):
        assert orient(self.NONE, "x", self.SWITCH, "sw") is True

    def test_both_ends_agree_so_only_one_edge_is_emitted(self):
        """The property that keeps the graph a DAG rather than a mesh of two-way edges."""
        for a_caps, a, b_caps, b in [
            (self.SWITCH, "aa", self.ROUTER, "bb"),
            (self.SWITCH, "bb", self.SWITCH, "aa"),
            (self.NONE, "zz", self.NONE, "aa"),
            (self.AP, "m", self.ROUTER, "n"),
        ]:
            a_says = orient(a_caps, a, b_caps, b)      # A's view: am I downstream?
            b_says = orient(b_caps, b, a_caps, a)      # B's view: am I downstream?
            assert a_says != b_says, f"both ends claimed the same role for {a}/{b}"

    def test_identical_peers_tie_break_deterministically_by_key(self):
        assert orient(self.SWITCH, "aaa", self.SWITCH, "bbb") is True
        assert orient(self.SWITCH, "bbb", self.SWITCH, "aaa") is False

    # ── the real-hardware tie that inverted the lab topology (2026-08-03) ──────────────────
    # Both the Netgear GS752TP access switch and the UCG Ultra gateway advertise 0x2800 =
    # bridge + router, so capability rank ties at 4 and the old code fell to a chassis-id sort,
    # recording the WAN gateway as depending on the access switch.
    BRIDGE_ROUTER = bytes([0x28, 0x00])

    def test_bridge_router_ties_on_capability_alone(self):
        assert direction_rank(self.BRIDGE_ROUTER) == 4
        assert direction_rank(self.BRIDGE_ROUTER) == direction_rank(self.ROUTER)

    def test_gateway_address_breaks_the_tie_toward_the_dot_one(self):
        # fortress 10.0.10.2 vs transformers 192.168.1.1 — chassis keys chosen so the OLD
        # arbitrary sort would have gone the wrong way ("f..." > "0...").
        assert orient(self.BRIDGE_ROUTER, "fortress-chassis", self.BRIDGE_ROUTER,
                      "0-transformers-chassis", "10.0.10.2", "192.168.1.1") is True
        assert orient(self.BRIDGE_ROUTER, "0-transformers-chassis", self.BRIDGE_ROUTER,
                      "fortress-chassis", "192.168.1.1", "10.0.10.2") is False

    def test_capability_still_outranks_the_address_convention(self):
        # a .1 switch must NOT be hoisted above a real router on a .2
        assert orient(self.SWITCH, "sw", self.ROUTER, "rtr", "10.0.0.1", "10.0.0.2") is True

    def test_address_hint_keeps_both_ends_in_agreement(self):
        for a_caps, a, b_caps, b, aip, bip in [
            (self.BRIDGE_ROUTER, "f", self.BRIDGE_ROUTER, "t", "10.0.10.2", "192.168.1.1"),
            (self.SWITCH, "aa", self.SWITCH, "bb", "10.0.0.1", "10.0.0.1"),   # both .1
            (self.SWITCH, "aa", self.SWITCH, "bb", "", ""),                    # neither parseable
            (self.ROUTER, "r", self.AP, "a", "192.168.1.1", "192.168.1.50"),
        ]:
            assert orient(a_caps, a, b_caps, b, aip, bip) != orient(b_caps, b, a_caps, a, bip, aip), \
                f"both ends claimed the same role for {a}/{b}"

    def test_gateway_hint_only_fires_on_a_parseable_dot_one(self):
        assert gateway_hint("10.0.10.1") == 1
        assert gateway_hint("10.0.10.2") == 0
        assert gateway_hint("192.168.1.1") == 1
        assert gateway_hint("") == 0
        assert gateway_hint("fe80::1") == 0            # IPv6 — no opinion
        assert gateway_hint("00:0d:3a:ef:5d:7b") == 0  # a chassis id, not an address
        assert gateway_hint("10.0.10.999") == 0        # out of range
        assert gateway_hint("10.0.1") == 0             # not four octets

    def test_omitting_addresses_preserves_the_old_behaviour(self):
        # every existing caller/test that passes four args must be unaffected
        assert orient(self.SWITCH, "aaa", self.SWITCH, "bbb") is True
        assert orient(self.SWITCH, "sw", self.ROUTER, "rtr") is True

    def test_rank_of_each_capability(self):
        assert direction_rank(self.ROUTER) == 4
        assert direction_rank(self.SWITCH) == 3
        assert direction_rank(self.AP) == 2
        assert direction_rank(self.NONE) == 1


class TestRoutingPeerIdentity:
    """The reason routing lives in this extension rather than a declarative group: BGP and
    OSPF identify peers with SNMP IpAddress — FOUR RAW BYTES — which is the same shape the
    declarative datasource destroys on LLDP. 10.0.10.3 is 0A 00 0A 03; three of those four
    bytes are control characters."""

    def test_ipaddress_decodes_to_dotted_quad(self):
        assert decode_ip(bytes([10, 0, 10, 3])) == "10.0.10.3"

    def test_the_bytes_that_would_have_been_mangled(self):
        raw = bytes([10, 0, 10, 3])
        assert raw.decode("utf-8", "ignore") != "10.0.10.3"   # what the old path produced
        assert decode_ip(raw) == "10.0.10.3"                  # what we produce

    def test_distinct_peers_stay_distinct(self):
        peers = [bytes([10, 0, 10, i]) for i in (1, 2, 3, 254)]
        assert len({decode_ip(p) for p in peers}) == 4

    def test_ipv6_router_id(self):
        raw = bytes.fromhex("20010db8000000000000000000000001")
        assert decode_ip(raw) == "2001:db8:0:0:0:0:0:1"

    def test_wrong_length_is_hex_not_invented(self):
        assert decode_ip(bytes([10, 0])) == "0x0a00"

    def test_already_rendered_passes_through(self):
        assert decode_ip("10.0.10.3") == "10.0.10.3"

    def test_empty(self):
        assert decode_ip(None) == ""


class TestBgpState:
    def test_established_is_the_only_up_state(self):
        assert bgp_is_established(6) is True
        for s in (1, 2, 3, 4, 5):
            assert bgp_is_established(s) is False, f"state {s} must not count as up"

    def test_labels(self):
        assert bgp_state_label(6) == "established"
        assert bgp_state_label(3) == "active"      # 'active' is NOT healthy — it is retrying
        assert bgp_state_label(1) == "idle"

    def test_unknown_state_is_reported_not_swallowed(self):
        assert "unknown" in bgp_state_label(99)


class TestOspfState:
    def test_full_is_healthy(self):
        assert ospf_is_healthy(8) is True

    def test_two_way_is_ALSO_healthy(self):
        """On a broadcast segment a router goes FULL only with the DR and BDR; with every other
        router it settles at twoWay by design. Treating that as a fault would page for normal
        OSPF behaviour on every LAN — the exact alert storm this project exists to avoid."""
        assert ospf_is_healthy(4) is True

    def test_everything_below_two_way_is_not_healthy(self):
        for s in (1, 2, 3):
            assert ospf_is_healthy(s) is False, f"state {s} must not count as healthy"

    def test_mid_negotiation_states_are_not_healthy(self):
        for s in (5, 6, 7):
            assert ospf_is_healthy(s) is False

    def test_labels(self):
        assert ospf_state_label(8) == "full"
        assert ospf_state_label(4) == "twoWay"
        assert ospf_state_label(1) == "down"


class TestLldpCoverage:
    """Exposes the silent gap: a port up with something attached, absent from the topology.
    Fixture mirrors the real lab switch — 4 physical ports up, 3 with neighbours, the AP on
    g1 invisible because the switch had no LLDP record for that port."""

    def test_the_real_lab_case(self):
        c = coverage(["g1", "g27", "g47", "g48"], ["g27", "g47", "g48"])
        assert c["up"] == 4 and c["covered"] == 3
        assert c["gap"] == 1 and c["gap_ports"] == ["g1"]

    def test_full_coverage_reports_no_gap(self):
        c = coverage(["g1", "g2"], ["g1", "g2"])
        assert c["gap"] == 0 and c["gap_ports"] == []

    def test_neighbour_on_a_port_we_did_not_list_as_up_is_not_a_gap(self):
        """A neighbour on a port missing from the up-list must never produce a NEGATIVE or
        phantom gap — set difference is one-directional on purpose."""
        c = coverage(["g1"], ["g1", "g99"])
        assert c["gap"] == 0 and c["up"] == 1

    def test_no_ports_up(self):
        c = coverage([], ["g1"])
        assert c == {"up": 0, "covered": 0, "gap": 0, "gap_ports": []}

    def test_gap_ports_are_sorted_and_deduped(self):
        c = coverage(["g3", "g1", "g1", "g2"], [])
        assert c["gap_ports"] == ["g1", "g2", "g3"]

    def test_blank_names_are_ignored(self):
        c = coverage(["g1", "", None], ["g1"])
        assert c["gap"] == 0


class TestBgpOidColumnNumbers:
    """Pins the BGP4-MIB column numbers. Shipped wrong once (.24/.25): .24 is
    bgpPeerInUpdateElapsedTime and .25 does not exist in bgpPeerEntry, so the flap counter and
    session uptime were silently reading the wrong object — or nothing. Nothing in the lab runs
    BGP, so no test and no live data would have caught it."""

    def test_column_numbers_match_rfc4273(self):
        from controlplane_extension import routing as r
        assert r.BGP_PEER_STATE.endswith(".15.3.1.2")
        assert r.BGP_PEER_ADMIN.endswith(".15.3.1.3")
        assert r.BGP_PEER_REMOTE_ADDR.endswith(".15.3.1.7")
        assert r.BGP_PEER_REMOTE_AS.endswith(".15.3.1.9")
        assert r.BGP_PEER_FSM_TRANSITIONS.endswith(".15.3.1.15"), "flap counter must be col 15"
        assert r.BGP_PEER_FSM_TIME.endswith(".15.3.1.16"), "established time must be col 16"

    def test_no_column_exceeds_the_table(self):
        """bgpPeerEntry ends at column 24; anything beyond is a typo, not an OID."""
        from controlplane_extension import routing as r
        for name, oid in r.BGP_COLUMNS.items():
            col = int(oid.rsplit(".", 1)[1])
            assert 1 <= col <= 24, f"{name} column {col} is outside bgpPeerEntry"

    def test_ospf_columns(self):
        from controlplane_extension import routing as r
        assert r.OSPF_NBR_RTR_ID.endswith(".14.10.1.3")
        assert r.OSPF_NBR_STATE.endswith(".14.10.1.6")
        assert r.OSPF_NBR_EVENTS.endswith(".14.10.1.7")
