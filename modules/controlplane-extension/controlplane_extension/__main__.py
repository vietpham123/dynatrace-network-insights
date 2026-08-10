"""
LLDP topology extension (remote / ActiveGate).

WHY THIS EXISTS AS PYTHON. The declarative SNMP datasource cannot deliver LLDP topology. It
decodes binary OCTET STRINGs as UTF-8 and drops invalid bytes, which destroys exactly the two
fields the feature depends on — lldpRemChassisId (the join key) and lldpRemSysCapEnabled (the
endpoint filter). Measured on real hardware, three distinct MACs collapsed to one string. See
docs/ENTERPRISE-READINESS.md §L; the failure is pinned by tests/test_codec.py.

Emits (logs):
  network.lldp  lldp.record="device"  one per polled device — its own chassis id
  network.lldp  lldp.record="link"    one per neighbour heard
  network.lldp  lldp.record="error"   one per device that failed, so failures are visible

The app joins link.remote_chassis_id against device.chassis_id to resolve a neighbour to a
managed device. Neighbours that resolve to nothing are UNMANAGED — surfaced deliberately, as
their own class, rather than dropped: an unmanaged switch in the fabric is a finding.
"""
import asyncio
from datetime import timedelta

from dynatrace_extension import Extension

from .codec import (
    bgp_is_established, bgp_state_label, classify, decode_capabilities, decode_chassis_id,
    decode_port_id, orient, ospf_is_healthy, ospf_state_label,
)
from .routing import ospf_neighbour_id, peer_address
from .snmp import (
    SnmpError, _as_int, _octets, collect_device, local_port_num,
)

DEFAULT_INTERVAL = 900  # topology changes on a work-order timescale, not a 60-second one
# How many devices to poll at once. SNMP is UDP and mostly latency-bound, so this can be well
# above CPU count; it is capped to stay polite on a shared ActiveGate.
MAX_CONCURRENT = 20


def parse_devices(raw: str):
    """'10.0.10.2, 10.0.10.3:1161' or one per line -> [(host, port)].

    Tolerant of both separators because operators paste from spreadsheets and from terminals.
    """
    out = []
    for tok in str(raw or "").replace(",", "\n").split("\n"):
        tok = tok.strip()
        if not tok or tok.startswith("#"):
            continue
        host, _, port = tok.partition(":")
        host = host.strip()
        if not host:
            continue
        out.append((host, _as_int(port, 161) or 161))
    return out


class LldpExtension(Extension):

    def initialize(self):
        try:
            interval = int(self._cfg().get("intervalSeconds", DEFAULT_INTERVAL) or DEFAULT_INTERVAL)
        except Exception:
            interval = DEFAULT_INTERVAL
        self.schedule(self.query, timedelta(seconds=max(60, interval)))

    def _cfg(self):
        """Activation config as a flat dict.

        MUST go through .config. ActivationConfig subclasses dict but calls super().__init__()
        with NO data, so dict(ac) is EMPTY — the real values sit behind the .config property
        (which resolves to .remote / pythonRemote). Proven on a real ActiveGate 2026-08-01:
        the previous dict(ac) version logged "deviceList is empty" against a fully populated
        monitoring configuration. The .get() fallbacks below cover SDK variants.
        """
        ac = self.get_activation_config()
        cfg = getattr(ac, "config", None)
        if isinstance(cfg, dict) and cfg:
            return dict(cfg)
        raw = dict(ac) if hasattr(ac, "keys") else dict(getattr(ac, "__dict__", {}))
        if "deviceList" not in raw:
            raw = next((v for v in raw.values() if isinstance(v, dict) and "deviceList" in v), raw)
        return raw
    def query(self):
        c = self._cfg()
        devices = parse_devices(c.get("deviceList", ""))
        if not devices:
            self.logger.error("deviceList is empty — nothing to poll")
            return

        # Capability gating — explicit booleans on the monitoring configuration.
        # (Feature sets were tried and rejected at upload; see extension.yaml.) Routing
        # defaults OFF so an upgrade can never silently switch on a new ingest stream.
        def flag(key, default):
            v = c.get(key, default)
            return str(v).lower() not in ("false", "0", "no", "none")
        want_lldp = flag("collectLldp", True)
        want_routing = flag("collectRouting", False)

        exclude_endpoints = str(c.get("excludeEndpoints", True)).lower() not in ("false", "0", "no")
        opts = dict(
            timeout=_as_int(c.get("timeoutSeconds"), 5) or 5,
            retries=_as_int(c.get("retries"), 2),
            max_reps=_as_int(c.get("maxRepetitions"), 10) or 10,
        )

        records, ok, failed, links, dropped, edges = [], 0, 0, 0, 0, 0

        # Poll everything FIRST, so naming can be consistent across the whole run (see roster),
        # and poll devices CONCURRENTLY.
        #
        # This used to be a plain for-loop calling asyncio.run() per device: one event loop per
        # device, executed strictly one after another. Two costs, both invisible at 2 devices
        # and crippling at scale:
        #   * every device's latency ADDS. A fleet is bounded by the sum of its slowest paths.
        #   * the GetBulk probe costs one timeout on any agent without it. Capped at 2s each,
        #     that is still 100 SECONDS across 50 such devices before a single metric is read.
        # A real fleet is ~1,500 devices (measured at two customer tenants), so serial polling
        # was never going to survive contact with one.
        #
        # Bounded concurrency, not unbounded: an ActiveGate runs many extensions and a fleet-
        # wide fan-out of open UDP sockets is antisocial. MAX_CONCURRENT is the knob.
        collected, errors = asyncio.run(self._collect_all(devices, c, want_lldp, want_routing, opts))
        for host, err in errors:
            failed += 1
            records.append({
                "content": f"LLDP poll failed for {host}: {err}",
                "log.source": "network.lldp", "lldp.record": "error",
                "device.address": host, "lldp.error": str(err)[:500],
                "severity": "ERROR", "dt.source": "cno-lldp"})
            self.logger.warning(f"LLDP {host}: {err}")

        # address -> the sysName WE polled from that device.
        #
        # Why this exists: the Topology page joins edges in NAME space, so a device must carry
        # the SAME name here as it does in the SNMP extension's data or it renders TWICE. That
        # happened live: 10.0.10.3 appeared both as "n/a" (its literal sysName, from SNMP) and
        # as "10.0.10.3" (this extension falling back to the address, because the neighbour's
        # LLDP sysName was empty). For a MANAGED neighbour we polled it ourselves, so we know
        # the authoritative sysName — use it and the duplicate collapses.
        # RAW sysName, NOT _text(). _text() maps the literal "n/a" to empty (§B6), which is
        # right for DISPLAY but wrong here: the SNMP extension emits sys_name verbatim as a
        # metric dimension, so to land on the SAME topology node this dimension must match it
        # byte for byte — "n/a" included. A real Netgear GSM7248V2 reports exactly that, and
        # cleaning it here is what made 10.0.10.3 render as two nodes. The app's deviceLabel()
        # already turns "n/a" into the IP at display time; that is the right layer for it.
        roster = {}
        for d in collected:
            nm = self._raw_name(d.get("sys_name")) or self._raw_name(d.get("loc_sys_name"))
            if nm:
                roster[d["host"]] = nm

        peers = 0
        for data in collected:
            ok += 1
            if want_lldp:
                recs, n_links, n_dropped = self._records_for(data, exclude_endpoints)
                edges += self._emit_edges(data, exclude_endpoints, roster)
                records.extend(recs)
                links += n_links
                dropped += n_dropped
            if want_routing:
                r_recs, n_peers = self._emit_routing(data, roster)
                records.extend(r_recs)
                peers += n_peers

        if records:
            self.report_log_events(records)
        # Say what was dropped. A silent filter reads as "there is nothing there".
        self.logger.info(
            f"controlplane: {ok}/{len(devices)} devices polled ({failed} failed) | "
            f"lldp={'on' if want_lldp else 'off'} {links} links, {edges} edges, "
            f"{dropped} endpoints excluded | "
            f"routing={'on' if want_routing else 'off'} {peers} adjacencies")

    def _records_for(self, data, exclude_endpoints):
        """Turn one device's raw walk into log records. All decoding goes through codec.py."""
        host = data["host"]
        local_name = self._text(data.get("loc_sys_name")) or self._text(data.get("sys_name"))
        local_chassis = decode_chassis_id(data["loc_chassis_subtype"], data["loc_chassis_id"])

        records = [{
            "content": f"LLDP device {local_name or host}: chassis {local_chassis or 'unknown'}",
            "log.source": "network.lldp", "lldp.record": "device",
            "device.address": host, "host.name": local_name or host,
            "lldp.chassis_id": local_chassis,
            "severity": "INFO", "dt.source": "cno-lldp"}]

        # local port number -> readable port name, for naming the near end of each link
        port_names = {}
        for idx, cols in data["local_ports"].items():
            name = decode_port_id(_as_int(cols.get("port_subtype")),
                                  _octets(cols["port_id"]) if "port_id" in cols else b"")
            desc = self._text(cols.get("port_desc"))
            port_names[idx] = name or desc or idx

        links = dropped = 0
        for idx, cols in sorted(data["remote"].items()):
            caps_raw = _octets(cols["cap_enabled"]) if "cap_enabled" in cols else b""
            klass = classify(caps_raw)
            if exclude_endpoints and klass == "endpoint":
                dropped += 1
                continue

            rem_chassis = decode_chassis_id(
                _as_int(cols.get("chassis_subtype")),
                _octets(cols["chassis_id"]) if "chassis_id" in cols else b"")
            rem_port = decode_port_id(
                _as_int(cols.get("port_subtype")),
                _octets(cols["port_id"]) if "port_id" in cols else b"")
            rem_name = self._text(cols.get("sys_name"))
            rem_mgmt = data.get("man_addr", {}).get(idx, "")
            near = port_names.get(local_port_num(idx), local_port_num(idx))
            caps = decode_capabilities(caps_raw)

            links += 1
            records.append({
                "content": (f"LLDP link {local_name or host}:{near} -> "
                            f"{rem_name or rem_chassis or 'unknown'}:{rem_port or '?'} [{klass}]"),
                "log.source": "network.lldp", "lldp.record": "link",
                "device.address": host, "host.name": local_name or host,
                "lldp.chassis_id": local_chassis,
                "lldp.local_port": near,
                "lldp.remote_chassis_id": rem_chassis,
                "lldp.remote_port": rem_port,
                "lldp.remote_sys_name": rem_name,
                # Attribute, NOT the join key — an IP join inherits the overlapping-IP
                # problem. Useful because it lines up with device.address for managed gear.
                "lldp.remote_mgmt_address": rem_mgmt,
                # infrastructure | endpoint | unknown. 'unknown' means the neighbour did not
                # advertise capabilities — NOT that we guessed. It is kept, never filtered.
                "lldp.remote_class": klass,
                "lldp.remote_capabilities": ",".join(caps),
                "severity": "INFO", "dt.source": "cno-lldp"})

        return records, links, dropped

    def _emit_edges(self, data, exclude_endpoints, roster=None):
        """Emit cno.dep.uses so the neighbour shows up on the Topology page.

        This is the metric the app's topology and the RCA suppression workflow both read, and
        the dependency extension's Smartscape rules build entities from — so it needs
        device.address AND upstream.address. The neighbour's address comes from
        lldpRemManAddrTable (see codec.parse_man_addr_index); a neighbour that does not
        publish one cannot become a topology node, so it is counted and logged rather than
        half-emitted.

        Direction is derived from the advertised capability bitmap, NOT the hostname — see
        codec.orient(). Both ends compute it identically, so the edge is emitted once.
        """
        host = data["host"]
        roster = roster or {}
        local_name = roster.get(host) or self._text(data.get("loc_sys_name")) or self._text(data.get("sys_name")) or host
        local_caps = data.get("loc_caps", b"")
        local_chassis = decode_chassis_id(data["loc_chassis_subtype"], data["loc_chassis_id"])
        emitted = skipped = 0

        for idx, cols in sorted(data["remote"].items()):
            caps_raw = _octets(cols["cap_enabled"]) if "cap_enabled" in cols else b""
            if exclude_endpoints and classify(caps_raw) == "endpoint":
                continue
            up_addr = data.get("man_addr", {}).get(idx, "")
            if not up_addr:
                skipped += 1
                continue

            rem_chassis = decode_chassis_id(
                _as_int(cols.get("chassis_subtype")),
                _octets(cols["chassis_id"]) if "chassis_id" in cols else b"")
            # Prefer the name WE polled for that address (roster) so a managed neighbour is
            # named identically to the SNMP extension's view of it — otherwise the Topology
            # page, which joins on name, draws the same device twice. Only fall back to the
            # neighbour's self-reported name, then the address (§B6), for UNMANAGED devices we
            # never poll.
            rem_name = roster.get(up_addr) or self._text(cols.get("sys_name")) or up_addr

            local_down = orient(local_caps, local_chassis or host, caps_raw, rem_chassis or up_addr,
                                host, up_addr)
            if local_down:
                d_addr, d_name, u_addr, u_name = host, local_name, up_addr, rem_name
            else:
                d_addr, d_name, u_addr, u_name = up_addr, rem_name, host, local_name

            self.report_metric("cno.dep.uses", 1, dimensions={
                "device.address": d_addr, "device.name": d_name,
                "upstream.address": u_addr, "upstream.name": u_name,
                "link_type": "data", "discovery": "lldp"})
            emitted += 1

        if skipped:
            # Never silent: a neighbour with no management address is invisible to topology.
            self.logger.info(
                f"lldp {host}: {skipped} neighbour(s) had no lldpRemManAddrTable entry, so they "
                f"appear as links but not as topology edges")
        return emitted

    async def _collect_all(self, devices, cfg, want_lldp, want_routing, opts):
        """Poll every device concurrently in ONE event loop, bounded by MAX_CONCURRENT.

        Returns (results, errors) so a device that fails is reported as a record rather than
        taking the run down with it — one unreachable device must never cost us the fleet.
        """
        sem = asyncio.Semaphore(MAX_CONCURRENT)
        async def one(host, port):
            async with sem:
                try:
                    return (await collect_device(host, port, cfg, want_lldp=want_lldp,
                                                 want_routing=want_routing, **opts), None)
                except Exception as e:                       # per-device isolation
                    return (None, (host, e))
        done = await asyncio.gather(*[one(h, p) for h, p in devices])
        return [d for d, _ in done if d is not None], [e for _, e in done if e is not None]

    def _emit_routing(self, data, roster=None):
        """BGP peers and OSPF neighbours as metrics, plus a log record per DOWN adjacency.

        Metrics not logs, unlike topology: this is a small, low-cardinality set (a handful of
        peers per edge device, not 48 ports) and it needs to be alertable — a detector on
        `cno.route.bgp.established < 1` is the whole point. The peer identity comes out of
        codec.decode_ip because it arrives as four raw bytes.
        """
        host = data["host"]
        roster = roster or {}
        name = roster.get(host) or self._text(data.get("loc_sys_name")) or self._text(data.get("sys_name")) or host
        r = data.get("routing") or {}
        out, n = [], 0

        for idx, cols in sorted((r.get("bgp") or {}).items()):
            peer = peer_address(cols, idx)
            if not peer:
                continue
            state = _as_int(cols.get("state"))
            up = bgp_is_established(state)
            dims = {"device.address": host, "host.name": name, "peer": peer,
                    "peer_as": str(_as_int(cols.get("remote_as")))}
            self.report_metric("cno.route.bgp.established", 1 if up else 0, dimensions=dims)
            self.report_metric("cno.route.bgp.state", state, dimensions=dims)
            self.report_metric("cno.route.bgp.flaps", _as_int(cols.get("transitions")), dimensions=dims)
            self.report_metric("cno.route.bgp.uptime_sec", _as_int(cols.get("uptime")), dimensions=dims)
            n += 1
            if not up:
                out.append({
                    "content": f"BGP peer {peer} (AS{_as_int(cols.get('remote_as'))}) on {name} is {bgp_state_label(state)}",
                    "log.source": "network.routing", "routing.protocol": "bgp",
                    "device.address": host, "host.name": name, "routing.peer": peer,
                    "routing.state": bgp_state_label(state),
                    "severity": "WARN", "dt.source": "cno-controlplane"})

        for idx, cols in sorted((r.get("ospf") or {}).items()):
            nbr = ospf_neighbour_id(cols, idx)
            if not nbr:
                continue
            state = _as_int(cols.get("state"))
            healthy = ospf_is_healthy(state)
            dims = {"device.address": host, "host.name": name, "neighbor": nbr}
            self.report_metric("cno.route.ospf.full", 1 if healthy else 0, dimensions=dims)
            self.report_metric("cno.route.ospf.state", state, dimensions=dims)
            self.report_metric("cno.route.ospf.events", _as_int(cols.get("events")), dimensions=dims)
            n += 1
            if not healthy:
                out.append({
                    "content": f"OSPF neighbour {nbr} on {name} is {ospf_state_label(state)}",
                    "log.source": "network.routing", "routing.protocol": "ospf",
                    "device.address": host, "host.name": name, "routing.peer": nbr,
                    "routing.state": ospf_state_label(state),
                    "severity": "WARN", "dt.source": "cno-controlplane"})

        # Say nothing rather than imply health: a device that does not implement these MIBs is
        # not "0 peers down", it is not a router. Only report when the MIB actually answered.
        if not r.get("bgp_supported") and not r.get("ospf_supported"):
            self.logger.debug(f"controlplane {host}: no BGP/OSPF MIB support, skipped")
        return out, n

    @staticmethod
    def _raw_name(value):
        """sysName exactly as the device reports it — no "n/a" normalisation. Used ONLY for
        metric dimensions that must match the SNMP extension's. See the roster note above."""
        if value is None:
            return ""
        return _octets(value).decode("utf-8", "replace").replace("\ufffd", "").strip("\x00").strip()

    @staticmethod
    def _text(value):
        """sysName and friends are text-typed, but devices still ship NULs and blanks. The
        literal 'n/a' is what a real Netgear GSM7248V2 returns for sysName — treat it as
        absent so downstream falls back to the address (§B6)."""
        if value is None:
            return ""
        s = _octets(value).decode("utf-8", "replace").replace("�", "").strip("\x00").strip()
        return "" if s.lower() in ("", "n/a", "none", "(none)", "(none).(none)") else s


def main():
    LldpExtension().run()


if __name__ == "__main__":
    main()
