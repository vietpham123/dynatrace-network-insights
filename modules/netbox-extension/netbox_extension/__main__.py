"""
NetBox -> Dynatrace SOURCE extension (remote / ActiveGate).

Ports the on-prem crons emit_inventory.py + emit_dependencies.py onto the AG so the device
roster and the declared cabling land in Grail as metrics, with no reach-back from cloud
workflows. Stdlib-only (urllib/json) — the same calls the crons made.

Emits:
  cno.inv.device        {device.name, device.address, device.role, netbox.id} = 1 active / 0 not
  cno.inv.linked        {device.name}                                          = 1 if DT-linked
  cno.dep.uses          {device.address, upstream.address, link_type=power, discovery=netbox, ...} = 1
  cno.dep.uses          {..., link_type=data, discovery=netbox, ...} = 1   (skipped if emitDataLinks is off)
  cno.dep.uses_network  {dt.entity.host, device.address, ...} = 1   (only if a DT API token is set)

link_type=data defaults ON, but on the CNO lab it is now switched OFF — and should be. That
default was written when there was no packaged, production-deployable live-LLDP source. There is
one now (modules/controlplane-extension), and as of 2026-08-05 the simulators answer LLDP, so
NetBox and LLDP were emitting the SAME EIGHT CABLES IN OPPOSITE DIRECTIONS — every link drawn
twice. Where a live source exists it should win: LLDP is measured from the devices, NetBox is what
somebody typed into a CMDB. Keep the default ON for sites with no LLDP; turn it off wherever there
is one. POWER always stays with NetBox — nothing else knows which outlet feeds which device.
Original rationale:
so NetBox's declared cabling is the only production-ready source of device<->device topology.
Turn emitDataLinks OFF only where a genuine live-LLDP source is already discovering these same
devices (e.g. the internal lab's emit_lldp.py) — NetBox derives the same edges' direction
independently, from its own role-slug rank table rather than LLDP's hostname-derived guess, and
the two can disagree on which end depends on which if both run against the same devices.

The companion declarative extension custom:cno.network.dependency maps cno.dep.* into
network:device Smartscape edges — this extension only produces the metrics.
"""
import json
import urllib.request
import urllib.parse
from datetime import timedelta

from dynatrace_extension import Extension

# role rank decides data-dependency direction: lower depends on higher (ap/console < access < core < wan-edge)
RANK = {"ap": 0, "console": 0, "access": 1, "core": 2, "wan-edge": 3, "pdu": 8, "ups": 9}


class NetboxExtension(Extension):

    def initialize(self):
        try:
            interval = int(self._cfg().get("intervalSeconds", 60) or 60)
        except Exception:
            interval = 60
        self.schedule(self.query, timedelta(seconds=max(30, interval)))

    # ---- config -----------------------------------------------------------------
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
        if "netboxUrl" not in raw:
            raw = next((v for v in raw.values() if isinstance(v, dict) and "netboxUrl" in v), raw)
        return raw
    def _nb(self, cfg, path):
        req = urllib.request.Request(
            f"{cfg['nb']}/api{path}",
            headers={"Authorization": f"Token {cfg['nbt']}", "Accept": "application/json"})
        try:
            return json.load(urllib.request.urlopen(req, timeout=20))
        except Exception as e:
            self.logger.warning(f"NetBox GET {path} failed: {e}")
            return {}

    def _nb_all(self, cfg, path):
        """Every result across ALL pages. NetBox caps page size server-side (default 50,
        max_page_size often 1000), so a bare ?limit=N silently truncates a fleet larger
        than N with nothing logged — the customer sees a partial inventory and assumes
        that IS their network. Follow the `next` link instead, and log if we stop early."""
        out, url, guard = [], f"{cfg['nb']}/api{path}", 0
        while url and guard < 200:
            guard += 1
            req = urllib.request.Request(
                url, headers={"Authorization": f"Token {cfg['nbt']}", "Accept": "application/json"})
            try:
                page = json.load(urllib.request.urlopen(req, timeout=20))
            except Exception as e:
                self.logger.warning(f"NetBox GET {url} failed after {len(out)} rows: {e}")
                return out
            out.extend(page.get("results", []))
            url = page.get("next")
        if url:
            self.logger.warning(f"NetBox paging hit the {guard}-page guard for {path}; "
                                f"returning {len(out)} rows — inventory may be INCOMPLETE")
        return out

    def _dt_get(self, cfg, path):
        if not (cfg["dt"] and cfg["dtt"]):
            return {}
        req = urllib.request.Request(f"{cfg['dt']}{path}", headers={"Authorization": f"Api-Token {cfg['dtt']}"})
        try:
            return json.load(urllib.request.urlopen(req, timeout=20))
        except Exception as e:
            self.logger.warning(f"DT GET {path} failed: {e}")
            return {}

    # ---- main poll --------------------------------------------------------------
    def query(self):
        c = self._cfg()
        cfg = {"nb": str(c.get("netboxUrl", "")).rstrip("/"), "nbt": c.get("netboxToken", ""),
               "dt": str(c.get("dtApiUrl", "")).rstrip("/"), "dtt": c.get("dtApiToken", ""),
               "emitDataLinks": bool(c.get("emitDataLinks", True))}
        if not (cfg["nb"] and cfg["nbt"]):
            self.logger.error("netboxUrl / netboxToken not configured")
            return
        self._inventory(cfg)
        self._dependencies(cfg)

    def _inventory(self, cfg):
        devs = self._nb_all(cfg, "/dcim/devices/?limit=500")
        n_active = n_linked = 0
        for d in devs:
            ip = ((d.get("primary_ip4") or {}).get("address") or "").split("/")[0]
            if not ip:
                continue
            active = 1 if d["status"]["value"] == "active" else 0
            linked = 1 if (d.get("custom_fields") or {}).get("dynatrace_entity_id") else 0
            n_active += active
            n_linked += linked
            self.report_metric("cno.inv.device", active, dimensions={
                "device.name": d["name"], "device.address": ip,
                "device.role": d["role"]["slug"], "netbox.id": str(d["id"])})
            self.report_metric("cno.inv.linked", linked, dimensions={"device.name": d["name"]})
        self.logger.info(f"inventory: {len(devs)} devices ({n_active} active, {n_linked} DT-linked)")

    def _dependencies(self, cfg):
        dev_cache = {}

        def device(did):
            if did not in dev_cache:
                dev_cache[did] = self._nb(cfg, f"/dcim/devices/{did}/")
            return dev_cache[did]

        def ip_of(dv):
            return ((dv.get("primary_ip4") or {}).get("address") or "").split("/")[0]

        def host_entity(hostname):
            sel = urllib.parse.quote(f'type("HOST"),entityName.startsWith("{hostname}")')
            hosts = self._dt_get(cfg, f"/api/v2/entities?entitySelector={sel}&from=-24h").get("entities", [])
            return hosts[0]["entityId"] if hosts else None

        n = 0
        for cable in self._nb_all(cfg, "/dcim/cables/?limit=1000"):
            ends, power = [], False
            for term in (cable.get("a_terminations") or []) + (cable.get("b_terminations") or []):
                if term.get("object_type") in ("dcim.poweroutlet", "dcim.powerport"):
                    power = True
                dv = (term.get("object") or {}).get("device") or {}
                if dv.get("id"):
                    ends.append((term.get("object_type"), device(dv["id"])))
            if len(ends) != 2:
                continue
            (ta, da), (tb, db) = ends
            ra, rb = da["role"]["slug"], db["role"]["slug"]

            if power:  # consumer (power PORT) CALLS provider (power OUTLET)
                consumer = da if ta == "dcim.powerport" else db
                provider = db if consumer is da else da
                cip, pip_ = ip_of(consumer), ip_of(provider)
                if cip and pip_:
                    self.report_metric("cno.dep.uses", 1, dimensions={
                        "device.address": cip, "device.name": consumer["name"],
                        "upstream.address": pip_, "upstream.name": provider["name"],
                        "link_type": "power", "cable": str(cable["id"]),
                        # PROVENANCE, on every edge. The controlplane extension stamps
                        # discovery=lldp; NetBox stamped nothing, so its edges arrived with a null
                        # and the app could not tell a DECLARED cable from a DISCOVERED adjacency.
                        # They are different claims: NetBox says how the estate was designed, LLDP
                        # says what the devices can currently see, and when they disagree that
                        # disagreement is the finding. A null hid it.
                        "discovery": "netbox"})
                    n += 1
                continue

            if "server" in (ra, rb):  # host CALLS network device
                server = da if ra == "server" else db
                netdev = db if server is da else da
                hid = host_entity(server.get("serial") or server["name"].lower())
                nip = ip_of(netdev)
                if hid and nip:
                    self.report_metric("cno.dep.uses_network", 1, dimensions={
                        "dt.entity.host": hid, "device.address": nip,
                        "device.name": netdev["name"], "cable": str(cable["id"])})
                    n += 1
                continue

            # device<->device data: on by default (no packaged live-LLDP extension exists yet, so
            # this is the only production-ready topology source) — see module docstring. Turn off
            # only where live-LLDP is already discovering these same devices (e.g. the lab).
            if not cfg["emitDataLinks"]:
                continue

            # lower rank depends on higher; tie-break by name sort
            if (RANK.get(ra, 1), da["name"]) <= (RANK.get(rb, 1), db["name"]):
                down, up = da, db
            else:
                down, up = db, da
            dip, uip = ip_of(down), ip_of(up)
            if dip and uip:
                self.report_metric("cno.dep.uses", 1, dimensions={
                    "device.address": dip, "device.name": down["name"],
                    "upstream.address": uip, "upstream.name": up["name"],
                    "link_type": "data", "cable": str(cable["id"]),
                    "discovery": "netbox"})   # see the power edge above — provenance on every edge
                n += 1
        self.logger.info(f"dependencies: emitted {n} edges")


def main():
    NetboxExtension().run()


if __name__ == "__main__":
    main()
