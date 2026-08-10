#!/usr/bin/env python3
"""
netflow_v9_collector.py — a NetFlow v9 collector that PRESERVES the interface
indices (INPUT_SNMP / OUTPUT_SNMP) the OTel netflowreceiver drops, and forwards
every flow to the local BindPlane collector over OTLP.

    generator ──v9/udp──▶ THIS decoder ──OTLP/HTTP──▶ BindPlane collector ──▶ Dynatrace

Why it exists: the OTel netflowreceiver decodes v9 but emits none of the interface
fields and "custom field mapping is not yet supported", so per-interface flow
drill-down is impossible through it. This decoder emits the SAME schema the receiver
does (source/destination.address, ports, network.transport, flow.io.bytes/packets,
flow.type=netflow_v9) PLUS flow.interface.input / flow.interface.output — and hands
off to BindPlane over OTLP. BindPlane stays the managed pipeline; it just ingests a
custom OTLP source instead of decoding NetFlow itself (the point of the demo).

Run:
    python3 netflow_v9_collector.py --listen-port 2055 --otlp-host 127.0.0.1 --otlp-port 4318
"""
import argparse
import http.client
import ipaddress
import json
import queue
import socket
import struct
import threading
import time

# v9 field type -> (otlp attribute key, kind)   kind: ip | int
FIELD = {
    1:  ("flow.io.bytes",        "int"),
    2:  ("flow.io.packets",      "int"),
    4:  ("_proto",               "int"),
    5:  ("flow.tos",             "int"),
    7:  ("source.port",          "int"),
    8:  ("source.address",       "ip"),
    10: ("flow.interface.input", "int"),
    11: ("destination.port",     "int"),
    12: ("destination.address",  "ip"),
    14: ("flow.interface.output","int"),
    # IPFIX IANA IEs 1/2/4/5/7/8/10/11/12/14 are IDENTICAL to the v9 field types above, so the
    # map is shared verbatim between the two versions. IPv6 is added because a real gateway sees
    # it and the lab v9 generator never emitted any.
    27: ("source.address",       "ip6"),
    28: ("destination.address",  "ip6"),
    # Everything below is sent by the UniFi UCG Ultra and was previously decoded-and-discarded.
    # Enumerated from its live templates 2026-08-03 (259 = TCP/UDP with 21 IEs, 261 = ICMP with 18).
    6:   ("flow.tcp_flags",      "int"),   # SYN/FIN/RST — scans, resets, half-open connections
    32:  ("flow.icmp_type_code", "int"),   # ICMP flows carry NO ports, so without this they are
                                           # indistinguishable from one another
    61:  ("flow.direction",      "int"),   # 0 ingress, 1 egress
    136: ("flow.end_reason",     "int"),   # idle timeout / active timeout / end of flow
    152: ("_start_ms",           "int"),   # flowStartMilliseconds — see to_otlp
    153: ("_end_ms",             "int"),   # flowEndMilliseconds
}
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}

# (exporterAddress, observationDomain/sourceId, templateId) -> [(fieldType, fieldLen, pen), ...]
#
# THE EXPORTER ADDRESS IS PART OF THE KEY, and that is not pedantry. Template ids start at 256
# for every exporter, and observation domains commonly default to 0 — the UniFi UCG Ultra uses
# domain 0. Keying on (domain, templateId) alone therefore makes two devices pointed at one
# collector overwrite each other's templates. Measured 2026-08-03: with two exporters both on
# domain 0 sending different layouts for template 256, the second definition won and the first
# exporter's records were silently DROPPED — or, when the lengths happen to line up, decoded
# against the wrong layout into plausible nonsense. Any real multi-device deployment hits this.
TEMPLATES = {}


def decode_value(kind, raw):
    if kind == "ip":
        return socket.inet_ntoa(raw[:4]) if len(raw) >= 4 else None
    if kind == "ip6":
        return socket.inet_ntop(socket.AF_INET6, raw[:16]) if len(raw) >= 16 else None
    return int.from_bytes(raw, "big")


def _parse_templates(body, key_prefix, ipfix):
    """Learn templates from a template set. IPFIX adds the enterprise bit; v9 does not."""
    p = 0
    while p + 4 <= len(body):
        tid, fcount = struct.unpack("!HH", body[p:p + 4]); p += 4
        if tid < 256:            # not a real template id; padding or malformed
            break
        fields = []
        for _ in range(fcount):
            if p + 4 > len(body):
                return
            ft, fl = struct.unpack("!HH", body[p:p + 4]); p += 4
            ent = None
            # IPFIX sets the top bit of the field id to mark an ENTERPRISE-specific element,
            # followed by a 4-byte PEN. Miss this and every subsequent field in the template
            # shifts by four bytes and the whole record decodes to plausible garbage.
            if ipfix and (ft & 0x8000):
                ft &= 0x7FFF
                if p + 4 > len(body):
                    return
                ent = struct.unpack("!I", body[p:p + 4])[0]; p += 4
            fields.append((ft, fl, ent))
        TEMPLATES[key_prefix + (tid,)] = fields


def _decode_record(body, p, tmpl):
    """Decode one record. Returns (rec, new_p) or (None, p) if the body is exhausted."""
    rec = {}
    for ft, fl, ent in tmpl:
        if fl == 0xFFFF:
            # IPFIX variable-length encoding: 1 length byte, or 255 then a 2-byte length.
            if p + 1 > len(body):
                return None, p
            n = body[p]; p += 1
            if n == 255:
                if p + 2 > len(body):
                    return None, p
                n = struct.unpack("!H", body[p:p + 2])[0]; p += 2
            if p + n > len(body):
                return None, p
            raw = body[p:p + n]; p += n
        else:
            if p + fl > len(body):
                return None, p
            raw = body[p:p + fl]; p += fl
        if ent is None:                      # enterprise fields are consumed but not mapped
            meta = FIELD.get(ft)
            if meta:
                v = decode_value(meta[1], raw)
                if v is not None:
                    rec[meta[0]] = v
    return rec, p


def parse_packet(data, exporter=None):
    """Decode one NetFlow v9 or IPFIX (v10) datagram into flow dicts, learning templates.

    Both versions are handled because the lab's two candidate exporters disagree: the
    generator speaks v9, while the UniFi UCG Ultra offers ONLY "NetFlow (IPFIX)" — a single
    checkbox with no version selector (verified in the UniFi UI 2026-08-03). Decoding just one
    of them would have meant either a dead lab harness or no real exporter.

    The two differ in framing, not in field semantics:
                              v9                        IPFIX (v10)
        header             20 bytes !HHIIII          16 bytes !HHIII  (no count/sysUptime)
        template set id    0                         2   (3 = options template, skipped)
        enterprise fields  n/a                       top bit of the field id + 4-byte PEN
        variable length    n/a                       length 0xFFFF -> 1- or 3-byte prefix
    The IANA information elements IPFIX uses for the fields we care about are numerically the
    same as the v9 field types, so FIELD is shared verbatim.
    """
    flows = []
    if len(data) < 16:
        return flows
    # `exporter` scopes the template cache. It defaults to None so existing callers and tests
    # keep working, but the UDP loop always supplies the datagram's source address.
    ver = struct.unpack("!H", data[:2])[0]
    if ver == 9:
        if len(data) < 20:
            return flows
        _, _count, _uptime, _secs, _seq, srcid = struct.unpack("!HHIIII", data[:20])
        off, ipfix, tmpl_set = 20, False, 0
    elif ver == 10:
        # IPFIX carries the total LENGTH where v9 carries a record count, and an observation
        # domain id where v9 carries a source id. Both act as the template-scoping key.
        _, length, _exp, _seq, srcid = struct.unpack("!HHIII", data[:16])
        data = data[:length] if 16 <= length <= len(data) else data
        off, ipfix, tmpl_set = 16, True, 2
    else:
        return flows

    while off + 4 <= len(data):
        fsid, length = struct.unpack("!HH", data[off:off + 4])
        if length < 4 or off + length > len(data):
            break
        body = data[off + 4: off + length]
        if fsid == tmpl_set:
            _parse_templates(body, (exporter, srcid), ipfix)
        elif ipfix and fsid == 3:
            pass                              # options template: scoped metadata, not flows
        elif fsid >= 256:
            tmpl = TEMPLATES.get((exporter, srcid, fsid))
            if tmpl:
                # Records are decoded one at a time rather than by a precomputed fixed width,
                # because an IPFIX template may contain variable-length fields.
                p, guard = 0, 0
                while p < len(body) and guard < 10000:
                    guard += 1
                    rec, np_ = _decode_record(body, p, tmpl)
                    if rec is None or np_ == p:
                        break                 # trailing set padding, or a truncated record
                    rec["_ver"] = "ipfix" if ipfix else "netflow_v9"
                    flows.append(rec); p = np_
        off += length
    return flows


# ── destination enrichment: IP -> ASN / org / rDNS ────────────────────────────────────────
#
# WHY IT LIVES HERE AND NOT IN THE APP. Flow records do not carry dst_as — the UCG Ultra sends
# no AS fields at all — so the app was resolving egress with a hardcoded nine-prefix table that
# matched NONE of the live traffic and collapsed 100% of it into one bar labelled "Other". A
# Dynatrace app also runs under a strict CSP and cannot call out to a lookup service. Resolving
# at ingest fixes both: one lookup per unique address instead of one per render, and the answer
# is stored in Grail with the flow, so historical records stay resolvable forever.
#
# WHY TEAM CYMRU RATHER THAN MaxMind. No account, no API key, no database file to ship and no
# cron to refresh it — Viet's standing rule is that every scheduled job outside the app is one
# more thing a customer must remember. The trade is a DNS dependency and Cymru's fair-use
# expectations, which the cache below is sized to respect. A customer who wants a fully offline
# path swaps _resolve_asn() for a GeoLite2-ASN reader; nothing else changes.
#
# NEVER BLOCK THE RECEIVE LOOP. A single uncached lookup is tens to hundreds of milliseconds,
# and this process is draining a UDP socket with no flow control — blocking on DNS drops
# datagrams, which silently loses flows. So the packet path only ever reads the cache, and
# unknown addresses are queued for a worker. The first flows to a new address ship WITHOUT the
# attributes and later ones carry them, which is the honest trade: a missing attribute is
# recoverable, a dropped datagram is not.
_DNS_TIMEOUT = 3.0
_POS_TTL = 24 * 3600     # ASN->org mappings are stable for days
_NEG_TTL = 15 * 60       # retry failures, but not in a hot loop
_MAX_CACHE = 50_000


def _resolvers():
    """System resolvers from /etc/resolv.conf, falling back to public ones."""
    out = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    out.append(parts[1])
    except OSError:
        pass
    return out or ["1.1.1.1", "8.8.8.8"]


def _skip_name(buf, i):
    """Advance past a DNS name, honouring compression pointers."""
    while i < len(buf):
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:      # pointer — always the last thing in a name
            return i + 2
        i += 1 + n
    return i


def dns_txt(name, server, timeout=_DNS_TIMEOUT):
    """Minimal DNS TXT query. Returns a list of strings (empty on any failure).

    Hand-rolled for the same reason the SNMP and NetFlow parsing is: the stdlib has no TXT
    query and pulling in dnspython for ~40 lines would add a deployment dependency to a script
    that is otherwise `python3 file.py`.
    """
    q = bytearray()
    q += struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)   # recursion desired
    for label in name.split("."):
        b = label.encode("ascii", "ignore")[:63]
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", 16, 1)                  # QTYPE=TXT QCLASS=IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(bytes(q), (server, 53))
        data, _ = s.recvfrom(4096)
    except (OSError, socket.timeout):
        return []
    finally:
        s.close()
    if len(data) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    i = 12
    for _ in range(qd):
        i = _skip_name(data, i) + 4
    out = []
    for _ in range(an):
        i = _skip_name(data, i)
        if i + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        rdata = data[i:i + rdlen]
        i += rdlen
        if rtype == 16:                                        # TXT: length-prefixed strings
            j, parts = 0, []
            while j < len(rdata):
                ln = rdata[j]
                parts.append(rdata[j + 1:j + 1 + ln].decode("ascii", "replace"))
                j += 1 + ln
            out.append("".join(parts))
    return out


def is_public(ip):
    """Only public unicast addresses are worth resolving — and are safe to send to a resolver.

    Private, loopback, link-local and multicast are excluded deliberately: a lookup would be
    meaningless AND it would publish the customer's internal addressing to a third party.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_reserved or a.is_unspecified)


def _resolve_asn(ip, server):
    """(asn, org) for an address via Team Cymru's DNS interface, or (None, None)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    if a.version != 4:
        return None, None                                     # v6 uses a different Cymru zone
    rev = ".".join(reversed(ip.split(".")))
    txt = dns_txt(f"{rev}.origin.asn.cymru.com", server)
    if not txt:
        return None, None
    # "13335 | 1.1.1.0/24 | US | apnic | 2011-08-11"; the first field can list several ASNs
    first = txt[0].split("|")[0].strip().split()
    if not first or not first[0].isdigit():
        return None, None
    asn = int(first[0])
    org = None
    det = dns_txt(f"AS{asn}.asn.cymru.com", server)
    if det:
        # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
        bits = det[0].split("|")
        if len(bits) >= 5:
            org = bits[4].strip() or None
    return asn, org


class Enricher:
    """Cache-only on the packet path; resolution happens on worker threads."""

    def __init__(self, enabled=True, workers=2):
        self.enabled = enabled
        self._cache = {}
        self._lock = threading.Lock()
        self._q = queue.Queue(maxsize=10_000)
        self._inflight = set()
        self._servers = _resolvers()
        self.hits = self.misses = self.resolved = 0
        if enabled:
            for _ in range(workers):
                threading.Thread(target=self._worker, daemon=True).start()

    def get(self, ip):
        """Attributes for an address RIGHT NOW. Queues a lookup when unknown; never blocks."""
        if not self.enabled or not ip or not is_public(ip):
            return {}
        now = time.time()
        with self._lock:
            hit = self._cache.get(ip)
            if hit and hit[0] > now:
                self.hits += 1
                return hit[1]
            self.misses += 1
            if ip in self._inflight:
                return {}
            self._inflight.add(ip)
        try:
            self._q.put_nowait(ip)
        except queue.Full:
            with self._lock:
                self._inflight.discard(ip)
        return {}

    def _worker(self):
        while True:
            ip = self._q.get()
            attrs = {}
            try:
                server = self._servers[0]
                asn, org = _resolve_asn(ip, server)
                if asn is not None:
                    attrs["asn"] = asn
                    if org:
                        attrs["org"] = org
                try:
                    attrs["rdns"] = socket.gethostbyaddr(ip)[0]
                except (OSError, socket.herror):
                    pass                                       # most addresses have no PTR
            except Exception:                                  # noqa: BLE001 — a worker must never die
                attrs = {}
            ttl = _POS_TTL if attrs else _NEG_TTL
            with self._lock:
                if len(self._cache) >= _MAX_CACHE:
                    self._cache.clear()                        # crude but bounded; TTLs re-warm it
                self._cache[ip] = (time.time() + ttl, attrs)
                self._inflight.discard(ip)
                if attrs:
                    self.resolved += 1
            self._q.task_done()


ENRICHER = Enricher(enabled=False)   # replaced in main(); disabled by default for tests


def to_otlp(flows, sampler):
    """Convert decoded flows to OTLP logs.

    TIMESTAMP. A flow is a summary of something that already happened, sometimes minutes ago —
    the UCG Ultra's default idle timeout is 5 minutes, so a record can describe traffic that
    finished long before the datagram was sent. Stamping every record at collector-receive time
    smears the whole window onto one instant and makes ordering and duration meaningless. When
    the exporter provides flowStartMilliseconds (IANA IE 152, present in both UniFi templates)
    the record is stamped with it instead; receive time is only a fallback for exporters that
    omit it.
    """
    now = int(time.time() * 1e9)
    recs = []
    for f in flows:
        proto = f.pop("_proto", None)
        start_ms = f.pop("_start_ms", None)
        end_ms = f.pop("_end_ms", None)
        ts = str(int(start_ms) * 1_000_000) if start_ms else str(now)
        # ipv6 addresses contain a colon; ipv4 never does
        v6 = ":" in str(f.get("source.address", "")) or ":" in str(f.get("destination.address", ""))
        attrs = [
            {"key": "flow.type", "value": {"stringValue": f.pop("_ver", "netflow_v9")}},
            {"key": "flow.sampler.address", "value": {"stringValue": sampler}},
            {"key": "network.type", "value": {"stringValue": "ipv6" if v6 else "ipv4"}},
        ]
        if start_ms and end_ms and int(end_ms) >= int(start_ms):
            attrs.append({"key": "flow.duration_ms",
                          "value": {"intValue": str(int(end_ms) - int(start_ms))}})
        if proto is not None:
            attrs.append({"key": "network.transport", "value": {"stringValue": PROTO.get(proto, str(proto))}})
        for k, v in f.items():
            # An exporter that does not populate a field sends the all-ones sentinel rather than
            # omitting it. Measured on the UCG Ultra 2026-08-03: flowDirection (IE 61) is 255 on
            # every single record. Emitting that verbatim puts a meaningless constant on every
            # flow — ingest paid for, and a reader could reasonably mistake 255 for a direction.
            if k == "flow.direction" and v == 255:
                continue
            val = {"stringValue": v} if isinstance(v, str) else {"intValue": str(v)}
            attrs.append({"key": k, "value": val})
        src = f.get("source.address", "?"); dst = f.get("destination.address", "?")
        # Enrich whichever ends are PUBLIC — both, for a transit flow. Doing only the destination
        # would leave the "what fills inbound" view as bare addresses, which is the same
        # unreadable-egress problem in the other direction. Absent attributes are simply omitted
        # rather than emitted empty: "not resolved yet" must not render as a value.
        for role, addr in (("src", src), ("dst", dst)):
            for k, v in ENRICHER.get(addr).items():
                key = f"flow.{role}_{k}"
                attrs.append({"key": key, "value": ({"intValue": str(v)} if isinstance(v, int)
                                                    else {"stringValue": v})})
        recs.append({"timeUnixNano": ts, "body": {"stringValue": f"{src} -> {dst}"}, "attributes": attrs})
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "cno-netflow-collector"}}]},
        "scopeLogs": [{"scope": {"name": "netflow_v9_collector"}, "logRecords": recs}],
    }]}


def ship(payload, host, port, timeout=5):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", "/v1/logs", json.dumps(payload).encode(), {"Content-Type": "application/json"})
        r = conn.getresponse(); r.read()
        return r.status
    finally:
        conn.close()


class Shipper:
    """Hands OTLP batches to the local agent from worker threads, never from the receive loop.

    WHY THIS IS NOT INLINE. Shipping used to happen directly in the recvfrom() loop with a 5s
    timeout, and the agent periodically stops accepting — measured 2026-08-03, ~0.6 timeouts a
    minute in clusters roughly every 8 minutes, which is backpressure from its own export queue
    to Dynatrace filling up. Inline, that costs twice: the batch is lost AND the socket goes
    unread for five seconds, so the kernel receive buffer overflows and DATAGRAMS are lost too.
    The second loss is the worse one, because a datagram can carry a template that later records
    depend on.

    So the loop hands off and returns immediately. A transient agent stall now costs latency
    instead of data, up to the depth of the queue.

    DROPS ARE COUNTED AND PRINTED, never silent. When the queue really is full the oldest batch
    is discarded rather than the newest — stale flow data is worth less than current — but the
    count is reported on every progress line so a saturated pipeline is visible rather than
    looking like a quiet network. Absence has to be legible; that lesson is all over this repo.
    """

    def __init__(self, host, port, workers=2, maxq=512, attempts=3):
        self.host, self.port, self.attempts = host, port, attempts
        self.q = queue.Queue(maxsize=maxq)
        self.sent = self.batches = self.failed = self.dropped = self.retried = 0
        self._lock = threading.Lock()
        for _ in range(workers):
            threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, payload, nflows):
        try:
            self.q.put_nowait((payload, nflows))
        except queue.Full:
            try:                                   # make room by discarding the OLDEST
                _, old = self.q.get_nowait()
                with self._lock:
                    self.dropped += old
                self.q.task_done()
                self.q.put_nowait((payload, nflows))
            except (queue.Empty, queue.Full):
                with self._lock:
                    self.dropped += nflows

    def _worker(self):
        while True:
            payload, nflows = self.q.get()
            ok = False
            for attempt in range(self.attempts):
                try:
                    st = ship(payload, self.host, self.port)
                    if 200 <= st < 300:
                        ok = True
                        break
                except Exception:                  # noqa: BLE001 — a worker must never die
                    pass
                if attempt + 1 < self.attempts:
                    with self._lock:
                        self.retried += 1
                    time.sleep(0.5 * (attempt + 1))
            with self._lock:
                if ok:
                    self.sent += nflows
                    self.batches += 1
                else:
                    self.failed += nflows
            self.q.task_done()

    def stats(self):
        with self._lock:
            return dict(sent=self.sent, batches=self.batches, failed=self.failed,
                        dropped=self.dropped, retried=self.retried, depth=self.q.qsize())


def main():
    ap = argparse.ArgumentParser(description="NetFlow v9 collector -> OTLP (ifIndex-preserving)")
    ap.add_argument("--listen-port", type=int, default=2055)
    ap.add_argument("--otlp-host", default="127.0.0.1")
    ap.add_argument("--otlp-port", type=int, default=4318)
    ap.add_argument("--no-enrich", action="store_true",
                    help="skip IP->ASN/org/rDNS lookups (they send PUBLIC destination addresses "
                         "to the system resolver; internal addresses are never looked up)")
    args = ap.parse_args()

    global ENRICHER
    ENRICHER = Enricher(enabled=not args.no_enrich)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A bigger kernel receive buffer absorbs the burst that arrives while a worker is retrying a
    # stalled agent. Best-effort: the OS may cap it below what is asked for, which is fine.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind(("0.0.0.0", args.listen_port))
    shipper = Shipper(args.otlp_host, args.otlp_port)
    print(f"netflow v9 collector: udp/{args.listen_port} -> OTLP "
          f"http://{args.otlp_host}:{args.otlp_port}/v1/logs "
          f"(rcvbuf={sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}, "
          f"enrich={'on' if ENRICHER.enabled else 'off'})", flush=True)
    total = 0
    while True:
        data, addr = sock.recvfrom(65535)
        flows = parse_packet(data, addr[0])
        if not flows:
            continue
        # Enrichment and OTLP encoding are cheap and cache-only; the network call is not, and is
        # the only thing handed to a worker.
        shipper.submit(to_otlp(flows, addr[0]), len(flows))
        total += len(flows)
        if total % 200 < len(flows):
            s = shipper.stats()
            e = ENRICHER
            enr = (f" | enrich {e.hits}h/{e.misses}m, {e.resolved} resolved"
                   if e.enabled else "")
            loss = ""
            if s["failed"] or s["dropped"]:
                loss = f" | LOST {s['failed'] + s['dropped']} (failed {s['failed']}, dropped {s['dropped']})"
            print(f"  decoded {total} flows, shipped {s['sent']} in {s['batches']} batches "
                  f"(queue {s['depth']}, retries {s['retried']}){enr}{loss}", flush=True)


if __name__ == "__main__":
    main()
