"""
Oxidized/Git -> Dynatrace COMPLIANCE + config-change extension (remote / ActiveGate).

Ports config_capture.py's read/evaluate path onto the AG: reads the device running-configs that
Oxidized captures into a Git-backed archive, evaluates ISO-27001:2022 controls against each, and
detects drift vs a golden baseline — shipping network.compliance + network.config LOGS to Grail.
(The lab's config_capture.py also SIMULATES changes against hardcoded golden configs; that demo
path is intentionally NOT ported — a real deployment reads Oxidized's actual archive.)

Emits (logs):
  network.compliance  {compliance.control, compliance.status, host.name, ...}  ISO-27001 pass/fail
  network.compliance  {compliance.status=capture_failed|capture_partial, ...}  capture health
  network.config      {config.drift_from_golden, config.diff, host.name, ...}  drift vs golden

Everything here is gated on the artefact actually BEING a configuration. Oxidized will happily
store a CLI refusal as a device's config and mark the node "success" (measured 2026-08-02),
so assess_capture() runs before platform detection and before grading — see the CAPTURE
HEALTH section for why that gate is a content test and not a file-size test.

The archive itself is read two ways, because the deployment we DOCUMENT is not the one the
code originally read. docs/CUSTOMER-HANDOFF.md tells customers to use Oxidized's own git
output backend ("no separate Git server is required"), and that backend produces a BARE
repository: `git rev-parse --is-bare-repository` -> true, no working tree, and each device
stored as a tracked blob named after the NODE with no file extension. Measured on the lab
ActiveGate 2026-08-02: `find /home/oxidized -name '*.cfg'` returned nothing, the default
deviceGlob "*.cfg" matched nothing, and the capability emitted ZERO records — not
not_assessed, total silence, for the exact deployment shape we recommend. See the ARCHIVE
ENUMERATION section; the plain-directory (file backend) path is unchanged and still wins
whenever it finds anything.

The archive is also REACHED two ways, and that is a separate axis from how it is read. Local
mode (configPath) is unchanged and is the right answer whenever Oxidized runs on the
ActiveGate host. Remote mode (remoteUrl) has the ActiveGate maintain its own git mirror of a
remote archive and refresh it every poll — see the REMOTE ARCHIVE section for why a local
filesystem path was the wrong single assumption, and for what a mirror costs. Both modes end
at the same place: a local path handed to the same reader, so nothing below _archive_source
knows or cares which one produced it.
"""
import base64
import fnmatch
import hashlib
import os
import posixpath
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit, urlunsplit

from dynatrace_extension import Extension

# ── ISO-27001:2022 controls, PER PLATFORM ────────────────────────────────────────────────
#
# These were originally a single flat map of Cisco-IOS substring checks applied to every
# device. Proven wrong on 2026-07-31: run against 61KB of real Nokia SR Linux running-config
# it reported 0/12 controls passing, while the device demonstrably HAD acl{}, aaa{
# authentication{} } and logging{} configured. The rules searched for "access-list",
# "aaa new-model" and "logging host" — Cisco spellings that simply do not occur in SRL. A
# customer on any non-Cisco fleet would have been shown a confident, specific, wrong
# ISO-27001 assessment, which is worse than showing nothing.
#
# Three rules govern this table now:
#   1. Rules are scoped to a PLATFORM, detected from the config text.
#   2. No matching platform  ->  NOT ASSESSED (never FAIL). A control that cannot be
#      evaluated is a coverage gap to report, not a violation to allege.
#   3. Every rule set carries VERIFIED. True means the predicates were executed against a
#      real running-config from that platform. False means they were written from vendor
#      documentation and have NEVER been tested — those results are marked with an asterisk
#      downstream so nobody mistakes them for a validated assessment.
#
# A predicate may return None to mean "not applicable to this platform" (e.g. NTP on FRR,
# which is a routing daemon and does not do time sync) — reported as n/a, not FAIL.

def _has(*needles):
    return lambda c: any(n in c for n in needles)

PLATFORMS = [
    {
        "id": "nokia-srlinux", "label": "Nokia SR Linux", "verified": True,
        # verified against a real SR Linux running-config (containerlab, 2026-07-31)
        "detect": lambda c: "network-instance" in c and ("admin-state" in c or "srl_nokia" in c),
        "controls": {
            "A.5.15": ("Access control — ACL defined", _has("acl {")),
            "A.5.37": ("Documented procedures — login banner", _has("login-banner", "banner {")),
            "A.8.5":  ("Secure authentication — AAA configured",
                       lambda c: "aaa {" in c and "authentication {" in c),
            "A.8.9":  ("Configuration management — logging configured", _has("logging {")),
            "A.8.15": ("Logging — buffered logging", _has("buffer messages")),
            "A.8.16": ("Monitoring — NTP time synchronization", _has("ntp {")),
            "A.8.21": ("Security of network services — no plaintext HTTP server",
                       lambda c: "http-server" not in c or "admin-state disable" in c),
            "A.8.22": ("Segregation of networks — network-instance (VRF) separation",
                       _has("network-instance")),
            "A.8.24": ("Cryptography — password stored hashed", _has("$y$", "$6$")),
            "A.8.26": ("Secure management — SSH server enabled", _has("ssh-server")),
        },
    },
    {
        "id": "frr", "label": "FRRouting", "verified": True,
        # verified against a real FRR running-config (containerlab, 2026-07-31)
        "detect": _has("frr version", "frr defaults"),
        "controls": {
            "A.5.15": ("Access control — ACL defined", _has("access-list")),
            "A.5.37": ("Documented procedures — login banner", _has("banner")),
            "A.8.5":  ("Secure authentication — VTY auth configured", _has("vty", "line vty")),
            "A.8.9":  ("Configuration management — remote logging", _has("log syslog", "log host")),
            "A.8.15": ("Logging — persistent logging", _has("log file", "log syslog")),
            "A.8.16": ("Monitoring — NTP time synchronization", lambda c: None),  # FRR does not do NTP
            "A.8.21": ("Security of network services — no HTTP server", lambda c: True),  # FRR serves no HTTP
            "A.8.22": ("Segregation of networks — VRF separation", _has("vrf ")),
            "A.8.24": ("Cryptography — password encryption", _has("service password-encryption")),
            "A.8.26": ("Secure management — integrated vtysh config", _has("service integrated-vtysh-config")),
        },
    },
    {
        "id": "cisco-ios", "label": "Cisco IOS / IOS-XE", "verified": True,
        # verified: 12/12 against the Cisco golden baseline (2026-07-31)
        "detect": _has("service timestamps", "ip cef", "aaa new-model", "line vty"),
        "controls": {
            "A.5.15": ("Access control — an ACL is defined", _has("access-list")),
            "A.5.37": ("Documented operating procedures — login banner set", _has("banner")),
            "A.8.5":  ("Secure authentication — AAA enabled, no telnet",
                       lambda c: "aaa new-model" in c and "transport input telnet" not in c),
            "A.8.8":  ("Vulnerability management — encrypted enable secret", _has("enable secret")),
            "A.8.9":  ("Configuration management — remote logging enabled", _has("logging host")),
            "A.8.15": ("Logging — buffered logging configured", _has("logging buffered")),
            "A.8.16": ("Monitoring activities — NTP time synchronization", _has("ntp server")),
            "A.8.21": ("Security of network services — HTTP server disabled", _has("no ip http server")),
            "A.8.22": ("Segregation of networks — VLAN segmentation present", _has("vlan ")),
            "A.8.24": ("Use of cryptography — password encryption enabled", _has("service password-encryption")),
            "A.8.26": ("Secure management — SSH-only VTY access", _has("transport input ssh")),
            "A.8.32": ("Change management — config change timestamps", _has("service timestamps")),
        },
    },
    # ── UNVERIFIED below this line ───────────────────────────────────────────────────────
    # Written from vendor documentation. NEVER executed against a real device of this
    # platform. Results are stamped compliance.verified=false and rendered with an asterisk,
    # so they can be used as a starting point and corrected once a customer shares a real
    # (sanitised) config. Do NOT promote a rule set to verified without running it.
    {
        "id": "juniper-junos", "label": "Juniper JunOS", "verified": False,
        "detect": lambda c: ("system {" in c and "root-authentication" in c) or "## Last commit" in c,
        "controls": {
            "A.5.15": ("Access control — firewall filter defined", _has("firewall {", "filter ")),
            "A.5.37": ("Documented procedures — login message", _has("message ", "announcement ")),
            "A.8.5":  ("Secure authentication — authentication-order set", _has("authentication-order")),
            "A.8.9":  ("Configuration management — remote syslog", _has("syslog {", "host ")),
            "A.8.16": ("Monitoring — NTP configured", _has("ntp {")),
            "A.8.21": ("Security of network services — web-management disabled",
                       lambda c: "web-management" not in c),
            "A.8.22": ("Segregation of networks — routing-instances / VLANs", _has("routing-instances", "vlans {")),
            "A.8.24": ("Cryptography — encrypted-password", _has("encrypted-password")),
            "A.8.26": ("Secure management — SSH enabled, telnet absent",
                       lambda c: "ssh {" in c and "telnet {" not in c),
        },
    },
    {
        "id": "arista-eos", "label": "Arista EOS", "verified": False,
        "detect": _has("! device:", "management api http-commands", "eos_"),
        "controls": {
            "A.5.15": ("Access control — an ACL is defined", _has("ip access-list")),
            "A.5.37": ("Documented procedures — login banner", _has("banner login", "banner motd")),
            "A.8.5":  ("Secure authentication — AAA configured", _has("aaa authentication")),
            "A.8.9":  ("Configuration management — remote logging", _has("logging host")),
            "A.8.15": ("Logging — buffered logging", _has("logging buffered")),
            "A.8.16": ("Monitoring — NTP configured", _has("ntp server")),
            "A.8.21": ("Security of network services — HTTP disabled",
                       lambda c: "no protocol http" in c or "protocol https" in c),
            "A.8.22": ("Segregation of networks — VLANs", _has("vlan ")),
            "A.8.26": ("Secure management — SSH management", _has("management ssh")),
        },
    },
    {
        "id": "paloalto-panos", "label": "Palo Alto PAN-OS", "verified": False,
        "detect": _has("<deviceconfig>", "<config version", "set deviceconfig"),
        "controls": {
            "A.5.15": ("Access control — security rules defined", _has("<rulebase>", "security {")),
            "A.8.5":  ("Secure authentication — auth profile", _has("authentication-profile")),
            "A.8.9":  ("Configuration management — syslog profile", _has("<syslog>", "log-settings")),
            "A.8.16": ("Monitoring — NTP configured", _has("<ntp-servers>", "ntp-servers")),
            "A.8.22": ("Segregation of networks — zones defined", _has("<zone>", "zone {")),
            "A.8.26": ("Secure management — permitted-ip on mgmt", _has("permitted-ip")),
        },
    },
    {
        "id": "netgear", "label": "Netgear (ProSafe / M-series)", "verified": False,
        # NOT verified: Oxidized could not retrieve a config from the lab's GSM7248V2 (telnet
        # only, no SSH) and the GS752TP exposes no CLI at all. Promote once a real pull works.
        "detect": _has("!Current Configuration:", "System Description \"GSM", "ProSafe"),
        "controls": {
            "A.5.15": ("Access control — an ACL is defined", _has("access-list", "mac access-list")),
            "A.5.37": ("Documented procedures — login banner", _has("banner")),
            "A.8.9":  ("Configuration management — remote logging", _has("logging host")),
            "A.8.16": ("Monitoring — SNTP/NTP configured", _has("sntp", "ntp ")),
            "A.8.22": ("Segregation of networks — VLANs", _has("vlan ")),
            "A.8.26": ("Secure management — SSH enabled", _has("ip ssh")),
        },
    },
]


def detect_platform(text):
    """First matching platform, or None -> the device is reported NOT ASSESSED."""
    for p in PLATFORMS:
        try:
            if p["detect"](text):
                return p
        except Exception:
            continue
    return None


# ── DEVICE IDENTITY ──────────────────────────────────────────────────────────────────────
#
# device.address is the JOIN KEY for this entire product, not a decoration. The SNMP extension
# builds its entities with idPattern network_device_{device.address}; data.ts fleetLogScope()
# filters LOG records with in(`device.address`,{...}) or in(`host.name`,{...}); and the three
# RCA workflows in deploy/alerting attach config-change evidence with norm(dev) ===
# lower(sys_name). A record carrying an empty address, or a name that does not string-equal the
# SNMP sysName, is dropped from the fleet view or silently fails to correlate.
#
# What this replaces: re.match(r"hostname (\S+)") and re.search(r"ip address (\d+\.\d+...)").
# Measured 2026-08-02 against the lab's real 5494-byte GSM7248V2 capture and against every
# fixture in tests/:
#
#   * device.address came out EMPTY for 100% of the corpus — including all three VERIFIED
#     Cisco goldens, which carry no numeric `ip address` at all (GOLDEN_SDWAN has
#     `ip address dhcp`). That rule has never once produced a value in this repository, so
#     the address dimension was dead product-wide, not merely on Netgear.
#   * The real FASTPATH capture contains NO `hostname` line. host.name fell back to the file
#     stem and was right only because the Oxidized node name happens to equal the device's
#     sysName — luck, not correctness. Its name is `snmp-server sysname "outpost"` (line 82)
#     and its address `network parms 10.0.10.3 255.255.255.0 10.0.10.1` (line 49).
#   * re.search matches ANYWHERE on a line, so the old address rule was measured returning a
#     commented-out address, an address quoted inside an interface description, an address
#     quoted in banner prose, and a `secondary` address. Worst of all, on an edge router whose
#     WAN stanza comes first it returned the ISP transit /30 (203.0.113.7) — a
#     plausible-but-wrong address is worse than none, because it mints a phantom
#     network_device_203.0.113.7 entity that never joins the SNMP fleet and can collide.
#   * `hostname` was LAST-wins while `ip address` was FIRST-wins. Measured: a config whose
#     banner body contains a line starting "hostname bogus" resolved to 'bogus', not 'REAL-SW'.
#
# Two rules govern the table below, mirroring PLATFORMS exactly:
#   1. Identity is PLATFORM-SCOPED, because the same token means different things per vendor.
#      On the real GSM7248V2, `set prompt "GSM7248V2"` is the MODEL NUMBER. It is deliberately
#      not a name rule at any priority — it is worse than the filename fallback.
#   2. An address is emitted ONLY when it is the MANAGEMENT address. When ambiguous, empty.
#      `verified` carries the same meaning it does in PLATFORMS.

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = r"(?:" + _OCTET + r"(?:\." + _OCTET + r"){3})"

# Quoted-with-spaces is tried FIRST because `\S+` truncated it: measured 2026-08-02,
# `hostname "Data Center 1"` resolved to '"Data', which after quote-stripping is 'Data'.
_NAMEV = r"""(?:"(?P<dq>[^"\n]+)"|'(?P<sq>[^'\n]+)'|(?P<bare>[^\s;"'#]+))"""


def _rx(body):
    """Anchor at line start, tolerating leading indentation ONLY.

    ONE greedy character class then a body at a FIXED offset — the same shape, for the same
    reason, as _ERR_LEAD/_ERR_BODY below: an anchored pattern with several quantified
    whitespace runs in front of an alternation backtracks catastrophically and pins the poll
    thread. Measured on these patterns: 100,000 leading blanks in 1.3ms, a 1MB config in 1.5ms.

    re.match rather than re.search is the correctness half. re.search is exactly what made the
    old address rule fire inside banner prose, interface descriptions and commented-out lines.
    """
    return re.compile(r"^[ \t]*" + body, re.I)


NAME_SYSNAME = _rx(r"snmp-server\s+sysname\s+" + _NAMEV)
NAME_HOSTNAME = _rx(r"hostname\s+" + _NAMEV)
NAME_SET_HOST = _rx(r"set\s+system\s+host-name\s+" + _NAMEV)
NAME_HOST_NAME = _rx(r"host-name\s+" + _NAMEV)
NAME_EOS_HDR = _rx(r"!\s*device:\s*" + _NAMEV)
NAME_PAN_SET = _rx(r"set\s+deviceconfig\s+system\s+hostname\s+" + _NAMEV)
NAME_PAN_XML = re.compile(r"<hostname>\s*([^<\s][^<]*?)\s*</hostname>", re.I)

ADDR_NET_PARMS = _rx(r"network\s+parms\s+(?P<ip>" + _IPV4 + r")\s")
ADDR_SERVICEPORT = _rx(r"serviceport\s+ip\s+(?P<ip>" + _IPV4 + r")\b")
ADDR_PAN_SET = _rx(r"set\s+deviceconfig\s+system\s+ip-address\s+(?P<ip>" + _IPV4 + r")\b")
ADDR_JUN_SET = _rx(r"set\s+interfaces\s+(?:fxp0|em0|me0|vme)\b.*?family\s+inet\s+address\s+"
                   r"(?P<ip>" + _IPV4 + r")\b")

_IF_START = re.compile(r"^(?P<ind>[ \t]*)interface\s+(?P<name>\S+)", re.I)
_IF_ADDR = _rx(r"ip(?:v4)?\s+address\s+(?P<ip>" + _IPV4 + r")\b(?P<rest>.*)$")
_MGMT_NAME = re.compile(r"^(management|mgmt|ma\d|me\d|fxp\d|em0|vme)", re.I)
# Switch virtual interfaces only — see the sole_interface arm in _ios_mgmt_address. A
# loopback is deliberately absent: it is routed and plausible, but it is a ROUTER's identity
# choice rather than an access switch's single SVI, so it belongs in the ambiguous bucket.
_SVI_NAME = re.compile(r"^(vlan|bvi|irb)", re.I)
# Anchored at BOTH ends so `no shutdown` cannot match.
_SHUTDOWN = re.compile(r"^[ \t]*shutdown[ \t]*$", re.I)
_MGMT_VRF = re.compile(r"^[ \t]*(?:ip\s+vrf\s+forwarding|vrf\s+forwarding|vrf)\s+"
                       r"(?:mgmt|management|Mgmt-intf)\b", re.I)
_SRL_MGMT = re.compile(r"^interface\s+mgmt0\b", re.I)
_JUN_MGMT = re.compile(r"^(?:fxp0|em0|me0|vme)\s*\{", re.I)

# Addresses that are never a device's management identity, so never an entity key.
_RESERVED_V4 = ("0.", "127.", "169.254.")


def _usable_ip(ip):
    return bool(ip) and ip != "0.0.0.0" and not ip.startswith(_RESERVED_V4) \
        and not ip.endswith(".255")


# A control character can reach a parsed name from a binary blob AUTO discovery swept up.
# errors="replace" does not help — NUL is valid UTF-8 — and _NAMEV's bare branch [^\s;"'#]+
# matches it while .strip() does not remove it. Measured 2026-08-02: a blob containing
# `hostname a\x00b` shipped host.name='a\x00b' in four fields including the JOIN KEY, which
# cannot be typed into a Grail filter and can never string-equal the SNMP sysName. The
# filename stem is a better answer than a name nobody can query.
_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_name(m):
    v = (m.group("dq") or m.group("sq") or m.group("bare") or "").strip()
    v = v.strip("\"'").rstrip(";,").strip()
    return "" if _CTRL_CHARS.search(v) else v


def _scan_name(lines, rules):
    """FIRST match wins, in rule-priority order — see the last-wins measurement above."""
    for rule, src in rules:
        for ln in lines:
            m = rule.match(ln)
            if m:
                v = _clean_name(m)
                if v:
                    return v, src
    return "", ""


def _first_rule_ip(lines, rule, src):
    for ln in lines:
        m = rule.match(ln)
        if m and _usable_ip(m.group("ip")):
            return m.group("ip"), src
    return "", ""


def _ios_style_addresses(lines):
    """(interface, ip, is_mgmt) for each PRIMARY address in an ADMIN-UP IOS/EOS stanza.

    Stanza-scoped rather than line-scoped because that is the only thing that makes the
    is_mgmt judgement possible at all: on IOS the management address is identified by the
    interface it sits under (Management0/0) or by `vrf forwarding Mgmt-intf`, never by the
    address line itself. `secondary` is dropped — it is by definition not the primary identity.

    A `shutdown` stanza contributes NOTHING, and that is a correctness rule rather than a
    refinement: an admin-down port is unreachable by definition, so nothing can ever poll it
    and it cannot be the address any telemetry arrives on. Measured 2026-08-02 — a
    staged-but-uncabled OOB port

        interface Management0/0
         description OOB - staged, not cabled
         ip address 192.168.1.1 255.255.255.0
         shutdown

    beat the live in-band SVI 10.0.100.5 outright, because _MGMT_NAME outranks everything.
    Across a fleet staged from one build sheet that is network_device_192.168.1.1 for every
    switch — the highest-collision address in networking — and with the SVI on `ip address
    dhcp` the shut port became the SOLE parsed address and was returned as sole_interface.

    The whole stanza is buffered and discarded on `shutdown` because the keyword can appear
    either side of the address line. `no shutdown` must not match, which is why the pattern is
    anchored at both ends.
    """
    out, pend = [], []
    cur, in_mgmt_vrf, shut = None, False, False
    for ln in lines:
        m = _IF_START.match(ln)
        if m or (cur and (not ln[:1].isspace() or ln.strip() in ("!", "exit"))):
            if not shut:
                out.extend(pend)
            pend = []
            cur, in_mgmt_vrf, shut = (m.group("name") if m else None), False, False
            continue
        if not cur:
            continue
        if _SHUTDOWN.match(ln):
            shut = True
            continue
        if _MGMT_VRF.match(ln):
            in_mgmt_vrf = True
            continue
        a = _IF_ADDR.match(ln)
        if a and "secondary" not in a.group("rest").lower():
            pend.append((cur, a.group("ip"), bool(_MGMT_NAME.match(cur)) or in_mgmt_vrf))
    if not shut:
        out.extend(pend)
    return out


def _ios_mgmt_address(lines):
    """Management address for IOS/EOS, or '' — never a guess."""
    found = [(i, ip, mg) for i, ip, mg in _ios_style_addresses(lines) if _usable_ip(ip)]
    mgmt = [ip for _, ip, mg in found if mg]
    if mgmt:
        return mgmt[0], "mgmt_interface"
    # Uniqueness is necessary but NOT sufficient, and the missing half was measured. The
    # argument for this arm is specifically the pure L2 access switch: it carries exactly ONE
    # addressed SVI and that SVI is its management address. It says nothing about a ROUTER
    # with one addressed physical port, and on a WAN-first edge router that port is the ISP
    # transit /30 — measured, `hostname BRANCH-RTR-07` with a single addressed
    # GigabitEthernet0/0/0 returned 203.0.113.7 stamped sole_interface, minting exactly the
    # phantom network_device_203.0.113.7 the DEVICE IDENTITY note says must never exist. The
    # module already refuses that config the moment a second interface is addressed, so
    # guessing on one was also self-inconsistent. Restricted to SVI-shaped names, which is the
    # population the argument actually covers. Refusing costs a null; guessing mints a phantom.
    if len(found) == 1 and _SVI_NAME.match(found[0][0]):
        return found[0][1], "sole_interface"
    return "", ""


def _brace_mgmt_address(lines, opener):
    """First address inside the named management-interface brace block (SR Linux / JunOS).

    Scoped by BRACE DEPTH, because the previous terminator did not scope anything. It was
    re.match(r"^(?:interface|ge-|xe-|et-)\\S"), and measured 2026-08-02 it:

      could not match `interface <name> {` AT ALL — SR Linux writes a space after `interface`
      and \\S demands a non-space at that exact offset, so `interface ethernet-1/1 {` and even
      `interface mgmt0 {` both scored False; and

      named none of `lo0 {`, `irb {`, `ae0 {`, `reth0 {`, `st0 {`, `vlan {`, `vme {`,
      `fxp1 {`, or the closing `}`.

    So whenever the named management interface carries no IPv4 — DHCP or IPv6-only, both
    ordinary — the scan ran to EOF and returned the FIRST address anywhere in the file,
    stamped `mgmt_interface`. Measured against canonically-ordered configs (JunOS sorts
    ge- < lo0 < me0 < vlan, and fxp0 < reth0 < st0):

      JunOS EX,  me0 on the ZTP DHCP default   -> returned the user SVI vlan.20  172.19.20.1
      JunOS SRX, fxp0 on DHCP                  -> returned the reth0 ISP WAN /30 198.51.100.2
      SR Linux,  mgmt0 on dhcp-client          -> returned ethernet-1/1          192.168.11.1

    The SRX row is precisely the ISP-transit phantom entity the DEVICE IDENTITY note above
    says must never be emitted, and SR Linux is a `"verified": True` platform in PLATFORMS.
    Depth starts at 1 when the opener carries no brace of its own, so an opener whose `{` sits
    on the following line still scopes rather than terminating immediately.
    """
    inside, depth = False, 0
    for ln in lines:
        s = ln.strip()
        if not inside:
            if opener.match(s):
                inside, depth = True, max(1, s.count("{") - s.count("}"))
            continue
        m = re.match(r"^address\s+(" + _IPV4 + r")(?:/\d+)?", s)
        if m and _usable_ip(m.group(1)):
            return m.group(1), "mgmt_interface"
        depth += s.count("{") - s.count("}")
        if depth <= 0:
            inside = False
    return "", ""


def _addr_netgear(text, lines):
    # VERIFIED against the lab's real GSM7248V2 capture (2026-08-02), line 49:
    #   network parms 10.0.10.3 255.255.255.0 10.0.10.1
    # `network protocol dhcp|bootp` leaves 0.0.0.0 on that line, which _usable_ip rejects.
    # serviceport is the out-of-band port and is the fallback, not the primary.
    ip, src = _first_rule_ip(lines, ADDR_NET_PARMS, "network_parms")
    return (ip, src) if ip else _first_rule_ip(lines, ADDR_SERVICEPORT, "serviceport")


def _addr_ios(text, lines):
    # UNVERIFIED. No artefact in this repository carries a numeric management address for
    # IOS/EOS — all three Cisco goldens have none and GOLDEN_SDWAN uses `ip address dhcp` — so
    # these rules are exercised only by synthetic fixtures. A real (sanitised) IOS capture with
    # a Management interface or a Mgmt-intf VRF is the single most valuable artefact to obtain.
    return _ios_mgmt_address(lines)


def _addr_frr(text, lines):
    # NOT APPLICABLE, not a gap. FRR is a routing daemon; its management address belongs to the
    # Linux host it runs on and is not in this config. Same convention as a control predicate
    # returning None — reported as n/a rather than as a missing value.
    return "", "n/a"


def _addr_junos(text, lines):
    ip, src = _first_rule_ip(lines, ADDR_JUN_SET, "fxp0")
    return (ip, src) if ip else _brace_mgmt_address(lines, _JUN_MGMT)


def _addr_srl(text, lines):
    return _brace_mgmt_address(lines, _SRL_MGMT)


def _panos_system_block(text):
    """The <system> element a PAN-OS export puts deviceconfig identity in, or None.

    First match in document order, which is a KNOWN limitation rather than a claim: a config
    carrying a nested <template> block has that template's <system> first, so both the name
    and the address would come from the placeholder. It is left as-is because no artefact in
    this repository — and no Oxidized `panos` capture we have seen — has that shape, so
    narrowing it further would be the untested vendor-doc guesswork PLATFORMS' `verified` flag
    exists to prevent. What is fixed here is the ASYMMETRY: the address was scoped and the
    name was not, so the two could disagree about which device they described.
    """
    blk = re.search(r"<system>(.*?)</system>", text, re.S | re.I)
    return blk.group(1) if blk else None


def _addr_panos(text, lines):
    ip, src = _first_rule_ip(lines, ADDR_PAN_SET, "deviceconfig_system")
    if ip:
        return ip, src
    # Scoped to the <system> element on purpose: a PAN-OS XML export contains many
    # <ip-address> elements inside address objects, any of which an unscoped search would take.
    blk = _panos_system_block(text)
    if blk:
        m = re.search(r"<ip-address>\s*(" + _IPV4 + r")\s*</ip-address>", blk, re.I)
        if m and _usable_ip(m.group(1)):
            return m.group(1), "deviceconfig_system"
    return "", ""


# `verified` follows PLATFORMS: True means these rules were EXECUTED against a real capture
# from that platform. "name" means only the name rule was. False means vendor documentation
# only — never run against real hardware of that vendor, and stated as such to a customer.
IDENTITY = {
    # VERIFIED: the lab's real 5494-byte GSM7248V2 FASTPATH capture. `snmp-server sysname` is
    # the SNMP sysName OBJECT itself, which is the same MIB object the SNMP extension reports
    # as sys_name — so host.name now matches the SNMP roster BY CONSTRUCTION rather than by the
    # filename coincidence it relies on today. That equality is what the RCA workflows' Lane A
    # join (norm(dev) === lower(sys_name)) depends on; rename the Oxidized node, or key
    # router.db by IP as is common, and today's luck evaporates silently.
    "netgear": {"name": [(NAME_SYSNAME, "snmp_sysname"), (NAME_HOSTNAME, "hostname")],
                "addr": _addr_netgear, "verified": True},
    # name VERIFIED against the three repo Cisco goldens; address rules UNVERIFIED (see
    # _addr_ios). The split is recorded rather than rounded to one flag because the two halves
    # genuinely have different evidence behind them.
    "cisco-ios": {"name": [(NAME_HOSTNAME, "hostname")],
                  "addr": _addr_ios, "verified": "name"},
    # UNVERIFIED — vendor documentation. The `! device: leaf1 (...)` capture header is an EOS
    # convention we have never seen in this lab.
    "arista-eos": {"name": [(NAME_HOSTNAME, "hostname"), (NAME_EOS_HDR, "device_header")],
                   "addr": _addr_ios, "verified": False},
    "frr": {"name": [(NAME_HOSTNAME, "hostname")], "addr": _addr_frr, "verified": "name"},
    # UNVERIFIED. The repo's JUNIPER_SET fixture is synthetic and does not even match
    # detect_platform, so only the GENERIC_NAME tier below is actually exercised for it.
    "juniper-junos": {"name": [(NAME_SET_HOST, "set_host_name"), (NAME_HOST_NAME, "host_name")],
                      "addr": _addr_junos, "verified": False},
    # UNVERIFIED. The repo's SRL_FULL fixture carries no host-name element at all (checked), so
    # the name rule here has never matched anything real.
    "nokia-srlinux": {"name": [(NAME_HOST_NAME, "host_name")],
                      "addr": _addr_srl, "verified": False},
    # UNVERIFIED. The repo's PANOS_XML fixture has neither a hostname nor an ip-address element.
    "paloalto-panos": {"name": [(NAME_PAN_SET, "set_hostname")],
                       "addr": _addr_panos, "verified": False},
}

# Used when detect_platform() returns None, and load-bearing rather than a courtesy: identity
# must still resolve for an UNFINGERPRINTED artefact, because the capture-failure record's
# entire purpose is to be findable and it is emitted precisely when fingerprinting failed.
# Measured: this tier alone recovers 'edge-01' from the JUNIPER_SET fixture, which no detect
# predicate matches.
GENERIC_NAME = [(NAME_HOSTNAME, "hostname"), (NAME_SET_HOST, "set_host_name"),
                (NAME_SYSNAME, "snmp_sysname")]

# Extensions Oxidized's FILE backend appends to a node name. Stripping ONLY these is the
# difference between an identity and a mangled one, because os.path.splitext strips whatever
# follows the LAST dot whether or not it is an extension — and the git backend's defining
# property is that its blobs have no extension at all.
#
# Measured 2026-08-02. Oxidized's router.db is very commonly keyed by management address
# ("10.0.10.3:netgear:user:pass"), so IP-named nodes are ordinary, and _meta's docstring calls
# an IPv4 stem "the strongest identity evidence available, stronger than anything in the file":
#
#   node "10.0.10.3"                 -> host.name '10.0.10'                addr ''  (was)
#   node "core-sw-1.lab.example.com" -> host.name 'core-sw-1.lab.example'  addr ''  (was)
#
# The address evidence is destroyed in exactly the deployment that produces it, and the damage
# lands on the records that most need to be findable: a failed capture has no in-config name
# or address, so the stem IS its identity, and fleetLogScope() filters on device.address and
# host.name — neither of which '10.0.10' appears in. It also COLLAPSES DEVICES: three
# IP-keyed nodes in one /24 all reported host.name '10.0.10' with no address, so 48 switches
# in a /24 are one device downstream. Only "10.0.10.3.cfg" behaved, which is the one shape
# the git backend never produces.
_CFG_EXT = {".cfg", ".conf", ".config", ".txt", ".xml", ".log", ".bak", ".run", ".ios"}


def _node_stem(rel):
    """The Oxidized NODE name for a config path — never a truncated one."""
    base = posixpath.basename(rel)
    root, ext = posixpath.splitext(base)
    return root if root and ext.lower() in _CFG_EXT else base


# ── ARCHIVE ENUMERATION ──────────────────────────────────────────────────────────────────
#
# Oxidized has two output backends and this module has to read both.
#
#   file backend  ->  a plain directory of files. What the old glob assumed, and what still
#                     takes priority: any hit on disk means git is never consulted.
#   git backend   ->  a BARE repository (output: git, single_repo: true), which is what
#                     docs/CUSTOMER-HANDOFF.md recommends. No working tree, so there is
#                     nothing on disk to glob; each device is a tracked blob named after the
#                     NODE, with NO FILE EXTENSION. Measured on the lab archive 2026-08-02:
#                       git rev-parse --is-bare-repository  -> true
#                       git ls-tree -r --long HEAD          -> "...  5494  outpost"
#                       find /home/oxidized -name '*.cfg'   -> nothing
#
# deviceGlob therefore defaults to AUTO (empty string) rather than "*.cfg". "*.cfg" cannot
# match a blob called `outpost`, and telling a customer to configure a pattern for a naming
# scheme Oxidized chose for them is a trap they hit silently.
#
# Setting deviceGlob="*" is NOT the workaround it looks like, which is why AUTO is a distinct
# mode rather than a documentation note: measured, walking a bare repository's own gitdir
# yields HEAD, config, packed-refs, hooks/*.sample and objects/** — and one binary object
# raised UnicodeDecodeError, turning the whole poll into an exception.
AUTO_GLOB = ""

# The AUTO deny-list. Three independent layers already stop a non-config from being graded
# (Oxidized's git backend commits ONLY node blobs; detect_platform returns not_assessed for
# anything unfingerprinted; assess_capture condemns junk), so this list exists for the
# hand-managed-repo case. It is still needed: measured, a README.md scores "ok" with 2
# substantive lines, so the content gate alone would let it through as a device.
_SKIP_NAMES = {".gitignore", ".gitattributes", ".gitmodules", ".keep", ".gitkeep",
               "head", "config", "description", "packed-refs", "index", "orig_head",
               "fetch_head", "commit_editmsg"}
_SKIP_EXT = {".md", ".markdown", ".rst", ".txt", ".log", ".json", ".yaml", ".yml",
             ".sample", ".png", ".jpg", ".gif", ".pdf", ".gz", ".bz2", ".xz", ".zip",
             ".tar", ".tgz", ".pack", ".idx", ".lock", ".swp", ".bak", ".pyc",
             # Executables, not captures. A hand-managed archive carries hook and helper
             # scripts (Oxidized itself is Ruby), and ".conf"/".cfg"/".txt" are deliberately
             # NOT treated the same way — those are plausible device-capture names.
             ".sh", ".bash", ".rb", ".py", ".pl"}
_SKIP_STEMS = {"readme", "license", "licence", "changelog", "contributing", "notice",
               "authors", "makefile", "dockerfile"}

# There is deliberately NO directory deny-list any more. It used to be
#   {".git", "hooks", "objects", "refs", "info", "logs", "branches", "modules"}
# applied to every parent segment, and it deleted whole Oxidized GROUPS by name. `groups:` is
# ordinary Oxidized configuration and `logs`, `info` and `modules` are ordinary group names,
# so under AUTO — which is now the DEFAULT — every device in such a group vanished with no
# record of any kind. Measured 2026-08-02 on a bare archive of seven groups, five were
# dropped: edge/sw1 and core/sw5 were read, and logs/sw2, info/sw3, modules/sw4, refs/sw6 and
# hooks/sw7 produced ZERO records. Not archive_empty either — that only fires when the whole
# list is empty — so it was the exact silent-device failure this module exists to remove, in
# the mode most deployments now run.
#
# What the list was actually protecting is git's own storage, and that is now detected by
# SHAPE instead of by name, at the only place it can occur: _list_disk prunes any directory
# that IS a gitdir (HEAD + objects/ + refs/). Tracked git blobs need no such guard at all —
# git never commits its own object store — and `.git` itself is still refused by the
# dot-segment rule in admits(), in both modes.


def _is_gitdir(d):
    """Does this directory hold git's own storage? Shape, not name — see the note above."""
    try:
        return (os.path.isfile(os.path.join(d, "HEAD"))
                and os.path.isdir(os.path.join(d, "objects"))
                and os.path.isdir(os.path.join(d, "refs")))
    except OSError:
        return False


def _auto_admits(rel):
    """Would AUTO discovery treat this repo-relative path as a device capture?

    AUTO ONLY. This list must never be consulted for an explicit pattern — see admits().
    """
    base = rel.split("/")[-1]
    if base.lower() in _SKIP_NAMES:
        return False
    stem, ext = posixpath.splitext(base)
    return ext.lower() not in _SKIP_EXT and stem.lower() not in _SKIP_STEMS


def _seg_match(rel, pattern):
    """glob.glob semantics, preserved exactly: '*' never crosses a '/'.

    An explicit pattern must keep behaving the way it does today, because operators already
    have "*.cfg" and "*/*.cfg" persisted in monitoring configurations. Segment-wise fnmatch is
    what makes "*.cfg" still exclude edge/sw2.cfg and "*/*.cfg" still work.
    """
    rp, pp = rel.split("/"), pattern.split("/")
    return len(rp) == len(pp) and all(fnmatch.fnmatchcase(r, p) for r, p in zip(rp, pp))


def admits(rel, pattern):
    """Is this repo-relative path a device capture, under the operator's chosen pattern?

    The deny-list applies to AUTO ONLY, and that split is not tidiness — running it against an
    explicit pattern silently broke two working deployments. Caught by review before shipping:

      deviceGlob="*.txt" matched nothing, because ".txt" is on the AUTO extension deny-list.
      Under the old glob it worked, and nothing would have told the operator it had stopped.

      An Oxidized group literally named `logs` or `info` (both on the AUTO directory
      deny-list) made "*/*.cfg" skip that entire group.

    An explicit pattern is an ASSERTION by the operator that these files are their devices, and
    it outranks any heuristic of ours. Only two guards survive in both modes, and both match
    what glob.glob already did: never descend into git's own storage (the old code's
    `".git" not in f`), and treat dot-segments the way glob treats them.

    That second guard used to be "never match a dot-file", justified as "glob does not
    either" — which is FALSE and was measured so. glob.glob DOES match a dot-segment when the
    pattern's own segment starts with a dot, so deviceGlob=".*.cfg" returned ['.hidden.cfg']
    under the old code and [] under this one: a real, if narrow, regression against
    requirement 2 hiding behind a wrong justification. The rule is now glob's actual rule —
    a dot-segment needs a dot-leading pattern segment — while `.git` stays refused outright in
    both modes so no pattern can walk into git's storage.
    """
    parts = rel.split("/")
    if any(p == ".git" for p in parts[:-1]):
        return False
    base = parts[-1]
    if not base:
        return False
    if pattern != AUTO_GLOB:
        pp = pattern.split("/")
        if len(parts) != len(pp):
            return False
        if any(s.startswith(".") and not p.startswith(".") for s, p in zip(parts, pp)):
            return False
        return _seg_match(rel, pattern)
    if any(p.startswith(".") for p in parts):
        return False
    return _auto_admits(rel)


# ── REMOTE ARCHIVE: the ActiveGate maintains its OWN mirror ──────────────────────────────
#
# configPath — a LOCAL FILESYSTEM PATH — was the only way this extension could reach the
# archive, and in the deployment measured on 2026-08-02 that single assumption forced:
# Oxidized in a container on cno-svc, the ActiveGate on a DIFFERENT VM (cno-ag), an NFS export
# to bridge the two, a foreign-owned repository (uid 30000), safe.directory handling, and then
# --no-ext-diff/--no-textconv/core.fsmonitor=false to close the command-execution hole that
# safe.directory opened. Every one of those is scaffolding around "the archive must already be
# a directory on this host". The archive is a GIT REPOSITORY; the ActiveGate can fetch it.
#
# Why a mirror and not Oxidized's REST API. The API returns only the CURRENT config. No
# history means no drift-vs-golden and no change-to-impact, and those two are the product
# differentiator — the reason this capability exists rather than a config-backup checkbox.
# `git clone --mirror` brings the whole history, including refs/tags/golden (verified), so
# goldenRef keeps working with no extra refspec and no second code path.
#
# Why the mirror adds no reader. A mirror is a BARE repository — exactly the shape the module
# already reads. Verified 2026-08-02 by running the real, unmodified functions against a
# `git clone --mirror` of a bare Oxidized archive:
#     _resolve_archive -> {'kind':'git','bare':True,'prefix':'','ownership':'same-user'}
#     _load_configs    -> mode=git tracked=3 loaded=['edge/branch-sw1','outpost'] unread=0
#     _prev_good_bytes -> 5494                     (the history walk works)
#     query()          -> "Config check outpost: DRIFTED from golden (2 lines)"  WARN
# So remote mode resolves configuration to a LOCAL PATH and then runs today's code against it,
# unchanged. `ownership='same-user'` there is not incidental: a mirror the ActiveGate created
# is owned by the ActiveGate user, so the whole safe.directory apparatus is inert for it. It
# stays because LOCAL mode still needs it.
#
# ONE authentication path: HTTPS with a token/PAT (plus unauthenticated http/https, and file://
# for testing). SSH IS OUT OF SCOPE — no schema field, no GIT_SSH_COMMAND, no known_hosts, and
# deliberately no design allowance for it. SSH drags in key files, key permissions, a
# known_hosts policy and a StrictHostKeyChecking security decision: a large second surface for
# an auth path that is not how a SERVICE reads GitLab / GitHub Enterprise / Bitbucket. Every
# option is one more thing to break at a customer. The stated cost of omitting it: a customer
# whose remote is ssh-only uses local-path mode, which is unchanged.

MIRROR_DIRNAME = "cno-oxidized-mirrors"

# Written ONLY after a fetch/clone that returned 0 AND passed _mirror_usable — see
# _mark_refreshed for why this owned marker exists instead of a git-native signal.
_REFRESH_MARKER = "cno-last-refresh"

# The floor under the staleness limit, and it is IMPLIED rather than chosen: intervalSeconds
# already ships with "maximum": 86400, so any limit below that would make a legally-configured
# 24-hour poll declare itself stale between its own polls. Three independent arguments land on
# the same number. Oxidized's own default interval is 3600s, so a healthy archive is already up
# to an hour behind the devices and sub-hour freshness is not a claim this data can support. A
# compliance posture is reported per DAY, so a day is the unit of the artefact. And the lab
# outage this module was hardened around ran 29 hours — a 24-hour limit catches that class
# inside the first day, before a whole reporting period is wrong.
STALE_FLOOR_SECONDS = 86400

# The literal fallback base, used when TMPDIR is not EEC-shaped (dt-sdk run, the simulator).
# Same path on a stock ActiveGate install.
_AG_DEFAULT_RUNTIME = "/var/lib/dynatrace/remotepluginmodule/agent/runtime"

# Deleted from the child environment of every NETWORK git call rather than merely unset by us.
# GIT_TRACE_CURL and GIT_CURL_VERBOSE dump request HEADERS, and the Authorization header is
# where the token lives, so an operator (or a support engineer) who exports one of these for
# unrelated debugging would otherwise put the customer's PAT into the extension log. The
# GIT_CONFIG_* entries go too: we set COUNT ourselves and a stale inherited KEY_n/VALUE_n pair
# from a parent process has no business reaching a call that carries a credential. GIT_ASKPASS
# and SSH_ASKPASS are dropped because GIT_TERMINAL_PROMPT=0 only closes the TERMINAL prompt —
# an inherited askpass helper is still invoked, and a GUI helper on a headless host hangs.
#
# GIT_SSL_NO_VERIFY is the same threat model with a worse outcome, and leaving it out was a
# hole. Measured 2026-08-02 against a real TLS listener presenting a self-signed
# CN=gitlab.example.com certificate:
#
#   without it                     handshake REJECTED by git, nothing sent
#   with GIT_SSL_NO_VERIFY=1       Authorization: Basic b2F1dGgyOmdscGF0LVNVUEVSU0VDUkVUMTIz
#   inherited from the AG's env     -> oauth2:glpat-SUPERSECRET123
#
# i.e. an inherited debug variable hands the customer's PAT to an unauthenticated third party,
# and it silently negates the ActiveGate trust store that is the stated reason there is no
# caCertPath / insecureSkipVerify property. Pinning http.sslVerify=true through GIT_CONFIG_*
# does NOT close it — measured, GIT_SSL_NO_VERIFY wins over the pinned config — so deleting the
# variable from the child environment is the only fix. GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM
# would redirect config resolution at a call carrying a credential, and GIT_PROXY_COMMAND is
# outright command execution.
#
# GIT_SSL_CAINFO is deliberately NOT dropped: it names an ADDITIONAL trust anchor rather than
# disabling verification, and a customer whose ActiveGate sets it to a corporate CA bundle
# would break. The system config that /etc/gitconfig provides is still honoured either way.
_ENV_DROP = re.compile(r"^(GIT_TRACE|GIT_CURL_VERBOSE|GIT_REDACT_COOKIES|GIT_ASKPASS|"
                       r"SSH_ASKPASS|GIT_CONFIG_COUNT$|GIT_CONFIG_KEY_|GIT_CONFIG_VALUE_|"
                       r"GIT_CONFIG_PARAMETERS$|GIT_SSL_NO_VERIFY$|GIT_CONFIG_GLOBAL$|"
                       r"GIT_CONFIG_SYSTEM$|GIT_PROXY_COMMAND$)")


def _interval_seconds(c):
    """intervalSeconds as an int, defaulting the way the schema does. Never raises."""
    try:
        return int(c.get("intervalSeconds", 900) or 900)
    except (TypeError, ValueError, AttributeError):
        return 900


def _budgets(interval):
    """-> (fetch, clone) second budgets, DERIVED from intervalSeconds. No new property.

    The target is a third of the poll interval: a fetch that ran longer would collide with the
    next poll. It cannot corrupt anything — the SDK skips an iteration while the previous one
    is still running (extension.py:872 `if not callback.running:`), and poll() holds its own
    per-instance lock as well — but it stalls the capability.

    The 60s FLOOR wins over that target below intervalSeconds=180, and the cost is stated here
    rather than implied, because the docstring used to claim the third was a hard ceiling and
    it is not:

        intervalSeconds=60   fetch=60s   = 100% of the interval, clone=240s = 4x
        intervalSeconds=180  fetch=60s   =  33%                  clone=240s
        intervalSeconds=900  fetch=300s  =  33%                  clone=1200s (capped)

    The floor is kept deliberately. A budget below ~60s starts killing healthy fetches of cold
    or large archives over a slow WAN link, and a killed fetch presents as archive_stale — i.e.
    tightening it to satisfy the ratio would manufacture the exact false-staleness this module
    is built to avoid, in exchange for an overrun that is already handled. At 60s the operator
    has asked for the minimum interval the schema allows, which is a claim about their archive
    being small and near; if it is not, they get a skipped iteration and one WARN naming the
    interval as the thing to raise.

    The clone budget is larger because it happens once and pulls cold history; the 1200s cap
    keeps even that bounded.

    A fetchTimeoutSeconds property was considered and rejected: it would be a second knob whose
    only sane value is a function of the first one.
    """
    fetch = max(60, min(300, interval // 3))
    return fetch, min(1200, 4 * fetch)


def _ag_runtime_dir():
    """'<agent>/runtime' derived from the TMPDIR the EEC sets, or '' if not EEC-shaped.

    Discovered rather than hardcoded so a non-default install root still works. Measured on the
    lab ActiveGate 2026-08-02 as dtuserag, the user the datasource actually runs as:

      TMPDIR = <agent>//runtime/datasources/working_directories/<dsid><epoch_ms>/tmp

    The double slash is verbatim from /proc/<pid>/environ and is why this cuts on the
    '/runtime/datasources/working_directories/' marker rather than counting path segments.
    """
    tmp = os.environ.get("TMPDIR", "") or ""
    marker = "/runtime/datasources/working_directories/"
    i = tmp.find(marker)
    return tmp[:i + len("/runtime")] if i > 0 else ""


def _mirror_root(base, config_id, url):
    """<base>/<sanitised monitoring-config-id>.git — the mirror directory for one config.

    Keyed on the MONITORING CONFIGURATION ID (SDK extension.py:318, "unique identifier of the
    monitoring configuration"), NOT on a hash of the URL, and the difference is deliberate in
    both directions. Two configurations pointing at different remotes cannot collide, because
    their ids differ. And editing the URL of one configuration lands on the SAME directory,
    which forces the URL-changed case to be handled explicitly in _refresh_mirror instead of
    silently accumulating one orphaned mirror per URL edit. Disk is therefore bounded by the
    number of monitoring configurations.

    Stated cost: deleting a monitoring configuration leaves its directory behind. It is a
    cache, the path is deterministic, and it is emitted on every archive record.

    The sha256 fallback is for environments with no id at all (dt-sdk run), where the URL is
    the only stable key available.
    """
    key = re.sub(r"[^A-Za-z0-9._-]", "_", str(config_id or "")).strip("._")[:64]
    if not key:
        key = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()[:16]
    return os.path.join(base, key + ".git")


def _sanitize_remote(url):
    """-> (url carrying NO password, username or '', the password the operator pasted or '').

    The third element is the password VALUE rather than a bare "there was one" flag, because
    the caller has to be able to USE it: an operator who pastes
    https://oauth2:glpat-xxx@gitlab.example.com/net/oxidized.git has unambiguously supplied
    their credential, and refusing it would break them without un-exposing anything that is
    already stored in the tenant. It is stripped out of the URL, used as the token, and the
    operator is told at WARN to move it to the secret field.

    Stripping it is what makes token hygiene STRUCTURAL rather than a cleanup step. Measured
    2026-08-02, this is the leak that matters:

        $ grep url <mirror>/config
          url = https://oauth2:glpat-SUPERSECRET123@gitlab.example.com/net/oxidized.git

    No command in this module is ever handed a URL containing a password — clone, fetch and
    the stored remote all use the value returned here — so there is nothing for git to write.

    Userinfo is percent-decoded, because that is what git does with it before sending; the
    caller redacts both the decoded and the raw spelling.
    """
    try:
        p = urlsplit(url)
    except ValueError:
        return url, "", ""
    if not p.netloc or "@" not in p.netloc:
        return url, "", ""
    userinfo, _, hostport = p.netloc.rpartition("@")
    user, _, pw = userinfo.partition(":")
    netloc = (user + "@" + hostport) if user else hostport
    return urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment)), unquote(user), unquote(pw)


def _redact(text, *secrets):
    """Replace every non-empty secret with '***'. Applied to ALL git stderr we log or emit.

    git already redacts userinfo from the URLs in its own messages — measured 2026-08-02, a
    remote carrying oauth2:glpat-SUPERSECRET123@ produced
    "fatal: unable to access 'https://gitlab.example.com/net/oxidized.git/'" — so this is the
    backstop for the path git cannot cover: a proxy or a server echoing the Authorization
    header back inside an error body.

    Both the raw token AND the base64 header value must be passed by every caller. A redactor
    that only looks for the raw token would miss the encoded form entirely, which is the form
    that actually travels on the wire.
    """
    out = text or ""
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


def _rmtree(path):
    shutil.rmtree(path, ignore_errors=True)
    try:
        # A plain FILE sitting where a mirror belongs would otherwise wedge the swap forever:
        # rmtree cannot remove it, and os.rename(<dir>, <file>) then fails on every poll.
        os.remove(path)
    except OSError:
        pass


# ── CAPTURE HEALTH: is this artefact even a configuration? ───────────────────────────────
#
# Measured in the lab on 2026-08-02 (Netgear GSM7248V2, FASTPATH). Oxidized authenticated
# successfully, but the 'enable' step was rejected ("Incorrect Password!") so the session
# stayed in User EXEC and every command was refused. Oxidized STORED THE REFUSAL TEXT AS THE
# CONFIG and marked the node status "success". The entire stored artefact was 272 bytes of:
#
#     !!COMMAND: show version
#     !                   ^
#     !% Invalid input detected at '^' marker.
#     ...
#
# detect_platform() returns None on that exact text — no fingerprint matches — so it already
# fell through to NOT ASSESSED rather than FAIL. That guard held and is kept. Three things it
# does not cover, which is the whole reason this section exists:
#
#   1. PARTIAL captures still fingerprint. Every detect predicate above keys off the first
#      few lines: cisco-ios on "service timestamps", netgear on "!Current Configuration:".
#      Truncate an IOS config after line 5 and detect_platform() confidently returns
#      cisco-ios with verified=True, then grades the controls against text that simply stops
#      before the ACLs. Measured 2026-08-02: the same device scores 12 pass / 0 fail on its
#      full config and 1 pass / 11 FAIL on the truncated one. Every predicate in PLATFORMS is
#      substring presence, so ABSENCE IS INDISTINGUISHABLE FROM TRUNCATION — that is
#      structural, no amount of rule tuning fixes it, only a gate in front of grading does.
#   2. Truncation also manufactures PASSES, which is worse. Run the predicates against an
#      empty string: nokia-srlinux A.8.21, frr A.8.21 and juniper-junos A.8.21 all return
#      True, because they are negative-polarity ("http-server" not in c). So a half-captured
#      file does not merely produce false FAILs, it can produce a clean bill of health. This
#      is why a non-ok verdict below discards the PASSES too, not just the fails.
#      The gate that actually closes this is TERMINATORS (see below): pager residue and CLI
#      error text only catch a truncation that leaves a mark, and this device's own byte
#      history only catches one big enough to trip a ratio. A session that dies on a line
#      boundary at 95% leaves no mark and trips no ratio — the missing end-of-config marker is
#      the only thing left, and it needs no git.
#   3. An earlier unprivileged session on the same switch returned a ~94-byte stub beginning
#      "!Current Configuration:" — which DOES match the netgear fingerprint. That artefact
#      grades 0/6 with all six controls at WARN: a device that is actually compliant reported
#      as totally non-compliant, with confidence. not_assessed never engages at all.
#
# And even when not_assessed does engage it is the wrong words. It reads as "we have no rules
# for this platform" — our coverage gap, ship and fix later — when the truth is "your backup
# is failing / the account lacks enable privilege", which is the customer's network ops team
# and is due today. Nothing anywhere said otherwise for 29 hours in the lab.
#
# The question deliberately NOT asked here is "did the capture fail?". That is unknowable
# from the artefact and guessing at it invites false alarms. The question asked instead is
# "does this file contain enough recognisable configuration to grade a control against?" —
# answerable from the text alone, vendor-neutral, and defensible to a customer, because "we
# did not assess this device because the file contained no configuration statements" is true
# regardless of why it happened.

# Oxidized writes a comment-prefixed header before each command's output. The measured
# artefact contains BOTH "!!COMMAND:" (Oxidized's comment method prepending '!' to a header
# that already carried one) and "!COMMAND:" — match both, plus the '#' variant the
# Juniper/SRL models emit.
#
# The leading run is ONE character class, not "\s*[!#;]{0,3}\s*". Two quantified whitespace
# runs either side of an optional class is quadratic in a line's indentation length, and these
# patterns are applied to every line of every artefact (twice, via _is_substantive). See the
# measurement above _ERR_LEAD — the same shape there was cubic and hung query() for 26s.
_CMD_HDR = re.compile(r"^[\s!#;]*COMMAND:\s", re.I)

# The bare caret position-marker the CLI prints under the offending token. Must be the WHOLE
# line: this deliberately does NOT match Cisco's "^C" banner delimiter (extra character, and
# inline on "banner motd ^C"), which is the only place a real config puts a caret.
_CARET_ONLY = re.compile(r"^[\s!#]*\^\s*$")

# Full CLI error grammar, anchored to line start after an optional comment prefix. Every
# entry is a complete vendor error sentence. Bare "invalid", "denied" and "error" are NOT
# here on purpose: they are ordinary ACL-remark and interface-description vocabulary, and
# requiring "% Invalid input DETECTED" rather than "invalid input" is exactly what keeps this
# list safe to apply to real configs.
_ERR_PHRASES = [
    r"%?\s*invalid input detected",                  # Cisco IOS/NX-OS, Netgear FASTPATH
    r"%?\s*incorrect password",                      # FASTPATH / HP enable rejection
    r"%?\s*permission denied",                       # IOS-XR, Linux-family
    r"%?\s*authorization failed",                    # TACACS+ command authorization
    r"%?\s*command authorization failed",
    r"%?\s*authentication failed",
    r"%?\s*access denied",
    r"%?\s*(unknown|unrecognized|invalid) command",  # Juniper / Arista / SRL / FRR
    r"%?\s*syntax error",
    r"%?\s*(is\s+)?ambiguous command",
    r"%?\s*incomplete command",
    r"%?\s*error:\s*(permission|access|privilege|authorization)",
    r"%?\s*you (do not|don't) have (the required |sufficient )?priv",
    r"%?\s*command not (found|authorized|allowed)",
    r"%?\s*login (invalid|incorrect|failed)",
    r"%?\s*connection (closed|refused|timed out)",
    r"%?\s*error fetching",                          # Oxidized's own failure text
    # NB: the '%' is mandatory here. An earlier draft matched a bare "timeout" and fired on
    # SR Linux "idle-timeout 3600" / "timeout 300" and IOS "exec-timeout 5 0" — all of which
    # are ordinary configuration. Caught by the corpus in tests/test_capture_health.py.
    r"%\s*timeout",
]

# Matched as TWO patterns, not one, and this is a correctness fix rather than a style choice.
# The single-regex form "^\s*[!#]?\s*(?:<18-way alternation>)" puts three quantified whitespace
# runs in sequence in front of an alternation, which backtracks catastrophically: measured
# 2026-08-02 on one call, 100 leading blanks = 26ms, 200 = 187ms, 400 = 1.4s, 1000 = 21s. A
# 6KB artefact with a few over-indented lines held query() for 26 SECONDS. That is worse than
# a crash — no exception reaches the SDK, the scheduled callback simply never returns and the
# poll thread is pinned. Splitting it makes the leading run unambiguous (one greedy character
# class, then the body anchored at a FIXED offset) so there is nothing to backtrack across:
# 200 blanks drops to 0.00ms and 100,000 to 0.4ms. Byte-identical verdicts on the whole corpus.
# Possessive quantifiers would also fix it but need Python 3.11; extension.yaml pins min 3.10.
_ERR_LEAD = re.compile(r"^[\s!#]*")
_ERR_BODY = re.compile(r"(?:" + "|".join(_ERR_PHRASES) + r")", re.I)


def _is_err(line):
    """Does this line READ as CLI error output? (grammar only — see _err_indices for context)"""
    return _ERR_BODY.match(line, _ERR_LEAD.match(line).end()) is not None


# Pager residue. Oxidized sends "terminal length 0" before collecting, so residue means
# paging was live and the capture is TRUNCATED at that point — the cleanest direct evidence
# of a partial capture, and vendor-general (IOS, FASTPATH, EOS, Comware and SROS all page).
#
# Two phrases were REMOVED after they were measured as false positives against a healthy IOS
# config on 2026-08-02, both because they are ordinary English rather than a pager prompt:
#   "press any key to continue"  fired on a security banner reading
#                                "Authorized access only. Press any key to continue."
#   "\bMORE:\s"                  fired on  snmp-server location "Rack12 DC2 MORE: wiki/..."
# Neither is a literal pager prompt on any supported vendor (IOS and EOS print "--More--",
# Comware "---- More ----", SROS "---(more)---"), so the recall they bought was zero and the
# false-positive surface was a whole device suppressed. What is left is punctuation-shaped and
# cannot occur in prose. This is also now banner-masked and recovery-checked (see
# _pager_indices), which the single unanchored re.search over the raw text was not — the error
# grammar had both guards and the pager pattern had neither, and that asymmetry was the defect.
_PAGER = re.compile(r"(--\s*more\s*--|--+\(\s*more|\x1b\[7m)", re.I)

_BANNER_START = re.compile(
    r"^\s*(banner\b|.*\bmessage\s+(motd|login)\b|set\s+system\s+login\s+message)", re.I)

# Thresholds. Named constants rather than literals because these are the numbers a customer
# will ask us to justify, and the corpus in tests/test_capture_health.py is what justifies
# them — that corpus, not these numbers, is the artefact worth preserving.
MIN_SUBSTANTIVE = 5     # below this there is nothing to grade an ISO-27001 control against
TINY_BYTES = 512        # ONLY ever used conjoined with MIN_SUBSTANTIVE and "no fingerprint"
NOISE_RATIO = 0.60      # command-echo + error + caret lines as a share of real content
FAST_PATH_SUBSTANTIVE = 20   # a clean, content-rich, fingerprinted capture short-circuits
RECOVERY_SUBSTANTIVE = 20    # config lines AFTER a defect that prove the session survived it
SHRINK_RATIO = 0.40     # vs this device's OWN last good capture
SHRINK_MIN_DROP = 512   # ...and an absolute floor, so small files cannot trip the ratio
SHRINK_LOOKBACK = 3     # revisions to walk back looking for a known-good reference

# End-of-config markers. The ONLY in-file signal that catches a CLEAN truncation — one that
# still fingerprints, carries no CLI error text and shows no pager residue. Requirement 1 is
# not covered without it: measured 2026-08-02 against a 7106-byte IOS config whose ACL, banner,
# logging, ntp and "line vty" stanzas all sit after a 48-port interface list, cutting the
# session anywhere in that list yields 7 FALSE FAILS (A.5.15 A.5.37 A.8.9 A.8.15 A.8.16 A.8.21
# A.8.26) and the gate says "ok" — at 30%, 41%, 50%, 75% AND 95% retention, even when handed a
# perfect prev_good_bytes, because the shrinkage arm needs a >40% drop AND a >512B absolute
# drop (so it cannot fire at all below prev=853B, which is all three repo goldens) and the
# reference poisons itself after one poll.
#
# Deliberately narrow. Only the IOS-family platforms are listed, because "show running-config"
# there emits exactly one standalone "end" line, always last, and the repo's own goldens
# (GOLDEN_9300 / GOLDEN_ACCESS / GOLDEN_SDWAN / MIN_FRR) all carry it. NOT listed, on purpose:
# nokia-srlinux and juniper-junos (brace fragments are legitimately unterminated),
# paloalto-panos (the set-format variant has no terminator at all), and netgear — Oxidized has
# never successfully pulled a config off the lab's FASTPATH switch, so asserting its terminator
# would be exactly the untested vendor-doc claim the PLATFORMS table's `verified` flag exists
# to prevent. The verdict is SUSPECT, never unusable: if some deployment's Oxidized model
# strips the marker, every device of that platform flags at WARN at once — loud, uniform and
# obviously a rule problem — rather than one device silently grading truncated text forever.
TERMINATORS = {"cisco-ios": ("end",), "arista-eos": ("end",), "frr": ("end",)}


def _decomment(line):
    """Strip leading Oxidized/vendor comment characters -> (payload, was_a_comment)."""
    s = line.strip()
    was = bool(re.match(r"^([!#]|//|;)", s))
    return re.sub(r"^(?:[!#]\s*|//\s*|;\s*)+", "", s).strip(), was


def _is_substantive(line):
    """Does this line carry an actual configuration statement?

    This is the PRIMARY signal, and it is deliberately size-independent — see the measured
    argument against a byte floor in assess_capture(). Conservative in both directions:
    comments never count (a file of only comments is not gradeable either way), '%'-prefixed
    system output never counts, and a lone token never counts, which excludes the base64/hash
    blob continuation lines in certificate and key material without excluding real config,
    because no config is ENTIRELY blobs.

    The accept clause — ends in one of "{ } ; >", or starts with "<", or has two or more
    whitespace-separated tokens — was chosen because it matches config syntax in every target
    vendor at once: IOS/EOS/FASTPATH "key value", Juniper braces AND set-format, SR Linux
    braces, PAN-OS XML AND "set deviceconfig", FRR, and even unsupported vendors (a real
    MikroTik export scores 8). It matches CLI refusal output in none of them.
    """
    if _CMD_HDR.match(line) or _CARET_ONLY.match(line) or _is_err(line):
        return False
    payload, was_comment = _decomment(line)
    if not payload or was_comment:
        return False
    if payload.startswith("%"):
        return False
    if payload[-1:] in "{};>" or payload.startswith("<"):
        return True
    return len(payload.split()) >= 2


def _banner_mask(lines):
    """True for every line sitting inside a banner / MOTD body.

    An operator's security banner is the one place a REAL config legitimately contains
    sentences like "Permission denied" or "Unauthorized access ... will be reported". This
    fired as a false positive on the first draft of the rule against the repo's own
    LAB-9300-1-1 golden with a realistic banner appended. Everything between the banner line
    and its delimiter is prose, not CLI output, so error phrases there must never count.
    """
    mask = [False] * len(lines)
    i = 0
    while i < len(lines):
        if _BANNER_START.match(lines[i]):
            tail = lines[i].rstrip()
            delim = tail[-1] if tail and tail[-1] in "^#~\"'" else None
            j = i + 1
            while j < len(lines) and j - i <= 25:
                mask[j] = True
                s = lines[j].strip()
                if (delim and delim in s) or s in ("EOF", "!"):
                    break
                j += 1
            i = j
        i += 1
    return mask


def _err_indices(lines):
    """Indices of error lines CORROBORATED as CLI output rather than as config prose.

    Two guards, and the pair replaces an earlier "within three lines below a command header or
    caret, or at EOF" adjacency window that was measured 2026-08-02 to be wrong in both
    directions at once:

      MISSED real refusals. Many Oxidized models emit no "!COMMAND:" header at all, so an
      artefact opening "% Authentication failed. / % Authorization failed." followed by eight
      lines of config had ZERO corroborated errors, graded, and produced 7 false FAILs. Same
      for TACACS+ "Command authorization failed." appearing mid-capture more than three lines
      below the single header.

      BOUGHT NOTHING. Across all eleven valid-config fixtures in tests/test_capture_health.py
      the adjacency clause discarded exactly zero false positives — the banner mask alone
      already took HOSTILE_BANNER from 1 raw hit to 0, and every other fixture was 0 to begin
      with. The ACL remark it was written for ("remark deny - permission denied, log all
      unknown command attempts") never matches the grammar anyway, because the grammar anchors
      at line start and that line starts with "remark".

    What actually distinguishes CLI output from config prose is provenance, so that is what is
    tested now. An error phrase counts when either:

      its payload is '%'-prefixed — the universal "this is system output, not configuration"
      marker, which no vendor's config syntax uses at line start (and which _is_substantive
      already refuses on the same grounds). This holds through a comment prefix, because
      Oxidized comment-prefixes the output it stores: the measured artefact's error lines are
      literally "!% Invalid input detected at '^' marker."; or

      the artefact is a COMMAND TRANSCRIPT — it contains an Oxidized command header or a bare
      caret marker somewhere — AND the line is not itself a comment. A device emitting an
      unprefixed refusal ("Command authorization failed.") is talking; a line an engineer
      commented out is not, and the comment character is the only thing that separates them
      once the artefact as a whole is known to be a transcript.

    That second clause needs the comment test because a real Oxidized capture IS a transcript,
    so "transcript" alone corroborates everything in the file: a healthy IOS capture carrying
    the trailing engineer comment "! access denied logging reviewed quarterly" was suspect
    until the not-a-comment conjunct was added. Costs nothing measurable — no vendor error
    sentence reaches us comment-prefixed WITHOUT also carrying its '%'.
    """
    banner = _banner_mask(lines)
    transcript = any(_CMD_HDR.match(l) or _CARET_ONLY.match(l) for l in lines)
    out = []
    for i, l in enumerate(lines):
        if banner[i] or not _is_err(l):
            continue
        payload, was_comment = _decomment(l)
        if payload.startswith("%") or (transcript and not was_comment):
            out.append(i)
    return out


def _pager_indices(lines):
    """Indices of pager residue, banner-masked — see the note above _PAGER."""
    banner = _banner_mask(lines)
    return [i for i, l in enumerate(lines) if not banner[i] and _PAGER.search(l)]


def _suffix_substantive(flags):
    """out[i] = how many substantive lines exist at or after index i."""
    out = [0] * (len(flags) + 1)
    for i in range(len(flags) - 1, -1, -1):
        out[i] = out[i + 1] + bool(flags[i])
    return out


def _unrecovered(idxs, after):
    """Of those defect positions, the ones the capture did NOT visibly recover from.

    A defect is only evidence of a broken or truncated capture if the capture stops there.
    RECOVERY_SUBSTANTIVE lines of real configuration AFTER it prove the session was alive and
    talking, which makes it an incident inside a healthy capture rather than the end of one.

    Measured 2026-08-02, and this is the single worst false positive the gate had. This
    deployment's Oxidized model issues three commands and only the last is graded; the
    GSM7248V2 artefact proves it. A Cisco device that simply does not implement "show bootvar"
    (deprecated on much of IOS-XE and NX-OS; "show inventory" behaves the same on IOSv/CSR1000v;
    a read-only TACACS+ account gets "Command authorization failed." on any one aux command)
    answers one of the three with an error and the other two perfectly. The old rule demanded a
    ZERO-error capture, so 1 error line beat 34 lines of captured configuration, no controls
    were graded, no drift was computed, and because the model reissues that command every poll
    the device NEVER graded again. Worse, the remediation the capture-failure record itself
    recommends — run the backup under a restricted read-only account — is a direct cause of it.
    """
    return [i for i in idxs if after[i + 1] < RECOVERY_SUBSTANTIVE]


def _missing_terminator(lines, plat_id):
    """True when a platform that ALWAYS emits an end-of-config marker did not emit one.

    Not banner-masked, deliberately: masking could hide a real "end" and manufacture a false
    truncation, whereas an "end" inside a banner body only costs a missed detection. Between
    the two, the false positive is the one that burns the alarm.
    """
    want = TERMINATORS.get(plat_id or "")
    return bool(want) and not any(l.strip().lower() in want for l in lines)


def assess_capture(text, platform, prev_good_bytes=None, auto_discovered=False):
    """Is this artefact usable as evidence? -> (verdict, reason, evidence)

    `platform` is the PLATFORMS entry from detect_platform(), or None. A bare bool is also
    accepted and means "fingerprinted, platform unknown" — that costs the TERMINATORS arm, so
    callers that have the entry should pass it.

    `auto_discovered` says the file was found by AUTO discovery rather than named by an
    operator's deviceGlob. It changes exactly one verdict — see archive_non_config — because
    the two modes carry different operator intent: an explicit glob is an ASSERTION that these
    files are devices, so a file with no configuration in it is a failed capture; AUTO makes no
    such claim and must not raise a collection-failure alarm over a stray file in the archive.

    verdict is one of:
      ok        grade normally
      suspect   real configuration, but PARTIAL — do not grade, do not compute drift
      unusable  not a configuration at all — do not grade, do not compute drift

    Why there is no simple minimum-file-size rule, which is the obvious first idea. Measured
    across a 17-case corpus (the repo's own GOLDEN configs from scripts/config_capture.py
    plus real fragments from every supported vendor):

        floor    catches the 3 bad artefacts    flags VALID configs
         128B              1/3                        0
         256B              2/3                        3
         300B              3/3                        4    <- minimum that works, already 4 FPs
         512B              3/3                        9
        1024B              3/3                       13

    There is no threshold with full recall and zero false positives. The distributions
    overlap: bad = 63 / 138 / 271B, valid = 223 / 230 / 300 / 317 / 485 / 529 / 602 / 666B.
    The repo's own smallest golden (LAB-SDWAN-8200-1, 485B) is 1.8x the size of the broken
    artefact, and a valid MikroTik export came in UNDER it at 223B. Nor can it be tuned out:
    SR Linux runs 61KB (see the note above PLATFORMS), PAN-OS XML runs to hundreds of KB, an
    FRR container is ~230B, so any absolute floor is implicitly per-platform — and the
    platform is precisely what we do not know, because the failure case IS the one where
    fingerprinting failed. Size therefore survives only as a CONJUNCT, in "stub_capture"
    below: no fingerprint AND under 512B AND under 5 substantive lines, three independent
    conditions.

    The cost asymmetry is what settles it. A false positive here does not mis-grade one
    control, it tells an operator their backup is broken when it is not. Burn that alarm once
    and the next real 29-hour outage gets ignored, so this signal has to be more trustworthy
    than the thing it guards.
    """
    fingerprinted = bool(platform)
    plat_id = platform.get("id") if isinstance(platform, dict) else None

    lines = [l for l in text.splitlines() if l.strip()]
    flags = [_is_substantive(l) for l in lines]
    subst = [l for l, s in zip(lines, flags) if s]
    after = _suffix_substantive(flags)
    hdrs = [l for l in lines if _CMD_HDR.match(l)]
    carets = [l for l in lines if _CARET_ONLY.match(l)]
    errs = _err_indices(lines)
    nbytes = len(text.encode("utf-8", "replace"))
    # Denominator excludes '!'-only separator lines (they decomment to empty), so an IOS
    # config with 60 separators cannot inflate its own noise ratio.
    denom = len([l for l in lines if _decomment(l)[0]]) or 1
    ev = {"bytes": nbytes, "substantive": len(subst), "errors": len(errs),
          "headers": len(hdrs), "carets": len(carets),
          "noise_ratio": round((len(hdrs) + len(errs) + len(carets)) / denom, 2)}

    # Defects the capture did not visibly recover from — see _unrecovered.
    errs_terminal = _unrecovered(errs, after)
    pager_terminal = _unrecovered(_pager_indices(lines), after)
    truncated = _missing_terminator(lines, plat_id)
    # The shrinkage arm is restricted to FINGERPRINTED captures. On a platform we have no rule
    # set for we never grade, so suppression buys nothing there and costs a permanent false
    # WARN: measured 2026-08-02, an operator deleting 40 obsolete MikroTik firewall rules
    # (3094B -> 223B) was reported capture_partial on every poll forever, because Oxidized only
    # commits on change so the large revision never leaves the SHRINK_LOOKBACK window.
    shrank = bool(prev_good_bytes and fingerprinted
                  and nbytes < SHRINK_RATIO * prev_good_bytes
                  and (prev_good_bytes - nbytes) > SHRINK_MIN_DROP)

    # Fast path: a fingerprinted, content-rich, clean capture is the overwhelming majority of
    # polls. It is evaluated LAST-signal-first rather than early-return-first, because an
    # earlier version returned here before the shrinkage and terminator arms were consulted and
    # silently made both unreachable for any capture with >=20 substantive lines — i.e. for
    # every real switch config, which is precisely the population they exist to protect.
    if (fingerprinted and len(subst) >= FAST_PATH_SUBSTANTIVE
            and not errs_terminal and not pager_terminal and not truncated and not shrank):
        return "ok", "", ev

    # ---- UNUSABLE: high confidence this is not a configuration at all --------------------
    if len(subst) == 0:
        # Same verdict, different STORY, and the discriminator is measured rather than
        # guessed. A real failed capture is loud about it: the lab's 272-byte artefact scores
        # headers=3 / carets=3 / errors=3. A stray file swept up by AUTO discovery — a binary
        # git object, an empty placeholder — scores 0/0/0 and never fingerprints. Calling that
        # "your device backup FAILED" at ERROR would burn exactly the alarm this whole gate
        # exists to protect. The `not fingerprinted` conjunct is load-bearing and was measured:
        # the lab's unprivileged FASTPATH stub also scores 0/0/0, but it DOES match the netgear
        # fingerprint, which is positive evidence that a real device answered — so it stays a
        # capture failure. Fingerprint, refusal markers, AUTO mode — and SIZE.
        #
        # `nbytes` is the fourth conjunct and it was missing. A ZERO-BYTE artefact is not
        # repository housekeeping: nobody commits an empty README, and the placeholder names
        # that exist for the purpose (.keep, .gitkeep) are already on _SKIP_NAMES. What an
        # empty file IS, in an archive Oxidized writes, is a device whose capture produced
        # nothing — the dead-backup case this whole gate exists to catch. Measured
        # 2026-08-02, a 0-byte capture came out INFO "NOT A DEVICE CONFIG ... Set a device
        # pattern to exclude it" under AUTO and ERROR capture_failed under an explicit glob:
        # the same artefact, and the AUTO wording told the operator to hide their broken
        # device. Non-empty content-free artefacts (whitespace, a binary git object) keep the
        # INFO verdict, because there the cost asymmetry above genuinely applies.
        if (auto_discovered and not fingerprinted and nbytes
                and not hdrs and not carets and not errs):
            return "unusable", "archive_non_config", ev
        return "unusable", "no_content", ev                    # the measured 272-byte artefact
    if len(errs) >= 2 and len(subst) < MIN_SUBSTANTIVE:
        return "unusable", "cli_refused", ev                   # enable rejected, User EXEC
    # Scales where a byte floor cannot: catches a 272-byte refusal and a hypothetical 50KB
    # file of nothing but repeated failing commands with the same test.
    if ev["noise_ratio"] >= NOISE_RATIO and len(subst) < 10:
        return "unusable", "mostly_command_echo", ev
    # The final conjunct is POSITIVE EVIDENCE OF A REFUSAL, and without it this arm claimed a
    # collection failure at ERROR against files that are complete, correct configuration.
    # Measured 2026-08-02: the corpus's own MikroTik fixture with two stanzas removed (133B, 4
    # substantive) and its Juniper set-format fixture with three lines removed (166B, 4) both
    # came out "unusable / stub_capture" at ERROR — a strictly stronger and more wrong claim
    # than the not_assessed INFO they produced before this gate existed. "Small, from a vendor
    # we have no rules for" is not evidence that anything failed; it is the definition of the
    # coverage gap not_assessed already reports, and such files now fall through to it.
    if (not fingerprinted and nbytes < TINY_BYTES and len(subst) < MIN_SUBSTANTIVE
            and (hdrs or carets or errs)):
        return "unusable", "stub_capture", ev

    # ---- SUSPECT: plausibly real configuration, but incomplete ---------------------------
    # Ordered by directness of evidence: what the file says about itself, then what it fails to
    # say, then what this device's own history says.
    if pager_terminal:
        return "suspect", "pager_truncation", ev
    if errs_terminal:
        return "suspect", "cli_error_mid_capture", ev
    if truncated:
        return "suspect", "no_end_of_config_marker", ev
    if shrank:
        ev["prev_good_bytes"] = prev_good_bytes
        return "suspect", "shrank_vs_last_good", ev
    # Only for a platform we would otherwise GRADE. Unfingerprinted small files belong to
    # not_assessed, per the stub_capture note above.
    if fingerprinted and len(subst) < MIN_SUBSTANTIVE:
        return "suspect", "too_little_content_to_grade", ev
    return "ok", "", ev


# Per-reason remediation. The reason code is what a detector fires on; this sentence is what
# lands in the ticket, and it is the difference between "your backup is broken" (network ops,
# due today) and "we have no rules for this platform" (us, ship and fix later). Requirement 2
# is not met by the status field alone — nobody reads a status field at 03:00.
CAPTURE_REASONS = {
    "no_content": "no configuration statements at all — the CLI refused every command. Check "
                  "the enable secret / privilege level for the account Oxidized authenticates with",
    "cli_refused": "the device refused the commands outright. Check the enable secret / "
                   "privilege level and the credentials in the Oxidized node definition",
    "mostly_command_echo": "almost entirely command echo and error text — the session never "
                           "reached a configuration prompt. Check enable / privilege level",
    "stub_capture": "a truncated stub carrying refusal markers and no recognisable "
                    "configuration. Check enable / privilege level and prompt detection",
    "wrong_device_config": "the stored configuration belongs to a DIFFERENT node, so THIS "
                           "device has no backup at all and the other device's record is "
                           "duplicated. Check the Oxidized node list for a duplicate name or IP",
    "pager_truncation": "pager residue at the point the capture stops — output paging was "
                        "live. Set 'terminal length 0' (or the model's equivalent) in Oxidized",
    "cli_error_mid_capture": "the capture ends in CLI error text — the session was refused or "
                             "died partway through. Check privilege level and session timeout",
    "no_end_of_config_marker": "the capture never reaches the end-of-config marker this "
                               "platform always emits, so it stopped partway through. Check "
                               "session timeout and pager settings",
    "shrank_vs_last_good": "a small fraction of this device's own last good capture. Confirm "
                           "this was an intended configuration reduction and not a truncated "
                           "session",
    "too_little_content_to_grade": "too few configuration statements to evaluate any control "
                                   "against. Check that the backup captures the full running-config",
    # The two ARCHIVE-shape reasons. Neither is a device's capture failing; both are the
    # archive not being what the extension was pointed at. They live in this table anyway
    # because config.capture.reason is what a detector fires on, and every value it can take
    # has to carry the sentence that lands in the ticket.
    "archive_empty": "ZERO device configurations were read from the archive this cycle, so "
                     "compliance coverage is zero rather than clean. Check Oxidized's output "
                     "backend and path, and clear the device pattern to auto-discover",
    # PARTIAL unreadability, which archive_empty cannot express because archive_empty only
    # fires when NOTHING loaded. This is the per-device half: the archive lists the file, the
    # other devices read fine, and this one does not.
    "archive_unreadable_file": "the archive lists this device but its stored configuration "
                               "could not be read back out of the repository's object store, "
                               "so THIS device has no usable backup this cycle even though "
                               "others in the same archive do. The repository or its local "
                               "mirror is damaged rather than misconfigured — run 'git fsck' "
                               "on the archive, and in remote mode delete the ActiveGate's "
                               "mirror directory to force a clean re-clone",
    # Worded for BOTH readings on purpose. The artefact carries no evidence either way — no
    # fingerprint, no refusal markers, no configuration — so asserting "housekeeping" and
    # recommending only "exclude it" told an operator to hide a device whose backup may
    # genuinely be dead. It states the likely case first and still names the other remediation
    "archive_non_config": "a file in the archive that is not a device configuration and shows "
                          "no sign of a failed capture — most likely repository housekeeping "
                          "swept up by auto-discovery. If it IS one of your nodes, its backup "
                          "produced nothing: check Oxidized's log for that node. Otherwise set "
                          "a device pattern to exclude it",
    "duplicate_device_name": "a DIFFERENT node in this archive reports the same device name, "
                             "so host.name cannot identify either of them downstream. The "
                             "configurations differ, so this is a duplicate name rather than a "
                             "mis-stored capture — check for a cloned template or a factory "
                             "default left in place on snmp-server sysname / hostname",
    # The three REMOTE-MODE freshness reasons. Kept distinct rather than folded into one
    # "archive problem" code because a detector fires on the code and the three carry
    # materially different losses: nothing at all, graded-but-ageing, and grading stopped.
    # None of them is archive_empty — that means "the mirror is fine and the pattern matched
    # nothing", which is a different fix entirely. Conflating those is the same mistake this
    # table already corrected for `unread` vs matched-none.
    "archive_unreachable": "the remote archive could not be reached and there is no usable "
                           "local mirror to fall back on, so compliance coverage is ZERO this "
                           "cycle rather than clean. Check that the ActiveGate can reach the "
                           "remote Git URL, and that the token is valid and still has read "
                           "access to the repository",
    "archive_stale": "the remote archive could not be refreshed, so devices were graded "
                     "against the last mirror that WAS successfully fetched. The findings are "
                     "real but they describe the archive as of that time, not as of now. Check "
                     "connectivity to the remote Git URL and the token's expiry",
    "archive_stale_refused": "the last successful refresh of the remote archive is older than "
                             "the staleness limit, so grading STOPPED rather than report a "
                             "compliance posture that has been decaying for longer than a "
                             "reporting period. No device was assessed this cycle. Restore "
                             "access to the remote Git URL",
    # LOCAL-mode unreachability. Deliberately NOT folded into archive_unreachable, by the same
    # argument the three freshness codes are kept apart: a detector fires on the code, and
    # archive_unreachable's remediation sentence sends the operator to check a remote Git URL
    # and rotate a PAT, neither of which exists in local mode. The fix here is a filesystem
    # one — the NFS export this extension's remote mode was built to replace is exactly what
    # drops out from under a co-located deployment.
    "archive_path_missing": "the configured archive path does not exist on this ActiveGate, or "
                            "is not a directory, so NO device was assessed this cycle and "
                            "compliance coverage is ZERO rather than clean. Confirm the path in "
                            "the monitoring configuration, that Oxidized is writing to it, and "
                            "— if it is a network mount — that the mount is still up",
}

# Deliberately NOT a CAPTURE_REASONS entry, and the distinction is the whole reason this
# constant exists separately. An unresolvable golden ref is a DRIFT precondition: every
# capture is intact, every control still grades, and the only thing unavailable is the
# comparison. Giving it a config.capture.reason would have put "an archive problem" on a poll
# where nothing about any capture failed — which the suite already asserts against ("a healthy
# capture must not be reported as any kind of archive problem") — and would have widened the
# meaning of the one field detectors fire on.
GOLDEN_MISSING_REMEDIATION = (
    "Tag the approved baseline in the archive (git -C <archive> tag -f golden HEAD), or "
    "correct the golden ref in the monitoring configuration")

# Reasons where the artefact is incomplete but the diff is still a fact worth reporting.
# Everything else suppresses drift, because a bad artefact replacing a good one produces a
# whole-config spurious "DRIFTED" — residual risk 3. Shrinkage is the exception BECAUSE it has
# no in-file evidence of corruption: "the file got smaller" is textually identical for a
# truncation and for an operator deleting 40 firewall rules, and a large deletion is exactly
# the event network.config exists to report. Measured 2026-08-02, suppressing it meant the
# device emitted NO drift record at all, on every poll, permanently — not one burnt alarm but
# a device that stops reporting, which is the failure mode this whole change exists to remove.
# Grading stays suppressed either way: if it IS a truncation, grading invents FAILs.
DRIFT_STILL_MEANINGFUL = {"shrank_vs_last_good"}


class ComplianceExtension(Extension):

    # Guards ONLY the lazy creation of the per-instance poll lock below. Class-level because
    # the tests build instances with object.__new__ and never run __init__ or initialize().
    _LOCK_GUARD = threading.Lock()

    def initialize(self):
        try:
            interval = _interval_seconds(self._cfg())
        except Exception:
            interval = 900
        # `self.poll`, NOT `self.query`, and the name is the whole point.
        #
        # Extension.run() schedules self.query UNCONDITIONALLY after calling initialize()
        # (sdk/extension.py:828-829, `if not self.is_helper:` — is_helper is a base property
        # that returns False for every datasource extension). So while the work lived in a
        # method called `query`, it was scheduled TWICE: once here at intervalSeconds and once
        # by the SDK at 60s. Verified against the real SDK 2026-08-02:
        #
        #     scheduled callbacks: 2
        #         query every 900.0 s
        #         query every 60.0 s
        #
        # _schedule_callback appends without dedup and each schedule gets its OWN
        # WrappedCallback carrying its own `.running` flag, so the SDK's overrun guard
        # (`if not callback.running`) protects a SCHEDULE, not a METHOD — the two callbacks
        # overlap freely in a 100-thread pool. Measured consequences, all three real:
        # the three _clone_fresh recovery paths race on the shared <mirror>.new staging
        # directory and emit a FALSE archive_unreachable ERROR blaming the customer's network
        # and PAT; every record is emitted twice; and the ActiveGate hits the customer's Git
        # host every 60s no matter what intervalSeconds says, which is a PAT rate-limit
        # exposure. _budgets' reasoning also assumed the cadence was intervalSeconds.
        #
        # Renaming the callback is the entire fix: the SDK then schedules the BASE
        # Extension.query, which is a documented no-op returning IgnoreStatus(). Overriding
        # is_helper to suppress the SDK's schedule was rejected — it is documented "Internal
        # property used by the EEC", and lying to the EEC about what kind of extension this is
        # would be exactly the kind of inference this deployment must not rest on.
        self.schedule(self.poll, timedelta(seconds=max(60, interval)))

    def _poll_slot(self):
        """The per-instance lock that stops two polls overlapping. Created on first use.

        Defence in depth behind the rename above, not a substitute for it: one monitoring
        configuration must never run two concurrent polls, because _clone_fresh stages every
        clone through a single shared <mirror>.new path. Per INSTANCE rather than per class
        because the EEC can run several monitoring configurations in one process, and a shared
        lock would let one configuration's 1200s clone budget starve another's poll.
        """
        lock = self.__dict__.get("_poll_lock")
        if lock is None:
            with ComplianceExtension._LOCK_GUARD:
                lock = self.__dict__.get("_poll_lock")
                if lock is None:
                    lock = self._poll_lock = threading.Lock()
        return lock

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
        if "configPath" not in raw:
            raw = next((v for v in raw.values() if isinstance(v, dict) and "configPath" in v), raw)
        return raw

    @staticmethod
    def _cfg_glob(c):
        """deviceGlob as a pattern, AUTO by default. Never raises.

        AUTO by default: an operator who has already persisted "*.cfg" keeps today's exact
        semantics, while a new deployment against Oxidized's git backend discovers
        extension-less node blobs, which is the only shape that backend produces.

        A named helper because THREE spellings have to collapse to the same thing and the
        collapse is what makes a schema change safe. deviceGlob was nullable:true AND
        default:"" at HEAD — a combination the tenant rejects at upload — so the default was
        removed, which means existing monitoring configurations still send "" while new ones
        send nothing at all. "", None and absent must all mean AUTO, and now that is one
        expression with a test on it rather than an inline idiom nobody would think to check.
        """
        return str(c.get("deviceGlob", AUTO_GLOB) or AUTO_GLOB).strip()

    def _archive_source(self, c):
        """Configuration -> (local path to read, freshness dict). Local mode is a passthrough.

        The ONE branch that selects a mode: a non-empty remoteUrl means remote, anything else
        means configPath exactly as before. configPath is not touched — same type, same
        nullable:false, same default, same semantics — so the co-located deployment stays the
        zero-added-complexity case it has always been.

        The freshness dict is the only thing that crosses back out, and it is what makes
        staleness impossible to serve silently. Its `state` is one of:

          fresh          the remote was contacted successfully this poll
          stale          it was not, but a mirror inside the staleness limit is being served
          stale_refused  it was not, and the mirror is older than the limit -> grading stops
          unavailable    no usable mirror at all, or the mirror answers a DIFFERENT remote

        Returning "" as the path is how the last two stop the poll: query() turns an empty
        path into exactly one archive-scoped ERROR record and emits nothing else, which is
        _empty_archive_record's precedent — coverage really is zero, and one present record
        explains the absence so it can be queried.

        Grading STALE-but-within-limit data is deliberate and is the entire value of holding a
        mirror. Refusing it would recreate the device-goes-silent failure this module fights.
        Refusing PAST the limit is equally deliberate: the module already argues at the
        capture_failed record that a stale dashboard number "is not merely incomplete, it is
        stale and wrong, and decays hourly".
        """
        raw = str(c.get("remoteUrl", "") or "").strip()
        if not raw:
            # age=0.0 EXPLICITLY, not by omission. _fresh_dims now omits age_seconds whenever
            # the age is None, because None has to mean "unknown" for archive_unreachable to
            # stop publishing a fabricated "0". Local mode reads the archive directly, so zero
            # is the true age of what it graded and it says so on purpose.
            return (str(c.get("configPath", "")).rstrip("/"),
                    {"source": "local", "state": "fresh", "age": 0.0})

        url, user, pasted = _sanitize_remote(raw)
        token = str(c.get("remoteToken", "") or "").strip()
        if pasted and not token:
            token = pasted
            self.logger.warning(
                "remoteUrl carries an embedded password; using it as the token for this poll, "
                "but it is stored as plain text in the monitoring configuration. Move it to "
                "the 'Remote Git token' secret field and remove it from the URL.")
        elif pasted:
            self.logger.warning(
                "remoteUrl carries an embedded password AND a token secret is set; the secret "
                "field wins. Remove the password from the URL.")
        elif user and not token:
            # BARE USERINFO WITH NO SECRET SET. This is the shape GitHub and Azure DevOps
            # document for a PAT — https://<PAT>@github.com/... — and it is the slot the
            # remoteUrl description itself points operators at, so it cannot be assumed to be
            # a harmless username. Measured 2026-08-02, treating it as one failed OPEN, which
            # is worse than the user:pw case that is handled above:
            #
            #   <mirror>/config   url = https://ghp_TOKENINUSERPOSITION1234@github.com/...
            #   every record      config.archive.url carrying the same
            #   and no warning of any kind
            #
            # config.archive.url is ingested as a log-record dimension, so it is permanent,
            # queryable and exportable; and per _mirror_root a deleted monitoring
            # configuration leaves the directory, so the tokenised <mirror>/config outlives
            # the configuration that created it.
            #
            # Nothing that works today breaks. A username with no password cannot authenticate
            # anyway — GIT_TERMINAL_PROMPT=0 blocks the password prompt — and _git_net rebuilds
            # the Basic username as "oauth2", which GitLab, GitHub and Bitbucket all accept
            # alongside a PAT. When the secret field IS set this branch does not fire and the
            # username is preserved exactly as documented.
            token = user
            url = urlunsplit(urlsplit(url)._replace(
                netloc=urlsplit(url).netloc.rpartition("@")[2]))
            self.logger.warning(
                "remoteUrl carries a bare userinfo value and no token secret is set; treating "
                "it as the token for this poll and stripping it from the URL. If it is a "
                "username, set the 'Remote Git token' secret field; if it is a PAT, move it "
                "there and remove it from the URL.")

        f = {"source": "remote", "url": url, "state": "unavailable",
             "reason": "archive_unreachable", "detail": "", "age": None, "mirror": "",
             "limit": 0}
        if token and urlsplit(url).scheme.lower() == "http":
            # Refused rather than silently downgraded. _git_net will not put a credential on a
            # cleartext connection (see its scheme gate), but dropping the header quietly would
            # present to the operator as an authentication failure against a reachable host,
            # which is the wrong diagnosis and sends them to rotate a working PAT. Both schema
            # descriptions promise HTTPS; this is where that promise is enforced.
            f["detail"] = ("the remote URL uses plain http:// and a token is configured. The "
                           "token was NOT sent, because HTTP would put it on the wire in "
                           "cleartext and git offers the credential preemptively, before any "
                           "challenge. Use an https:// URL for the remote archive")
            self.logger.error(
                "refusing to authenticate over plain http:// — change remoteUrl to https://")
            return "", f
        base = self._mirror_base()
        if not base:
            f["detail"] = ("no writable directory is available on this ActiveGate to hold the "
                           "mirror (tried the agent runtime extensions directory and the "
                           "system temporary directory)")
            return "", f
        f["mirror"] = _mirror_root(base, getattr(self, "monitoring_config_id", ""), url)

        interval = _interval_seconds(c)
        fetch_budget, clone_budget = _budgets(interval)
        state, detail = self._refresh_mirror(url, token, f["mirror"], fetch_budget, clone_budget)
        age = self._mirror_age(f["mirror"])
        # 2x so a SINGLE missed refresh never blanks the view at any cadence: 86400s at the
        # default 900s interval, 172800s at the 86400s maximum.
        f.update(detail=detail, age=age, limit=max(STALE_FLOOR_SECONDS, 2 * interval))

        if state == "fresh":
            f.update(state="fresh", reason="", age=0.0)
            return f["mirror"], f
        if state == "stale":
            # age is None for a mirror that has never been marked — an operator's hand-created
            # directory, or a marker someone deleted. Unprovable freshness is refused rather
            # than assumed; that is the safe direction and the only one consistent with
            # requirement 3.
            if age is not None and age <= f["limit"]:
                f.update(state="stale", reason="archive_stale")
                return f["mirror"], f
            f.update(state="stale_refused", reason="archive_stale_refused")
            return "", f
        # age is dropped for "unavailable" on purpose. config.archive.last_refresh has to mean
        # "when this mirror last reached THIS url", and the only unavailable case that HAS a
        # readable mirror is the URL-changed one — where the marker's timestamp belongs to the
        # PREVIOUS remote. Stamping it would attach a real timestamp to a repository we are
        # deliberately not serving. The record's own text carries the story instead.
        f.update(state="unavailable", reason="archive_unreachable", age=None)
        return "", f

    @staticmethod
    def _fresh_dims(fresh):
        """Freshness dimensions stamped on EVERY record this poll emits.

        A positive heartbeat riding on records that already exist, so freshness is never
        inferred from silence and no new stream is needed. `source` is deliberately NOT called
        `mode`: config.archive.mode already ships and means the READ mode (dir | git), which is
        an orthogonal axis — a remote mirror is always read in git mode, and a local path can
        be either.

        In local mode there is no remote and no refresh, so only the three fields that are
        meaningful in both modes are emitted. `refreshed` is the field consumers must branch
        on; the contract is that "no" means UNKNOWN, not healthy.

        age_seconds is OMITTED rather than defaulted whenever the age is genuinely unknown,
        which is the same rule last_refresh has always followed. It used to be
        str(int(fresh.get("age") or 0)), so the one state where the age is unknowable —
        archive_unreachable, where _archive_source sets age=None deliberately — published
        "0", i.e. "refreshed 0 seconds ago" stamped on the WORST state this module can
        report. A detector written as age_seconds > limit could never fire on it. Absent now
        means unknown in both fields, and the two states that legitimately have an age of
        zero (local mode, and a remote refreshed this poll) both set it EXPLICITLY.
        """
        d = {"config.archive.source": fresh.get("source", "local"),
             "config.archive.refreshed": "yes" if fresh.get("state") == "fresh" else "no"}
        age = fresh.get("age")
        if age is not None:
            d["config.archive.age_seconds"] = str(int(age))
        if fresh.get("source") != "remote":
            return d
        d["config.archive.url"] = fresh.get("url", "")
        if age is not None:
            d["config.archive.last_refresh"] = datetime.fromtimestamp(
                time.time() - age, timezone.utc).isoformat(timespec="seconds")
        return d

    def _mirror_base(self):
        """First writable base directory, in preference order; '' when none. Never raises.

        Measured on the lab ActiveGate 2026-08-02 as dtuserag, the user the datasource actually
        runs as, because every obvious answer turned out to be wrong there:

          getent passwd dtuserag        -> home is '/', shell /usr/sbin/nologin
          the datasource's own environ  -> NO HOME AT ALL (USER, LOGNAME, PWD=/, PATH, LANG,
                                           TMPDIR, INVOCATION_ID, JOURNAL_STREAM, SYSTEMD_EXEC_PID)
          git config --global, no HOME  -> fatal: $HOME not set
          write to /                    -> denied
          the datasource CWD            -> .../working_directories/<dsid><epoch_ms>, a name the
                                           extension cannot predict or rediscover after restart
          .../agent/runtime/extensions  -> writable, drwxr-xr-x dtuserag:dtuserag, 16G free

        The SDK offers no state directory (its only disk state is Path("snapshot.json") relative
        to CWD, extension.py:1262), so the framework's own convention is the working directory —
        which is the one place measured NOT to be addressable across restarts.

        Order, each entry with the failure it prevents:
          1. the EEC-derived runtime dir  — survives datasource restart, ActiveGate restart and
             reboot, and follows a non-default install root.
          2. the literal stock path       — for `dt-sdk run` and the simulator, where TMPDIR is
             not EEC-shaped.
          3. the system temp dir          — last resort, WARNed with its cost.

        Both ActiveGate candidates require their PARENT to already exist. Without that check a
        developer machine would have os.makedirs manufacture a plausible-looking
        /var/lib/dynatrace tree that no ActiveGate owns.

        Mode 0700, not 0755, and that is not caution for its own sake: the mirror holds device
        RUNNING-CONFIGS. The real capture this module was built against carries password
        hashes, and any archive holds SNMP communities. On candidate 3 the parent is 1777.

        Rejected, with the reason each was rejected:
          runtime/extensions/cache/<name>/<version>  version-scoped, so a version bump silently
                                                     orphans the mirror, and the EEC prunes it
          log/extensions                             collected into support archives
          agent/conf/userdata                        operator input, and under conf
          /tmp on a stock Ubuntu AG                  /usr/lib/tmpfiles.d/tmp.conf is
                                                     "D /tmp 1777 root root -" -> emptied at boot
          /var/tmp                                   1777, and age-based tmpfiles reaping can
                                                     delete individual git objects out from
                                                     under a live repository
        """
        cands = []
        rt = _ag_runtime_dir()
        if rt:
            cands.append((os.path.join(rt, "extensions", MIRROR_DIRNAME), True))
        cands.append((os.path.join(_AG_DEFAULT_RUNTIME, "extensions", MIRROR_DIRNAME), True))
        cands.append((os.path.join(tempfile.gettempdir(), MIRROR_DIRNAME), False))
        for d, needs_parent in cands:
            try:
                if needs_parent and not os.path.isdir(os.path.dirname(d)):
                    continue
                os.makedirs(d, mode=0o700, exist_ok=True)
                os.chmod(d, 0o700)
                if not os.access(d, os.W_OK | os.X_OK):
                    continue
            except OSError:
                continue
            if not needs_parent:
                self.logger.warning(
                    f"holding the Oxidized mirror in {d}: no ActiveGate runtime directory was "
                    f"writable. On a stock ActiveGate /tmp is emptied at every boot, so the "
                    f"whole archive will be re-cloned after a reboot, and the parent directory "
                    f"is world-traversable while the mirror holds device running-configs.")
            return d
        return ""

    def _mirror_usable(self, mirror):
        """Can this mirror be READ? One plumbing call, and it is the only probe needed.

        Measured 2026-08-02 against a mirror with 21 bytes of garbage written into its packfile,
        which is the corruption mode a killed clone or a full disk actually produces:

          rev-parse --is-bare-repository     rc 0, prints "true"  <- DOES NOT DETECT IT
          rev-parse -q --verify HEAD^{commit} rc 1                 <- detects it
          ls-tree -r HEAD                    rc 128 "not a tree object"
          show HEAD:outpost                  rc 128 "packed object ... is corrupt"
          fetch                              rc 1   "did not send all necessary objects"

        The same probe returns non-zero for every other unreadable state: missing directory,
        empty directory, objects/ removed, dangling HEAD, and unborn HEAD.
        """
        return bool(os.path.isdir(mirror)) and self._git(
            mirror, "rev-parse", "-q", "--verify", "HEAD^{commit}", quiet=True)[1]

    def _mark_refreshed(self, mirror):
        """Record a VERIFIED successful contact with the remote. Never raises.

        This small piece of owned state exists because every git-native signal was measured to
        lie. FETCH_HEAD's mtime was the intended reuse; on the ActiveGate's git 2.34.1:

          no-op fetch, remote unchanged, rc 0   before=1785683283 after=1785683284  ADVANCED
          FAILED fetch,                  rc 128 before=1785683284 after=1785683286  ADVANCED

        A FAILED fetch advances it, so using it would report a dead archive as freshly
        refreshed — precisely the false-all-clear class this module exists to remove. Reflogs
        are no help either: bare repositories default core.logAllRefUpdates=false, and a reflog
        records ref CHANGES rather than successful contacts.

        The commit date is not the signal either, and this is the more tempting mistake:
        Oxidized commits only on CHANGE, so a healthy, stable fleet's HEAD can legitimately be
        weeks old. `git log -1 --format=%cI HEAD` would alarm on a network that is working
        perfectly.

        mtime is what is read back (it cannot be malformed); the ISO timestamp inside is for an
        operator who SSHs into the ActiveGate to look.
        """
        try:
            with open(os.path.join(mirror, _REFRESH_MARKER), "w") as fh:
                fh.write(datetime.now(timezone.utc).isoformat(timespec="seconds") + "\n")
        except OSError as e:
            self.logger.warning(f"could not write the refresh marker in {mirror}: {e}")

    def _mirror_age(self, mirror):
        """Seconds since the last VERIFIED refresh; None if it has never been refreshed."""
        try:
            return max(0.0, time.time() - os.path.getmtime(
                os.path.join(mirror, _REFRESH_MARKER)))
        except OSError:
            return None

    def _refresh_mirror(self, url, token, mirror, fetch_budget, clone_budget):
        """Bring the mirror up to date -> (state, detail). Never raises.

        state is "fresh", "stale" (fetch failed, last-good data is intact and servable) or
        "unavailable" (nothing safe to serve).

        Deliberately absent: --force. The mirror refspec is +refs/*:refs/* (verified in the
        cloned config), so a rewound or force-pushed remote is ALREADY handled —
        "+ 93fcded...42d30e0 master -> master (forced update)", rc 0.

        --prune --prune-tags is load-bearing rather than tidiness. Measured, it is what deletes
        branches and tags the remote deleted. Without it a `golden` tag deleted upstream keeps
        resolving in the mirror forever, and drift keeps reporting "matches golden" against a
        baseline that no longer exists — a fifth route into this codebase's recurring
        false-all-clear.

        A CHANGED URL re-clones rather than `git remote set-url`, for two measured reasons.
        Repointing a mirror whose HEAD is refs/heads/master at a remote whose default branch is
        `main` and fetching gives rc 0 and leaves HEAD on the now-deleted master ->
        "fatal: Not a valid object name HEAD" (git 2.34.1, the ActiveGate's version; git 2.50.1
        self-heals via followRemoteHEAD, added in 2.48 — do NOT depend on it). And set-url
        would keep the previous remote's objects, serving them by SHA.

        When that re-clone FAILS the state is "unavailable", never "stale": the mirror on disk
        answers a DIFFERENT remote, and serving it under the new URL — which is the URL stamped
        on every record — would be an affirmative lie rather than merely old data. It is left
        on disk untouched so the next poll can retry without re-downloading anything.
        """
        if not self._mirror_usable(mirror):
            return self._clone_fresh(url, token, mirror, clone_budget)
        stored = self._git(mirror, "config", "--get-all", "remote.origin.url", quiet=True)[0]
        if (stored.splitlines() or [""])[0].strip() != url:
            state, detail = self._clone_fresh(url, token, mirror, clone_budget)
            if state == "fresh":
                return state, detail
            return "unavailable", (f"the remote URL changed and the new remote could not be "
                                   f"cloned; the mirror on disk holds a DIFFERENT repository "
                                   f"and was not served. {detail}")
        ok, err = self._git_net(["-C", mirror, "fetch", "--quiet", "--prune", "--prune-tags",
                                 "--", "origin"], token=token, url=url, timeout=fetch_budget)
        if not ok:
            return "stale", err
        if not self._mirror_usable(mirror):
            return self._clone_fresh(url, token, mirror, clone_budget)
        self._mark_refreshed(mirror)
        return "fresh", ""

    def _clone_fresh(self, url, token, mirror, budget):
        """Clone to <mirror>.new, verify it, then swap. Never destroys a good mirror first.

        `clone --mirror`, never `init --bare` + `remote add` + `fetch`. Measured on the
        ActiveGate's git 2.34.1, against a remote whose default branch is `master`:

          init --bare -b main; remote add --mirror=fetch; fetch
            HEAD symref  -> refs/heads/main
            ls-tree HEAD -> fatal: Not a valid object name HEAD

        init+fetch manufactures a dangling HEAD whenever the ActiveGate's init.defaultBranch
        differs from the remote's — i.e. on every stock Ubuntu ActiveGate against an Oxidized
        repository on `master`. That is the exact failure _empty_archive_record already
        special-cases ("Confirm HEAD points at a branch that exists (Oxidized's default is
        'master')"). clone --mirror takes HEAD from the remote and ls-tree works first time,
        and it brings refs/tags across so goldenRef needs no extra refspec.

        The staging directory is what makes the staleness contract real rather than nominal: a
        re-clone that fails because the network is down must not destroy the last-good data.
        <mirror>.new is removed before AND after every attempt, because of an asymmetry
        measured 2026-08-02 — a FAILED clone removes its own destination (rc 128, directory
        absent), but a KILLED clone, which is exactly what a timeout produces, leaves a partial
        directory that clone can then never reuse: "fatal: destination path '...' already
        exists and is not an empty directory".

        A crash between the rmtree and the rename self-heals on the next poll, because
        _refresh_mirror step 1 finds no usable mirror and clones again.
        """
        new = mirror + ".new"
        _rmtree(new)
        ok, err = self._git_net(["clone", "--mirror", "--quiet", "--", url, new],
                                token=token, url=url, timeout=budget)
        if not ok:
            _rmtree(new)
            return "unavailable", err

        # rc 0 is not sufficient. See _mirror_usable: a corrupt object store still answers
        # --is-bare-repository with "true". But "rc 0 and HEAD does not resolve" is NOT one
        # state, it is two, and collapsing them into archive_unreachable was a misdiagnosis
        # that sent every first-day deployment to the wrong place. Measured 2026-08-02, both
        # of these produced "UNREACHABLE ... check that the token is valid":
        #
        #   (a) the remote is reachable and EMPTY  — the state before Oxidized's first push
        #   (b) the remote is reachable and holds real configs on refs/heads/master while
        #       HEAD points at refs/heads/main — the Oxidized default-branch mismatch
        #
        # while the SAME repositories read through local configPath produced the correct
        # story: "nothing committed at this path yet ... Confirm Oxidized has completed a
        # first successful backup", and "it does have branches, so this is not an empty
        # archive ... Confirm HEAD points at a branch that exists (Oxidized's default is
        # 'master')". _empty_archive_record already tells those two apart with for-each-ref.
        #
        # So the clone is INSTALLED and the diagnosis is delegated to the code that can
        # actually make it — but only when there is no readable mirror to lose. With one
        # present (the URL-change path) the conservative refusal stands, because an
        # unreadable replacement must never displace readable data.
        if not self._mirror_usable(new) and self._mirror_usable(mirror):
            _rmtree(new)
            return "unavailable", (err or "the clone completed but its HEAD commit could not "
                                          "be read back, and the existing mirror was kept")

        # Swap. The old mirror is moved ASIDE rather than deleted, because _rmtree is
        # shutil.rmtree(ignore_errors=True) and can PARTIALLY succeed — one undeletable
        # subdirectory (a root-owned file dropped in by an operator or a support script; the
        # mirror path is printed on every archive record, which invites them in) left the
        # directory non-empty, made os.rename fail, and the handler then deleted the freshly
        # downloaded clone that had already been verified. Both copies gone. Measured
        # 2026-08-02, that converted a recoverable state into a PERMANENT one:
        #
        #   poll2 re-clone: unavailable | could not install the new mirror at <mirror>
        #      mirror usable now: False   top-level left: ['objects']   .new kept: False
        #   poll3 ... identical, and every poll after it
        #
        # i.e. archive_unreachable forever plus an unbounded full re-download every interval —
        # strictly worse than the stale-but-servable contract this mode exists to provide.
        # Moving aside is only worth doing for a mirror that is READABLE; an unusable one has
        # nothing to lose, so it is removed as before.
        keep = self._mirror_usable(mirror)
        old = mirror + ".old"
        _rmtree(old)
        stashed = False
        if keep:
            try:
                os.rename(mirror, old)
                stashed = True
            except OSError as e:
                # Refuse rather than fall back to deleting it: a readable mirror that cannot
                # be moved aside is still a readable mirror, and serving it stale beats
                # destroying it. <mirror>.new is left for the next poll's entry _rmtree.
                return "unavailable", (f"the existing mirror could not be moved aside ({e}), "
                                       f"so it was left in place rather than destroyed")
        else:
            _rmtree(mirror)
        try:
            os.rename(new, mirror)
        except OSError as e:
            if stashed:
                try:
                    os.rename(old, mirror)      # put the last-good one back
                except OSError:
                    pass
            return "unavailable", f"could not install the new mirror at {mirror}: {e}"
        _rmtree(old)
        self._mark_refreshed(mirror)
        return "fresh", ""

    def _git_net(self, args, *, token, url, timeout):
        """Network git in its OWN PROCESS GROUP -> (ok, REDACTED stderr). Never raises.

        Separate from _git rather than a flag on it, because _git bakes in four things that are
        each wrong for a call carrying a credential: `-C path` as the first argument, a fixed
        20s budget, an INHERITED environment, and raw-stderr logging. Keeping them apart also
        means the 273 tests covering _git keep covering exactly what they covered.

        THE TOKEN NEVER TOUCHES argv. Measured 2026-08-02, `-c` values are visible to any local
        user: `ps -eo args` showed the secret. It travels in the environment instead, and that
        channel was verified to reach `clone` and not merely `fetch`, using an observable side
        effect: GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=protocol.file.allow VALUE_0=never turned a
        file:// clone into "fatal: transport 'file' not allowed". Verified on git 2.34.1 that
        the header arrives (it appears in the parsed command line) and that the count of the
        secret persisted into <mirror>/config is ZERO.

        Do NOT try to override the URL per-invocation instead. Measured, and it fails SILENTLY:
        remote.<name>.url is multi-valued, so -c and GIT_CONFIG_* APPEND. `config --get` returns
        the override, `--get-all` shows both, and fetch uses the FIRST — the repository's own
        value. GIT_TRACE confirmed it connected to the original URL, rc 0, no output. Only
        `git remote set-url` (persisted) or a positional URL (argv, world-readable) actually
        change it, which closes the door on every "just put the token in the URL for one call"
        variant.

        http.followRedirects=false, and the cost is stated and accepted. With git's default
        (`initial`) the extraHeader configured for the original URL travels to the redirect
        TARGET. A customer whose remote redirects gets a loud, honest fetch failure naming the
        redirect rather than a silent credential disclosure to a host they did not configure.

        credential.helper="" resets the helper list, so a system-wide `store` helper in
        /etc/gitconfig can never write the credential to disk. Nothing is handed to a helper
        anyway — http.extraHeader carries the Authorization header directly. (HOME is unset on
        the ActiveGate, so --global writes would fail regardless, but that is a coincidence of
        that host's configuration and is not relied on.)

        System config is deliberately NOT disabled: the ActiveGate's CA trust store is
        configured there (docs/ENTERPRISE-READINESS.md, docs/CUSTOMER-HANDOFF.md), and reusing
        it is why there is no caCertPath property and no insecure-TLS toggle.

        subprocess.run(timeout=) kills ONLY THE DIRECT CHILD, and `git fetch` over https spawns
        git-remote-https. Measured 2026-08-02:

          sh -c 'sleep 30 & wait', timeout=2                     -> TimeoutExpired, and
                                                                    "99593 1 sleep 30" SURVIVES
          same with start_new_session=True + os.killpg(SIGKILL)  -> 0 survivors

        So the _git pattern would leak an orphaned transport helper holding a socket on EVERY
        POLL. http.lowSpeedLimit/lowSpeedTime make git abort a stalled transfer by itself; the
        process-group kill is the backstop for a hung TCP connect, which git exposes no config
        for.
        """
        header = ""
        # HTTPS ONLY, and http:// is excluded deliberately rather than by omission. An
        # Authorization header is meaningless for file://, and over plain http it is a
        # cleartext credential disclosure: measured 2026-08-02 against a listening socket that
        # captured the raw bytes, `http://` produced
        #
        #   GET /net/oxidized.git/info/refs?service=git-upload-pack HTTP/1.1
        #   Authorization: Basic b2F1dGgyOmdscGF0LVNVUEVSU0VDUkVUMTIz
        #     -> oauth2:glpat-SUPERSECRET123
        #
        # on the FIRST request, to a server that never issued a 401 — git's extraHeader is
        # preemptive, so a typo'd or hijacked hostname harvests the PAT without asking. Both
        # schema descriptions already promise HTTPS ("Sent as an HTTPS Authorization header",
        # "HTTPS only"); this is the code finally matching them. _archive_source refuses the
        # combination outright so it cannot present as a silent auth failure.
        if token and urlsplit(url).scheme.lower() == "https":
            user = _sanitize_remote(url)[1] or "oauth2"
            header = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("ascii")

        env = {k: v for k, v in os.environ.items() if not _ENV_DROP.match(k)}
        env["GIT_TERMINAL_PROMPT"] = "0"      # a credential prompt is an infinite hang
        env["GCM_INTERACTIVE"] = "never"
        pairs = [("credential.helper", ""),
                 ("http.followRedirects", "false"),
                 ("http.lowSpeedLimit", "1000"),
                 ("http.lowSpeedTime", str(max(5, timeout // 3)))]
        if header:
            pairs.insert(0, (f"http.{url}.extraHeader", f"Authorization: Basic {header}"))
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for i, (k, v) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v

        proc = None
        try:
            proc = subprocess.Popen(
                ["git", "-c", "core.fsmonitor=false", *args],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                env=env, start_new_session=True)
            try:
                _, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.communicate()
                op = next((a for a in args if a in ("clone", "fetch")), "git")
                return False, f"{op} timed out after {timeout}s"
            return proc.returncode == 0, _redact(err.strip(), token, header)
        except Exception as e:
            if proc is not None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    pass
            # Redacted like every other path: an OSError from Popen can carry the argv, and a
            # future edit that puts a secret there must not be able to leak it through here.
            return False, _redact(str(e), token, header)

    def _git(self, path, *args, quiet=False):
        """Run git -> (stdout, ok, stderr). The ok flag is not optional; see below.

        stderr is returned rather than discarded because the quiet=True probes are exactly the
        ones whose failure gets DIAGNOSED downstream, and throwing git's own sentence away
        meant the diagnosis was guessed. Measured 2026-08-02: a bare archive with one commit
        on refs/heads/main but HEAD pointing at a missing refs/heads/production made ls-tree
        exit 128 "fatal: Not a valid object name HEAD", and the operator was told "the archive
        is a git repository with nothing committed at this path yet (unborn HEAD, or an empty
        tree). Confirm Oxidized has completed a first successful backup" — for an archive that
        had completed one. Wrong cause, and no evidence to notice it was wrong.

        quiet=True suppresses the warning for probes whose FAILURE is an ordinary, expected
        answer (does this path exist in that ref?). Those run once per device per poll, and a
        fleet-sized poll logging a warning for every device every interval is how a log stops
        being read — the same reasoning that hoisted the repo/ref preconditions out of the loop.

        This returned .stdout alone and never looked at returncode. Measured 2026-08-02: with
        no 'golden' ref in the archive — the normal state of a first deployment, and of the
        lab — `git diff golden HEAD` exits 128 with "fatal: bad revision 'golden'" and an
        EMPTY stdout, which the drift caller read as "no diff" and reported as
        "matches golden (0 lines)" at INFO. Identical result when configPath is not a git
        repo at all. That is not a missing signal, it is an affirmative FALSE ALL-CLEAR: the
        extension asserts a device is on its intended config when it has never compared it to
        anything. Callers must branch on ok rather than on the emptiness of stdout.

        That guard is also what makes the dubious-ownership condition safe. On an ActiveGate
        the extension runs as a DIFFERENT user from the one that owns the Oxidized archive
        (the lab's is uid 30000), which is the expected production state, not an edge case.
        Measured 2026-08-02: every command here then exits 128 ("detected dubious ownership"),
        `diff` exits 129 — so all of them are caught and the caller reports drift "unknown".
        _resolve_archive grants a NARROW, per-invocation trust when it sees this; see there.

        Two hardening flags, both because trust may be granted to a FOREIGN-OWNED repository:

          core.fsmonitor=false, unconditionally. A repo-supplied fsmonitor hook is a command
          the repo's owner chose and we would run.

          errors="replace" on the decode. text=True raises UnicodeDecodeError on a binary blob
          (measured on a packed git object), and the bare `except` below would turn that into
          a silent skip — i.e. a device that vanishes. Replacement characters instead let the
          content gate reach an honest verdict on the artefact.

        The drift call adds --no-ext-diff --no-textconv for the same reason; it is on the
        caller because ls-tree/show/log/cat-file are pure plumbing and were measured never to
        invoke either mechanism, while `git diff` in a repo with diff.external and a
        .gitattributes textconv EXECUTED the repo's own script as us (measured, rc 0).
        """
        try:
            pre = list(getattr(self, "_trust", ()))
            r = subprocess.run(["git", "-C", path, *pre, "-c", "core.fsmonitor=false", *args],
                               capture_output=True, text=True, errors="replace", timeout=20)
            if r.returncode != 0:
                err = r.stderr.strip()
                if not quiet:
                    self.logger.warning(f"git {' '.join(args)} rc={r.returncode}: {err[:200]}")
                return "", False, err
            return r.stdout, True, ""
        except Exception as e:
            self.logger.warning(f"git {' '.join(args)} failed: {e}")
            return "", False, str(e)

    def _prev_good_bytes(self, path, rel, current):
        """Byte size of this device's most recent revision that is itself a healthy capture.

        This is the only signal that catches a CLEAN truncation — one that still fingerprints,
        carries no CLI error text and shows no pager residue. A truncated Cisco config is
        textually indistinguishable from a smaller valid Cisco config, so the only sound
        reference is this device's own history. That also makes it self-calibrating and
        therefore free of the cross-vendor threshold problem that sinks every absolute size
        rule (see assess_capture).

        Bounded on purpose: one `git log` plus at most SHRINK_LOOKBACK+1 `git show` calls per
        device per poll. Revisions whose blob equals the current text are skipped — Oxidized
        commits each capture, so HEAD is usually the file we are already holding.

        Returns None whenever git cannot answer. configPath without a git repo is a supported
        deployment mode per the README, so this arm must degrade to "not checked" and never
        to a finding.

        `rel` is REPOSITORY-ROOT-relative (arch["prefix"] + the device's path), and both calls
        below now spell it the one uniform way, because the previous spelling was broken
        outright on the deployment we document. "<rev>:./<path>" is -C-relative and needs a
        working tree; a bare repository has none, so measured 2026-08-02 on the lab archive it
        returns rc 128 "relative path syntax can't be used outside working tree" — for every
        device, every poll, killing the clean-truncation guard fleet-wide and (via the same
        spelling in the `tracked` probe) drift with it. ":(top)<path>" is the pathspec form
        that is root-relative regardless of -C: a plain "configs/sw1.cfg" issued from a
        subdirectory matches 0 revisions, which is silent, not an error.
        """
        out, ok, _ = self._git(path, "log", "-n", str(SHRINK_LOOKBACK + 1), "--format=%H",
                               "--", f":(top){rel}")
        if not ok:
            return None
        for sha in out.split():
            blob, ok, _ = self._git(path, "show", f"{sha}:{rel}")
            if not ok or not blob or blob == current:
                continue
            verdict, _, ev = assess_capture(blob, detect_platform(blob))
            if verdict == "ok":
                return ev["bytes"]
        return None

    @staticmethod
    def _only_diff(text):
        return [ln for ln in text.splitlines()
                if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]

    @staticmethod
    def _meta(text, fallback, plat_id=None):
        """-> (host, ip, name_source, addr_source). `fallback` is the Oxidized node/file stem.

        FALLBACK ORDER
          name:  platform rule -> generic rule -> filename stem      (never empty)
          addr:  platform rule -> filename stem IF it is IPv4 -> ''  (never a guess)

        The stem is an acceptable NAME fallback because a record nobody can find is worse than
        a record with an imperfect label — and the capture-failure record exists to be found.
        It is NOT acceptable as a SILENT one, which is why *_source is emitted alongside: a
        fleet reporting name_source=filename is a countable coverage gap in Grail rather than
        an invisible one, and "parsed from the device" stays distinguishable from "guessed".

        The stem IS a sound ADDRESS when it parses as IPv4, and this is not a guess: Oxidized's
        router.db is very commonly keyed by management address ("10.0.10.3:netgear:user:pass"),
        so in that convention the stem is the address Oxidized actually DIALLED — the strongest
        identity evidence available, stronger than anything in the file.

        Quote stripping happens in _clean_name, and the incomplete version of it is what this
        replaces: the old rule stripped quotes but captured with \\S+ first, so it truncated
        `hostname "Data Center 1"` to 'Data' before the stripping ever ran.
        """
        lines = text.splitlines()
        ident = IDENTITY.get(plat_id or "")
        name = src_n = ip = src_a = ""
        if ident:
            name, src_n = _scan_name(lines, ident["name"])
            ip, src_a = ident["addr"](text, lines)
        if not name:
            name, src_n = _scan_name(lines, GENERIC_NAME)
        if not name and plat_id == "paloalto-panos":
            # Scoped to <system> exactly as the ADDRESS rule is. They used to disagree — the
            # address was scoped and the name was an unscoped document-wide search — so on a
            # config carrying a nested <template> the two could describe different devices.
            # Falls back to the whole document when there is no <system> element, which costs
            # nothing: without one there is no scope to respect.
            m = NAME_PAN_XML.search(_panos_system_block(text) or text)
            if m:
                name, src_n = m.group(1).strip(), "xml_hostname"
        if not _usable_ip(ip):
            # "n/a" survives — FRR has no management address BY DESIGN, and reporting that as a
            # missing value would make a correct config look like an extraction failure.
            ip, src_a = "", ("n/a" if src_a == "n/a" else "")
        if not ip and re.fullmatch(_IPV4, fallback or "") and _usable_ip(fallback):
            ip, src_a = fallback, "filename"
        if not name:
            name, src_n = fallback, "filename"
        return name, ip, (src_n or "none"), (src_a or "none")

    def _resolve_archive(self, path):
        """Classify configPath and establish the MINIMUM git trust needed. Never raises.

        -> {kind: "dir"|"git", bare: bool, root: str, prefix: str, ownership: str}
        `prefix` is configPath's own path inside the repository, "" at the root.

        One introspection call classifies every case. Two details are not cosmetic:

          splitlines(), not split(). A bare repository emits an EMPTY third line for
          --show-prefix, and split() silently drops it, shifting every subsequent field.

          --show-toplevel is unusable here: it exits 128 on a bare repository. The root is the
          gitdir itself when bare, and its parent otherwise, which is also exactly the value
          safe.directory has to name (measured: safe.directory=<a subdirectory> still fails,
          and for a non-bare repo safe.directory=<gitdir> fails — only the worktree root works).

        OWNERSHIP. The archive is owned by the Oxidized user (uid 30000 in the lab) and the
        ActiveGate runs as someone else, so "dubious ownership" is the NORMAL production state.
        Handling is deliberately in three parts:
          1. Try with NO trust at all first, so the majority of deployments grant nothing.
          2. On failure grant narrowly and per-invocation: safe.directory=<root> only, via -c.
             Measured, that is exactly as capable as safe.directory=* across ls-tree, show,
             log, diff and cat-file (all rc 0), so the wildcard buys zero capability and only
             widens trust. It is used for the single discovery rev-parse above and nowhere
             else. Never write the user's --global config; that is their machine, not ours.
          3. Say so out loud — a warning naming the granted path, plus
             config.archive.ownership on the archive record — because silently trusting
             another user's repository is not a thing to do quietly.
        """
        a = {"kind": "dir", "bare": False, "root": path, "prefix": "", "ownership": "n/a"}
        self._trust = []
        out, ok, _ = self._git(path, "-c", "safe.directory=*", "rev-parse",
                               "--is-bare-repository", "--absolute-git-dir", "--show-prefix",
                               quiet=True)
        if not ok:
            return a
        ln = out.splitlines()
        if len(ln) < 2:
            return a
        a["kind"] = "git"
        a["bare"] = ln[0].strip() == "true"
        gitdir = ln[1].strip()
        a["prefix"] = ln[2].strip() if len(ln) > 2 else ""
        # --show-toplevel for the non-bare case, NOT dirname(gitdir). They agree for an
        # ordinary checkout and disagree for a LINKED WORKTREE, where --absolute-git-dir is
        # <main>/.git/worktrees/<name> and the parent is therefore <main>/.git/worktrees — a
        # path git will never accept as safe.directory for this repository. Measured
        # 2026-08-02 under foreign ownership: safe.directory=<...>/worktrees rc 128 "detected
        # dubious ownership", safe.directory=<--show-toplevel> rc 0. The old value degraded
        # SAFELY (every git call failed, drift went to "unknown", no false all-clear) but the
        # warning named a path the operator could do nothing with. --show-toplevel is only
        # asked for when NOT bare, because it exits 128 on a bare repository.
        if a["bare"]:
            a["root"] = gitdir
        else:
            top, top_ok, _ = self._git(path, "-c", "safe.directory=*", "rev-parse",
                                       "--show-toplevel", quiet=True)
            a["root"] = (top.strip() if top_ok and top.strip()
                         else (os.path.dirname(gitdir.rstrip("/")) or "/"))
        if self._git(path, "rev-parse", "--git-dir", quiet=True)[1]:
            a["ownership"] = "same-user"
        else:
            a["ownership"] = "foreign-owner"
            self._trust = ["-c", "safe.directory=" + a["root"]]
            self.logger.warning(
                f"{path} is a git archive owned by another user; granting "
                f"safe.directory={a['root']} for this poll only (read-only plumbing, with "
                f"core.fsmonitor=false and --no-ext-diff/--no-textconv on diff). Prefer giving "
                f"the ActiveGate user read access to the Oxidized archive.")
        return a

    def _list_disk(self, path, pattern):
        """Device paths on disk, configPath-relative, POSIX-separated."""
        hits = []
        for dirpath, dirnames, filenames in os.walk(path):
            # Never walk git's own storage, detected by SHAPE (HEAD + objects/ + refs/) rather
            # than by directory NAME. This replaces the _SKIP_DIRS name list, which deleted
            # whole Oxidized groups called `logs`/`info`/`modules` — see the note where that
            # list used to live. Shape-based pruning also covers the case the name list was
            # really written for and the dot-prune misses: configPath pointing AT a gitdir,
            # whose hooks/objects/refs/info/logs children are not dot-directories. Measured:
            # `git rev-parse --is-bare-repository` inside a non-bare repo's .git returns
            # FALSE, so that deployment does reach this walk.
            if _is_gitdir(dirpath):
                dirnames[:] = []
                continue
            # Dot-directories stay pruned, matching the old `".git" not in f` filter.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fn in filenames:
                rel = os.path.relpath(os.path.join(dirpath, fn), path).replace(os.sep, "/")
                if admits(rel, pattern):
                    hits.append(rel)
        return sorted(hits)

    def _list_git(self, path, pattern, prefix):
        """-> (paths relative to configPath, blobs seen under prefix, git error).

        paths is None when ls-tree itself failed; the error string says why.

        --full-name is mandatory: from a subdirectory, ls-tree otherwise reports
        prefix-relative paths, which would then be prefixed a second time by the caller.
        The blobs-seen count is what lets the empty-archive record say "the repository holds N
        tracked files and your pattern matched none of them" instead of just "nothing found".

        -z is mandatory for CORRECTNESS, not for tidiness. ls-tree is porcelain-quoting by
        default (core.quotePath), so any path containing a non-ASCII byte, a double quote, a
        backslash or a control character comes back C-QUOTED — `"m\\303\\274nchen-sw"`, quotes
        and octal escapes included. The literal was then admitted, `git show HEAD:"m\\303..."`
        exited 128 under quiet=True, and _load_configs dropped the device with no log line, no
        record and no archive_empty (that only fires when the list is ENTIRELY empty).
        Measured 2026-08-02 on a 6-node bare archive: 6 tracked, 6 admitted, 3 loaded, and
        `sw-münchen`, `café-rtr` and the whole `édge/` group silently gone — the exact
        total-silence class this module exists to remove, reachable only on the git read path
        that the documented deployment uses. -c core.quotePath=false is NOT sufficient: it
        still quotes `"`, `\\` and control characters. -z disables quoting outright and keeps
        the TAB before the path, so only the record separator changes.
        """
        out, ok, err = self._git(path, "ls-tree", "-r", "-z", "--full-name", "--long", "HEAD",
                                 quiet=True)
        if not ok:
            return None, 0, err
        seen, hits = 0, []
        for line in out.split("\0"):
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            root_rel = parts[1]
            if prefix and not root_rel.startswith(prefix):
                continue
            seen += 1
            rel = root_rel[len(prefix):] if prefix else root_rel
            if admits(rel, pattern):
                hits.append(rel)
        return sorted(hits), seen, ""

    def _load_configs(self, path, pattern, arch):
        """-> (mode, [(rel, text)], blobs_seen, [unread rel], git_error). Disk first, git second.

        The fourth element is the LIST of files that matched but could not be read, not a
        count. It used to be a count, and the count was only ever consulted by
        _empty_archive_record — which runs only when NOTHING loaded. So a partial failure was
        totally silent: measured 2026-08-02 on a 3-device mirror with one blob missing from
        the object store, poll 3 emitted 16 records covering sw1 and sw3, ZERO records of any
        kind naming sw2, no archive record, and config.archive.refreshed="yes" on all of them.
        The fleet went from 3 devices to 2 while the poll reported itself fresh — the exact
        total-silence class this module exists to remove. The identities are carried out so
        _poll can emit one capture_failed per unread file.

        Disk wins for two reasons, and neither is inertia. It preserves today's behaviour
        exactly for every file-backend deployment. And in a NON-bare repository the working
        tree holds the CURRENT capture while HEAD holds the last COMMITTED one — reading HEAD
        there would quietly report yesterday's config as today's.

        Disk-first also fixes a live misdetection: a plain directory that happens to sit inside
        an unrelated git checkout classifies as kind="git", but ls-tree at that prefix returns
        0 blobs. Globbing disk first is what keeps that deployment working.

        The bare case skips the disk walk ENTIRELY rather than relying on it finding nothing —
        a bare repo's own gitdir is full of files (HEAD, config, packed-refs, hooks/*.sample,
        objects/**) and one binary object was measured raising UnicodeDecodeError.
        """
        disk = [] if arch["bare"] else self._list_disk(path, pattern)
        if disk:
            out, unread = [], []
            for rel in disk:
                try:
                    with open(os.path.join(path, rel), errors="replace") as fh:
                        out.append((rel, fh.read()))
                except Exception as e:
                    unread.append(rel)
                    self.logger.warning(f"read {rel} failed: {e}")
            return "dir", out, len(disk), unread, ""
        if arch["kind"] != "git":
            return "dir", [], 0, [], ""
        rels, seen, err = self._list_git(path, pattern, arch["prefix"])
        if rels is None:
            return "git", [], 0, [], err
        # A blob that matched the pattern but could not be READ is a different failure from a
        # pattern that matched nothing, and conflating them produced advice the operator had
        # already taken ("clear the device pattern to auto-discover" — it was already auto).
        # The identities are carried out so _empty_archive_record can say which happened AND
        # so _poll can name each unread device individually.
        out, unread, read_err = [], [], ""
        for rel in rels:
            txt, ok, e = self._git(path, "show", f"HEAD:{arch['prefix']}{rel}", quiet=True)
            if ok:
                out.append((rel, txt))
            else:
                unread.append(rel)
                read_err = read_err or e
                self.logger.warning(f"git show HEAD:{arch['prefix']}{rel} failed: {e[:160]}")
        return "git", out, seen, unread, read_err

    def _empty_archive_record(self, path, pattern, mode, arch, seen, unread=0, err=""):
        """Reading ZERO devices must never be silent. Non-negotiable.

        This is the highest-impact failure in the module and its 2026-08-02 lab presentation
        was TOTAL SILENCE: a correctly-configured bare Oxidized archive, the default deviceGlob
        of "*.cfg", nothing on disk to glob, and not one log record of any kind. An absence
        cannot be queried, so no detector and no dashboard downstream could ever have found it
        — the same failure class as the 29-hour capture outage this module was hardened for.
        ERROR, with the diagnosis naming the actual cause and the actual fix.
        """
        shown = "auto" if pattern == AUTO_GLOB else repr(pattern)
        tail = f" git said: {err[:200]}" if err else ""
        if unread:
            # The pattern DID match; the reads failed. Saying "matched none of them" here sent
            # operators to change a setting that was already correct.
            why = (f"the archive is a {'bare ' if arch['bare'] else ''}git repository holding "
                   f"{seen} tracked file(s); device pattern {shown} matched {unread} of them "
                   f"but NONE could be read out of the object store.{tail}")
        elif arch["kind"] == "git" and seen and pattern == AUTO_GLOB:
            # AUTO already IS the fix the explicit-pattern branch recommends, so recommending
            # it again was a no-op. What is left is a real archive whose every tracked file
            # looked like housekeeping to auto-discovery.
            why = (f"the archive is a {'bare ' if arch['bare'] else ''}git repository holding "
                   f"{seen} tracked file(s), and auto-discovery classified every one of them "
                   f"as repository housekeeping rather than a device capture. Confirm "
                   f"configPath points at the directory Oxidized writes nodes to, or set an "
                   f"explicit device pattern to override auto-discovery")
        elif arch["kind"] == "git" and seen:
            why = (f"the archive is a {'bare ' if arch['bare'] else ''}git repository holding "
                   f"{seen} tracked file(s), but device pattern {shown} matched none of them. "
                   f"Oxidized's git backend names each blob after the NODE with no file "
                   f"extension, so a pattern like '*.cfg' cannot match it — clear the device "
                   f"pattern to auto-discover")
        elif arch["kind"] == "git" and err and self._git(
                path, "for-each-ref", "--count=1", "--format=%(refname)", quiet=True)[0].strip():
            # ls-tree FAILED and the repository does have refs, so "nothing committed here
            # yet" is the wrong story. Measured 2026-08-02: a bare archive with one commit on
            # refs/heads/main and HEAD pointing at a missing refs/heads/production produced
            # exactly that message, for an archive that had completed a backup. git's stderr
            # cannot separate the two cases on its own — an unborn HEAD and a dangling HEAD
            # both say "fatal: Not a valid object name HEAD" — so the discriminator is whether
            # ANY ref exists, which costs one subprocess on an already-failed path.
            why = (f"the archive is a git repository whose contents could NOT be listed, so "
                   f"whether it holds any device configuration is unknown — it does have "
                   f"branches, so this is not an empty archive.{tail} Confirm HEAD points at a "
                   f"branch that exists (Oxidized's default is 'master') and that the "
                   f"ActiveGate user can read {path}")
        elif arch["kind"] == "git":
            why = ("the archive is a git repository with nothing committed at this path yet "
                   "(unborn HEAD, or an empty tree). Confirm Oxidized has completed a first "
                   "successful backup and that configPath points at the right subdirectory")
        else:
            why = (f"no files under {path} matched device pattern {shown}, and the path is not "
                   f"a git repository. Confirm Oxidized's output backend and its output path")
        self.logger.error(f"no device configs read from {path}: {why}")
        return {
            "content": (f"Config archive EMPTY: read 0 device configurations from {path} — "
                        f"{why}. NO device was assessed this cycle, so compliance coverage is "
                        f"ZERO, not clean. This is a COLLECTION failure: there is nothing to "
                        f"fix on any device's configuration."),
            "log.source": "network.compliance", "host.name": "", "device.address": "",
            "compliance.framework": "ISO-27001:2022", "compliance.status": "archive_empty",
            "compliance.platform": "unknown", "compliance.verified": "false",
            "config.capture.status": "failed", "config.capture.reason": "archive_empty",
            "config.archive.path": path, "config.archive.mode": mode,
            "config.archive.bare": "true" if arch["bare"] else "false",
            "config.archive.ownership": arch["ownership"],
            "config.archive.tracked_files": str(seen),
            "config.archive.device_glob": pattern,
            "severity": "ERROR", "dt.source": "cno-config"}

    def _unreadable_file_record(self, path, rel, mode, arch, err=""):
        """One ERROR for a device the archive LISTS but cannot produce the bytes for.

        Without this the device is not degraded, it is ABSENT — and an absence cannot be
        queried, which is the failure this whole module is organised against. Emitted per
        FILE rather than once per archive so the device keeps its identity: a fleet view that
        silently drops from 3 rows to 2 looks healthy, while 2 healthy rows plus one ERROR row
        naming sw2 is a fact somebody can alert on.

        Shaped exactly like the capture_failed records so no consumer needs a new branch —
        compliance.status=capture_failed, config.capture.status=failed, ERROR — and told apart
        by config.capture.reason. Identity comes from the filename stem via _meta with empty
        text, which is the honest source here: there are no bytes to parse a hostname out of,
        and device.identity.name_source="filename" says exactly that.
        """
        stem = _node_stem(rel)
        dev, ip, src_n, src_a = self._meta("", stem)
        self.logger.error(f"{rel} is listed in the archive at {path} but could not be read: "
                          f"{err[:160]}")
        return {
            "content": (f"Config capture FAILED on {dev}: the archive lists {rel} but its "
                        f"contents could not be read back — "
                        f"{CAPTURE_REASONS['archive_unreadable_file']}. This device was NOT "
                        f"assessed this cycle, while other devices in the same archive were, "
                        f"so its absence from the compliance view is a COLLECTION failure and "
                        f"not a clean result."
                        + (f" git said: {err[:200]}" if err else "")),
            "log.source": "network.compliance", "host.name": dev, "device.address": ip,
            "device.identity.name_source": src_n, "device.identity.address_source": src_a,
            "compliance.framework": "ISO-27001:2022", "compliance.status": "capture_failed",
            "compliance.platform": "unknown", "compliance.verified": "false",
            "config.capture.status": "failed",
            "config.capture.reason": "archive_unreadable_file",
            "config.capture.file": rel,
            "config.archive.path": path, "config.archive.mode": mode,
            "config.archive.bare": "true" if arch["bare"] else "false",
            "config.archive.ownership": arch["ownership"],
            "severity": "ERROR", "dt.source": "cno-config"}

    def _archive_unavailable_record(self, fresh):
        """The remote archive cannot be graded from. Exactly one record, ERROR, never silent.

        Covers BOTH halting reasons, because from a consumer's point of view they are the same
        event — this poll assessed nothing — and they are told apart by config.capture.reason:

          archive_unreachable    no usable mirror at all. Coverage is zero and there is
                                 nothing to fall back on.
          archive_stale_refused  a mirror exists but its last verified refresh is older than
                                 the limit, so grading stopped ON PURPOSE.

        Zero device records this poll follows _empty_archive_record's precedent exactly:
        coverage really is zero, and one present record explains the absence so it can be
        queried. An absence cannot be.
        """
        reason = fresh.get("reason", "archive_unreachable")
        age, limit = fresh.get("age"), fresh.get("limit") or STALE_FLOOR_SECONDS
        if reason == "archive_stale_refused":
            aged = (f"{int(age)}s old" if age is not None
                    else "of unknown age (it has never been successfully refreshed)")
            head = (f"Config archive STALE BEYOND LIMIT: the local mirror of "
                    f"{fresh.get('url', '')} is {aged}, past the {int(limit)}s limit, so NO "
                    f"device was graded this cycle")
        else:
            head = (f"Config archive UNREACHABLE: {fresh.get('url', '')} could not be fetched "
                    f"and no usable local mirror is available, so NO device was assessed this "
                    f"cycle")
        detail = fresh.get("detail") or ""
        self.logger.error(f"{head}. {detail}")
        return {
            "content": (f"{head} — {CAPTURE_REASONS[reason]}. Compliance coverage is ZERO, not "
                        f"clean. This is a COLLECTION failure: there is nothing to fix on any "
                        f"device's configuration."
                        + (f" git said: {detail[:300]}" if detail else "")),
            "log.source": "network.compliance", "host.name": "", "device.address": "",
            "compliance.framework": "ISO-27001:2022", "compliance.status": reason,
            "compliance.platform": "unknown", "compliance.verified": "false",
            "config.capture.status": "failed", "config.capture.reason": reason,
            "config.archive.path": fresh.get("mirror", ""),
            "config.archive.stale_limit_seconds": str(int(limit)),
            "severity": "ERROR", "dt.source": "cno-config", **self._fresh_dims(fresh)}

    def _path_missing_record(self, path, fresh):
        """LOCAL mode cannot reach configPath. Exactly one ERROR record, never silent.

        This closed the last hole in "reading zero devices is never silent", and it was in the
        one mode the remote-mode change promised not to regress. Measured 2026-08-02, before
        this existed:

            LOCAL missing path        -> records: 0
            LOCAL path-is-a-file      -> records: 0
            LOCAL default configPath  -> records: 0   (only self.logger.error)
            REMOTE, no writable base  -> records: 1   ERROR archive_unreachable

        i.e. remote mode fixed its half and left the local half silent, side by side, while
        _empty_archive_record's own docstring says "Reading ZERO devices must never be silent.
        Non-negotiable" and the README says "Reading zero devices is now always an ERROR
        record". Both were false for the deployment shape the guide recommends. The triggering
        event is mundane and likely — an NFS export or a bind mount dropping — and its
        signature was a dashboard that simply stopped changing.

        Archive-scoped (host.name ""), exactly like _archive_unavailable_record: no device can
        be named because none was read, and the record exists to make the ABSENCE queryable.

        The freshness dimensions are OVERRIDDEN rather than passed through, and the first
        version of this record got it wrong in exactly the way _fresh_dims was just fixed for:

            content ....... "Config archive UNREACHABLE: '/nope' is not a directory"
            refreshed ..... "yes"          <- contradicts the sentence next to it
            age_seconds ... "0"            <- "refreshed 0 seconds ago", on a dead archive

        Local mode reports state="fresh"/age=0.0 because it normally reads the archive directly
        and that is a true statement about a directory that EXISTS. Here it does not, so the
        one honest answer is that freshness is unknown: refreshed="no" and no age at all.
        """
        fresh = dict(fresh or {}, state="unavailable", age=None)
        self.logger.error(f"configPath not a directory: {path!r}")
        return {
            "content": (f"Config archive UNREACHABLE: {path!r} is not a directory on this "
                        f"ActiveGate, so NO device was assessed this cycle — "
                        f"{CAPTURE_REASONS['archive_path_missing']}. Compliance coverage is "
                        f"ZERO, not clean. This is a COLLECTION failure: there is nothing to "
                        f"fix on any device's configuration."),
            "log.source": "network.compliance", "host.name": "", "device.address": "",
            "compliance.framework": "ISO-27001:2022",
            "compliance.status": "archive_path_missing",
            "compliance.platform": "unknown", "compliance.verified": "false",
            "config.capture.status": "failed",
            "config.capture.reason": "archive_path_missing",
            "config.archive.path": path,
            "severity": "ERROR", "dt.source": "cno-config", **self._fresh_dims(fresh)}

    def _golden_missing_record(self, path, golden, is_repo, configured):
        """The baseline drift is measured against does not resolve. One archive-scoped record
        saying that "unknown" means NOT CHECKED.

        Why it needs a record at all. Measured 2026-08-02 with the golden tag simply never
        created — the DEFAULT state of every first deployment, and also exactly what
        --prune-tags correctly produces once the tag is deleted upstream:

            drift records   : [('sw1','unknown','yes','INFO'), ('sw2','unknown','yes','INFO')]
            archive records : []

        Zero queryable trace, only a logger.warning. And the consumer turned those rows GREEN:
        ConfigChanges.tsx computed driftState as drift === "yes" ? "drifted" : stale ?
        "unknown" : "ok", so drift="unknown" against a freshly-refreshed archive rendered a
        "✓ on intended" pill and counted into the "devices with a golden baseline" tile for
        devices that have no baseline at all. That is this module's recurring false all-clear
        arriving through the one door still open. The consumer is fixed too; this record is the
        half that makes the condition queryable instead of merely not-green.

        Two placement decisions, both of which the first attempt got wrong and the suite
        caught.

        It carries NO config.capture.* fields. Nothing about any capture failed — every device
        was read and every control was graded — so tagging it as an archive/capture problem
        would misdescribe the poll and widen the meaning of the one field detectors fire on.
        The suite asserts this directly: "a healthy capture must not be reported as any kind
        of archive problem".

        And it rides on network.compliance, NOT network.config, even though it is ABOUT drift.
        network.config is the per-device drift-verdict stream: every existing consumer and
        helper treats "a network.config record" as "a device's verdict" and reaches straight
        for config.drift_from_golden. An archive-scoped record there is a nameless phantom row
        in every one of them. network.compliance is already where the archive-scoped
        operational records live (archive_stale, archive_unavailable, archive_empty) — this is
        collection health, which is exactly what those are.

        Severity is graded by INTENT, because "no golden ref" is a supported configuration and
        not automatically a fault — activationSchema.json says of goldenRef: "Drift is skipped
        if absent."

          configured (the operator named a ref, and it does not resolve)   WARN
          not configured (left blank; the conventional 'golden' is absent) INFO

        Firing WARN every poll for a deployment that never asked for drift would burn exactly
        the alert channel this module keeps deliberately quiet, while INFO still leaves the
        state fully queryable.
        """
        why = ("it is not a Git repository, so there is no ref to resolve" if not is_repo
               else f"the ref {golden!r} does not resolve to a commit")
        how = (f"the golden ref {golden!r} is set in the monitoring configuration but "
               if configured else
               f"no golden ref is configured and the conventional {golden!r} baseline is "
               f"absent, so ")
        log = self.logger.warning if configured else self.logger.info
        log(f"drift unavailable: golden ref {golden!r} not resolvable in {path} "
            f"(git repo: {is_repo}). Devices will report drift 'unknown', NOT 'matches'.")
        return {
            "content": (f"Config drift NOT EVALUATED: {how}{why}. Every device this cycle "
                        f"reports drift 'unknown', which means NOT CHECKED and must not be "
                        f"read as 'matches the intended configuration'. "
                        f"{GOLDEN_MISSING_REMEDIATION}."),
            "log.source": "network.compliance", "host.name": "", "device.address": "",
            "config.drift_status": "not_evaluated",
            "config.golden_ref": golden,
            "config.golden_ref_configured": "yes" if configured else "no",
            "config.archive.path": path,
            "severity": "WARN" if configured else "INFO", "dt.source": "cno-config"}

    def _archive_stale_record(self, fresh):
        """Serving last-good data. WARN, and devices ARE still graded.

        WARN rather than ERROR on purpose: dt.source == "cno-config" and severity == "ERROR" is
        the clean low-cardinality alert trigger this module established, and it must keep
        meaning "grading stopped". A transient network hiccup must not fire the same alert as a
        dead archive.

        config.capture.status is "stale" rather than "failed" because nothing about any
        device's CAPTURE failed — the archive is intact, it is simply not current.
        """
        age, limit = int(fresh.get("age") or 0), int(fresh.get("limit") or STALE_FLOOR_SECONDS)
        detail = fresh.get("detail") or ""
        self.logger.warning(
            f"serving a STALE mirror of {fresh.get('url', '')}: last successful refresh was "
            f"{age}s ago (limit {limit}s). {detail}")
        return {
            "content": (f"Config archive STALE: {fresh.get('url', '')} could not be refreshed "
                        f"this cycle, so every device below was graded against the mirror as "
                        f"of {age}s ago (limit {limit}s, after which grading STOPS). The "
                        f"findings are real but they describe the archive at that time, not "
                        f"now — a device that has drifted since is still reported as matching. "
                        f"{CAPTURE_REASONS['archive_stale']}."
                        + (f" git said: {detail[:300]}" if detail else "")),
            "log.source": "network.compliance", "host.name": "", "device.address": "",
            "compliance.framework": "ISO-27001:2022", "compliance.status": "archive_stale",
            "compliance.platform": "unknown", "compliance.verified": "false",
            "config.capture.status": "stale", "config.capture.reason": "archive_stale",
            "config.archive.path": fresh.get("mirror", ""),
            "config.archive.stale_limit_seconds": str(limit),
            "severity": "WARN", "dt.source": "cno-config", **self._fresh_dims(fresh)}

    def poll(self):
        """One collection cycle. Scheduled from initialize() at intervalSeconds.

        NOT named `query`: see initialize() for why that name caused this method to be
        scheduled twice.
        """
        lock = self._poll_slot()
        if not lock.acquire(blocking=False):
            # Same semantics as the SDK's own overrun guard: skip the iteration rather than
            # queue it. Queuing would let a slow archive build an unbounded backlog of polls
            # that each re-clone into the same staging directory.
            self.logger.warning(
                "previous poll is still running; skipping this iteration. If this repeats, "
                "raise intervalSeconds — the archive is taking longer to refresh than the "
                "poll interval allows.")
            return
        try:
            return self._poll()
        finally:
            lock.release()

    def _poll(self):
        c = self._cfg()
        # The ONE insertion point for remote mode. Everything after this line reads a local
        # path and cannot tell how it got there — see _archive_source.
        path, fresh = self._archive_source(c)
        if not path and fresh.get("source") == "remote":
            # Remote mode with nothing safe to serve. Exactly one record, and returning here is
            # what stops a stale-beyond-limit archive from being graded.
            return self.report_log_events([self._archive_unavailable_record(fresh)])
        golden = c.get("goldenRef", "golden") or "golden"
        pattern = self._cfg_glob(c)
        if not path or not os.path.isdir(path):
            # LOCAL mode's half of "reading zero devices is never silent". This used to be a
            # bare `return` after a log line — see _path_missing_record for the measurement.
            return self.report_log_events([self._path_missing_record(path, fresh)])

        arch = self._resolve_archive(path)
        mode, loaded, seen, unread, gerr = self._load_configs(path, pattern, arch)
        texts = dict(loaded)
        files = sorted(texts)

        # Resolve the git preconditions ONCE per poll, not once per device. Neither fact can
        # change between devices in the same pass, and the per-device alternative costs a
        # failing subprocess call AND an identical warning line for every device every
        # interval — on any real fleet that is thousands of both, which is how a log stops
        # being read. A configPath that is not a git repo is a supported deployment mode
        # (README), and a first deployment legitimately has no golden ref yet, so neither of
        # these is an error condition; they just mean drift and the shrinkage arm are
        # unavailable this pass. _resolve_archive has already answered "is this a repo?", so
        # the probe that used to live here is gone rather than duplicated — and it is now the
        # answer that survives a foreign-owned archive, which the old bare probe did not.
        is_repo = arch["kind"] == "git"
        # The graded bytes came off DISK whenever mode == "dir" (see _load_configs: in a
        # non-bare repository the working tree holds the CURRENT capture and HEAD holds the
        # last COMMITTED one). Drift therefore has to diff golden against the WORKING TREE
        # there, not against HEAD — see the diff call below.
        graded_from_worktree = is_repo and mode == "dir"
        golden_ok = is_repo and self._git(
            path, "rev-parse", "--verify", f"{golden}^{{commit}}", quiet=True)[1]

        # The node name Oxidized actually dialled, per file. Used to catch a capture stored
        # against the wrong device — see the identity check in the loop.
        stems = {_node_stem(f).lower(): f for f in files}

        records, summary, claimed = [], [], {}
        for rel in files:
            # `rel` is configPath-relative and NOT a basename. Oxidized writes one directory
            # per group the moment `groups:` is configured, and deviceGlob is free text in
            # activationSchema.json with no constraint against subdirectories, so "*/*.cfg" is
            # a supported and ordinary setting. With basename, every git pathspec then matched
            # NOTHING — and `git diff` exits 0 for a pathspec that matches nothing, so the
            # returncode guard in _git cannot see it and the empty stdout was read as "no
            # drift". Measured 2026-08-02 on a device that had swapped `transport input ssh`
            # for `transport input telnet` and dropped its logging host: "matches golden (0
            # lines)", drift=no, INFO. `root_rel` is the same path spelled from the REPOSITORY
            # ROOT, which is the only spelling git accepts; `rel` stays the record's file field.
            text = texts[rel]
            root_rel = arch["prefix"] + rel
            stem = _node_stem(rel)

            # detect_platform BEFORE _meta: identity rules are platform-scoped, because the
            # same token means different things per vendor (on the real GSM7248V2 `set prompt`
            # is the model number, not the name). These two lines used to be the other way up.
            plat = detect_platform(text)
            dev, ip, src_n, src_a = self._meta(text, stem, plat["id"] if plat else None)
            # Stamped on every record that carries an identity, so a fleet whose names all came
            # from filenames is a countable coverage gap rather than an invisible assumption.
            ident = {"host.name": dev, "device.address": ip,
                     "device.identity.name_source": src_n,
                     "device.identity.address_source": src_a}

            # --- capture health gate: run BEFORE grading and before drift ---------------
            # Grading a broken artefact is worse than not grading it. See the CAPTURE HEALTH
            # section above for the 2026-08-02 measurements this is built on. The shrinkage
            # arm is the only one that costs subprocess calls, so it is consulted last: only
            # when every text-only arm has already said ok, and only when there is a repo to
            # ask. An artefact already condemned by its own contents needs no history.
            auto = pattern == AUTO_GLOB
            verdict, why, ev = assess_capture(text, plat, auto_discovered=auto)
            # `plat` in the condition, not just `is_repo`: the shrinkage arm is restricted to
            # fingerprinted captures, so for an unsupported vendor this would spend one
            # `git log` plus up to SHRINK_LOOKBACK+1 `git show` calls per device per poll to
            # compute a number assess_capture is then guaranteed to ignore.
            if verdict == "ok" and is_repo and plat:
                prev_good = self._prev_good_bytes(path, root_rel, text)
                if prev_good:
                    verdict, why, ev = assess_capture(text, plat, prev_good, auto_discovered=auto)

            # --- identity: is this file even THIS device's config? ----------------------
            # A perfectly valid configuration stored under the wrong node is still an unusable
            # artefact, so this overrides any verdict above. Measured 2026-08-02 with an
            # Oxidized session bleed writing one device's config into another's file: the
            # victim emitted ZERO records — no capture failure, no not_assessed, no drift, it
            # simply vanished from the compliance view, which is the 29-hour-silence class of
            # failure again and undetectable downstream because nothing can query an absence —
            # while the innocent device got a doubled record set carrying drift=yes AND
            # drift=no in the same poll.
            #
            # Collision-based, not equality-based: `dev != stem` alone is the NORMAL case for
            # any archive whose nodes are named by IP or inventory ID. It only trips when the
            # parsed hostname belongs to a DIFFERENT file in this same poll, which is positive
            # evidence of a mis-stored capture rather than a naming convention.
            # POSITIVE EVIDENCE of a bleed is required, and one of the two arms had none.
            # `dev in stems` is strong: the parsed hostname is literally another NODE'S NAME in
            # this archive. `other` alone is not — it only says two configs report the same
            # name, which is what a cloned template, a factory default, or a shared inventory
            # name produces. A genuine bleed stores the SAME BYTES under two nodes, so that is
            # the discriminator added here. Measured 2026-08-02 without it: two switches
            # sharing an `snmp-server sysname`, both captures perfectly valid, and the second
            # was reported "Config capture FAILED ... contains no usable configuration" at
            # ERROR over a healthy 5497-byte config, with ZERO compliance records — the
            # victim-goes-silent outcome this guard exists to detect, manufactured by the
            # guard. It now falls through to the duplicate-name branch below, which keeps the
            # device graded.
            other = claimed.get(dev.lower())
            bled = dev.lower() in stems or (other and texts.get(other) == text)
            if dev.lower() != stem.lower() and bled:
                verdict, why = "unusable", "wrong_device_config"
                # Report under the FILENAME, so the device whose backup is broken is the one
                # named in the record and cannot go silent. The address is dropped with it:
                # it was parsed from the OTHER device's config and would attach this record to
                # the wrong entity — which is the failure being reported, not a fix for it.
                dev, ip = stem, ""
                ident = {"host.name": dev, "device.address": "",
                         "device.identity.name_source": "filename",
                         "device.identity.address_source": "none"}
            elif dev.lower() != stem.lower() and other:
                # Two DIFFERENT configurations reporting the same device name. Not a bleed —
                # nothing about this device's capture is wrong — but host.name has stopped
                # being an identity, and host.name is half of fleetLogScope()'s filter and the
                # whole of the RCA workflows' Lane A join (norm(dev) === lower(sys_name)).
                # Reported at WARN and the device is still graded, because condemning the
                # capture was the defect. host.name falls back to the NODE NAME so the two
                # devices stay distinguishable downstream, with name_source saying so.
                collided, dev = dev, stem
                ident = {"host.name": dev, "device.address": ip,
                         "device.identity.name_source": "filename",
                         "device.identity.address_source": src_a}
                records.append({
                    "content": (f"Device name COLLISION on {rel}: this capture reports the "
                                f"device name {collided!r}, which {other} already reported "
                                f"this cycle, and the two configurations are NOT identical — "
                                f"so this is a duplicate name, not a mis-stored capture. "
                                f"{CAPTURE_REASONS['duplicate_device_name']}. host.name falls "
                                f"back to the Oxidized node name {stem!r} so the two devices "
                                f"remain distinguishable; compliance for this device WAS "
                                f"still evaluated."),
                    "log.source": "network.compliance", **ident,
                    "compliance.framework": "ISO-27001:2022",
                    "compliance.status": "duplicate_device_name",
                    "compliance.platform": plat["id"] if plat else "unknown",
                    "compliance.verified": "false",
                    "config.capture.file": rel,
                    "device.identity.reported_name": collided,
                    "device.identity.collides_with": other,
                    "severity": "WARN", "dt.source": "cno-config"})
                summary.append(f"{rel} duplicate-name")
            claimed[dev.lower()] = rel

            # --- a file in the archive that is not a device config at all ---------------
            # AUTO discovery only, and never for an artefact that fingerprints or carries
            # refusal markers — see the three conjuncts in assess_capture. This is INFO because
            # nothing is broken: the archive simply contains something we correctly declined to
            # grade. Emitting it at all (rather than skipping quietly) keeps AUTO's reach
            # auditable, so an operator can see what it swept up and narrow deviceGlob.
            if why == "archive_non_config":
                records.append({
                    "content": (f"Archive file {rel}: NOT A DEVICE CONFIG — {ev['bytes']} bytes "
                                f"with no configuration statements and no sign of a failed "
                                f"capture (no command echo, no CLI error text, no platform "
                                f"fingerprint). Skipped, not assessed, and NOT reported as a "
                                f"capture failure. {CAPTURE_REASONS['archive_non_config']}."),
                    "log.source": "network.compliance", **ident,
                    "compliance.framework": "ISO-27001:2022",
                    "compliance.status": "archive_non_config",
                    "compliance.platform": "unknown", "compliance.verified": "false",
                    "config.capture.status": "skipped",
                    "config.capture.reason": "archive_non_config",
                    "config.capture.bytes": str(ev["bytes"]),
                    "config.capture.file": rel,
                    "severity": "INFO", "dt.source": "cno-config"})
                summary.append(f"{rel} non-config")
                continue

            if verdict != "ok":
                failed = verdict == "unusable"
                drift_ok = why in DRIFT_STILL_MEANINGFUL
                # Severity is the point of this record, not a detail. The repo already draws
                # this line: ERROR appears exactly once elsewhere, at
                # controlplane_extension/__main__.py "LLDP poll failed for {host}", which is
                # a COLLECTION failure — while every WARN in both extensions is a FINDING
                # derived from data we did collect. A dead backup is a collection failure.
                # It must also not be WARN: on a large fleet the per-control WARN stream is
                # thousands of records and the one saying "your backup is dead" would be
                # invisible in it. ERROR keeps dt.source=="cno-config" and ERROR a clean,
                # low-cardinality alert trigger. A partial capture is WARN because the device
                # is still reachable and still being backed up, just incompletely.
                records.append({
                    "content": (
                        f"Config capture {'FAILED' if failed else 'PARTIAL'} for {dev}: the stored "
                        f"artefact is {ev['bytes']} bytes and "
                        f"{'contains no usable configuration' if failed else 'looks incomplete'} "
                        f"({why}) — {CAPTURE_REASONS.get(why, 'see config.capture.reason')}. "
                        f"ISO-27001 was NOT evaluated"
                        f"{' (drift IS still reported below)' if drift_ok else ' and drift was NOT computed'}"
                        f" — grading an incomplete capture invents FAILs on controls that are "
                        f"actually configured, and can invent PASSes on the negative-polarity ones. "
                        f"This is a COLLECTION failure, not a compliance finding: there is nothing "
                        f"to fix on the device's configuration."),
                    "log.source": "network.compliance", **ident,
                    "compliance.framework": "ISO-27001:2022",
                    # Distinct from not_assessed ON PURPOSE, and this is the whole point of
                    # requirement 2. not_assessed means "good artefact, we have no rule set
                    # for its syntax" — our gap, a stable state you can ship with, fixed by
                    # writing predicates. capture_failed means "no usable artefact at all" —
                    # the customer's network ops team, fixed by granting privilege or fixing
                    # credentials. Routing both into one INFO-coloured bucket is what sent
                    # the lab's 29-hour outage to nobody. The asymmetry that settles it:
                    # not_assessed means we never graded this device, while capture_failed
                    # can hit a device that graded 12/12 yesterday — so the dashboard number
                    # is not merely incomplete, it is stale and wrong, and decays hourly.
                    "compliance.status": "capture_failed" if failed else "capture_partial",
                    "compliance.platform": plat["id"] if plat else "unknown",
                    "compliance.verified": "false",
                    "config.capture.status": "failed" if failed else "partial",
                    "config.capture.reason": why,
                    "config.capture.bytes": str(ev["bytes"]),
                    "config.capture.substantive_lines": str(ev["substantive"]),
                    "config.capture.file": rel,
                    "severity": "ERROR" if failed else "WARN", "dt.source": "cno-config"})
                if "prev_good_bytes" in ev:
                    records[-1]["config.capture.prev_bytes"] = str(ev["prev_good_bytes"])
                summary.append(f"{dev} capture-{verdict} ({why})")
                if not drift_ok:
                    # Skips grading AND drift. Drift is suppressed rather than reported as
                    # "unknown" because ConfigChanges.tsx computes "on intended config" as
                    # drift !== "yes", so an "unknown" would render as healthy — the same false
                    # all-clear this change exists to remove. The capture record above carries
                    # the signal instead.
                    continue
                grade = False   # DRIFT_STILL_MEANINGFUL: fall through to the diff, never grade
            else:
                grade = True

            # --- ISO-27001 compliance over the captured config ---
            # Platform-scoped. An unrecognised platform is NOT ASSESSED, never FAIL — alleging
            # a violation we cannot actually evaluate is the defect this replaced.
            if grade and plat is None:
                records.append({
                    "content": (f"ISO-27001 on {dev}: NOT ASSESSED — no rule set matches this "
                                f"platform's configuration syntax. This is a coverage gap, not a finding."),
                    "log.source": "network.compliance", **ident,
                    "compliance.framework": "ISO-27001:2022", "compliance.status": "not_assessed",
                    "compliance.platform": "unknown", "compliance.verified": "false",
                    "severity": "INFO", "dt.source": "cno-config"})
                summary.append(f"{dev} not-assessed")
            elif grade:
                verified = bool(plat["verified"])
                # An unverified rule set is usable but must never read as a validated result.
                mark = "" if verified else " *"
                passed = total = 0
                for cid, (name, rule) in plat["controls"].items():
                    try:
                        res = rule(text)
                    except Exception as e:
                        self.logger.warning(f"{plat['id']} {cid} on {dev} raised: {e}")
                        res = None
                    if res is None:
                        status, sev = "not_applicable", "INFO"
                    else:
                        status = "pass" if res else "fail"
                        sev = "INFO" if res else "WARN"
                        total += 1
                        passed += bool(res)
                    records.append({
                        "content": f"ISO-27001 {cid} on {dev} [{plat['label']}{mark}]: {status.upper()} — {name}",
                        "log.source": "network.compliance", **ident,
                        "compliance.framework": "ISO-27001:2022", "compliance.control": cid,
                        "compliance.control_name": name, "compliance.status": status,
                        "compliance.platform": plat["id"], "compliance.platform_label": plat["label"],
                        # false => rules written from vendor docs, never run against real hardware.
                        # The UI renders these with an asterisk; do not treat as a validated assessment.
                        "compliance.verified": "true" if verified else "false",
                        "severity": sev, "dt.source": "cno-config"})
                if not verified:
                    records.append({
                        "content": (f"ISO-27001 on {dev}: rule set for {plat['label']} is UNVERIFIED — "
                                    f"derived from vendor documentation and never tested against a real "
                                    f"{plat['label']} device. Treat results as indicative and share a "
                                    f"sanitised config to have them validated."),
                        "log.source": "network.compliance", **ident,
                        "compliance.framework": "ISO-27001:2022", "compliance.status": "unverified_ruleset",
                        "compliance.platform": plat["id"], "compliance.verified": "false",
                        "severity": "WARN", "dt.source": "cno-config"})
                summary.append(f"{dev} {passed}/{total}")

            # --- drift vs the golden ref (best-effort; needs git + a repo at configPath) ---
            # Only reached for a capture that passed the health gate (or shrank, which is a
            # real diff), so a bad artefact can no longer replace a good one and produce a
            # whole-config spurious "DRIFTED".
            #
            # The tracked check is not redundant with _git's returncode guard, and this is the
            # third route to the same false all-clear. `git diff <ref> HEAD -- <pathspec>`
            # exits 0 with empty stdout when the pathspec matches nothing in either tree, so
            # the command genuinely SUCCEEDED — it just compared nothing — and empty stdout was
            # then read as "no drift". Measured 2026-08-02 on a device present on disk but
            # never committed (a node Oxidized has only just started capturing, or a file
            # copied in): "Config check ...: matches golden (0 lines)", drift=no, INFO, for a
            # config that has never been compared to anything. cat-file -e is one cheap
            # existence test that converts every such case into an honest "unknown".
            #
            # Both calls use the root-relative spelling (see _prev_good_bytes): "<ref>:<path>"
            # for the object lookup and ":(top)<path>" for the pathspec. Verified identical
            # results on bare same-user, bare foreign-owned, a grouped node (edge/branch-sw1)
            # and a non-bare repo with configPath in a subdirectory.
            #
            # --no-ext-diff --no-textconv is a security flag, not a formatting one. Measured
            # 2026-08-02: a repository carrying diff.external plus a .gitattributes textconv
            # EXECUTED its own script as the ActiveGate user, rc 0. The archive is
            # foreign-owned by design, so its contents are not our code to run. With the flags
            # the script does not run and the diff is byte-identical.
            #
            # HEAD is in the diff ONLY when the graded bytes came out of HEAD. This is the
            # FOURTH route to the same false all-clear and the only one still open after the
            # three above. _load_configs is disk-first, and in a non-bare repository the
            # working tree holds the CURRENT capture while HEAD holds the last COMMITTED one —
            # so `diff golden HEAD` grades one artefact and compares a different one. Measured
            # 2026-08-02 on README shape #2, "a Git checkout", with Oxidized's file backend
            # overwriting sw1.cfg in the worktree and nothing committing it: the SAME bytes
            # produced A.8.5, A.8.9 and A.8.26 = FAIL at WARN and, in the same poll,
            # config.drift_from_golden="no" at INFO, "matches golden (0 lines)". Per the note
            # above, ConfigChanges.tsx renders drift !== "yes" as "on intended config", so the
            # record set painted green over three control failures — permanently, because in a
            # file-backend deployment nothing ever commits the worktree. Dropping HEAD makes
            # git compare golden to the working tree, which is what was graded.
            tracked = golden_ok and self._git(
                path, "cat-file", "-e", f"{golden}:{root_rel}", quiet=True)[1]
            against = [golden] if graded_from_worktree else [golden, "HEAD"]
            out, ok, _ = self._git(path, "diff", "--no-ext-diff", "--no-textconv", *against,
                                   "--", f":(top){root_rel}") if tracked else ("", False, "")
            if not ok:
                records.append({
                    "content": (f"Config check {dev}: NOT COMPARED — {rel} could not be compared "
                                f"against golden ref {golden!r} in {path} (no such ref, the file is "
                                f"not in that ref, or configPath is not a git repo). Drift for this "
                                f"device is UNKNOWN, not zero."),
                    "log.source": "network.config", **ident,
                    "config.action": "scheduled check", "config.drift_from_golden": "unknown",
                    "config.diff": "", "severity": "INFO", "dt.source": "cno-config"})
            else:
                drift = self._only_diff(out)
                records.append({
                    "content": f"Config check {dev}: {'DRIFTED from golden' if drift else 'matches golden'} ({len(drift)} lines)",
                    "log.source": "network.config", **ident,
                    "config.action": "scheduled check", "config.drift_from_golden": "yes" if drift else "no",
                    "config.diff": "\n".join(drift)[:1800],
                    "severity": "WARN" if drift else "INFO", "dt.source": "cno-config"})

        # A file the archive LISTS but cannot produce bytes for. Emitted whether or not
        # anything else loaded — the all-or-nothing wiring is what made a partial failure
        # invisible. When NOTHING loaded, _empty_archive_record below tells the archive-level
        # story as well; the two are complementary, not duplicates.
        for rel in unread:
            records.append(self._unreadable_file_record(path, rel, mode, arch, gerr))
        if not files:
            records.append(
                self._empty_archive_record(path, pattern, mode, arch, seen, len(unread), gerr))
        if fresh.get("state") == "stale":
            # Devices above WERE graded, off data of a known age. The record naming that age
            # rides alongside them rather than replacing them.
            records.append(self._archive_stale_record(fresh))
        # One archive-scoped record qualifying the drift="unknown" verdicts this poll emitted,
        # rather than one per device. Gated on a verdict ACTUALLY EXISTING, not on `files`:
        # a device whose capture was condemned by the health gate has its drift suppressed
        # entirely, so a poll can read files and still produce no verdict at all — and with
        # nothing to qualify this record would be describing an evaluation that never ran.
        # (When nothing loaded, _empty_archive_record has already reported the bigger failure.)
        if not golden_ok and any(r.get("config.drift_from_golden") == "unknown"
                                 for r in records):
            records.append(self._golden_missing_record(
                path, golden, is_repo, bool(str(c.get("goldenRef", "") or "").strip())))
        # Freshness is stamped CENTRALLY rather than at each of the nine record sites, and that
        # is a correctness choice: requirement 3 is "staleness is never silent", so a record
        # type added later must not be able to forget the dimension that carries it. The dict
        # is computed once because it is identical for every record in a poll.
        dims = self._fresh_dims(fresh)
        for r in records:
            r.update(dims)
        if records:
            self.report_log_events(records)
        self.logger.info(f"compliance: {len(files)} configs from {mode} archive "
                         f"(bare={arch['bare']}, owner={arch['ownership']}), "
                         f"refresh={fresh.get('state', 'fresh')} "
                         f"age={int(fresh.get('age') or 0)}s, "
                         f"{len(records)} log records; " + ", ".join(summary))


def main():
    ComplianceExtension().run()


if __name__ == "__main__":
    main()
