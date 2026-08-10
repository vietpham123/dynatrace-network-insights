"""Tests for the capture-health gate, built around the EXACT artefact Oxidized stored in the
lab on 2026-08-02 (Netgear GSM7248V2, FASTPATH).

Like tests/test_codec.py in the controlplane extension, this file exists to pin a defect we
measured, not to exercise the happy path. Oxidized logged in, had its 'enable' rejected
("Incorrect Password!"), had every subsequent command refused, then STORED THE REFUSAL TEXT
AS THE DEVICE'S CONFIG and marked the node "success". Nothing anywhere said so for 29 hours.

The most important tests in here are not the ones that catch the broken artefacts — those are
easy. They are TestSmallButValidMustNeverBeFlagged. A false positive on this gate does not
mis-grade one control, it tells an operator their config backup is broken when it is not, and
one burnt alarm buys the next real 29-hour outage a free pass. The repo's own smallest golden
config is 485 bytes against a 272-byte broken artefact, and a valid MikroTik export is smaller
than both, so every case in that class is a config a naive size rule would have condemned.
"""
import logging
import re
import subprocess
import time

import pytest

from oxidized_extension.__main__ import (
    CAPTURE_REASONS, ComplianceExtension, PLATFORMS, TERMINATORS,
    _ERR_PHRASES, _err_indices, _is_err, assess_capture, detect_platform,
)

# ── the measured artefacts ───────────────────────────────────────────────────────────────

# What Oxidized committed for the GSM7248V2 on 2026-08-02, node status "success". This is the
# whole file. The artefact on disk measured 272 bytes and this transcription is 271 — one byte
# of trailing whitespace that did not survive being copied out of the archive. Left as
# transcribed rather than padded to hit a round number: the assertions below pin what is
# actually in this file, and none of the logic is size-sensitive anyway.
BAD_272 = """!!COMMAND: show version
!                   ^
!% Invalid input detected at '^' marker.
!
!!COMMAND: show bootvar
!                      ^
!% Invalid input detected at '^' marker.
!
!COMMAND: show running-config
                  ^
% Invalid input detected at '^' marker.
"""

# The earlier, worse observation on the same switch: an unprivileged session that did not
# refuse outright but returned a short stub. It opens with "!Current Configuration:", so it
# MATCHES the netgear fingerprint — the pre-existing detect_platform() is-None guard does not
# engage at all, and all six Netgear controls previously graded FAIL at WARN against it.
#
# The lab observation was ~94 bytes; this reconstruction is 63 and is deliberately NOT padded
# to match. Nothing in the gate looks at the size of a fingerprinted artefact, so padding it
# would only encode a number that carries no meaning.
STUB_UNPRIVILEGED = """!Current Configuration:
!System Description "GSM7248V2"
!
exit
"""

ENABLE_REJECTED = """!!COMMAND: enable
!Incorrect Password!
!
!!COMMAND: show running-config
!                      ^
!% Invalid input detected at '^' marker.
"""

# ── valid configurations that must never be flagged ──────────────────────────────────────

# The three GOLDEN entries from the repo's own scripts/config_capture.py, verbatim. These are
# the calibration set: 666B, 529B and 485B against a 272B broken artefact.
GOLDEN_9300 = """hostname LAB-9300-1-1
service timestamps log datetime msec
service password-encryption
!
enable secret 9 $9$Qd3kFcoreHASH
aaa new-model
banner login ^C Authorized access only ^C
no ip http server
!
vlan 40
 name PROD
!
interface TenGigabitEthernet1/1/1
 description WAN uplink to SDWAN-1
 switchport mode trunk
!
interface GigabitEthernet1/0/13
 description ACCESS-uplink to rack B
 switchport mode access
 switchport access vlan 40
 spanning-tree portfast
!
ip access-list extended GUEST-ACL
 permit ip 10.20.0.0 0.0.255.255 any
 deny   ip any any log
!
logging host 10.88.40.4
logging buffered 16384
ntp server 10.88.40.4
!
line vty 0 4
 transport input ssh
!
end
"""

GOLDEN_ACCESS = """hostname LAB-ACCESS-1
service timestamps log datetime msec
service password-encryption
!
enable password cisco123
banner login ^C Authorized access only ^C
no ip http server
!
vlan 50
 name ACCESS
!
interface GigabitEthernet1/1/1
 description uplink to CORE-1
 switchport mode trunk
!
interface GigabitEthernet1/0/2
 description AP-01
 switchport access vlan 50
!
ip access-list extended MGMT-ACL
 permit ip 10.88.40.0 0.0.0.255 any
 deny   ip any any log
!
logging buffered 8192
!
line vty 0 4
 transport input ssh telnet
!
end
"""

GOLDEN_SDWAN = """hostname LAB-SDWAN-8200-1
service timestamps log datetime msec
!
enable secret 9 $9$Sd8wanHASH
aaa new-model
no ip http server
!
vlan 100
 name WAN
!
interface GigabitEthernet0/0/0
 description WAN1 uplink
 ip address dhcp
!
ip access-list extended WAN-ACL
 permit ip 10.0.0.0 0.255.255.255 any
 deny   ip any any log
!
router bgp 65001
 neighbor 10.88.40.253 remote-as 65000
 timers bgp 30 90
!
logging host 10.88.40.4
logging buffered 16384
!
line vty 0 4
 transport input ssh
!
end
"""

# A complete, compliant FRR container config — and SMALLER than the 272-byte broken artefact
# is not far off. This is the case that kills any byte floor at or above 256B.
MIN_FRR = """frr version 8.4.2
frr defaults traditional
hostname r1
no ipv6 forwarding
service integrated-vtysh-config
service password-encryption
log syslog informational
!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
!
line vty
!
end
"""

# UNSUPPORTED vendor, entirely valid, 223 bytes. Two of the three tiny-arm conditions hold
# (no fingerprint, under 512B) — only the substantive-line count saves it. Calling this
# "capture failed" would be a worse defect than the one being fixed.
MIKROTIK = """/interface bridge
add name=bridge1 protocol-mode=rstp
/ip address
add address=192.168.88.1/24 interface=bridge1 network=192.168.88.0
/system identity
set name=router1
/system ntp client
set enabled=yes primary-ntp=10.1.1.1
"""

JUNIPER_SET = """set system host-name edge-01
set system root-authentication encrypted-password "$6$abcdef"
set system services ssh protocol-version v2
set system syslog host 10.1.1.5 any notice
set system ntp server 10.1.1.1
set security zones security-zone trust interfaces ge-0/0/0.0
set firewall filter PROTECT term 1 then accept
"""

# A healthy FASTPATH capture — what the GSM7248V2 should have produced on 2026-08-02 had the
# enable step succeeded. Netgear quotes the hostname and expresses the management address as
# "network parms", which no regex in _meta matches, so device.address stays empty for this
# platform.
FASTPATH_VALID = """!Current Configuration:
!System Description "GSM7248V2 ProSafe 48-port"
hostname "lab-gsm7248"
network parms 10.10.0.11 255.255.255.0 10.10.0.1
vlan database
vlan 10
exit
logging host 10.1.1.5
sntp server 10.1.1.1
ip ssh server enable
banner motd "Authorized access only"
access-list 1 permit 10.0.0.0 0.255.255.255
exit
"""

# A full Nokia SR Linux capture. SRL is deliberately absent from TERMINATORS (a brace fragment
# is legitimately unterminated, and the real device runs to 61KB), so this platform is where
# the shrinkage arm is still the only thing standing between a clean truncation and a graded
# one — which makes it the right fixture for testing that arm rather than a Cisco config, where
# the end-of-config marker would fire first and the git plumbing would never be exercised.
SRL_FULL = """    system {
        information {
            location lab
            contact netops
        }
        aaa {
            authentication {
                idle-timeout 3600
                admin-user {
                    password $y$j9T$hashhashhash
                }
            }
        }
        ssh-server {
            admin-state enable
        }
        logging {
            buffer messages {
                subsystem all
            }
            remote-server 10.1.1.5 {
                transport udp
            }
        }
        ntp {
            admin-state enable
            server 10.1.1.1 {
            }
        }
        banner {
            login-banner "Authorized access only"
        }
    }
    acl {
        ipv4-filter mgmt-in {
            entry 10 {
                action accept
            }
        }
    }
    network-instance mgmt {
        admin-state enable
        interface mgmt0.0 {
        }
    }
    network-instance default {
        admin-state enable
        protocols {
            bgp {
                autonomous-system 65001
            }
        }
    }
"""

SRL_FRAGMENT = """    system {
        information {
            location lab
        }
        aaa {
            authentication {
                idle-timeout 3600
            }
        }
        ssh-server {
            admin-state enable
        }
    }
    network-instance mgmt {
        admin-state enable
    }
"""

# ── configurations engineered to break the rule (the false-positive register) ────────────

# A security banner is the one place a real config legitimately says "Permission denied", and
# an ACL remark is the one place it legitimately says "unknown command". Both fired on the
# first draft of the error list.
HOSTILE_BANNER = GOLDEN_9300 + """banner motd ^C
% Unauthorized access is prohibited. Invalid input will be logged and reported.
% Permission denied notices are generated for all syntax error attempts.
^C
ip access-list extended MGMT
 remark deny - permission denied, log all unknown command attempts
 permit tcp any any eq 22
end
"""

PANOS_XML = """<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <permitted-ip><entry name="10.0.0.0/8"/></permitted-ip>
          <ntp-servers><primary-ntp-server><ntp-server-address>10.1.1.1</ntp-server-address></primary-ntp-server></ntp-servers>
        </system>
      </deviceconfig>
      <rulebase>
        <security><rules>
          <entry name="Invalid input detected"><description>syntax error test rule</description><action>deny</action></entry>
        </rules></security>
      </rulebase>
    </entry>
  </devices>
</config>
"""

# "timeout" as ordinary configuration. An earlier draft of _ERR_PHRASES matched a bare
# "timeout" and condemned all three of these lines.
TIMEOUT_WORDS = """    system {
        aaa {
            authentication {
                idle-timeout 3600
            }
        }
        ssh-server {
            admin-state enable
            timeout 300
        }
    }
    network-instance default {
        admin-state enable
        protocols {
            bgp {
                timeout 90
            }
        }
    }
"""

# ── partial captures ─────────────────────────────────────────────────────────────────────

# Paging was live, so the capture stops wherever the pager stopped it.
PAGER_TRUNCATED = """!COMMAND: show running-config
service timestamps debug datetime msec
hostname LAB-9300-1-1
aaa new-model
ip cef
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
--More--
"""

# The nastiest case in the whole set: the session died partway through a Cisco capture. It
# has no error text, no pager residue, and it FINGERPRINTS as cisco-ios with verified=True,
# because "service timestamps" is line 4. Textually it is indistinguishable from a small but
# valid IOS config, so nothing inside the file can catch it — only this device's own history
# can. See TestPartialCaptureThatStillFingerprints.
PARTIAL_CISCO = """!COMMAND: show running-config
Building configuration...
!
service timestamps debug datetime msec
service password-encryption
!
hostname LAB-9300-1-1
!
boot-start-marker
boot-end-marker
!
aaa new-model
!
ip cef
!
interface GigabitEthernet1/0/1
 switchport mode access
"""


def _verdict(text, prev_good=None):
    # The PLATFORMS entry, not a bool: the TERMINATORS arm needs the platform id, and passing
    # a bare bool silently disables it. That is exactly how the end-of-config check went
    # untested in the first draft of this file, and how the fast path went unnoticed shadowing
    # the shrinkage arm — a helper that under-supplies its subject makes whole arms unreachable
    # from the tests while they stay reachable in production.
    v, why, _ = assess_capture(text, detect_platform(text), prev_good)
    return v, why


class TestTheArtefactWeMeasured:
    """The 272 bytes Oxidized stored as a config on 2026-08-02, and its two relatives."""

    def test_272_byte_artefact_is_unusable(self):
        assert _verdict(BAD_272) == ("unusable", "no_content")

    def test_272_byte_artefact_has_zero_substantive_lines(self):
        # 11 non-blank lines, every one of them a command echo, a caret or an error.
        _, _, ev = assess_capture(BAD_272, False)
        assert ev["bytes"] == 271          # 272 on disk; see the note on BAD_272
        assert ev["substantive"] == 0
        assert ev["noise_ratio"] == 1.0

    def test_enable_rejection_is_unusable(self):
        verdict, _ = _verdict(ENABLE_REJECTED)
        assert verdict == "unusable"

    def test_unprivileged_stub_is_unusable(self):
        assert _verdict(STUB_UNPRIVILEGED) == ("unusable", "no_content")

    def test_unprivileged_stub_defeats_the_pre_existing_guard(self):
        """Why the detect_platform() is-None guard was never sufficient on its own.

        The stub opens with "!Current Configuration:", which is the netgear fingerprint. The
        platform IS identified, so the not_assessed branch never runs, and before this gate
        existed all six Netgear controls graded FAIL at WARN against four lines of comments —
        a compliant switch reported as totally non-compliant, with confidence.
        """
        plat = detect_platform(STUB_UNPRIVILEGED)
        assert plat is not None and plat["id"] == "netgear"
        graded = [cid for cid, (_, rule) in plat["controls"].items() if rule(STUB_UNPRIVILEGED)]
        assert graded == [], "stub would have graded 0/6 — every control a false FAIL"

    def test_the_original_guard_still_holds_for_the_272_byte_case(self):
        # Not a regression test for new code: this documents that the existing behaviour we
        # were told to preserve really is what it claims to be.
        assert detect_platform(BAD_272) is None


class TestSmallButValidMustNeverBeFlagged:
    """The class that matters. Every one of these is a config a size rule would condemn."""

    @pytest.mark.parametrize("text", [
        pytest.param(GOLDEN_9300, id="repo-golden-LAB-9300-1-1-666B"),
        pytest.param(GOLDEN_ACCESS, id="repo-golden-LAB-ACCESS-1-529B"),
        pytest.param(GOLDEN_SDWAN, id="repo-golden-LAB-SDWAN-8200-1-485B"),
        pytest.param(MIN_FRR, id="minimal-but-complete-FRR-230B"),
        pytest.param(MIKROTIK, id="MikroTik-unsupported-vendor-223B"),
        pytest.param(FASTPATH_VALID, id="healthy-Netgear-FASTPATH"),
        pytest.param(JUNIPER_SET, id="Juniper-set-format-no-fingerprint-317B"),
        pytest.param(SRL_FRAGMENT, id="Nokia-SRL-brace-fragment"),
        pytest.param(HOSTILE_BANNER, id="Cisco-banner-and-ACL-remark-full-of-error-phrases"),
        pytest.param(PANOS_XML, id="PAN-OS-XML-rule-named-Invalid-input-detected"),
        pytest.param(TIMEOUT_WORDS, id="SRL-idle-timeout-and-timeout-as-real-config"),
    ])
    def test_valid_config_is_ok(self, text):
        verdict, why = _verdict(text)
        assert verdict == "ok", f"FALSE POSITIVE: {why}"

    def test_the_smallest_valid_golden_is_larger_than_the_broken_artefact(self):
        """The measurement that rules out a byte floor as the trigger.

        485B valid vs 272B broken leaves no headroom, and MikroTik below closes the gap
        entirely: a valid config that is SMALLER than the artefact we must condemn. There is
        no threshold with full recall and zero false positives.
        """
        assert min(len(g.encode()) for g in (GOLDEN_9300, GOLDEN_ACCESS, GOLDEN_SDWAN)) == 485
        assert len(BAD_272.encode()) == 271
        assert len(MIKROTIK.encode()) < len(BAD_272.encode())

    def test_a_routine_edit_does_not_trip_the_shrinkage_arm(self):
        """Both directions, because one direction is vacuous.

        The original version of this test asserted only that a 700B -> 666B edit stays ok, and
        it passed for prev_good=700, 61000 AND 1_000_000_000 — it would have passed against a
        rule of `nbytes < prev_good`. It could not fail, because the fast path returned before
        prev_good_bytes was read at all. Pinning the NEGATIVE alone cannot detect a dead arm;
        the positive assertion below is what makes this test able to fail.
        """
        assert _verdict(GOLDEN_9300, prev_good=700) == ("ok", "")
        assert _verdict(GOLDEN_9300, prev_good=61000) == ("suspect", "shrank_vs_last_good")


class TestPartialCaptureThatStillFingerprints:
    """Residual risk 1 — the case the not_assessed path does not cover at all."""

    def test_partial_cisco_still_fingerprints_as_verified_cisco_ios(self):
        plat = detect_platform(PARTIAL_CISCO)
        assert plat is not None and plat["id"] == "cisco-ios" and plat["verified"] is True

    def test_grading_a_partial_capture_invents_failures(self):
        """The damage being prevented, measured rather than asserted.

        Same device, same rule set: the full config passes everything it is graded on, the
        truncated one fails most of it — purely because the text stops before the ACLs. Every
        predicate in PLATFORMS is substring presence, so absence is indistinguishable from
        truncation; this is structural and no rule tuning fixes it.
        """
        plat = detect_platform(PARTIAL_CISCO)
        fails_partial = [cid for cid, (_, rule) in plat["controls"].items() if rule(PARTIAL_CISCO) is False]
        fails_full = [cid for cid, (_, rule) in plat["controls"].items() if rule(GOLDEN_9300) is False]
        assert len(fails_partial) >= 6
        assert len(fails_partial) > len(fails_full)

    def test_truncation_can_also_manufacture_a_pass(self):
        """Why a non-ok verdict discards the PASSES too, not just the FAILs.

        Three negative-polarity controls return True against an empty string. Keeping passes
        on a partial capture would turn a broken backup into a clean compliance report, which
        is strictly worse than the false-FAIL problem being fixed.
        """
        free_passes = [(p["id"], cid) for p in PLATFORMS
                       for cid, (_, rule) in p["controls"].items() if rule("") is True]
        assert ("nokia-srlinux", "A.8.21") in free_passes
        assert ("frr", "A.8.21") in free_passes
        assert ("juniper-junos", "A.8.21") in free_passes

    def test_pager_residue_is_caught_from_the_text_alone(self):
        assert _verdict(PAGER_TRUNCATED) == ("suspect", "pager_truncation")

    def test_clean_truncation_is_caught_from_the_text_alone_with_no_git(self):
        """This assertion was inverted, and the inversion was the point of the defect.

        It used to read "nothing inside the file gives it away" and pin ("ok", "") with no
        reference, treating this device's git history as the only possible signal. That is
        false for the IOS family: `show running-config` always terminates in a standalone
        "end", and a truncated capture does not have one. Relying on history instead meant the
        gate needed a git repo, needed >853B of previous capture, and needed the previous
        capture not to have been a truncation itself — three conditions that all failed in the
        lab at once, so requirement 1 was uncovered in practice.
        """
        assert "end" not in [l.strip() for l in PARTIAL_CISCO.splitlines()]
        assert _verdict(PARTIAL_CISCO) == ("suspect", "no_end_of_config_marker")
        # ...and it does not need the history to say so.
        assert _verdict(PARTIAL_CISCO, prev_good=61000)[0] == "suspect"


# ── extension-level behaviour ────────────────────────────────────────────────────────────

def _ext(tmp_path, **cfg):
    """A ComplianceExtension with no SDK lifecycle.

    object.__new__ bypasses Extension.__init__ so the test never tries to reach EEC, whether
    the real SDK or the conftest stub is installed.
    """
    ext = object.__new__(ComplianceExtension)
    ext.logger = logging.getLogger("test-oxidized-extension")
    ext.emitted = []
    ext._cfg = lambda: {"configPath": str(tmp_path), **cfg}
    ext.report_log_events = ext.emitted.extend
    return ext


def _git(d, *args):
    subprocess.run(["git", "-C", str(d), *args], check=True,
                   capture_output=True, text=True)


def _repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "test")
    return tmp_path


def _commit(tmp_path, name, text, msg="capture"):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    _git(tmp_path, "add", name)
    _git(tmp_path, "commit", "-q", "-m", msg)


class TestTheGateInsideQuery:
    def test_unusable_artefact_emits_no_fail_controls_and_no_drift(self, tmp_path):
        """Requirement 1, end to end: nothing is graded and nothing is compared."""
        (tmp_path / "sw-lon-01.cfg").write_text(BAD_272)
        ext = _ext(tmp_path)
        ext.poll()

        assert [r for r in ext.emitted if r.get("compliance.status") == "fail"] == []
        assert [r for r in ext.emitted if "compliance.control" in r] == []
        assert [r for r in ext.emitted if r["log.source"] == "network.config"] == []
        assert len(ext.emitted) == 1

    def test_the_record_says_backup_broken_not_coverage_gap(self, tmp_path):
        """Requirement 2: an operator must be able to tell these two apart without reading
        prose, and must be routed to network ops rather than to us."""
        (tmp_path / "sw-lon-01.cfg").write_text(BAD_272)
        ext = _ext(tmp_path)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "capture_failed"
        assert rec["compliance.status"] != "not_assessed"
        assert rec["severity"] == "ERROR"
        assert rec["log.source"] == "network.compliance"
        assert rec["config.capture.status"] == "failed"
        assert rec["config.capture.reason"] == "no_content"
        assert rec["config.capture.bytes"] == "271"   # 272 on disk; see the note on BAD_272
        assert rec["config.capture.file"] == "sw-lon-01.cfg"
        assert rec["dt.source"] == "cno-config"
        # The remediation has to be in the text, because the text is what lands in a ticket.
        assert "COLLECTION failure" in rec["content"]
        assert "privilege" in rec["content"]
        # Device-level notice, so it must stay out of the per-control channel every consumer
        # filters on (isNotNull(compliance.control)).
        assert "compliance.control" not in rec

    def test_stub_that_fingerprints_is_still_gated(self, tmp_path):
        (tmp_path / "gsm7248.cfg").write_text(STUB_UNPRIVILEGED)
        ext = _ext(tmp_path)
        ext.poll()

        assert len(ext.emitted) == 1
        assert ext.emitted[0]["compliance.status"] == "capture_failed"
        # The platform WAS identified; the gate, not detect_platform, is what saved this.
        assert ext.emitted[0]["compliance.platform"] == "netgear"

    def test_partial_capture_is_warn_and_distinct_from_failed(self, tmp_path):
        (tmp_path / "core-1.cfg").write_text(PAGER_TRUNCATED)
        ext = _ext(tmp_path)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "capture_partial"
        assert rec["config.capture.reason"] == "pager_truncation"
        assert rec["severity"] == "WARN"
        assert [r for r in ext.emitted if "compliance.control" in r] == []
        assert [r for r in ext.emitted if r["log.source"] == "network.config"] == []

    def test_shrinkage_against_git_history_gates_a_clean_truncation(self, tmp_path):
        """The partial capture that no text-only signal can see (residual risk 1).

        Uses SR Linux precisely BECAUSE it has no end-of-config marker: on a Cisco config the
        terminator arm fires first and this test would pass without the git walk running at all.
        """
        _repo(tmp_path)
        big = SRL_FULL + "".join(
            f"    interface ethernet-1/{n} {{\n        admin-state enable\n    }}\n"
            for n in range(1, 60))
        _commit(tmp_path, "srl-1.cfg", big, "good capture")
        _commit(tmp_path, "srl-1.cfg", SRL_FRAGMENT, "capture regression")

        ext = _ext(tmp_path)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "capture_partial"
        assert rec["config.capture.reason"] == "shrank_vs_last_good"
        assert int(rec["config.capture.prev_bytes"]) == len(big.encode())
        assert [r for r in ext.emitted if "compliance.control" in r] == []


class TestNoRegressionForGoodConfigs:
    """Requirement 4. A healthy capture must behave exactly as it did before the gate."""

    def test_good_config_still_grades_every_control(self, tmp_path):
        (tmp_path / "LAB-9300-1-1.cfg").write_text(GOLDEN_9300)
        ext = _ext(tmp_path)
        ext.poll()

        controls = [r for r in ext.emitted if "compliance.control" in r]
        plat = detect_platform(GOLDEN_9300)
        assert len(controls) == len(plat["controls"])
        assert {r["compliance.status"] for r in controls} <= {"pass", "fail", "not_applicable"}
        assert all(r["compliance.platform"] == "cisco-ios" for r in controls)
        assert [r for r in ext.emitted if "config.capture.status" in r] == []

    def test_good_config_still_emits_exactly_one_drift_record(self, tmp_path):
        _repo(tmp_path)
        _commit(tmp_path, "LAB-9300-1-1.cfg", GOLDEN_9300)
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "LAB-9300-1-1.cfg", GOLDEN_9300.replace("ntp server 10.88.40.4\n", ""),
                "someone removed ntp")

        ext = _ext(tmp_path)
        ext.poll()

        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert drift[0]["severity"] == "WARN"
        assert "-ntp server 10.88.40.4" in drift[0]["config.diff"]

    def test_unrecognised_platform_is_still_not_assessed_not_capture_failed(self, tmp_path):
        """The pre-existing coverage-gap path must survive intact.

        MikroTik is a real, complete config for a vendor we have no rule set for. It is the
        exact thing not_assessed is for, and mislabelling it capture_failed would be a worse
        defect than the one this change fixes.
        """
        (tmp_path / "mt-01.cfg").write_text(MIKROTIK)
        ext = _ext(tmp_path)
        ext.poll()

        notices = [r for r in ext.emitted
                   if r["log.source"] == "network.compliance" and r["host.name"]]
        assert len(notices) == 1
        assert notices[0]["compliance.status"] == "not_assessed"
        assert notices[0]["severity"] == "INFO"


class TestFalseAllClearOnDrift:
    """A missing golden ref used to be reported as 'matches golden (0 lines)' at INFO.

    Measured 2026-08-02: `git diff golden HEAD` exits 128 with an empty stdout when the ref
    does not exist — the normal state of a first deployment — and the old code read empty
    stdout as 'no drift'. That is an affirmative wrong claim, not a missing signal.
    """

    def test_missing_golden_ref_reports_unknown_not_match(self, tmp_path):
        _repo(tmp_path)
        _commit(tmp_path, "LAB-9300-1-1.cfg", GOLDEN_9300)

        ext = _ext(tmp_path)
        ext.poll()

        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "unknown"
        assert "matches golden" not in drift[0]["content"]
        assert "NOT COMPARED" in drift[0]["content"]

    def test_non_git_configpath_reports_unknown_not_match(self, tmp_path):
        (tmp_path / "LAB-9300-1-1.cfg").write_text(GOLDEN_9300)

        ext = _ext(tmp_path)
        ext.poll()

        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "unknown"

    def test_every_device_still_gets_exactly_one_drift_record(self, tmp_path):
        """The git preconditions are resolved once per poll; the records stay per-device.

        Hoisting the repo/ref checks out of the loop is what stops a fleet-sized poll from
        emitting thousands of identical git warnings, but it must not collapse the per-device
        reporting along with them.
        """
        (tmp_path / "a.cfg").write_text(GOLDEN_9300)
        (tmp_path / "b.cfg").write_text(GOLDEN_SDWAN)
        ext = _ext(tmp_path)
        ext.poll()

        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(drift) == 2
        assert {r["host.name"] for r in drift} == {"LAB-9300-1-1", "LAB-SDWAN-8200-1"}
        assert all(r["config.drift_from_golden"] == "unknown" for r in drift)


class TestHostnameCorrelation:
    """host.name is how an operator finds the failing device. Netgear FASTPATH quotes it."""

    def test_fastpath_quoted_hostname_loses_its_quotes(self, tmp_path):
        (tmp_path / "node.cfg").write_text(FASTPATH_VALID)
        ext = _ext(tmp_path)
        ext.poll()

        assert ext.emitted[0]["host.name"] == "lab-gsm7248"

    def test_unquoted_hostname_is_untouched(self, tmp_path):
        (tmp_path / "node.cfg").write_text(GOLDEN_9300)
        ext = _ext(tmp_path)
        ext.poll()

        assert ext.emitted[0]["host.name"] == "LAB-9300-1-1"


# ══════════════════════════════════════════════════════════════════════════════════════════
# Second round. Everything below pins a defect found by an adversarial review of the gate
# above and REPRODUCED before it was fixed. They divide into two kinds, and the first kind
# matters more: a false positive in this gate tells an operator their backup is broken when it
# is not, and the whole argument for the gate is that it must be more trustworthy than the
# thing it guards.
#
# A coverage fact that shaped this round: of the ladder's arms, four were never produced by
# any fixture in the first 37 tests — cli_refused, mostly_command_echo, stub_capture and
# too_little_content_to_grade had zero occurrences of their reason string in this file. Three
# of the four false positives found later lived in exactly those untested arms.
# TestEveryArmIsReachable at the bottom is the structural guard against that recurring.
# ══════════════════════════════════════════════════════════════════════════════════════════

# A realistic full IOS capture: the security stanzas an ISO-27001 control looks for (ACL,
# banner, logging, ntp, "no ip http server", "line vty") all sit AFTER a 48-port interface
# list, which is the order `show running-config` actually emits them in. That ordering is the
# whole reason a truncation is dangerous — the repo's compact goldens put everything in the
# first 20 lines, so cutting them mostly removes nothing a control tests for, and they
# understate the damage.
IOS_HEAD = """!COMMAND: show running-config
Building configuration...
!
version 17.9
service timestamps debug datetime msec
service password-encryption
!
hostname LAB-9300-1-1
!
enable secret 9 $9$Qd3kFcoreHASH
aaa new-model
!
ip cef
!
"""
IOS_INTERFACES = "".join(
    f"interface GigabitEthernet1/0/{n}\n description access port {n}\n switchport mode access\n"
    f" switchport access vlan 40\n spanning-tree portfast\n!\n" for n in range(1, 49))
IOS_TAIL = """ip access-list extended GUEST-ACL
 permit ip 10.20.0.0 0.0.255.255 any
 deny   ip any any log
!
banner login ^C Authorized access only ^C
!
no ip http server
logging host 10.88.40.4
logging buffered 16384
ntp server 10.88.40.4
!
vlan 40
 name PROD
!
line vty 0 4
 transport input ssh
!
end
"""
IOS_FULL = IOS_HEAD + IOS_INTERFACES + IOS_TAIL


def _truncate(text, fraction):
    """Cut a capture on a line boundary — a dead session leaves no partial line."""
    cut = text[:int(len(text) * fraction)]
    return cut[:cut.rfind("\n") + 1]


def _fails(text):
    plat = detect_platform(text)
    return [cid for cid, (_, rule) in plat["controls"].items() if rule(text) is False]


def _controls(ext):
    """The per-control records — the channel every downstream consumer filters on."""
    return [r for r in ext.emitted if "compliance.control" in r]


def _all_fixtures():
    """Every config-shaped string defined at module scope, for corpus-wide sweeps."""
    return [v for k, v in sorted(globals().items())
            if isinstance(v, str) and k.isupper() and "\n" in v]


class TestBenignAuxCommandMustNotSilenceTheDevice:
    """FALSE POSITIVE, and the worst one the gate had.

    The measured GSM7248V2 artefact proves this deployment's Oxidized model issues three
    commands and comment-prefixes each; only the last is graded. A device that does not
    implement one of the auxiliary commands — "show bootvar" is deprecated across much of
    IOS-XE and NX-OS, "show inventory" behaves the same on IOSv/CSR1000v, and a read-only
    TACACS+ account answers "Command authorization failed." to any single one of them —
    answers that one with an error and the other two perfectly.

    The gate demanded a zero-error capture, so one error line beat 34 lines of captured
    configuration. Nothing graded, no drift, and PERMANENTLY: the model reissues that command
    every poll. The remediation the capture-failure record itself recommends (run the backup
    under a restricted read-only account) is a direct cause of it.
    """

    AUX_REFUSED = ("""!!COMMAND: show version
!Cisco IOS XE Software, Version 17.09.04a
!
!!COMMAND: show bootvar
!                ^
!% Invalid input detected at '^' marker.
!
!!COMMAND: show running-config
""" + IOS_FULL[IOS_FULL.index("Building configuration..."):])

    def test_the_capture_is_healthy_despite_the_refused_aux_command(self):
        assert _verdict(self.AUX_REFUSED) == ("ok", "")

    def test_the_error_line_is_still_seen__it_is_the_verdict_that_changed(self):
        """Not fixed by weakening the grammar. The error is detected; it is judged recovered."""
        _, _, ev = assess_capture(self.AUX_REFUSED, detect_platform(self.AUX_REFUSED))
        assert ev["errors"] == 1
        assert ev["substantive"] > 30, "34 lines of config were captured AFTER the error"

    def test_the_device_still_grades_and_still_reports_drift(self, tmp_path):
        (tmp_path / "LAB-9300-1-1.cfg").write_text(self.AUX_REFUSED)
        ext = _ext(tmp_path)
        ext.poll()

        assert [r for r in ext.emitted if "config.capture.status" in r] == []
        assert len(_controls(ext)) == len(detect_platform(IOS_FULL)["controls"])
        assert [r["compliance.status"] for r in _controls(ext)].count("fail") == 0
        assert len([r for r in ext.emitted if r["log.source"] == "network.config"]) == 1

    def test_a_session_that_dies_at_the_error_is_still_caught(self):
        """The fix must not cost the true positive. Recovery is evidenced by config AFTER the
        error; a session that stops there has none, and is still suspect."""
        died = self.AUX_REFUSED[:self.AUX_REFUSED.index("!!COMMAND: show running-config")]
        assert _verdict(died)[0] != "ok"

    def test_it_does_not_merely_flag_once__it_never_stops(self, tmp_path):
        """Permanence is what makes this severe rather than noisy: the aux command is reissued
        every poll, so before the fix the device never graded again."""
        (tmp_path / "LAB-9300-1-1.cfg").write_text(self.AUX_REFUSED)
        for _ in range(3):
            ext = _ext(tmp_path)
            ext.poll()
            assert len(_controls(ext)) == 12


class TestPagerPatternMustNotMatchProse:
    """FALSE POSITIVE. The error grammar was banner-masked and corroborated; the pager pattern
    was a bare re.search over the whole raw text with neither guard and identical blast radius
    (whole device suppressed). That asymmetry was the defect — the code already knew banners
    are hostile territory and did not apply the knowledge here.
    """

    @pytest.mark.parametrize("suffix, id_", [
        ("banner motd ^C\nAuthorized access only. Press any key to continue.\n^C\n",
         "security-banner-says-press-any-key"),
        ('snmp-server location "Rack12 DC2 MORE: wiki/net/dc2"\n', "snmp-location-contains-MORE:"),
    ])
    def test_prose_in_a_healthy_config_is_not_pager_residue(self, suffix, id_):
        text = IOS_FULL.replace("end\n", suffix + "end\n")
        verdict, why = _verdict(text)
        assert verdict == "ok", f"FALSE POSITIVE ({id_}): {why}"

    def test_a_comment_separator_early_in_the_capture_is_not_a_truncation(self):
        """Paging truncates by definition, so residue the capture then RECOVERED from — 20+
        lines of config after it — cannot have ended the capture."""
        assert _verdict("!--- more ---\n" + IOS_FULL) == ("ok", "")
        assert _verdict("--More--\n" + IOS_FULL) == ("ok", "")

    def test_real_pager_residue_at_the_end_still_fires(self):
        assert _verdict(PAGER_TRUNCATED) == ("suspect", "pager_truncation")

    @pytest.mark.parametrize("marker", ["--More--", "---- More ----", "--More-- ", "---(more)---"])
    def test_vendor_pager_spellings_are_still_caught(self, marker):
        assert _verdict(_truncate(IOS_FULL, 0.4) + marker + "\n")[0] == "suspect"


class TestStubCaptureNeedsEvidenceOfARefusal:
    """FALSE POSITIVE, and a strictly stronger claim than the behaviour it replaced.

    "no fingerprint AND under 512B AND under 5 substantive lines" is not evidence that a
    capture failed. It is the definition of "small config from a vendor we have no rules for",
    which is exactly what not_assessed exists to report. The arm asserted a COLLECTION FAILURE
    at ERROR against complete, correct configuration files.
    """

    MIKROTIK_SMALLER = """/interface bridge
add name=bridge1 protocol-mode=rstp
/ip address
add address=192.168.88.1/24 interface=bridge1 network=192.168.88.0
"""
    JUNIPER_SMALLER = """set system host-name edge-01
set system root-authentication encrypted-password "$6$abcdef"
set system services ssh protocol-version v2
set system ntp server 10.1.1.1
"""

    @pytest.mark.parametrize("text, id_", [
        (MIKROTIK_SMALLER, "the-corpus-MikroTik-with-two-stanzas-removed-133B"),
        (JUNIPER_SMALLER, "the-corpus-Juniper-set-with-three-lines-removed-166B"),
    ])
    def test_a_complete_config_from_an_unsupported_vendor_is_not_a_capture_failure(self, text, id_):
        verdict, why = _verdict(text)
        assert verdict == "ok", f"FALSE POSITIVE ({id_}): {why}"

    def test_it_lands_in_not_assessed_at_INFO__the_pre_existing_coverage_gap_path(self, tmp_path):
        """The regression this arm caused, stated as the operator sees it: before the gate
        existed this file produced not_assessed/INFO, and the gate turned it into
        capture_failed/ERROR — a worse defect than the one the gate fixes."""
        (tmp_path / "mt-01.cfg").write_text(self.MIKROTIK_SMALLER)
        ext = _ext(tmp_path)
        ext.poll()

        # Scoped to the DEVICE. An archive-scoped drift notice can ride alongside
        # (this fixture is a plain directory, so no golden ref resolves) and it is
        # not what this test is about.
        notice = [r for r in ext.emitted
                  if r["log.source"] == "network.compliance" and r["host.name"]]
        assert len(notice) == 1
        assert notice[0]["compliance.status"] == "not_assessed"
        assert notice[0]["severity"] == "INFO"

    def test_a_stub_WITH_refusal_evidence_is_still_unusable(self):
        """The true positive the arm was written for keeps firing: same size, same line count,
        but now carrying a command header and a caret marker."""
        assert _verdict("""!COMMAND: show running-config
                  ^
router one
router two
""") == ("unusable", "stub_capture")


class TestErrorsAreCorroboratedByProvenanceNotProximity:
    """FALSE NEGATIVE both ways round, from a three-line adjacency window that bought nothing.

    Measured across all eleven fixtures in TestSmallButValidMustNeverBeFlagged, the adjacency
    clause discarded exactly ZERO false positives — the banner mask alone already took
    HOSTILE_BANNER from one raw grammar hit to none, and every other fixture had none to begin
    with. The ACL remark it was written for never matches the grammar at all, because the
    grammar anchors at line start and that line starts with "remark".
    """

    NO_HEADER_AUTH_FAILURE = """% Authentication failed.
% Authorization failed.
Building configuration...
service timestamps debug datetime msec
hostname LAB-9300-1-1
enable secret 9 $9$Qd3kFcoreHASH
aaa new-model
ip cef
interface GigabitEthernet1/0/1
 switchport mode access
"""
    TACACS_MID_CAPTURE = """!COMMAND: show running-config
service timestamps debug datetime msec
hostname LAB-CORE-1
enable secret 9 $9$hash
aaa new-model
ip cef
interface GigabitEthernet1/0/1
 switchport mode access
Command authorization failed.
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 40
"""

    def test_an_auth_failure_at_the_TOP_of_a_headerless_capture_is_caught(self):
        """Many Oxidized models emit no "!COMMAND:" header at all, so there was nothing within
        three lines to corroborate against and this graded, inventing 7 FAILs."""
        assert _verdict(self.NO_HEADER_AUTH_FAILURE) == ("suspect", "cli_error_mid_capture")

    def test_a_tacacs_refusal_far_below_the_only_header_is_caught(self):
        assert _verdict(self.TACACS_MID_CAPTURE) == ("suspect", "cli_error_mid_capture")

    def test_an_engineer_comment_using_error_vocabulary_is_NOT_caught(self):
        """The false positive the old EOF branch had, and the reason proximity was replaced by
        provenance rather than simply deleted. This line is not '%'-prefixed and the artefact
        is not a command transcript, so nothing corroborates it as device output."""
        assert _verdict(IOS_FULL + "! access denied logging reviewed quarterly\n") == ("ok", "")

    def test_the_banner_mask_is_still_what_saves_HOSTILE_BANNER(self):
        assert _verdict(HOSTILE_BANNER) == ("ok", "")

    def test_a_comment_prefixed_percent_error_is_still_corroborated(self):
        """The comment character is what separates an engineer's note from device output —
        but only for errors WITHOUT a '%'. Oxidized comment-prefixes the output it stores, so
        the measured artefact's own error lines are "!% Invalid input detected at '^' marker."
        and all three must still count."""
        lines = [l for l in BAD_272.splitlines() if l.strip()]
        assert len(_err_indices(lines)) == 3


class TestCleanTruncationOfAFingerprintedConfig:
    """Residual risk 1, which was NOT actually covered before this round.

    The three arms claimed to cover it are pager residue (absent in a clean cut), CLI error
    text (absent) and shrinkage vs history (unreachable behind the fast path, unable to fire
    below prev=853B, and self-poisoning after one poll). What is left is the end-of-config
    marker, which needs no git and no history.
    """

    def test_the_full_config_is_healthy_and_fails_nothing(self):
        assert _verdict(IOS_FULL) == ("ok", "")
        assert _fails(IOS_FULL) == []

    @pytest.mark.parametrize("fraction", [0.30, 0.41, 0.50, 0.75, 0.95])
    def test_truncation_still_fingerprints_and_still_invents_failures(self, fraction):
        """The damage, measured rather than asserted — including at 95%, where every
        size-based signal is blind."""
        cut = _truncate(IOS_FULL, fraction)
        assert detect_platform(cut)["id"] == "cisco-ios"
        assert len(_fails(cut)) == 7, "controls that ARE configured, graded FAIL"

    @pytest.mark.parametrize("fraction", [0.30, 0.41, 0.50, 0.75, 0.95])
    def test_and_every_one_of_them_is_now_gated_without_git(self, fraction):
        assert _verdict(_truncate(IOS_FULL, fraction)) == ("suspect", "no_end_of_config_marker")

    @pytest.mark.parametrize("fraction", [0.2, 0.3, 0.5, 0.8])
    def test_the_repo_goldens_are_covered_too__they_are_all_under_the_shrink_floor(self, fraction):
        """SHRINK_MIN_DROP=512 with SHRINK_RATIO=0.40 requires 0.6*prev > 512, so the shrinkage
        arm CANNOT fire for any config under 853B — which is all three repo goldens."""
        assert all(len(g.encode()) < 853 for g in (GOLDEN_9300, GOLDEN_ACCESS, GOLDEN_SDWAN))
        assert _verdict(_truncate(GOLDEN_9300, fraction))[1] == "no_end_of_config_marker"

    def test_the_gate_suppresses_grading_and_drift_for_it(self, tmp_path):
        _repo(tmp_path)
        _commit(tmp_path, "LAB-9300-1-1.cfg", IOS_FULL)
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "LAB-9300-1-1.cfg", _truncate(IOS_FULL, 0.5), "session died")

        ext = _ext(tmp_path)
        ext.poll()

        assert len(ext.emitted) == 1
        assert ext.emitted[0]["config.capture.reason"] == "no_end_of_config_marker"
        assert ext.emitted[0]["severity"] == "WARN"
        assert _controls(ext) == []
        assert [r for r in ext.emitted if r["log.source"] == "network.config"] == []

    def test_a_truncated_revision_can_no_longer_poison_the_shrink_reference(self, tmp_path):
        """_prev_good_bytes accepts a historical blob as "last good" only if it assesses ok.
        Before the terminator arm a truncated blob assessed ok, so after ONE poll the reference
        became the truncation itself and the arm never fired again."""
        ext = _ext(tmp_path)
        assert assess_capture(_truncate(IOS_FULL, 0.5),
                              detect_platform(IOS_FULL))[0] != "ok"

    def test_frr_is_covered_and_the_brace_vendors_are_deliberately_not(self):
        assert set(TERMINATORS) == {"cisco-ios", "arista-eos", "frr"}
        assert _verdict(MIN_FRR) == ("ok", "")
        assert _verdict(_truncate(MIN_FRR, 0.5)) == ("suspect", "no_end_of_config_marker")
        # A brace fragment is legitimately unterminated; asserting a marker for these would be
        # an untested vendor-doc claim of exactly the kind PLATFORMS' `verified` flag prevents.
        for text in (SRL_FRAGMENT, SRL_FULL, JUNIPER_SET, PANOS_XML, FASTPATH_VALID):
            assert _verdict(text) == ("ok", "")


class TestShrinkageArmIsReachableAndProportionate:
    """Three defects in one arm: it could not fire, and where it could it fired on the wrong
    thing and then silenced the device."""

    def test_the_fast_path_no_longer_shadows_it(self):
        """It returned before prev_good_bytes was read, so the arm could only fire on captures
        with FEWER than 20 substantive lines — never on a real switch config. The existing
        green test passed only because PARTIAL_CISCO happens to have 8."""
        big = SRL_FULL + "".join(
            f"    interface ethernet-1/{n} {{\n        admin-state enable\n    }}\n"
            for n in range(1, 20))
        _, _, ev = assess_capture(big, detect_platform(big))
        assert ev["substantive"] >= 20, "must be past the fast-path threshold to be a real test"
        assert _verdict(big, prev_good=10_000_000) == ("suspect", "shrank_vs_last_good")

    def test_it_is_restricted_to_platforms_we_would_actually_grade(self, tmp_path):
        """FALSE POSITIVE, and a permanent one. An operator deleting 40 obsolete MikroTik
        firewall rules (3094B -> 223B) was reported capture_partial on EVERY poll forever:
        Oxidized only commits on change, so the large revision never leaves the lookback
        window. On a platform with no rule set, suppression protects no grading at all — it
        only costs the alarm."""
        _repo(tmp_path)
        big = MIKROTIK + "".join(
            f"/ip firewall filter\nadd chain=forward action=drop dst-port={p} protocol=tcp\n"
            for p in range(1000, 1040))
        _commit(tmp_path, "mt-01.cfg", big, "before cleanup")
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "mt-01.cfg", MIKROTIK, "operator removed 40 obsolete rules")

        ext = _ext(tmp_path)
        ext.poll()

        assert [r for r in ext.emitted if "config.capture.status" in r] == []
        assert [r["compliance.status"] for r in ext.emitted
                if r["log.source"] == "network.compliance"] == ["not_assessed"]

    def test_when_it_does_fire_it_no_longer_silences_drift(self, tmp_path):
        """A large config reduction is precisely the event network.config exists to report, and
        suppressing it produced NO drift record at all, permanently. Shrinkage is the one arm
        with no in-file evidence of corruption — "the file got smaller" is textually identical
        for a truncation and for a real edit — so the diff is reported as the fact it is while
        grading stays suppressed."""
        _repo(tmp_path)
        big = SRL_FULL + "".join(
            f"    interface ethernet-1/{n} {{\n        admin-state enable\n    }}\n"
            for n in range(1, 60))
        _commit(tmp_path, "srl-1.cfg", big, "before")
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "srl-1.cfg", SRL_FRAGMENT, "after")

        ext = _ext(tmp_path)
        ext.poll()

        capture = [r for r in ext.emitted if r.get("config.capture.reason") == "shrank_vs_last_good"]
        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(capture) == 1 and capture[0]["severity"] == "WARN"
        assert len(drift) == 1 and drift[0]["config.drift_from_golden"] == "yes"
        # ...but never graded: if it IS a truncation, grading invents FAILs.
        assert _controls(ext) == []

    def test_every_other_reason_still_suppresses_drift(self, tmp_path):
        """Residual risk 3: a bad artefact replacing a good one must not produce a whole-config
        spurious DRIFTED. Shrinkage is the single, argued exception."""
        _repo(tmp_path)
        _commit(tmp_path, "sw-lon-01.cfg", GOLDEN_9300)
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "sw-lon-01.cfg", BAD_272, "enable rejected")

        ext = _ext(tmp_path)
        ext.poll()

        assert [r for r in ext.emitted if r["log.source"] == "network.config"] == []


class TestGitPathsResolveFromTheRightDirectory:
    """Two independent path bugs, each of which disabled a whole feature fleet-wide and each
    of which reinstated the affirmative false all-clear the _git returncode flag was added to
    remove. Neither was visible to a test that puts everything in the repo root."""

    def test_configPath_below_the_repo_root_still_gets_shrinkage(self, tmp_path):
        """`git show <rev>:<path>` resolves from the REPOSITORY ROOT; only `<rev>:./<path>` is
        relative to -C's directory. `git log -- <rel>` on the line above IS -C-relative, so the
        lookup half-worked and then failed on every blob — two warnings per device per poll and
        the arm dead — the moment configPath was the documented "checkout with configs in a
        subdirectory" layout."""
        _repo(tmp_path)
        big = SRL_FULL + "".join(
            f"    interface ethernet-1/{n} {{\n        admin-state enable\n    }}\n"
            for n in range(1, 60))
        _commit(tmp_path, "configs/srl-1.cfg", big, "good")
        _commit(tmp_path, "configs/srl-1.cfg", SRL_FRAGMENT, "regression")

        ext = _ext(tmp_path / "configs")
        ext.poll()

        assert ext.emitted[0]["config.capture.reason"] == "shrank_vs_last_good"
        assert int(ext.emitted[0]["config.capture.prev_bytes"]) == len(big.encode())

    def test_a_nested_deviceGlob_still_sees_real_drift(self, tmp_path):
        """Oxidized writes one directory per group the moment `groups:` is configured, and
        deviceGlob is free text with no constraint against subdirectories. With a basename
        pathspec every diff matched NOTHING — and `git diff` exits 0 for a pathspec that
        matches nothing, so the returncode guard cannot see it and empty stdout read as
        "no drift". This device swapped SSH for telnet and was reported as matching golden."""
        _repo(tmp_path)
        _commit(tmp_path, "core/LAB-9300-1-1.cfg", GOLDEN_9300)
        _git(tmp_path, "branch", "golden")
        _commit(tmp_path, "core/LAB-9300-1-1.cfg",
                GOLDEN_9300.replace("transport input ssh", "transport input telnet"), "drift")

        ext = _ext(tmp_path, deviceGlob="*/*.cfg")
        ext.poll()

        drift = [r for r in ext.emitted if r["log.source"] == "network.config"]
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert drift[0]["severity"] == "WARN"
        assert "+ transport input telnet" in drift[0]["config.diff"]


class TestUntrackedFileIsUnknownNotClean:
    """The third route to the same false all-clear. `git diff <ref> HEAD -- <pathspec>` exits 0
    with empty stdout when the pathspec matches nothing in either tree — the command genuinely
    succeeded, it just compared nothing — so the returncode guard added earlier cannot see it.
    """

    def test_a_device_absent_from_the_golden_ref_reports_unknown(self, tmp_path):
        _repo(tmp_path)
        _commit(tmp_path, "LAB-9300-1-1.cfg", GOLDEN_9300)
        _git(tmp_path, "branch", "golden")
        # A node Oxidized has only just started capturing: on disk, never committed.
        (tmp_path / "LAB-SDWAN-8200-1.cfg").write_text(GOLDEN_SDWAN)

        ext = _ext(tmp_path)
        ext.poll()

        by_host = {r["host.name"]: r for r in ext.emitted if r["log.source"] == "network.config"}
        assert by_host["LAB-SDWAN-8200-1"]["config.drift_from_golden"] == "unknown"
        assert "NOT COMPARED" in by_host["LAB-SDWAN-8200-1"]["content"]
        # ...and the device that IS in the ref is still compared for real.
        assert by_host["LAB-9300-1-1"]["config.drift_from_golden"] == "no"


class TestAConfigStoredAgainstTheWrongDevice:
    """The worst REPORTED outcome found: a device vanishes from the poll entirely.

    An Oxidized session bleed writes one device's config into another's file. Both files are
    perfectly valid configs and the gate had no identity test, so host.name came from the
    config text: the victim emitted ZERO records — no capture failure, no not_assessed, no
    drift — and no consumer can query an absence, while the innocent device received a doubled
    record set carrying drift=yes AND drift=no in the same poll.
    """

    def test_the_victim_still_reports_and_says_why(self, tmp_path):
        (tmp_path / "LAB-9300-1-1.cfg").write_text(GOLDEN_SDWAN)      # bled
        (tmp_path / "LAB-SDWAN-8200-1.cfg").write_text(GOLDEN_SDWAN)
        ext = _ext(tmp_path)
        ext.poll()

        victim = [r for r in ext.emitted if r["host.name"] == "LAB-9300-1-1"]
        assert len(victim) == 1
        assert victim[0]["compliance.status"] == "capture_failed"
        assert victim[0]["config.capture.reason"] == "wrong_device_config"
        assert victim[0]["severity"] == "ERROR"
        assert "DIFFERENT node" in victim[0]["content"]

    def test_the_innocent_device_is_not_doubled_or_contradicted(self, tmp_path):
        (tmp_path / "LAB-9300-1-1.cfg").write_text(GOLDEN_SDWAN)
        (tmp_path / "LAB-SDWAN-8200-1.cfg").write_text(GOLDEN_SDWAN)
        ext = _ext(tmp_path)
        ext.poll()

        innocent = [r for r in ext.emitted if r["host.name"] == "LAB-SDWAN-8200-1"]
        assert len(_controls(ext)) == len(detect_platform(GOLDEN_SDWAN)["controls"])
        assert len([r for r in innocent if r["log.source"] == "network.config"]) == 1

    def test_nodes_named_by_IP_are_not_flagged(self, tmp_path):
        """The check is collision-based, not equality-based. hostname != filename is the NORMAL
        case for any archive whose nodes are named by management IP or inventory ID; it only
        trips when the parsed hostname belongs to a DIFFERENT file in the same poll."""
        (tmp_path / "10.88.40.10.cfg").write_text(GOLDEN_9300)
        (tmp_path / "10.88.40.11.cfg").write_text(GOLDEN_SDWAN)
        ext = _ext(tmp_path)
        ext.poll()

        assert [r for r in ext.emitted if "config.capture.status" in r] == []
        assert {r["host.name"] for r in ext.emitted if r["host.name"]} == {"LAB-9300-1-1", "LAB-SDWAN-8200-1"}


class TestMalformedInputCannotStallThePoll:
    """A hang is worse than a crash: no exception reaches the SDK, the scheduled callback never
    returns and the poll thread is pinned.

    _ERR was "^\\s*[!#]?\\s*(?:<18-way alternation>)" — three quantified whitespace runs in
    sequence in front of an alternation, matched twice per line of every artefact. Cost was
    cubic in the length of a line's INDENTATION: 100 leading blanks 26ms, 200 187ms, 1000 21s.
    """

    def test_a_pathological_artefact_is_assessed_promptly(self, tmp_path):
        (tmp_path / "bad.cfg").write_text("".join(" " * 300 + f"line {i}\n" for i in range(20)))
        ext = _ext(tmp_path)
        start = time.perf_counter()
        ext.poll()
        assert time.perf_counter() - start < 2.0, "measured 26.0s before the fix"

    def test_the_grammar_is_unchanged__this_was_a_performance_fix_only(self):
        """Splitting one regex into two must not quietly re-scope what counts as an error, so
        the old single-pattern form is reconstructed here and compared line by line against
        every fixture in this file."""
        old = re.compile(r"^\s*[!#]?\s*(?:" + "|".join(_ERR_PHRASES) + r")", re.I)
        compared = 0
        for text in _all_fixtures():
            for line in text.splitlines():
                compared += 1
                assert bool(old.match(line)) == bool(_is_err(line)), repr(line)
        assert compared > 250


class TestEveryArmIsReachableAndExplainsItself:
    """Structural guards, added because four of the ladder's arms had no fixture at all in the
    first round and three of the four later turned out to be defective."""

    ARM_FIXTURES = {
        "no_content": BAD_272,
        "cli_refused": "!!COMMAND: show running-config\n!% Invalid input detected at '^' marker.\n"
                       "!!COMMAND: show version\n!% Invalid input detected at '^' marker.\n"
                       "some residual line\nanother residual line\n",
        "mostly_command_echo": "!COMMAND: show version\n!COMMAND: show inventory\n"
                               "!COMMAND: show running-config\n!COMMAND: show vlan\n"
                               "hostname sw1\ninterface gi1\n",
        "stub_capture": "!COMMAND: show running-config\n                  ^\nrouter one\nrouter two\n",
        "pager_truncation": PAGER_TRUNCATED,
        "cli_error_mid_capture": TestErrorsAreCorroboratedByProvenanceNotProximity.TACACS_MID_CAPTURE,
        "no_end_of_config_marker": PARTIAL_CISCO,
        "too_little_content_to_grade": "set deviceconfig system hostname fw-01\n"
                                       "set deviceconfig system ntp-servers primary 10.1.1.1\n"
                                       "set rulebase security rules allow-web action allow\n"
                                       "set deviceconfig system permitted-ip 10.0.0.0/8\n",
    }

    @pytest.mark.parametrize("reason", sorted(ARM_FIXTURES))
    def test_the_arm_can_actually_be_reached(self, reason):
        assert _verdict(self.ARM_FIXTURES[reason])[1] == reason

    def test_shrinkage_and_wrong_device_are_covered_by_their_own_classes(self):
        """Every reason has a fixture SOMEWHERE, and the exceptions are named, not implied.

        The archive- and identity-shape reasons are excluded from ARM_FIXTURES because none is
        reachable from `_verdict(text)`: archive_empty is a property of the ARCHIVE (no device
        text exists to assess), archive_non_config needs the auto_discovered flag, and
        duplicate_device_name is a property of the POLL (it needs a second device in the same
        pass). All are covered end to end in tests/test_archive_and_identity.py —
        TestEmptyArchiveIsNeverSilent, TestAutoDiscoverySweepsCarefully and
        TestDuplicateDeviceNameIsNotACaptureFailure.

        The three FRESHNESS reasons are excluded for the same structural reason: they describe
        whether the archive could be REACHED, which no artefact's text can express. They are
        covered end to end in tests/test_remote_archive.py — TestRemoteUnreachableWithAWarmMirror
        (archive_stale), TestStalenessIsNeverSilent (archive_stale_refused) and
        TestRemoteUnreachableWithNoMirror (archive_unreachable).

        The last two are excluded on the same "not a property of any artefact's text" grounds.
        archive_unreadable_file is a property of the OBJECT STORE (the archive lists the file
        and cannot produce its bytes, so there is no text to assess) and archive_path_missing
        is a property of the FILESYSTEM (configPath is not a directory, so there is no archive
        at all). Both are covered end to end in test_archive_and_identity.py —
        TestUnreadableBlobsAreNeverSilent and TestLocalArchiveUnreachableIsNeverSilent.

        An unresolvable golden ref is deliberately NOT in this table at all: it is a drift
        precondition, not a capture outcome, so it carries no config.capture.reason. See
        GOLDEN_MISSING_REMEDIATION and TestMissingGoldenRefIsNeverSilent.
        """
        assert set(self.ARM_FIXTURES) | {"shrank_vs_last_good", "wrong_device_config",
                                         "archive_empty", "archive_non_config",
                                         "duplicate_device_name", "archive_unreachable",
                                         "archive_stale", "archive_stale_refused",
                                         "archive_unreadable_file", "archive_path_missing"} \
            == set(CAPTURE_REASONS)

    @pytest.mark.parametrize("reason", sorted(CAPTURE_REASONS))
    def test_every_reason_carries_operator_facing_remediation(self, reason):
        """The reason code is what a detector fires on; this sentence is what lands in the
        ticket, and requirement 2 is not met by a status field nobody reads at 03:00."""
        text = CAPTURE_REASONS[reason]
        assert len(text) > 60 and text[-1] not in ".!"

    def test_the_record_never_enters_the_per_control_channel(self, tmp_path):
        """Every consumer filters on isNotNull(compliance.control). A device-level notice that
        carried one would be counted as a control result."""
        for name, text in (("a.cfg", BAD_272), ("b.cfg", PAGER_TRUNCATED),
                           ("c.cfg", _truncate(IOS_FULL, 0.5))):
            (tmp_path / name).write_text(text)
        ext = _ext(tmp_path)
        ext.poll()

        capture = [r for r in ext.emitted if "config.capture.status" in r]
        assert len(capture) == 3
        assert all("compliance.control" not in r for r in capture)
        assert all(r["log.source"] == "network.compliance" for r in capture)
        assert all(r["dt.source"] == "cno-config" for r in capture)


class TestTheExtendedFalsePositiveCorpus:
    """The load-bearing class, second round. TestSmallButValidMustNeverBeFlagged has eleven
    cases and all eleven land in the fast path or the trailing `return "ok"` — none of them can
    exercise an arm that fires, which is how four false positives shipped in arms no fixture
    reached. These are the shapes that actually broke it: real configs carrying pager words,
    error vocabulary, refused auxiliary commands and legitimate deletions.
    """

    CASES = {
        "IOS behind a 3-command Oxidized model, all succeeding":
            "!!COMMAND: show version\n!Cisco IOS XE Software, Version 17.09.04a\n"
            "!!COMMAND: show running-config\n" + IOS_FULL,
        "IOS where ONE auxiliary command is unsupported":
            TestBenignAuxCommandMustNotSilenceTheDevice.AUX_REFUSED,
        "IOS + trailing engineer comment using error vocabulary":
            IOS_FULL + "! access denied logging reviewed quarterly\n",
        "IOS + ACL remark full of error words": IOS_FULL.replace(
            "end\n", "ip access-list extended X\n remark deny - permission denied, log all "
                     "unknown command attempts\n permit tcp any any eq 22\nend\n"),
        "IOS + snmp-server location containing 'MORE:'": IOS_FULL.replace(
            "end\n", 'snmp-server location "Rack12 DC2 MORE: wiki/net/dc2"\nend\n'),
        "IOS + banner saying 'Press any key to continue'": IOS_FULL.replace(
            "end\n", "banner motd ^C\nAuthorized access only. Press any key to "
                     "continue.\n^C\nend\n"),
        "IOS + banner full of error phrases": IOS_FULL.replace(
            "end\n", "banner motd ^C\n% Unauthorized access is prohibited.\n"
                     "% Permission denied notices are generated.\n^C\nend\n"),
        "IOS + exec-timeout as ordinary configuration": IOS_FULL.replace(
            "end\n", "line con 0\n exec-timeout 5 0\nend\n"),
        "MikroTik with two stanzas removed":
            TestStubCaptureNeedsEvidenceOfARefusal.MIKROTIK_SMALLER,
        "Juniper set-format with three lines removed":
            TestStubCaptureNeedsEvidenceOfARefusal.JUNIPER_SMALLER,
        "Cumulus /etc/network/interfaces":
            "auto lo\niface lo inet loopback\nauto swp1\niface swp1\n  bridge-access 10\n"
            "auto bridge\niface bridge\n  bridge-ports swp1 swp2\n  bridge-vids 10 20\n",
        "PAN-OS set format":
            "set deviceconfig system hostname fw-01\n"
            "set deviceconfig system ntp-servers primary-ntp-server address 10.1.1.1\n"
            "set rulebase security rules allow-web action allow\n"
            "set deviceconfig system permitted-ip 10.0.0.0/8\n"
            "set zone trust network layer3 ethernet1/1\n"
            "set shared authentication-profile ldap method ldap\n",
        "Nokia SR Linux, full": SRL_FULL,
    }

    @pytest.mark.parametrize("name", sorted(CASES))
    @pytest.mark.parametrize("prev_good", [None, 700])
    def test_no_valid_config_is_ever_flagged(self, name, prev_good):
        verdict, why = _verdict(self.CASES[name], prev_good)
        assert verdict == "ok", f"FALSE POSITIVE ({name}, prev={prev_good}): {why}"

    def test_the_first_round_corpus_is_still_clean_too(self):
        for text in (GOLDEN_9300, GOLDEN_ACCESS, GOLDEN_SDWAN, MIN_FRR, MIKROTIK,
                     FASTPATH_VALID, JUNIPER_SET, SRL_FRAGMENT, HOSTILE_BANNER,
                     PANOS_XML, TIMEOUT_WORDS):
            assert _verdict(text) == ("ok", "")

    def test_and_none_of_this_cost_a_true_positive(self):
        assert _verdict(BAD_272)[0] == "unusable"
        assert _verdict(STUB_UNPRIVILEGED)[0] == "unusable"
        assert _verdict(ENABLE_REJECTED)[0] == "unusable"
        assert _verdict(PAGER_TRUNCATED) == ("suspect", "pager_truncation")
        assert _verdict(PARTIAL_CISCO) == ("suspect", "no_end_of_config_marker")
        assert _verdict(_truncate(IOS_FULL, 0.95)) == ("suspect", "no_end_of_config_marker")
