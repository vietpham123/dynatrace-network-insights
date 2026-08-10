"""Tests for reading a REAL Oxidized archive, and for device identity.

Two defects measured against the live lab on 2026-08-02, both of which blocked the compliance
capability for a customer following our own deployment guide:

  DEFECT 1  The extension read ZERO files from a correctly-configured Oxidized archive.
            docs/CUSTOMER-HANDOFF.md tells customers to use Oxidized's git output backend.
            That backend produces a BARE repository — no working tree, nothing on disk to
            glob — and stores each device as a tracked blob named after the NODE with no file
            extension ("outpost", 5494 bytes). glob("*.cfg") matched nothing, so the module
            emitted nothing at all. Not not_assessed: total silence, which no consumer can
            query. TestBareGitArchive and TestEmptyArchiveIsNeverSilent pin both halves.

  DEFECT 2  device.address was EMPTY for 100% of the corpus and host.name was right by luck.
            The real FASTPATH capture has no `hostname` line — its name is
            `snmp-server sysname "outpost"` and its address `network parms 10.0.10.3 ...` —
            and device.address is the join key the SNMP entity idPattern, fleetLogScope() and
            the three RCA workflows are all built on. TestRealFastpathCapture is the anchor.

The class that matters most here is TestGitFailureNeverReportsAMatch. Everything else adds
signal; that one protects the property the whole module was hardened around — a git failure
must never be reported as "matches golden". Reading configs out of git multiplies the number
of ways git can fail (bare repos, foreign ownership, unborn HEAD, binary blobs), so every one
of those failure modes is asserted to land on "unknown", never on a clean bill of health.
"""
import logging
import os
import re
import subprocess

import pytest

from oxidized_extension.__main__ import (
    AUTO_GLOB, CAPTURE_REASONS, ComplianceExtension, IDENTITY, PLATFORMS, _JUN_MGMT,
    _SRL_MGMT, _brace_mgmt_address, _is_gitdir, _node_stem, admits, assess_capture,
    detect_platform,
)

ARTEFACTS = os.path.join(os.path.dirname(__file__), "artefacts")

# The REAL capture Oxidized stored for the lab's Netgear GSM7248V2 on 2026-08-02, 5494 bytes,
# copied out of the archive's git object store. Two changes and only two, both documented in
# the file itself: the two distinct 128-hex password hashes were replaced with obviously-fake
# constants and the chassis serial number was redacted, because this repository is a customer
# deliverable and those are real credentials from a real switch.
#
# Every line this test suite reasons about is byte-identical to the archive:
#   line 46  set prompt "GSM7248V2"                            <- the MODEL, a decoy
#   line 49  network parms 10.0.10.3 255.255.255.0 10.0.10.1    <- the management address
#   line 82  snmp-server sysname "outpost"                      <- the SNMP sysName
# Verified equivalent to the untouched original: same platform (netgear), same verdict
# ("ok", ""), same _meta output ('outpost', '10.0.10.3', 'snmp_sysname', 'network_parms').
#
# This replaces reliance on the FASTPATH_VALID fixture in test_capture_health.py for anything
# vendor-factual. That fixture uses `hostname "lab-gsm7248"`, which is FABRICATED syntax —
# real FASTPATH emits zero `hostname` lines — so a fix validated only against it still fails
# in the lab. It is kept there, and exercised below, purely as a quoted-name case.
REAL_FASTPATH = open(os.path.join(ARTEFACTS, "gsm7248v2-fastpath-good.cfg")).read()

# The 272-byte FAILED capture from the same switch, verbatim: Oxidized authenticated, had its
# 'enable' rejected, had every command refused, stored the refusal and marked the node
# "success". test_capture_health.py transcribes this as BAD_272 (271 bytes — one byte of
# trailing whitespace lost in transcription); this is the artefact itself.
REAL_REFUSED = open(os.path.join(ARTEFACTS, "gsm7248v2-refused.cfg")).read()


def _ext(path, **cfg):
    """A ComplianceExtension with no SDK lifecycle — same construction as test_capture_health."""
    ext = object.__new__(ComplianceExtension)
    ext.logger = logging.getLogger("test-oxidized-extension")
    ext.emitted = []
    ext._cfg = lambda: {"configPath": str(path), **cfg}
    ext.report_log_events = ext.emitted.extend
    return ext


def _git(d, *args, check=True):
    return subprocess.run(["git", "-C", str(d), *args], check=check,
                          capture_output=True, text=True)


def _bare_archive(tmp_path, blobs, branch="main"):
    """A bare repository shaped exactly like Oxidized's git output backend.

    Built by committing in a scratch worktree and pushing, because that is the only way to get
    a bare repo whose HEAD resolves. Blob names carry NO extension, which is the whole point:
    Oxidized names each blob after the node.
    """
    bare = tmp_path / "configs.git"
    work = tmp_path / "_work"
    _git(tmp_path, "init", "-q", "--bare", str(bare))
    work.mkdir()
    _git(work, "init", "-q", "-b", branch)
    _git(work, "config", "user.email", "test@example.invalid")
    _git(work, "config", "user.name", "test")
    for name, text in blobs.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text(text)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "capture")
    _git(work, "push", "-q", str(bare), f"{branch}:{branch}")
    _git(bare, "symbolic-ref", "HEAD", f"refs/heads/{branch}")
    return bare


def _recommit(bare, blobs, branch="main", msg="capture"):
    """Add another revision to a bare archive, the way Oxidized commits each new capture."""
    work = bare.parent / "_work"
    for name, text in blobs.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text(text)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", msg)
    _git(work, "push", "-q", str(bare), f"{branch}:{branch}")


class _foreign_owner:
    """Make git treat the repository as owned by another user, for the length of a block.

    GIT_TEST_ASSUME_DIFFERENT_OWNER is git's own switch for this and produces the identical
    failure the lab produces: rc 128 "fatal: detected dubious ownership in repository at ...".
    The alternative — actually chown'ing to another uid — needs root, which a test suite must
    not need. Verified 2026-08-02 that the two paths are indistinguishable to this module:
    every plumbing command exits 128 (diff 129) and the narrow safe.directory grant fixes both.
    """

    def __enter__(self):
        os.environ["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"

    def __exit__(self, *exc):
        os.environ.pop("GIT_TEST_ASSUME_DIFFERENT_OWNER", None)
        return False


def _named(text, name):
    """The same FASTPATH capture under a different sysName, for multi-device fixtures."""
    return text.replace('snmp-server sysname "outpost"', f'snmp-server sysname "{name}"')


def _controls(ext):
    return [r for r in ext.emitted if "compliance.control" in r]


def _drift(ext):
    return [r for r in ext.emitted if r["log.source"] == "network.config"]


# ══════════════════════════════════════════════════════════════════════════════════════════
# DEFECT 1 — reading a real Oxidized archive
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestBareGitArchive:
    """The deployment shape docs/CUSTOMER-HANDOFF.md recommends, which read zero files."""

    def test_a_bare_repo_has_nothing_on_disk_to_glob(self, tmp_path):
        """The reproduction, before any assertion about the fix.

        This is why the defect is total silence rather than a wrong answer: there is no file
        anywhere under configPath for the old `glob(path + "/*.cfg")` to return, and the blob
        that IS there has no extension, so even a working tree would not have matched.
        """
        import glob as _glob
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})

        assert _git(bare, "rev-parse", "--is-bare-repository").stdout.strip() == "true"
        assert _glob.glob(os.path.join(str(bare), "*.cfg")) == []
        listed = _git(bare, "ls-tree", "-r", "--name-only", "HEAD").stdout.split()
        assert listed == ["outpost"], "Oxidized names the blob after the NODE, no extension"

    def test_the_device_is_read_graded_and_identified(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        assert ext.emitted, "0 records is the defect: an absence cannot be queried"
        assert len(_controls(ext)) == len(detect_platform(REAL_FASTPATH)["controls"])
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert {r["device.address"] for r in _controls(ext)} == {"10.0.10.3"}
        assert [r for r in ext.emitted if "config.capture.status" in r] == []

    def test_grouped_nodes_in_subdirectories_are_read_too(self, tmp_path):
        """Oxidized writes one directory per group the moment `groups:` is configured, and in
        the git backend those become path-bearing blob names, still with no extension."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH,
                                        "edge/branch-sw1": _named(REAL_FASTPATH, "branch-sw1")})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost", "branch-sw1"}
        assert [r for r in ext.emitted if "config.capture.status" in r] == [], \
            "both captures are healthy; neither may be reported as a capture problem"
        assert {r["device.address"] for r in _controls(ext)} == {"10.0.10.3"}

    def test_a_failed_capture_in_a_bare_archive_still_reports_as_failed(self, tmp_path):
        """The capture-health gate must reach artefacts read out of git, not just off disk."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_REFUSED})
        ext = _ext(bare)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "capture_failed"
        assert rec["config.capture.reason"] == "no_content"
        assert rec["config.capture.bytes"] == "272"      # the artefact's true size
        assert rec["severity"] == "ERROR"
        assert _controls(ext) == []
        assert _drift(ext) == []

    def test_drift_is_computed_against_a_golden_ref_in_a_bare_archive(self, tmp_path):
        """`<rev>:./<path>` — the spelling this module used everywhere — is rc 128 on a bare
        repo ("relative path syntax can't be used outside working tree"), so before this change
        the shrinkage arm and the `tracked` probe both died on every device, every poll."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        _git(bare, "branch", "golden", "main")
        _recommit(bare, {"outpost": REAL_FASTPATH.replace('snmp-server location "basement"',
                                                          'snmp-server location "roof"')})
        ext = _ext(bare)
        ext.poll()

        drift = _drift(ext)
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert '+snmp-server location "roof"' in drift[0]["config.diff"]

    def test_the_shrinkage_arm_works_in_a_bare_archive(self, tmp_path):
        """The clean-truncation guard, which needs `git log` + `git show` against blobs that
        exist only inside the object store."""
        # The drop has to clear BOTH SHRINK_RATIO (0.40) and SHRINK_MIN_DROP (512B), so the
        # previous revision must be well over twice the size of this one.
        big = REAL_FASTPATH + "".join(
            f"interface 0/{n}\nvlan pvid 10\nvlan participation include 10\nexit\n"
            for n in range(100, 400))
        bare = _bare_archive(tmp_path, {"outpost": big})
        _recommit(bare, {"outpost": REAL_FASTPATH}, msg="session died early")
        ext = _ext(bare)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["config.capture.reason"] == "shrank_vs_last_good"
        assert int(rec["config.capture.prev_bytes"]) == len(big.encode())


class TestPlainDirectoryStillWorksUnchanged:
    """Requirement 2. The file-output backend is a supported deployment and must not regress."""

    def test_a_plain_directory_of_cfg_files_is_read(self, tmp_path):
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        ext = _ext(tmp_path)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert len(_controls(ext)) == len(detect_platform(REAL_FASTPATH)["controls"])

    def test_an_explicit_glob_keeps_glob_semantics_exactly(self):
        """`*` must not cross a '/', or "*.cfg" would start matching grouped subdirectories
        that an operator's existing monitoring configuration has never included."""
        assert admits("sw1.cfg", "*.cfg") is True
        assert admits("edge/sw2.cfg", "*.cfg") is False
        assert admits("edge/sw2.cfg", "*/*.cfg") is True
        assert admits("sw1.cfg", "*/*.cfg") is False

    @pytest.mark.parametrize("rel, pattern", [
        ("sw1.txt", "*.txt"),          # ".txt" is on the AUTO extension deny-list
        ("sw1.json", "*.json"),
        ("logs/sw1.cfg", "*/*.cfg"),   # "logs" is on the AUTO directory deny-list
        ("info/sw1.cfg", "*/*.cfg"),
        ("README.md", "*.md"),         # "readme" is on the AUTO stem deny-list
    ])
    def test_the_auto_denylist_never_overrides_an_explicit_pattern(self, rel, pattern):
        """A regression I introduced and review caught before it shipped.

        Applying the AUTO deny-list to an explicit pattern silently broke two working
        deployments: deviceGlob="*.txt" matched nothing, and an Oxidized group literally named
        `logs` or `info` disappeared from "*/*.cfg". Both worked under the old glob, and
        nothing anywhere would have told the operator they had stopped — a device going silent
        is the failure class this whole module exists to remove. An explicit pattern is the
        operator ASSERTING these files are their devices; it outranks any heuristic of ours.
        """
        assert admits(rel, pattern) is True

    @pytest.mark.parametrize("rel, pattern", [(".hidden.cfg", "*.cfg"), (".git/x.cfg", "*/*.cfg")])
    def test_the_two_guards_that_do_survive_in_both_modes(self, rel, pattern):
        """glob.glob does not match dot-files, and the old code filtered `".git" not in f`."""
        assert admits(rel, pattern) is False

    def test_it_is_differentially_identical_to_the_glob_it_replaced(self, tmp_path):
        """Requirement 2 stated as strongly as it can be: for EVERY explicit pattern, the new
        lister returns exactly what `[f for f in glob.glob(path/pattern) if ".git" not in f]`
        returned. Asserting equivalence against the old implementation is what makes this
        provable rather than argued — the deny-list regressions above were both found this way,
        and neither was visible to any hand-written case.
        """
        import glob as _glob

        tree = ["sw1.cfg", "sw2.cfg", "sw1.txt", "notes.md", "README.md", ".hidden.cfg",
                "10.0.0.1.cfg", "core/sw3.cfg", "core/sw4.txt", "edge/sw5.cfg",
                "logs/sw6.cfg", "info/sw7.cfg", "deep/er/sw8.cfg", ".git/objects/x.cfg",
                "outpost", "edge/branch-sw1"]
        for rel in tree:
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x\n")

        ext = _ext(tmp_path)
        for pattern in ("*.cfg", "*/*.cfg", "*.txt", "*/*.txt", "sw1.cfg", "sw?.cfg", "*",
                        "*/*", "**.cfg", "core/*.cfg", "[se]*.cfg", "*.md", "deep/*/*.cfg"):
            old = sorted(
                os.path.relpath(f, str(tmp_path)).replace(os.sep, "/")
                for f in _glob.glob(os.path.join(str(tmp_path), pattern))
                if ".git" not in f and os.path.isfile(f))
            assert ext._list_disk(str(tmp_path), pattern) == old, f"diverged on {pattern!r}"

    def test_auto_finds_what_no_glob_pattern_was_ever_configured_for(self, tmp_path):
        """The other half: AUTO picks up the extension-less node blobs that are the ONLY thing
        Oxidized's git backend produces, and leaves repository housekeeping alone."""
        for rel in ("outpost", "edge/branch-sw1", "sw1.cfg", "README.md", ".hidden"):
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x\n")
        ext = _ext(tmp_path)

        assert ext._list_disk(str(tmp_path), AUTO_GLOB) == [
            "edge/branch-sw1", "outpost", "sw1.cfg"]

    def test_an_explicit_txt_pattern_works_end_to_end(self, tmp_path):
        (tmp_path / "outpost.txt").write_text(REAL_FASTPATH)
        ext = _ext(tmp_path, deviceGlob="*.txt")
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}

    def test_the_working_tree_wins_over_HEAD_in_a_non_bare_repo(self, tmp_path):
        """Disk-first is not inertia. In a non-bare repo the working tree is the CURRENT
        capture and HEAD is the last COMMITTED one, so reading HEAD would report yesterday's
        configuration as today's — silently, and only for git-backed deployments."""
        _git(tmp_path, "init", "-q", "-b", "main")
        _git(tmp_path, "config", "user.email", "test@example.invalid")
        _git(tmp_path, "config", "user.name", "test")
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "yesterdays committed capture")
        (tmp_path / "outpost.cfg").write_text(_named(REAL_FASTPATH, "renamed-today"))

        ext = _ext(tmp_path)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"renamed-today"}, \
            "reading HEAD here would report yesterday's committed capture as today's"

    def test_a_plain_directory_nested_in_an_unrelated_checkout_still_works(self, tmp_path):
        """A live misdetection the disk-first order fixes. The path classifies as kind="git"
        because it sits inside someone else's checkout, but ls-tree at that prefix returns 0
        blobs — so a git-first order would have read nothing and reported archive_empty."""
        _git(tmp_path, "init", "-q", "-b", "main")
        _git(tmp_path, "config", "user.email", "test@example.invalid")
        _git(tmp_path, "config", "user.name", "test")
        (tmp_path / "README.md").write_text("unrelated checkout\n")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "unrelated")
        configs = tmp_path / "oxidized-output"
        configs.mkdir()
        (configs / "outpost.cfg").write_text(REAL_FASTPATH)      # never committed

        ext = _ext(configs)
        ext.poll()
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}


class TestAutoDiscoverySweepsCarefully:
    """AUTO is the new default, so what it declines to pick up is as load-bearing as what it
    does. Three independent layers guard this and the deny-list is the outermost."""

    def test_extensionless_blobs_are_discovered_without_any_pattern(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare, deviceGlob=AUTO_GLOB)
        ext.poll()
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}

    def test_repository_housekeeping_is_not_mistaken_for_a_device(self, tmp_path):
        """A README.md was measured assessing "ok" with 2 substantive lines, so the content
        gate alone would have graded it as a device. The deny-list is what stops that."""
        bare = _bare_archive(tmp_path, {
            "outpost": REAL_FASTPATH,
            "README.md": "# Oxidized archive\n\nManaged by netops, do not edit by hand.\n",
            ".gitignore": "*.tmp\n"})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in ext.emitted if r["host.name"]} == {"outpost"}

    def test_a_non_config_file_is_INFO_not_a_capture_failure(self, tmp_path):
        """The AUTO-mode refinement. A stray file with NO refusal evidence and NO fingerprint
        is the archive's shape, not a device's backup failing — claiming ERROR "your backup is
        broken" over it burns exactly the alarm this module exists to protect."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH, "placeholder": "\n\n\n"})
        ext = _ext(bare)
        ext.poll()

        rec = [r for r in ext.emitted if r.get("config.capture.reason") == "archive_non_config"]
        assert len(rec) == 1
        assert rec[0]["severity"] == "INFO"
        assert rec[0]["compliance.status"] == "archive_non_config"
        assert rec[0]["config.capture.status"] == "skipped"
        assert "NOT reported as a capture failure" in rec[0]["content"]
        # ...and it never enters the per-control channel every consumer filters on.
        assert "compliance.control" not in rec[0]

    def test_an_explicit_glob_keeps_calling_it_a_capture_failure(self, tmp_path):
        """The discriminator is operator INTENT, and it has to cut both ways. Naming a pattern
        is an assertion that these files are devices, so an empty one is a failed capture."""
        (tmp_path / "outpost.cfg").write_text("\n\n\n")
        ext = _ext(tmp_path, deviceGlob="*.cfg")
        ext.poll()

        assert ext.emitted[0]["compliance.status"] == "capture_failed"
        assert ext.emitted[0]["severity"] == "ERROR"

    def test_a_real_refusal_is_still_ERROR_even_under_AUTO(self, tmp_path):
        """The true positive must survive the refinement. The lab's 272-byte artefact scores
        headers=3 / carets=3 / errors=3; a stray file scores 0/0/0."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_REFUSED})
        ext = _ext(bare)
        ext.poll()

        assert ext.emitted[0]["compliance.status"] == "capture_failed"
        assert ext.emitted[0]["severity"] == "ERROR"

    def test_a_fingerprinted_stub_is_still_ERROR_even_with_no_refusal_markers(self):
        """The `not fingerprinted` conjunct, which is the one that is easy to leave out.

        The lab's unprivileged FASTPATH stub also scores 0/0/0 — but it MATCHES the netgear
        fingerprint, which is positive evidence that a real device answered. Downgrading it to
        INFO would re-open the exact hole the capture-health gate was built to close.
        """
        stub = '!Current Configuration:\n!System Description "GSM7248V2"\n!\nexit\n'
        assert detect_platform(stub)["id"] == "netgear"
        assert assess_capture(stub, detect_platform(stub), auto_discovered=True)[1] == "no_content"


class TestEmptyArchiveIsNeverSilent:
    """The single highest-impact defect: reading zero devices produced NOTHING. An absence
    cannot be queried, so no detector, dashboard or workflow downstream could ever see it —
    the same failure class as the 29-hour capture outage this module was hardened for."""

    def test_bare_archive_with_the_old_default_glob_names_the_real_cause(self, tmp_path):
        """The exact lab state on 2026-08-02, and the reason changing the default is not
        sufficient on its own: an existing monitoring configuration already has "*.cfg"
        persisted, so it stays broken until someone is TOLD what to change."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH, "edge/branch-sw1": "x\n"})
        ext = _ext(bare, deviceGlob="*.cfg")
        ext.poll()

        assert len(ext.emitted) == 1
        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_empty"
        assert rec["severity"] == "ERROR"
        assert rec["config.archive.bare"] == "true"
        assert rec["config.archive.tracked_files"] == "2"
        assert rec["config.archive.device_glob"] == "*.cfg"
        assert rec["config.archive.mode"] == "git"
        # The record has to carry the fix, not just the symptom.
        assert "no file extension" in rec["content"]
        assert "clear the device pattern to auto-discover" in rec["content"]
        assert "coverage is ZERO, not clean" in rec["content"]

    def test_an_empty_plain_directory_is_reported_too(self, tmp_path):
        ext = _ext(tmp_path)
        ext.poll()

        assert len(ext.emitted) == 1
        assert ext.emitted[0]["compliance.status"] == "archive_empty"
        assert ext.emitted[0]["config.archive.mode"] == "dir"
        assert "not a git repository" in ext.emitted[0]["content"]

    def test_a_repo_with_an_unborn_HEAD_is_reported_as_such(self, tmp_path):
        """A first deployment where Oxidized has not completed a backup yet. Distinct wording,
        because the remediation is "wait / check Oxidized", not "change your pattern"."""
        _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "configs.git"))
        ext = _ext(tmp_path / "configs.git")
        ext.poll()

        assert ext.emitted[0]["compliance.status"] == "archive_empty"
        assert "nothing committed" in ext.emitted[0]["content"]

    def test_the_archive_record_stays_out_of_the_per_control_channel(self, tmp_path):
        ext = _ext(tmp_path)
        ext.poll()
        assert "compliance.control" not in ext.emitted[0]
        assert ext.emitted[0]["dt.source"] == "cno-config"
        assert ext.emitted[0]["log.source"] == "network.compliance"

    def test_both_archive_reasons_carry_remediation(self):
        for reason in ("archive_empty", "archive_non_config"):
            assert len(CAPTURE_REASONS[reason]) > 60
            assert CAPTURE_REASONS[reason][-1] not in ".!"


class TestForeignOwnedArchive:
    """On an ActiveGate the extension runs as a DIFFERENT user from the one owning the archive
    (uid 30000 in the lab). "Dubious ownership" is therefore the expected production state."""

    def test_without_the_grant_git_fails_loudly_rather_than_silently(self, tmp_path):
        """The precondition for everything else here: git refuses, with a non-zero rc that
        _git's returncode guard can see. If it returned empty output at rc 0 instead, the
        drift caller would read it as "no diff"."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        with _foreign_owner():
            r = _git(bare, "ls-tree", "-r", "--name-only", "HEAD", check=False)
        assert r.returncode == 128
        assert "dubious ownership" in r.stderr

    def test_the_archive_is_read_anyway_and_the_records_are_identical(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        clean = _ext(bare)
        clean.poll()
        with _foreign_owner():
            foreign = _ext(bare)
            foreign.poll()

        assert foreign.emitted == clean.emitted
        assert {r["device.address"] for r in _controls(foreign)} == {"10.0.10.3"}

    def test_the_grant_is_narrow_and_named_not_a_wildcard(self, tmp_path):
        """safe.directory=* was measured to be exactly as capable as safe.directory=<root>
        across ls-tree, show, log, diff and cat-file, so the wildcard buys zero capability and
        only widens trust. It is used for the single discovery rev-parse and nowhere else."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare)
        with _foreign_owner():
            arch = ext._resolve_archive(str(bare))

        assert arch["ownership"] == "foreign-owner"
        assert ext._trust == ["-c", "safe.directory=" + str(bare)]
        assert "safe.directory=*" not in ext._trust

    def test_a_same_user_archive_is_granted_nothing(self, tmp_path):
        """Most deployments must never trust anything. Trying untrusted FIRST is what keeps it
        that way, rather than granting unconditionally and hoping."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare)
        arch = ext._resolve_archive(str(bare))

        assert arch["ownership"] == "same-user"
        assert ext._trust == []

    def test_the_ownership_is_stamped_where_an_operator_can_see_it(self, tmp_path):
        """Silently trusting another user's repository is not a thing to do quietly, so it is
        on the archive record as well as in a warning."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        with _foreign_owner():
            ext = _ext(bare, deviceGlob="*.cfg")      # forces the archive record
            ext.poll()

        assert ext.emitted[0]["config.archive.ownership"] == "foreign-owner"

    def test_a_hostile_repo_cannot_execute_its_own_code_through_the_diff(self, tmp_path):
        """Trust is being granted to a foreign-owned repository, so its configuration is not
        our code to run. Measured 2026-08-02: with diff.external plus a .gitattributes textconv
        a plain `git diff` EXECUTED the repo's script as us, rc 0. --no-ext-diff --no-textconv
        stops it and leaves the diff byte-identical, which is what makes the flags free."""
        _git(tmp_path, "init", "-q", "-b", "main")
        _git(tmp_path, "config", "user.email", "test@example.invalid")
        _git(tmp_path, "config", "user.name", "test")
        marker = tmp_path / "EXECUTED"
        script = tmp_path / "hostile.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
        script.chmod(0o755)
        (tmp_path / ".gitattributes").write_text("*.cfg diff=pwn\n")
        (tmp_path / "sw1.cfg").write_text(REAL_FASTPATH)
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "one")
        _git(tmp_path, "branch", "golden")
        (tmp_path / "sw1.cfg").write_text(
            REAL_FASTPATH.replace('snmp-server location "basement"',
                                  'snmp-server location "roof"'))
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "two")
        _git(tmp_path, "config", "diff.external", str(script))
        _git(tmp_path, "config", "diff.pwn.textconv", str(script))

        # The hazard is real in this repo: an unhardened diff runs the script.
        _git(tmp_path, "diff", "golden", "HEAD", "--", ":(top)sw1.cfg", check=False)
        assert marker.exists(), "fixture is not actually hostile; the test would prove nothing"
        marker.unlink()

        ext = _ext(tmp_path)
        ext.poll()

        assert not marker.exists(), "the archive executed its own code as the ActiveGate user"
        drift = _drift(ext)
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert '+snmp-server location "roof"' in drift[0]["config.diff"]


class TestGitFailureNeverReportsAMatch:
    """Requirement 4, and the property the rest of this module is built on. Reading configs out
    of git multiplies the ways git can fail, so every one of them is asserted to land on
    "unknown". `git diff` exits 0 with empty stdout in several of these, which is why the
    returncode guard alone is not enough and the `tracked` probe is still load-bearing."""

    def _assert_never_matches(self, ext):
        for r in _drift(ext):
            assert r["config.drift_from_golden"] != "no", \
                f"FALSE ALL-CLEAR: {r['content']}"
            assert "matches golden" not in r["content"]

    def test_missing_golden_ref_in_a_bare_archive(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        assert len(_drift(ext)) == 1
        assert _drift(ext)[0]["config.drift_from_golden"] == "unknown"
        self._assert_never_matches(ext)

    def test_a_blob_absent_from_the_golden_ref(self, tmp_path):
        """`git diff` returns rc 0 with EMPTY stdout for a path missing from one side, so the
        command genuinely succeeded — it just compared nothing. Measured on a grouped node."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        _git(bare, "branch", "golden", "main")
        _recommit(bare, {"edge/branch-sw1": _named(REAL_FASTPATH, "branch-sw1")}, msg="new node")

        ext = _ext(bare)
        ext.poll()

        by_host = {r["host.name"]: r for r in _drift(ext)}
        assert by_host["branch-sw1"]["config.drift_from_golden"] == "unknown"
        assert "NOT COMPARED" in by_host["branch-sw1"]["content"]
        assert by_host["outpost"]["config.drift_from_golden"] == "no"   # genuinely compared

    def test_a_foreign_owned_archive_whose_grant_is_refused(self, tmp_path, monkeypatch):
        """Belt and braces: if the narrow safe.directory grant were ever ineffective, every
        git call fails rc 128 and drift must degrade to unknown — never to a clean report."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        _git(bare, "branch", "golden", "main")
        ext = _ext(bare)
        real_git = ComplianceExtension._git

        def no_trust(self, path, *args, **kw):
            self._trust = []                     # sabotage the grant, keep everything else
            return real_git(self, path, *args, **kw)

        monkeypatch.setattr(ComplianceExtension, "_git", no_trust)
        with _foreign_owner():
            ext.poll()

        self._assert_never_matches(ext)

    def test_an_unreadable_golden_ref_name(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare, goldenRef="no-such-ref")
        ext.poll()

        assert _drift(ext)[0]["config.drift_from_golden"] == "unknown"
        self._assert_never_matches(ext)

    def test_a_binary_blob_does_not_crash_the_poll_or_silence_a_device(self, tmp_path):
        """text=True raises UnicodeDecodeError on a binary blob and the bare `except` in _git
        turned that into a silent skip — a device that vanishes. errors="replace" lets the
        content gate reach an honest verdict instead."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        work = bare.parent / "_work"
        (work / "junk").write_bytes(bytes(range(256)) * 8)
        _git(work, "add", "-A")
        _git(work, "commit", "-q", "-m", "a binary object in the archive")
        _git(work, "push", "-q", str(bare), "main:main")

        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}, \
            "the real device must still be graded"
        junk = [r for r in ext.emitted if r["host.name"] == "junk"]
        assert len(junk) == 1 and junk[0]["compliance.status"] == "archive_non_config"
        self._assert_never_matches(ext)


# ══════════════════════════════════════════════════════════════════════════════════════════
# DEFECT 2 — device identity
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestRealFastpathCapture:
    """The anchor. Everything else in this section is a hazard; this is the measured artefact."""

    def test_the_premise__there_is_no_hostname_line_at_all(self):
        """The brief's "host.name falls back to the filename" is right, and the reason it
        looked correct in the lab is that the Oxidized node name happens to equal the sysName.
        That is luck. Rename the node — or key router.db by IP, which is the common convention
        — and every downstream correlation silently loses its join."""
        assert [l for l in REAL_FASTPATH.splitlines() if l.lower().startswith("hostname")] == []
        assert 'snmp-server sysname "outpost"' in REAL_FASTPATH
        assert "network parms 10.0.10.3 255.255.255.0 10.0.10.1" in REAL_FASTPATH

    def test_device_address_is_populated_from_network_parms(self):
        """THE assertion. device.address is the join key for the SNMP entity idPattern
        (network_device_{device.address}), for fleetLogScope() in data.ts, and for the RCA
        workflows. It was empty for this device, and for every other config in the repo."""
        host, ip, src_n, src_a = ComplianceExtension._meta(REAL_FASTPATH, "outpost", "netgear")
        assert ip == "10.0.10.3"
        assert src_a == "network_parms"
        assert host == "outpost"
        assert src_n == "snmp_sysname", "the name must come from the device, not the filename"

    def test_the_name_now_comes_from_the_device_even_when_the_node_is_named_by_IP(self):
        """The luck removed. `snmp-server sysname` IS the SNMP sysName object, so host.name
        matches the SNMP extension's sys_name by construction — which is exactly the equality
        the RCA workflows' Lane A join (norm(dev) === lower(sys_name)) depends on."""
        host, ip, src_n, _ = ComplianceExtension._meta(REAL_FASTPATH, "10.0.10.3", "netgear")
        assert (host, src_n) == ("outpost", "snmp_sysname")
        assert ip == "10.0.10.3"

    def test_end_to_end_through_query_from_a_bare_archive(self, tmp_path):
        bare = _bare_archive(tmp_path, {"10.0.10.3": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        # Device-scoped: this fixture has no golden tag, so an archive-scoped drift notice
        # rides alongside. It carries no identity at all, which is the point of it.
        devices = [r for r in ext.emitted if r["host.name"]]
        assert {r["host.name"] for r in devices} == {"outpost"}
        assert {r["device.address"] for r in devices} == {"10.0.10.3"}
        assert {r["device.identity.name_source"] for r in devices} == {"snmp_sysname"}

    def test_set_prompt_is_the_MODEL_and_must_never_be_a_name_source(self):
        """The measured reason identity is platform-scoped. On this device `set prompt` yields
        "GSM7248V2", the model number — worse than the filename fallback, and it would collapse
        every switch of the same model onto one host.name."""
        assert 'set prompt "GSM7248V2"' in REAL_FASTPATH
        host, _, _, _ = ComplianceExtension._meta(REAL_FASTPATH, "fallback-stem", "netgear")
        assert host == "outpost" and host != "GSM7248V2"
        stripped = REAL_FASTPATH.replace('snmp-server sysname "outpost"', "")
        assert ComplianceExtension._meta(stripped, "fallback-stem", "netgear")[0] == "fallback-stem"

    def test_the_failed_capture_still_gets_an_identity_so_it_can_be_found(self):
        """The capture-failure record's entire purpose is to be findable, and it is emitted
        precisely when there is no config to parse. The stem is used, and LABELLED."""
        host, ip, src_n, src_a = ComplianceExtension._meta(REAL_REFUSED, "outpost", None)
        assert (host, src_n) == ("outpost", "filename")
        assert (ip, src_a) == ("", "none")


class TestAddressExtractionRefusesToGuess:
    """A plausible-but-wrong address is worse than none: it mints a phantom
    network_device_<ip> entity that never joins the SNMP fleet and can collide with a real
    one. Every case here was measured returning a wrong value from `re.search`."""

    @pytest.mark.parametrize("text, id_", [
        ("hostname sw1\n! ip address 192.0.2.99 255.255.255.0\n", "commented-out"),
        ("hostname sw1\ninterface Gi0/1\n description was ip address 192.0.2.1 before\n",
         "inside-an-interface-description"),
        ("hostname sw1\nbanner motd ^C\nSee the runbook quoting the ip address 10.255.255.1\n^C\n",
         "banner-prose"),
        ("hostname sw1\ninterface Vlan10\n ip address 10.9.9.9 255.255.255.0 secondary\n",
         "a-secondary-address"),
    ])
    def test_a_false_positive_no_longer_yields_an_address(self, text, id_):
        assert ComplianceExtension._meta(text, "sw1", "cisco-ios")[1] == "", id_

    def test_the_WAN_first_edge_router_refuses_rather_than_returning_the_ISP_transit(self):
        """The dangerous one. First-wins over `ip address` returned 203.0.113.7 — the ISP
        transit /30 — for a device whose identity is 10.0.0.9. Two or more candidate addresses
        with no management marker is ambiguous, and ambiguity must resolve to empty."""
        edge = ("hostname edge-01\n"
                "interface GigabitEthernet0/0\n description ISP transit\n"
                " ip address 203.0.113.7 255.255.255.252\n!\n"
                "interface Vlan99\n ip address 10.0.0.9 255.255.255.0\n!\n")
        host, ip, _, src_a = ComplianceExtension._meta(edge, "edge-01", "cisco-ios")
        assert host == "edge-01"
        assert ip == "", "203.0.113.7 would mint a phantom entity that never joins the fleet"
        assert src_a == "none", "the gap must be countable, not silently absent"

    @pytest.mark.parametrize("text, want, want_src", [
        ("hostname sw1\ninterface Management0/0\n ip address 10.0.10.9 255.255.255.0\n!\n"
         "interface Vlan10\n ip address 10.1.1.1 255.255.255.0\n!\n",
         "10.0.10.9", "mgmt_interface"),
        ("hostname sw1\ninterface GigabitEthernet0\n vrf forwarding Mgmt-intf\n"
         " ip address 10.0.10.9 255.255.255.0\n!\n", "10.0.10.9", "mgmt_interface"),
        ("hostname acc1\ninterface Vlan10\n ip address 10.0.10.5 255.255.255.0\n!\n",
         "10.0.10.5", "sole_interface"),
    ])
    def test_an_unambiguous_management_address_is_extracted(self, text, want, want_src):
        """UNVERIFIED against real hardware — no artefact in this repository carries a numeric
        management address for IOS/EOS (all three Cisco goldens have none, GOLDEN_SDWAN uses
        `ip address dhcp`), so these are synthetic. Marked here for the same reason PLATFORMS
        marks "verified": False."""
        _, ip, _, src = ComplianceExtension._meta(text, "stem", "cisco-ios")
        assert (ip, src) == (want, want_src)

    @pytest.mark.parametrize("bad", ["0.0.0.0", "127.0.0.1", "169.254.1.1", "10.0.0.255"])
    def test_an_address_that_can_never_be_an_identity_is_rejected(self, bad):
        text = f"hostname sw1\ninterface Vlan10\n ip address {bad} 255.255.255.0\n!\n"
        assert ComplianceExtension._meta(text, "sw1", "cisco-ios")[1] == ""

    def test_an_IPv4_filename_stem_IS_used_and_is_not_a_guess(self):
        """Oxidized's router.db is very commonly keyed by management address
        ("10.0.10.3:netgear:user:pass"), so in that convention the stem is the address Oxidized
        actually DIALLED — stronger evidence than anything in the file."""
        _, ip, _, src = ComplianceExtension._meta("hostname sw1\nend\n", "10.88.40.10", "cisco-ios")
        assert (ip, src) == ("10.88.40.10", "filename")

    def test_a_non_IPv4_stem_is_never_promoted_to_an_address(self):
        _, ip, _, src = ComplianceExtension._meta("hostname sw1\nend\n", "core-sw-1", "cisco-ios")
        assert (ip, src) == ("", "none")

    def test_frr_reports_not_applicable_rather_than_a_gap(self):
        """FRR is a routing daemon; its management address belongs to the Linux host. Same
        convention as a control predicate returning None."""
        frr = "frr version 8.4.2\nfrr defaults traditional\nhostname r1\nend\n"
        _, ip, _, src = ComplianceExtension._meta(frr, "r1", "frr")
        assert (ip, src) == ("", "n/a")


class TestNameExtractionHazards:
    def test_quoted_hostname_loses_its_quotes(self):
        """Already fixed before this change and pinned by test_capture_health.py; re-asserted
        here because the rewrite moved the stripping into _clean_name."""
        assert ComplianceExtension._meta('hostname "lab-gsm7248"\n', "node", "netgear")[0] \
            == "lab-gsm7248"
        assert ComplianceExtension._meta("hostname 'lab-gsm7248'\n", "node", "netgear")[0] \
            == "lab-gsm7248"

    def test_a_quoted_name_containing_spaces_is_no_longer_truncated(self):
        """The half of the quote handling that was NOT fixed: `\\S+` captured '"Data' and the
        strip then produced 'Data'. Quoted-with-spaces is tried first for exactly this."""
        assert ComplianceExtension._meta('hostname "Data Center 1"\n', "node", "cisco-ios")[0] \
            == "Data Center 1"

    def test_the_first_hostname_wins_not_the_last(self):
        """`hostname` was last-wins while `ip address` was first-wins — inconsistent, and
        measured resolving to 'bogus' for a config whose banner body contains a line starting
        "hostname bogus"."""
        text = ("hostname REAL-SW\nbanner motd ^C\nhostname bogus is not the name\n^C\nend\n")
        assert ComplianceExtension._meta(text, "stem", "cisco-ios")[0] == "REAL-SW"

    def test_an_unfingerprinted_artefact_still_resolves_a_name(self):
        """The generic tier is load-bearing, not a courtesy: the capture-failure record exists
        to be found and is emitted precisely when fingerprinting failed. Measured — this alone
        recovers 'edge-01' from the repo's JUNIPER_SET fixture, which no detect predicate
        matches."""
        juniper_set = ("set system host-name edge-01\n"
                       "set system services ssh protocol-version v2\n")
        assert detect_platform(juniper_set) is None
        host, _, src_n, _ = ComplianceExtension._meta(juniper_set, "stem", None)
        assert (host, src_n) == ("edge-01", "set_host_name")

    def test_the_source_is_always_reported_so_a_coverage_gap_is_countable(self):
        for text, stem, plat, want in (
                (REAL_FASTPATH, "outpost", "netgear", "snmp_sysname"),
                ("hostname sw1\n", "stem", "cisco-ios", "hostname"),
                ("nothing useful here at all\n", "node-7", None, "filename")):
            assert ComplianceExtension._meta(text, stem, plat)[2] == want


class TestIdentityTableMirrorsPlatforms:
    """Requirement 5. The `verified` discipline PLATFORMS exists to enforce has to extend to
    identity, or we repeat the exact mistake that table was built to prevent."""

    def test_every_platform_has_an_identity_rule_set(self):
        assert {p["id"] for p in PLATFORMS} == set(IDENTITY)

    def test_only_the_platform_with_a_real_capture_is_marked_verified(self):
        """netgear is True because a real 5494-byte GSM7248V2 capture was run through these
        rules. cisco-ios and frr are "name" — the name rule was verified against the repo
        goldens, the address rules were not. Everything else is vendor documentation."""
        assert IDENTITY["netgear"]["verified"] is True
        assert IDENTITY["cisco-ios"]["verified"] == "name"
        assert IDENTITY["frr"]["verified"] == "name"
        for pid in ("arista-eos", "juniper-junos", "nokia-srlinux", "paloalto-panos"):
            assert IDENTITY[pid]["verified"] is False, f"{pid} has no real capture behind it"

    @pytest.mark.parametrize("pid", sorted(IDENTITY))
    def test_no_rule_set_can_raise_on_arbitrary_text(self, pid):
        """A vendor rule that throws would take the whole poll down for every device after it."""
        for text in ("", "\x00\xff garbage", "hostname\n", "interface\n", "a" * 5000):
            ComplianceExtension._meta(text, "stem", pid)


# ══════════════════════════════════════════════════════════════════════════════════════════
# ROUND TWO — defects found by adversarial review of the fixes above, all reproduced first
#
# Three of these are in the SAME failure class the module exists to remove (a device that is
# present in the archive but emits nothing, or a false all-clear), and two of those were
# introduced by the round-one change itself and reachable only on its new git read path.
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestLsTreeQuotingDoesNotDeleteDevices:
    """A device that git C-quotes must not vanish. Introduced by the round-one git read path.

    `git ls-tree` porcelain-quotes any path holding a non-ASCII byte, a double quote, a
    backslash or a control character (core.quotePath, on by default), so `sw-münchen` came back
    as the literal `"sw-m\\303\\274nchen"`. admits() passed the quoted literal, `git show
    HEAD:"sw-m\\303\\274nchen"` exited 128 under quiet=True, and _load_configs dropped it with
    no log line and no record. archive_empty could not fire either — it only triggers when the
    list is ENTIRELY empty. Measured 2026-08-02: 6 tracked, 6 admitted, 3 loaded, 3 devices
    silently gone. Non-ASCII hostnames are ordinary outside en-US networks, and a non-ASCII
    GROUP name deletes every device in the group.
    """

    NAMES = ["outpost", "sw-münchen", "café-rtr", "sw#1", "sw with space", "édge/sw1"]

    def test_every_tracked_node_is_read_whatever_its_name(self, tmp_path):
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n.replace("/", "-"))
                                        for n in self.NAMES})
        ext = _ext(bare)
        ext.poll()

        got = {r["host.name"] for r in _controls(ext)}
        assert got == {n.replace("/", "-") for n in self.NAMES}, "a device vanished"

    def test_the_lister_returns_real_paths_not_quoted_literals(self, tmp_path):
        bare = _bare_archive(tmp_path, {n: "x\n" for n in self.NAMES})
        rels, seen, err = _ext(bare)._list_git(str(bare), AUTO_GLOB, "")

        assert seen == len(self.NAMES)
        assert sorted(rels) == sorted(self.NAMES)
        assert not any('\\3' in r or r.startswith('"') for r in rels), "C-quoted literal leaked"

    def test_a_non_ascii_group_does_not_take_its_devices_with_it(self, tmp_path):
        bare = _bare_archive(tmp_path, {"édge/sw1": _named(REAL_FASTPATH, "sw1"),
                                        "édge/sw2": _named(REAL_FASTPATH, "sw2")})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"sw1", "sw2"}


class TestDriftComparesWhatWasActuallyGraded:
    """The FOURTH route to a false all-clear, and the only one left open after round one.

    _load_configs is disk-first, and its own comment says why: in a NON-bare repository the
    working tree holds the CURRENT capture and HEAD holds the last COMMITTED one. Drift diffed
    `golden HEAD` regardless, so in a git checkout — README deployment shape #2, and what
    Oxidized's FILE backend produces when its output directory is version-controlled — the
    graded bytes and the diffed bytes were different objects. Nothing ever commits the
    worktree there, so this was permanent rather than transient.
    """

    IOS = ("!\nservice timestamps debug datetime msec\nservice password-encryption\n"
           "hostname EDGE-RTR-1\n!\nenable secret 5 $1$abc$xyz\naaa new-model\n!\n"
           "ip access-list standard MGMT\n permit 10.0.0.0 0.255.255.255\n!\n"
           "banner motd ^C Authorized only ^C\nlogging buffered 16384\n"
           "logging host 10.0.0.5\nntp server 10.0.0.6\nno ip http server\nvlan 10\n!\n"
           "line vty 0 4\n transport input ssh\n!\nend\n")

    def _checkout_with_uncommitted_drift(self, tmp_path):
        repo = tmp_path / "archive"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "test@example.invalid")
        _git(repo, "config", "user.name", "test")
        (repo / "sw1.cfg").write_text(self.IOS)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "baseline")
        _git(repo, "branch", "golden", "main")
        # Oxidized's file backend overwrites the working tree. Nothing commits it.
        (repo / "sw1.cfg").write_text(
            self.IOS.replace("transport input ssh", "transport input telnet")
                    .replace("logging host 10.0.0.5\n", ""))
        return repo

    def test_the_graded_bytes_and_the_diffed_bytes_are_the_same_object(self, tmp_path):
        ext = _ext(self._checkout_with_uncommitted_drift(tmp_path))
        ext.poll()

        drift = _drift(ext)
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert drift[0]["severity"] == "WARN"
        assert "-logging host 10.0.0.5" in drift[0]["config.diff"]
        assert "+ transport input telnet" in drift[0]["config.diff"]

    def test_it_cannot_report_a_clean_bill_over_failing_controls(self, tmp_path):
        """The record set previously asserted BOTH: three ISO controls failing on the config,
        and "matches golden" at INFO on the same bytes in the same poll. ConfigChanges.tsx
        renders drift !== "yes" as "on intended config", so that painted green."""
        ext = _ext(self._checkout_with_uncommitted_drift(tmp_path))
        ext.poll()

        failed = {r["compliance.control"] for r in _controls(ext)
                  if r["compliance.status"] == "fail"}
        assert {"A.8.5", "A.8.9", "A.8.26"} <= failed
        for r in _drift(ext):
            assert r["config.drift_from_golden"] != "no", f"FALSE ALL-CLEAR: {r['content']}"
            assert "matches golden" not in r["content"]

    def test_a_committed_checkout_with_no_drift_still_reports_no(self, tmp_path):
        """The other direction: the fix must not manufacture drift on a clean worktree."""
        repo = tmp_path / "archive"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "test@example.invalid")
        _git(repo, "config", "user.name", "test")
        (repo / "sw1.cfg").write_text(self.IOS)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "baseline")
        _git(repo, "branch", "golden", "main")

        ext = _ext(repo)
        ext.poll()

        assert [r["config.drift_from_golden"] for r in _drift(ext)] == ["no"]

    def test_a_bare_archive_still_diffs_against_HEAD(self, tmp_path):
        """Bare skips the disk walk entirely, so HEAD IS what was graded and must stay in the
        diff — the fix is conditional on provenance, not a blanket removal."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        _git(bare, "branch", "golden", "main")
        _recommit(bare, {"outpost": REAL_FASTPATH.replace('snmp-server location "basement"',
                                                          'snmp-server location "roof"')})
        ext = _ext(bare)
        ext.poll()

        assert _drift(ext)[0]["config.drift_from_golden"] == "yes"
        assert '+snmp-server location "roof"' in _drift(ext)[0]["config.diff"]


class TestTheNodeStemIsNeverTruncated:
    """os.path.splitext strips whatever follows the LAST dot, extension or not.

    The git backend's defining property is that blobs carry NO extension, so splitext had
    nothing to strip and amputated the last dot-segment instead. Oxidized's router.db is
    commonly keyed by management address, so IP-named nodes are ordinary — and _meta's own
    docstring calls an IPv4 stem the strongest identity evidence available. Measured
    2026-08-02: node "10.0.10.3" produced host.name '10.0.10' and an EMPTY address, in exactly
    the deployment docs/CUSTOMER-HANDOFF.md recommends.
    """

    @pytest.mark.parametrize("rel, want", [
        ("10.0.10.3", "10.0.10.3"),                                  # the git backend's shape
        ("10.0.10.3.cfg", "10.0.10.3"),                              # the file backend's
        ("site/10.88.40.11", "10.88.40.11"),
        ("core-sw-1.lab.example.com", "core-sw-1.lab.example.com"),  # an FQDN node
        ("outpost", "outpost"),
        ("sw1.cfg", "sw1"),
        ("sw1.conf", "sw1"),
        ("edge/branch-sw1", "branch-sw1"),
    ])
    def test_only_a_real_config_extension_is_stripped(self, rel, want):
        assert _node_stem(rel) == want

    def test_an_IP_named_node_recovers_its_address_in_a_bare_archive(self, tmp_path):
        """The record that most needs to be findable is the one for a FAILED capture: it has no
        in-config name or address, so the stem IS its identity. fleetLogScope() filters on
        device.address and host.name, and '10.0.10' is in neither set."""
        bare = _bare_archive(tmp_path, {"10.0.10.3": REAL_REFUSED})
        ext = _ext(bare)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "capture_failed"
        assert rec["host.name"] == "10.0.10.3"
        assert rec["device.address"] == "10.0.10.3"
        assert rec["device.identity.address_source"] == "filename"

    def test_devices_in_one_subnet_do_not_collapse_onto_one_identity(self, tmp_path):
        """48 IP-keyed switches in a /24 were ONE device downstream: every one of them
        reported host.name '10.0.10' with no address."""
        bare = _bare_archive(tmp_path, {f"10.0.10.{n}": REAL_REFUSED for n in (3, 4, 5)})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in ext.emitted if r["host.name"]} == {"10.0.10.3", "10.0.10.4", "10.0.10.5"}
        assert {r["device.address"] for r in ext.emitted} == {"10.0.10.3", "10.0.10.4",
                                                              "10.0.10.5"}


class TestBraceBlocksAreScopedByDepth:
    """_brace_mgmt_address ran to EOF whenever the management interface had no IPv4.

    Its terminator, re.match(r"^(?:interface|ge-|xe-|et-)\\S"), could not match
    `interface <name> {` AT ALL — SR Linux writes a space after `interface` and \\S demands a
    non-space at that offset — and named none of lo0/irb/ae0/reth0/st0/vlan or the closing
    brace. A management interface on DHCP or IPv6-only is ordinary, and then the FIRST address
    anywhere in the file was returned stamped `mgmt_interface`.
    """

    JUNOS_HEAD = "system {\n    host-name lab-rtr;\n    root-authentication {\n" \
                 "        encrypted-password \"$6$abc\";\n    }\n}\n"

    def _junos(self, mgmt_body, second):
        return (self.JUNOS_HEAD + "interfaces {\n" + mgmt_body + second + "}\n")

    def test_a_dhcp_fxp0_does_not_borrow_the_reth0_ISP_transit(self):
        """The SRX cluster case, and precisely the phantom-entity failure the DEVICE IDENTITY
        note says must never happen — an ISP transit /30 as a device's identity."""
        text = self._junos(
            "    fxp0 {\n        unit 0 {\n            family inet {\n"
            "                dhcp;\n            }\n        }\n    }\n",
            "    reth0 {\n        unit 0 {\n            family inet {\n"
            "                address 198.51.100.2/30;\n            }\n        }\n    }\n")
        assert _brace_mgmt_address(text.splitlines(), _JUN_MGMT) == ("", "")

    def test_a_dhcp_me0_does_not_borrow_a_user_SVI(self):
        """JunOS sorts ge- < lo0 < me0 < vlan, so a user VLAN follows the ZTP default me0."""
        text = self._junos(
            "    me0 {\n        unit 0 {\n            family inet {\n"
            "                dhcp;\n            }\n        }\n    }\n",
            "    vlan {\n        unit 20 {\n            family inet {\n"
            "                address 172.19.20.1/24;\n            }\n        }\n    }\n")
        assert _brace_mgmt_address(text.splitlines(), _JUN_MGMT) == ("", "")

    def test_an_ipv6_only_management_interface_does_not_borrow_a_loopback(self):
        text = self._junos(
            "    fxp0 {\n        unit 0 {\n            family inet6 {\n"
            "                address 2001:db8::1/64;\n            }\n        }\n    }\n",
            "    lo0 {\n        unit 0 {\n            family inet {\n"
            "                address 10.255.0.1/32;\n            }\n        }\n    }\n")
        assert _brace_mgmt_address(text.splitlines(), _JUN_MGMT) == ("", "")

    def test_an_srlinux_mgmt0_on_dhcp_does_not_borrow_ethernet_1_1(self):
        """SR Linux is a `"verified": True` platform, and `mgmt0` on dhcp-client is the
        containerlab default. `interface ethernet-1/1 {` could not terminate the scan."""
        text = ("interface mgmt0 {\n    admin-state enable\n    subinterface 0 {\n"
                "        ipv4 {\n            dhcp-client {\n            }\n"
                "        }\n    }\n}\n"
                "interface ethernet-1/1 {\n    admin-state enable\n    subinterface 0 {\n"
                "        ipv4 {\n            address 192.168.11.1/24 {\n            }\n"
                "        }\n    }\n}\n")
        assert _brace_mgmt_address(text.splitlines(), _SRL_MGMT) == ("", "")

    def test_a_real_management_address_is_still_returned(self):
        """The controls. Scoping must not cost recall on the configs that do carry one."""
        junos = self._junos(
            "    fxp0 {\n        unit 0 {\n            family inet {\n"
            "                address 10.0.10.7/24;\n            }\n        }\n    }\n", "")
        srl = ("interface mgmt0 {\n    admin-state enable\n    subinterface 0 {\n"
               "        ipv4 {\n            address 172.20.20.3/24 {\n            }\n"
               "        }\n    }\n}\n")
        assert _brace_mgmt_address(junos.splitlines(), _JUN_MGMT) == \
            ("10.0.10.7", "mgmt_interface")
        assert _brace_mgmt_address(srl.splitlines(), _SRL_MGMT) == \
            ("172.20.20.3", "mgmt_interface")


class TestAnAdminDownInterfaceIsNotAnIdentity:
    """A shut port is unreachable by definition, so no telemetry can ever arrive on it.

    A staged-but-uncabled OOB `Management0/0` on 192.168.1.1 beat the live in-band SVI outright
    because _MGMT_NAME outranks everything. Across a fleet staged from one build sheet that is
    network_device_192.168.1.1 for every switch.
    """

    SHUT_OOB = ("!\nservice timestamps debug datetime\nhostname BR-RTR-14\naaa new-model\n!\n"
                "interface Management0/0\n description OOB - staged, not cabled\n"
                " ip address 192.168.1.1 255.255.255.0\n shutdown\n!\n"
                "interface Vlan100\n description IN-BAND MGMT\n"
                " ip address 10.0.100.5 255.255.255.0\n!\n"
                "line vty 0 4\n transport input ssh\nend\n")

    def test_a_live_svi_beats_a_shut_management_port(self):
        assert ComplianceExtension._meta(self.SHUT_OOB, "sw", "cisco-ios")[1] == "10.0.100.5"

    def test_a_shut_port_is_not_promoted_by_being_the_only_one(self):
        """With the SVI on DHCP the shut port became the SOLE parsed address and was returned
        as sole_interface — the highest-collision address in networking, fleet-wide."""
        text = self.SHUT_OOB.replace("ip address 10.0.100.5 255.255.255.0", "ip address dhcp")
        _, ip, _, src = ComplianceExtension._meta(text, "sw", "cisco-ios")
        assert (ip, src) == ("", "none")

    def test_no_shutdown_does_not_disable_an_interface(self):
        text = ("hostname sw1\ninterface Management0/0\n ip address 10.0.10.9 255.255.255.0\n"
                " no shutdown\n!\n")
        assert ComplianceExtension._meta(text, "sw", "cisco-ios")[1] == "10.0.10.9"

    def test_shutdown_before_the_address_line_also_counts(self):
        text = ("hostname sw1\ninterface Vlan10\n shutdown\n"
                " ip address 10.0.10.9 255.255.255.0\n!\n")
        assert ComplianceExtension._meta(text, "sw", "cisco-ios")[1] == ""


class TestSoleInterfaceOnlyAppliesToTheCaseItArguesFor:
    """`sole_interface` exists for the pure L2 access switch: one addressed SVI, and that SVI
    IS the management address. It said nothing about a ROUTER with one addressed physical
    port, where that port is the ISP transit /30 — and the module already refuses that config
    the moment a second interface is addressed, so guessing on one was self-inconsistent."""

    def test_a_wan_only_edge_router_refuses(self):
        text = ("!\nservice timestamps debug datetime\nhostname BRANCH-RTR-07\naaa new-model\n!\n"
                "interface GigabitEthernet0/0/0\n description ISP transit\n"
                " ip address 203.0.113.7 255.255.255.252\n!\n"
                "line vty 0 4\n transport input ssh\nend\n")
        _, ip, _, src = ComplianceExtension._meta(text, "br07", "cisco-ios")
        assert (ip, src) == ("", "none"), "203.0.113.7 would mint a phantom entity"

    def test_the_access_switch_the_rule_was_written_for_still_works(self):
        text = "hostname acc1\ninterface Vlan10\n ip address 10.0.10.5 255.255.255.0\n!\n"
        assert ComplianceExtension._meta(text, "stem", "cisco-ios")[1:4:2] == \
            ("10.0.10.5", "sole_interface")

    def test_an_explicit_management_interface_is_unaffected(self):
        text = ("hostname sw1\ninterface GigabitEthernet0\n vrf forwarding Mgmt-intf\n"
                " ip address 10.0.10.9 255.255.255.0\n!\n")
        assert ComplianceExtension._meta(text, "sw", "cisco-ios")[1] == "10.0.10.9"


class TestAutoDiscoveryDoesNotDeleteOxidizedGroups:
    """The AUTO directory deny-list removed whole groups by NAME.

    `groups:` is ordinary Oxidized configuration and `logs`, `info` and `modules` are ordinary
    group names — all three were on the list, applied to every parent segment. Under AUTO,
    which is now the DEFAULT, every device in such a group vanished with no record of any
    kind, and archive_empty could not fire because the list was not empty. Measured
    2026-08-02: 5 of 7 groups dropped. Git's own storage is now recognised by SHAPE instead.
    """

    GROUPS = ["edge", "core", "logs", "info", "modules", "refs", "hooks", "branches", "objects"]

    def test_a_group_named_after_a_git_internal_is_still_read(self, tmp_path):
        bare = _bare_archive(tmp_path, {f"{g}/sw{i}": _named(REAL_FASTPATH, f"sw{i}")
                                        for i, g in enumerate(self.GROUPS)})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == \
            {f"sw{i}" for i in range(len(self.GROUPS))}

    def test_the_same_holds_for_the_file_backend_on_disk(self, tmp_path):
        for g in ("logs", "info", "edge"):
            (tmp_path / g).mkdir()
            (tmp_path / g / "sw.cfg").write_text(_named(REAL_FASTPATH, f"{g}-sw"))
        ext = _ext(tmp_path)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"logs-sw", "info-sw", "edge-sw"}

    def test_git_storage_is_still_never_walked(self, tmp_path):
        """What the name list was actually protecting. A nested repository under configPath is
        pruned by SHAPE (HEAD + objects/ + refs/), which is what makes the name list
        unnecessary — and it also covers configPath pointing AT a gitdir, whose
        hooks/objects/refs children are not dot-directories and so escape the dot-prune."""
        (tmp_path / "sw1.cfg").write_text(REAL_FASTPATH)
        _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "mirror.git"))
        assert _is_gitdir(str(tmp_path / "mirror.git"))

        ext = _ext(tmp_path)
        assert ext._list_disk(str(tmp_path), AUTO_GLOB) == ["sw1.cfg"]
        assert ext._list_disk(str(tmp_path), "*/*") == []

    def test_configPath_pointing_at_a_gitdir_reads_nothing_off_disk(self, tmp_path):
        """`git rev-parse --is-bare-repository` inside a non-bare repo's .git returns FALSE, so
        that deployment does reach the disk walk."""
        repo = tmp_path / "r"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "test@example.invalid")
        _git(repo, "config", "user.name", "test")
        (repo / "sw1.cfg").write_text(REAL_FASTPATH)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "c")

        assert _ext(repo / ".git")._list_disk(str(repo / ".git"), AUTO_GLOB) == []


class TestEmptyArchiveDiagnosesTheActualCause:
    """`_list_git` collapsed every failure into "unborn HEAD", and threw git's sentence away."""

    def test_a_dangling_HEAD_is_not_reported_as_an_empty_archive(self, tmp_path):
        """Measured: one commit on refs/heads/main, HEAD -> a missing refs/heads/production.
        git says "fatal: Not a valid object name HEAD" — the SAME sentence an unborn HEAD
        produces — so the discriminator is whether any ref exists."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        _git(bare, "symbolic-ref", "HEAD", "refs/heads/production")
        ext = _ext(bare)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_empty"
        assert "nothing committed" not in rec["content"], "wrong cause: the archive has one"
        assert "branch that exists" in rec["content"]
        assert "Not a valid object name" in rec["content"], "git's own evidence is discarded"

    def test_a_genuinely_unborn_HEAD_still_says_so(self, tmp_path):
        _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "configs.git"))
        ext = _ext(tmp_path / "configs.git")
        ext.poll()

        assert "nothing committed" in ext.emitted[0]["content"]

    def test_unreadable_blobs_are_not_blamed_on_the_pattern(self, tmp_path):
        """The pattern matched; the object store could not answer. Telling the operator to
        "clear the device pattern to auto-discover" was a no-op — it was already auto.

        Selected BY STATUS rather than by position: an unreadable blob now also emits its own
        per-device archive_unreadable_file ERROR (see TestUnreadableBlobsAreNeverSilent), and
        that one is emitted first. Which record comes first is not what this test is about.
        """
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        sha = _git(bare, "rev-parse", "HEAD:outpost").stdout.strip()
        os.remove(os.path.join(str(bare), "objects", sha[:2], sha[2:]))

        ext = _ext(bare)
        ext.poll()

        rec = next(r for r in ext.emitted if r["compliance.status"] == "archive_empty")
        assert "matched 1 of them but NONE could be read" in rec["content"]
        assert "matched none of them" not in rec["content"]

    def test_auto_is_not_told_to_switch_to_auto(self, tmp_path):
        """With AUTO already selected, "clear the device pattern to auto-discover" is advice
        the operator has already taken."""
        bare = _bare_archive(tmp_path, {"README.md": "# archive\n", "notes.txt": "hi\n"})
        ext = _ext(bare)
        ext.poll()

        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_empty"
        assert "clear the device pattern" not in rec["content"]
        assert "auto-discovery classified every one of them" in rec["content"]

    def test_an_explicit_pattern_is_still_told_to_clear_itself(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(bare, deviceGlob="*.cfg")
        ext.poll()

        assert "clear the device pattern to auto-discover" in ext.emitted[0]["content"]


class TestDuplicateDeviceNameIsNotACaptureFailure:
    """The bleed guard condemned a healthy device, producing the outcome it was written to
    detect. `other` alone — two configs reporting the same name — is what a cloned template or
    a factory default produces; a genuine bleed stores the SAME BYTES under two nodes."""

    def test_a_duplicate_sysname_is_still_graded(self, tmp_path):
        same = _named(REAL_FASTPATH, "GSM7248V2")
        bare = _bare_archive(tmp_path, {"sw-a": same, "sw-b": same + "! second switch\n"})
        ext = _ext(bare)
        ext.poll()

        assert [r for r in ext.emitted if r.get("compliance.status") == "capture_failed"] == []
        graded = {r["host.name"] for r in _controls(ext)}
        assert graded == {"GSM7248V2", "sw-b"}, "the colliding device must still be assessed"

    def test_the_collision_is_reported_and_the_names_stay_distinct(self, tmp_path):
        same = _named(REAL_FASTPATH, "GSM7248V2")
        bare = _bare_archive(tmp_path, {"sw-a": same, "sw-b": same + "! second switch\n"})
        ext = _ext(bare)
        ext.poll()

        dup = [r for r in ext.emitted if r.get("compliance.status") == "duplicate_device_name"]
        assert len(dup) == 1
        assert dup[0]["severity"] == "WARN"
        assert dup[0]["host.name"] == "sw-b"
        assert dup[0]["device.identity.reported_name"] == "GSM7248V2"
        assert dup[0]["device.identity.collides_with"] == "sw-a"
        assert dup[0]["device.identity.name_source"] == "filename"
        # Same convention as archive_empty / archive_non_config: a status that is ABOUT the
        # archive rather than about a control must stay out of the per-control channel, or it
        # lands in Overview.tsx's pass/fail/not_assessed counts as an unknown value.
        assert "compliance.control" not in dup[0]

    def test_a_real_session_bleed_is_still_condemned(self, tmp_path):
        """Byte-identical text under two nodes. The victim must keep its ERROR."""
        bare = _bare_archive(tmp_path, {"sw-a": _named(REAL_FASTPATH, "GSM7248V2"),
                                        "sw-b": _named(REAL_FASTPATH, "GSM7248V2")})
        ext = _ext(bare)
        ext.poll()

        victim = [r for r in ext.emitted if r["host.name"] == "sw-b"]
        assert len(victim) == 1
        assert victim[0]["compliance.status"] == "capture_failed"
        assert victim[0]["config.capture.reason"] == "wrong_device_config"
        assert victim[0]["severity"] == "ERROR"

    def test_a_hostname_matching_another_node_name_is_still_condemned(self, tmp_path):
        """The other bleed arm: the parsed name is literally another NODE'S name."""
        bare = _bare_archive(tmp_path, {"outpost": _named(REAL_FASTPATH, "branch-sw1"),
                                        "branch-sw1": _named(REAL_FASTPATH, "branch-sw1")})
        ext = _ext(bare)
        ext.poll()

        victim = [r for r in ext.emitted if r["host.name"] == "outpost"]
        assert victim[0]["config.capture.reason"] == "wrong_device_config"
        assert victim[0]["severity"] == "ERROR"


class TestAnEmptyCaptureIsNeverCalledHousekeeping:
    """A ZERO-BYTE artefact is not a stray file. Nobody commits an empty README, and the
    placeholder names that exist for the purpose are already on _SKIP_NAMES. What an empty file
    IS, in an archive Oxidized writes, is a device whose capture produced nothing."""

    def test_a_zero_byte_capture_is_a_capture_failure_under_AUTO(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH, "sw-dead": ""})
        ext = _ext(bare)
        ext.poll()

        dead = [r for r in ext.emitted if r["host.name"] == "sw-dead"]
        assert len(dead) == 1
        assert dead[0]["compliance.status"] == "capture_failed"
        assert dead[0]["severity"] == "ERROR"
        assert dead[0]["config.capture.reason"] == "no_content"

    def test_a_non_empty_stray_file_keeps_the_INFO_verdict(self, tmp_path):
        """The cost asymmetry still applies where the artefact carries actual bytes: crying
        "your backup is broken" over repository housekeeping burns the alarm."""
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH, "placeholder": "\n\n\n"})
        ext = _ext(bare)
        ext.poll()

        rec = [r for r in ext.emitted if r.get("config.capture.reason") == "archive_non_config"]
        assert len(rec) == 1 and rec[0]["severity"] == "INFO"

    def test_the_wording_no_longer_tells_an_operator_to_hide_a_device(self):
        """It cannot know which case it is, so it must not assert one and offer only its
        remediation. The old sentence ended "Set a device pattern to exclude it"."""
        text = CAPTURE_REASONS["archive_non_config"]
        assert "If it IS one of your nodes" in text
        assert "check Oxidized's log for that node" in text


class TestControlCharactersNeverReachTheJoinKey:
    """host.name is shipped in four fields including the join key. errors="replace" does not
    help — NUL is valid UTF-8 — and _NAMEV's bare branch matches it."""

    @pytest.mark.parametrize("raw", ["a\x00b", "sw\x07-1", "sw\x1b[31m", "sw\x7f"])
    def test_a_parsed_name_with_a_control_character_falls_back_to_the_stem(self, raw):
        text = f"!Current Configuration:\nhostname {raw}\nvlan 10\nsntp client mode broadcast\n"
        name, _, src, _ = ComplianceExtension._meta(text, "node-7", "netgear")
        assert name == "node-7"
        assert src == "filename"

    def test_a_binary_blob_does_not_poison_the_fleet(self, tmp_path):
        bare = _bare_archive(tmp_path, {"outpost": REAL_FASTPATH})
        work = bare.parent / "_work"
        (work / "junk").write_bytes(b"hostname a\x00b\n" + bytes(range(256)) * 4)
        _git(work, "add", "-A")
        _git(work, "commit", "-q", "-m", "binary")
        _git(work, "push", "-q", str(bare), "main:main")

        ext = _ext(bare)
        ext.poll()

        for r in ext.emitted:
            assert not re.search(r"[\x00-\x1f\x7f]", r["host.name"]), repr(r["host.name"])


class TestLinkedWorktreeGetsAUsableTrustGrant:
    """`--absolute-git-dir` in a linked worktree is <main>/.git/worktrees/<name>, so
    dirname() named <main>/.git/worktrees — a path git will never accept for this repository.
    It degraded SAFELY (everything failed, drift went to "unknown") but the operator-facing
    remediation named a path they could do nothing with."""

    def test_the_granted_path_is_the_worktree_root(self, tmp_path):
        main = tmp_path / "main"
        main.mkdir()
        _git(main, "init", "-q", "-b", "main")
        _git(main, "config", "user.email", "test@example.invalid")
        _git(main, "config", "user.name", "test")
        (main / "sw1.cfg").write_text(REAL_FASTPATH)
        _git(main, "add", "-A")
        _git(main, "commit", "-q", "-m", "c")
        live = tmp_path / "live"
        _git(main, "worktree", "add", "-q", str(live), "-b", "live")

        arch = _ext(live)._resolve_archive(str(live))
        assert os.path.realpath(arch["root"]) == os.path.realpath(str(live))
        assert not arch["root"].endswith("worktrees")

    def test_a_foreign_owned_linked_worktree_still_reads_and_grades(self, tmp_path):
        main = tmp_path / "main"
        main.mkdir()
        _git(main, "init", "-q", "-b", "main")
        _git(main, "config", "user.email", "test@example.invalid")
        _git(main, "config", "user.name", "test")
        (main / "sw1.cfg").write_text(REAL_FASTPATH)
        _git(main, "add", "-A")
        _git(main, "commit", "-q", "-m", "c")
        live = tmp_path / "live"
        _git(main, "worktree", "add", "-q", str(live), "-b", "live")

        ext = _ext(live)
        with _foreign_owner():
            ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        for r in _drift(ext):
            assert r["config.drift_from_golden"] != "no", f"FALSE ALL-CLEAR: {r['content']}"


class TestDotLeadingPatternsMatchWhatGlobMatched:
    """The surviving guard was documented as "never match a dot-file (glob does not either)",
    which is false: glob matches a dot-segment when the PATTERN's segment starts with a dot.
    deviceGlob=".*.cfg" therefore returned ['.hidden.cfg'] before and [] after — a real, if
    narrow, regression against requirement 2 hiding behind a wrong justification."""

    def test_a_dot_leading_pattern_matches_dot_files(self):
        assert admits(".hidden.cfg", ".*.cfg") is True
        assert admits(".hidden.cfg", "*.cfg") is False

    def test_git_storage_is_still_unreachable_by_any_pattern(self):
        for pattern in ("*/*.cfg", ".*/*.cfg", ".git/*.cfg", "*/*"):
            assert admits(".git/objects/x.cfg", pattern) is False
            assert admits(".git/config", pattern) is False

    def test_auto_still_refuses_every_dot_segment(self):
        for rel in (".hidden.cfg", ".config/sw1", "core/.hidden"):
            assert admits(rel, AUTO_GLOB) is False

    def test_it_is_differentially_identical_on_a_widened_tree(self, tmp_path):
        """Requirement 2 restated against the cases the round-one differential missed: a
        filename CONTAINING ".git" (the old filter was a whole-path substring test), a
        directory whose name ends ".git", and dot-leading patterns."""
        import glob as _glob

        tree = ["sw1.cfg", "sw1.git.cfg", ".hidden.cfg", ".hidden.txt", "core/sw2.cfg",
                "core/.hidden.cfg", "backup.git/sw9.cfg", "logs/sw3.cfg", "sw.txt",
                "10.0.0.1.cfg", "outpost", "deep/er/sw8.cfg"]
        for rel in tree:
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x\n")

        ext = _ext(tmp_path)
        for pattern in (".*.cfg", ".*.txt", "*/.*.cfg", "*.cfg", "*/*.cfg", "core/*.cfg",
                        "sw?.cfg", "[se]*.cfg", "deep/*/*.cfg", "*.txt", "*"):
            old = sorted(
                os.path.relpath(f, str(tmp_path)).replace(os.sep, "/")
                for f in _glob.glob(os.path.join(str(tmp_path), pattern))
                if os.path.isfile(f))
            assert ext._list_disk(str(tmp_path), pattern) == old, f"diverged on {pattern!r}"


class TestUnreadableBlobsAreNeverSilent:
    """A device the archive LISTS but cannot produce bytes for must not vanish.

    Named in test_capture_health.py's exhaustiveness guard as archive_unreadable_file's
    end-to-end coverage. The failure this pins is TOTAL SILENCE for one device while its
    neighbours grade normally: the fleet quietly shrinks and every remaining row is green, so
    nothing downstream can tell that a device stopped being assessed. _load_configs counted
    `unread` for exactly this purpose and the count was only ever wired to the all-or-nothing
    archive_empty path, which fires only when NOTHING loaded.
    """

    def _break_one(self, tmp_path, victim="sw2"):
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n) for n in
                                        ("sw1", "sw2", "sw3")})
        sha = _git(bare, "rev-parse", f"HEAD:{victim}").stdout.strip()
        os.remove(os.path.join(str(bare), "objects", sha[:2], sha[2:]))
        return bare

    def test_the_device_gets_its_own_error_record_and_its_neighbours_still_grade(self, tmp_path):
        bare = self._break_one(tmp_path)
        ext = _ext(bare)
        ext.poll()

        graded = {r["host.name"] for r in ext.emitted if "compliance.control" in r}
        assert graded == {"sw1", "sw3"}, "the readable devices must still be assessed"

        failed = [r for r in ext.emitted
                  if r.get("config.capture.reason") == "archive_unreadable_file"]
        assert len(failed) == 1, "exactly one record for the one unreadable blob"
        assert failed[0]["config.capture.file"] == "sw2"
        assert failed[0]["severity"] == "ERROR"
        assert failed[0]["compliance.status"] == "capture_failed"
        assert failed[0]["config.capture.status"] == "failed"

    def test_the_record_names_the_device_rather_than_the_archive(self, tmp_path):
        """A row that says "something in the archive broke" is not alertable per device."""
        bare = self._break_one(tmp_path)
        ext = _ext(bare)
        ext.poll()

        rec = next(r for r in ext.emitted
                   if r.get("config.capture.reason") == "archive_unreadable_file")
        assert rec["host.name"] == "sw2", "identity comes from the filename stem"
        assert rec["device.identity.name_source"] == "filename", \
            "and it says so — there are no bytes to parse a hostname out of"
        assert "sw2" in rec["content"]

    def test_a_partial_failure_does_not_report_the_archive_as_empty(self, tmp_path):
        """archive_empty means coverage is zero. Two of three devices graded, so it is not."""
        bare = self._break_one(tmp_path)
        ext = _ext(bare)
        ext.poll()

        assert not [r for r in ext.emitted if r.get("compliance.status") == "archive_empty"]


class TestLocalArchiveUnreachableIsNeverSilent:
    """configPath not being a directory used to emit ZERO records.

    Named in test_capture_health.py's exhaustiveness guard as archive_path_missing's coverage.
    _empty_archive_record's docstring calls "reading zero devices must never be silent"
    non-negotiable and the README says it is always an ERROR record; both were false in LOCAL
    mode, which is the deployment shape the setup guide recommends. The triggering event is an
    NFS export or bind mount dropping — precisely the deployment remote mode exists to replace.
    """

    @pytest.mark.parametrize("shape", ["missing", "file", "empty"])
    def test_an_unreachable_path_is_one_error_record_not_silence(self, tmp_path, shape):
        if shape == "missing":
            path = str(tmp_path / "not-there")
        elif shape == "file":
            path = str(tmp_path / "a-file")
            open(path, "w").write("x")
        else:
            path = ""

        ext = _ext(path)
        ext.poll()

        assert len(ext.emitted) == 1, f"{shape}: an absence that emits nothing cannot be queried"
        rec = ext.emitted[0]
        assert rec["severity"] == "ERROR"
        assert rec["config.capture.reason"] == "archive_path_missing"
        assert rec["compliance.status"] == "archive_path_missing"
        assert rec["dt.source"] == "cno-config"
        assert rec["host.name"] == "", "archive-scoped: no device was read, so none is named"

    def test_it_is_not_blamed_on_a_remote_or_a_token(self, tmp_path):
        """archive_unreachable's remediation names a Git URL and a PAT. Neither exists here."""
        ext = _ext(str(tmp_path / "not-there"))
        ext.poll()

        content = ext.emitted[0]["content"]
        assert "token" not in content.lower()
        assert "remote git url" not in content.lower()
        assert "not a directory" in content

    def test_it_does_not_claim_to_be_freshly_refreshed(self, tmp_path):
        """The record says UNREACHABLE. It must not also say "refreshed 0 seconds ago".

        Local mode normally reports state="fresh"/age=0.0, which is true of a directory that
        exists — it is read directly, so there is no cached copy to be behind. Passing that
        through here produced refreshed="yes" and age_seconds="0" on a record whose own
        content sentence says the archive is gone: the same fabricated-zero defect that
        _fresh_dims was fixed for on archive_unreachable, reintroduced one record over.
        """
        ext = _ext(str(tmp_path / "not-there"))
        ext.poll()

        rec = ext.emitted[0]
        assert rec["config.archive.source"] == "local"
        assert rec["config.archive.refreshed"] == "no"
        assert "config.archive.age_seconds" not in rec, \
            "absent means unknown; a fabricated 0 reads as 'refreshed just now'"
        assert "config.archive.last_refresh" not in rec


def _golden_missing(ext):
    return [r for r in ext.emitted if r.get("config.drift_status") == "not_evaluated"]


class TestMissingGoldenRefIsNeverSilent:
    """No golden baseline -> every device reports drift 'unknown' and that must be queryable.

    This is the DEFAULT state of every first deployment, not an edge case: until somebody tags
    a baseline there is nothing to diff against. It is also what --prune-tags correctly
    produces once the tag is deleted upstream. Before this record existed the condition
    produced a logger.warning and no Grail evidence at all, while the Config Drift panel
    rendered the resulting drift="unknown" rows as a green "✓ on intended config" tick.
    """

    def test_a_missing_golden_ref_emits_exactly_one_record(self, tmp_path):
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n) for n in ("sw1", "sw2")})
        ext = _ext(bare)          # no golden tag was ever created
        ext.poll()

        recs = _golden_missing(ext)
        assert len(recs) == 1, "once per poll, not once per device"
        assert recs[0]["host.name"] == ""
        assert recs[0]["config.golden_ref"] == "golden"

    def test_it_is_not_reported_as_a_capture_or_archive_problem(self, tmp_path):
        """Every capture is intact and every control graded. Only the comparison is missing,
        so it must not widen config.capture.reason — the field detectors fire on."""
        bare = _bare_archive(tmp_path, {"sw1": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        rec = _golden_missing(ext)[0]
        assert "config.capture.reason" not in rec
        assert "config.capture.status" not in rec
        assert "compliance.status" not in rec

    def test_it_never_appears_as_a_phantom_device_row(self, tmp_path):
        """network.config is the per-device drift-verdict stream, and every consumer treats a
        record there as a device. An archive-scoped record on it is a nameless extra row in
        all of them — which is what the first version of this record did, and what 17 tests
        in this suite caught. It belongs on network.compliance with the other archive-scoped
        operational records, and it must carry no verdict of its own."""
        bare = _bare_archive(tmp_path, {"sw1": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        rec = _golden_missing(ext)[0]
        assert rec["log.source"] == "network.compliance"
        assert "config.drift_from_golden" not in rec
        assert all(r["host.name"] for r in ext.emitted
                   if r["log.source"] == "network.config"), \
            "every record on the drift stream must still name a device"

    def test_the_record_says_unknown_means_not_checked(self, tmp_path):
        """The whole point: 'no drift' here must not be readable as 'matches'."""
        bare = _bare_archive(tmp_path, {"sw1": REAL_FASTPATH})
        ext = _ext(bare)
        ext.poll()

        content = _golden_missing(ext)[0]["content"]
        assert "NOT CHECKED" in content
        assert "not be read as 'matches" in content

    def test_severity_is_graded_by_whether_the_operator_asked_for_drift(self, tmp_path):
        """goldenRef is nullable and the schema says "Drift is skipped if absent", so a blank
        one is a supported configuration rather than a fault. WARNing on it every poll would
        burn the alert channel for a deployment that never wanted drift; INFO still leaves the
        state fully queryable. An explicitly named ref that does not resolve IS a fault."""
        bare = _bare_archive(tmp_path, {"sw1": REAL_FASTPATH})

        blank = _ext(bare)
        blank.poll()
        assert _golden_missing(blank)[0]["severity"] == "INFO"
        assert _golden_missing(blank)[0]["config.golden_ref_configured"] == "no"

        named = _ext(bare, goldenRef="release-2026-07")
        named.poll()
        assert _golden_missing(named)[0]["severity"] == "WARN"
        assert _golden_missing(named)[0]["config.golden_ref_configured"] == "yes"
        assert _golden_missing(named)[0]["config.golden_ref"] == "release-2026-07"

    def test_devices_are_still_graded_and_still_report_drift_unknown(self, tmp_path):
        """The captures are fine. Only drift is unavailable."""
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n) for n in ("sw1", "sw2")})
        ext = _ext(bare)
        ext.poll()

        assert {r["host.name"] for r in ext.emitted if "compliance.control" in r} == {"sw1", "sw2"}
        verdicts = [r for r in ext.emitted if "config.drift_from_golden" in r]
        assert verdicts and all(r["config.drift_from_golden"] == "unknown" for r in verdicts)

    def test_a_resolvable_golden_ref_emits_no_such_record(self, tmp_path):
        bare = _bare_archive(tmp_path, {"sw1": REAL_FASTPATH})
        _git(bare, "tag", "-f", "golden", "HEAD")
        ext = _ext(bare)
        ext.poll()

        assert _golden_missing(ext) == []

    def test_an_empty_archive_does_not_also_complain_about_the_baseline(self, tmp_path):
        """archive_empty is the bigger failure and already says coverage is zero. Qualifying a
        drift verdict that was never produced would be noise on top of it."""
        _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "configs.git"))
        ext = _ext(tmp_path / "configs.git")
        ext.poll()

        assert [r["config.capture.reason"] for r in ext.emitted] == ["archive_empty"]
        assert _golden_missing(ext) == []


class TestOnlyArchiveScopedRecordsMayOmitADevice:
    """A record with no host.name is either archive-scoped or a bug.

    Several tests express "these are the devices" as a set comprehension over every emitted
    record. Those had to be scoped to records that NAME a device once archive-scoped records
    (archive_stale, golden-ref-missing, ...) could ride alongside device records in a healthy
    poll. This is the guard that keeps the protection they used to give: a spurious nameless
    record is caught here once, centrally, instead of four times by accident.
    """

    # Every archive-scoped record this module is allowed to emit, identified the way a
    # consumer would have to identify it. Anything nameless outside this set is a defect.
    ARCHIVE_SCOPED = ("config.capture.reason", "config.drift_status")

    def _poll(self, tmp_path, **cfg):
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n) for n in ("sw1", "sw2")})
        ext = _ext(bare, **cfg)
        ext.poll()
        return ext

    def test_a_nameless_record_always_declares_what_it_is_about(self, tmp_path):
        ext = self._poll(tmp_path)          # no golden tag -> the drift-notice record fires
        nameless = [r for r in ext.emitted if not r["host.name"]]

        assert nameless, "this fixture is meant to produce one, or it is not testing anything"
        for r in nameless:
            assert any(k in r for k in self.ARCHIVE_SCOPED), \
                f"nameless record with no archive-scoped marker: {r.get('content', '')[:120]}"

    def test_every_record_that_grades_or_judges_a_device_names_one(self, tmp_path):
        """The inverse, and the one that actually matters: a verdict about a device that does
        not say WHICH device is unusable downstream — host.name is the join key."""
        ext = self._poll(tmp_path)

        for r in ext.emitted:
            if "compliance.control" in r or "config.drift_from_golden" in r:
                assert r["host.name"], f"unattributed verdict: {r.get('content', '')[:120]}"

    def test_a_fully_healthy_poll_emits_no_nameless_records_at_all(self, tmp_path):
        """With a golden baseline present and the archive readable there is nothing to report
        at archive scope, so every record should belong to a device."""
        bare = _bare_archive(tmp_path, {n: _named(REAL_FASTPATH, n) for n in ("sw1", "sw2")})
        _git(bare, "tag", "-f", "golden", "HEAD")
        ext = _ext(bare)
        ext.poll()

        assert [r for r in ext.emitted if not r["host.name"]] == []
