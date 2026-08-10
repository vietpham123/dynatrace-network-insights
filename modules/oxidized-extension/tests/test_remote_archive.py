"""Tests for REMOTE mode: the ActiveGate maintains its own mirror of a remote Git archive.

The defect these pin is a DESIGN defect rather than a bug. configPath — a local filesystem
path — was the only way this extension could reach the archive, and in the deployment measured
on 2026-08-02 that one assumption forced Oxidized in a container on cno-svc, the ActiveGate on
a different VM, an NFS export to bridge them, a foreign-owned repository (uid 30000),
safe.directory handling, and then --no-ext-diff/--no-textconv/core.fsmonitor=false to close the
command-execution hole safe.directory opened. All of it scaffolding around one wrong assumption.

Every remote here is a `file://` URL, so the suite needs no network and no server. That is not
a weaker test than it looks: file:// exercises the identical clone/fetch/prune/refspec
machinery, and it reproduces the credential leak exactly — measured 2026-08-02, `git clone
--mirror "file://oauth2:SECRET@/path/src.git"` succeeds AND writes the password into
<mirror>/config, byte-for-byte the https failure this module has to prevent. The two things
file:// cannot reach — argv exposure and the child environment — are covered by a fake `git` on
PATH that records its argv and environment (TestTheTokenNeverLeaks), and the orphaned-transport
-helper failure is covered by a fake `git` that backgrounds a child (TestATimeoutKillsTheWholeProcessGroup).

The two classes that matter most are TestRemoteUnreachableWithAWarmMirror and
TestStalenessIsNeverSilent. Holding a mirror creates a failure mode this module did not have
before — serving data that is real but OLD — and serving it silently would be a fifth instance
of the false all-clear the rest of the module was hardened against. One is asserted to keep
grading and say so at WARN; the other is asserted to STOP grading and say so at ERROR.
"""
import json
import logging
import os
import subprocess
import tempfile
import time

import pytest

from oxidized_extension.__main__ import (
    AUTO_GLOB, CAPTURE_REASONS, MIRROR_DIRNAME, STALE_FLOOR_SECONDS, ComplianceExtension,
    _ag_runtime_dir, _budgets, _interval_seconds, _mirror_root, _redact, _sanitize_remote,
)

ARTEFACTS = os.path.join(os.path.dirname(__file__), "artefacts")
SCHEMA = os.path.join(os.path.dirname(__file__), "..", "extension", "activationSchema.json")

# The same real 5494-byte GSM7248V2 capture the rest of the suite is anchored on, so a device
# read through a mirror is asserted to produce the SAME identity and the SAME grading as one
# read off disk — which is the point of remote mode adding no second reader.
REAL_FASTPATH = open(os.path.join(ARTEFACTS, "gsm7248v2-fastpath-good.cfg")).read()

TOKEN = "glpat-SUPERSECRET123"


def _git(d, *args, check=True):
    return subprocess.run(["git", "-C", str(d), *args], check=check,
                          capture_output=True, text=True)


def _named(text, name):
    return text.replace('snmp-server sysname "outpost"', f'snmp-server sysname "{name}"')


def _remote(tmp_path, blobs, name="src.git", branch="main"):
    """A bare repository standing in for the customer's Git host, reachable over file://.

    Shaped exactly like Oxidized's git output backend: blob names carry no extension because
    Oxidized names each blob after the node.
    """
    bare = tmp_path / name
    work = tmp_path / ("_work_" + name.replace(".", "_"))
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, capture_output=True)
    work.mkdir()
    _git(work, "init", "-q", "-b", branch)
    _git(work, "config", "user.email", "test@example.invalid")
    _git(work, "config", "user.name", "test")
    _push(bare, blobs, branch=branch)
    _git(bare, "symbolic-ref", "HEAD", f"refs/heads/{branch}")
    return bare


def _push(bare, blobs, branch="main", msg="capture"):
    work = bare.parent / ("_work_" + bare.name.replace(".", "_"))
    for name, text in blobs.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text(text)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", msg)
    _git(work, "push", "-q", str(bare), f"{branch}:{branch}")


def _url(bare):
    return "file://" + str(bare)


CONFIG_ID = "monitoring-config-0001"


def _ext(**cfg):
    """A ComplianceExtension with no SDK lifecycle — same construction as the sibling suites."""
    ext = object.__new__(ComplianceExtension)
    ext.logger = logging.getLogger("test-oxidized-remote")
    ext.emitted = []
    ext.monitoring_config_id = cfg.pop("config_id", CONFIG_ID)
    ext._cfg = lambda: dict(cfg)
    ext.report_log_events = ext.emitted.extend
    return ext


@pytest.fixture
def ag(tmp_path, monkeypatch):
    """An EEC-shaped TMPDIR, so _mirror_base resolves the way it does on the ActiveGate.

    Measured on the lab ActiveGate 2026-08-02, the datasource's TMPDIR is
    <agent>//runtime/datasources/working_directories/<dsid><epoch_ms>/tmp and <agent>/runtime/
    extensions is a writable dtuserag-owned directory. Both halves are reproduced here rather
    than stubbed, so _ag_runtime_dir and _mirror_base are exercised for real.
    """
    runtime = tmp_path / "agent" / "runtime"
    (runtime / "extensions").mkdir(parents=True)
    wd = runtime / "datasources" / "working_directories" / "ds1770000000000" / "tmp"
    wd.mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(wd))
    # tempfile caches gettempdir() in a module global, so the last-resort candidate is pinned
    # inside tmp_path too — no test may create directories in the real system temp.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "systmp"))
    return runtime


def _mirror_path(ag, config_id=CONFIG_ID):
    return ag / "extensions" / MIRROR_DIRNAME / (config_id + ".git")


def _controls(ext):
    return [r for r in ext.emitted if "compliance.control" in r]


def _drift(ext):
    return [r for r in ext.emitted if r["log.source"] == "network.config"]


def _archive_records(ext):
    return [r for r in ext.emitted
            if r.get("config.capture.reason", "").startswith("archive_")
            and r.get("host.name") == ""]


def _age_back(mirror, seconds):
    """Make the last verified refresh look `seconds` old, the way a real outage would."""
    marker = os.path.join(str(mirror), "cno-last-refresh")
    t = time.time() - seconds
    os.utime(marker, (t, t))


# ══════════════════════════════════════════════════════════════════════════════════════════
# Requirement 1 — configure a remote URL, mirror it, read it with the EXISTING reader
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestFirstPollClonesAndReads:

    def test_the_device_is_read_graded_and_identified_through_the_mirror(self, tmp_path, ag):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        assert ext.emitted, "0 records is the defect: an absence cannot be queried"
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert {r["device.address"] for r in _controls(ext)} == {"10.0.10.3"}
        assert [r for r in ext.emitted if "config.capture.status" in r] == [], \
            "a healthy capture must not be reported as any kind of archive problem"

    def test_the_mirror_is_a_bare_repo_the_existing_reader_already_understands(self, tmp_path, ag):
        """Requirement 1's other half: NO second reader.

        _resolve_archive is the module's own classifier and it is asked here directly. A mirror
        must land on exactly the shape the bare-repo path was written for, and it must be
        same-user — a mirror the ActiveGate created is owned by the ActiveGate, so the whole
        safe.directory apparatus is inert for it (it stays for local mode, which still needs it).
        """
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH, "edge/branch-sw1": _named(REAL_FASTPATH, "branch-sw1")})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        mirror = _mirror_path(ag)
        assert mirror.is_dir()
        arch = ext._resolve_archive(str(mirror))
        assert arch == {"kind": "git", "bare": True, "root": str(mirror), "prefix": "",
                        "ownership": "same-user"}
        assert {r["host.name"] for r in _controls(ext)} == {"outpost", "branch-sw1"}

    def test_the_mirror_directory_is_private(self, tmp_path, ag):
        """The mirror holds device RUNNING-CONFIGS — the anchor capture carries password
        hashes, and any archive holds SNMP communities. 0700, not 0755."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _ext(remoteUrl=_url(src)).poll()

        base = ag / "extensions" / MIRROR_DIRNAME
        assert oct(base.stat().st_mode & 0o777) == "0o700"

    def test_drift_against_a_golden_tag_survives_the_mirror(self, tmp_path, ag):
        """`clone --mirror` brings refs/tags across, so goldenRef needs no extra refspec and no
        second code path. This is the capability that rules out Oxidized's REST API, which
        returns only the current config."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _git(src, "tag", "golden", "main")
        _push(src, {"outpost": REAL_FASTPATH.replace('snmp-server location "basement"',
                                                     'snmp-server location "roof"')})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        drift = _drift(ext)
        assert len(drift) == 1
        assert drift[0]["config.drift_from_golden"] == "yes"
        assert '+snmp-server location "roof"' in drift[0]["config.diff"]

    def test_the_history_walk_works_through_the_mirror(self, tmp_path, ag):
        """The clean-truncation guard needs `git log` + `git show` against blobs that exist
        only inside the object store. A shallow clone would kill this, which is why there is
        no --depth anywhere in this design."""
        big = REAL_FASTPATH + "".join(
            f"interface 0/{n}\nvlan pvid 10\nvlan participation include 10\nexit\n"
            for n in range(100, 400))
        src = _remote(tmp_path, {"outpost": big})
        _push(src, {"outpost": REAL_FASTPATH}, msg="session died early")
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        rec = [r for r in ext.emitted if "config.capture.reason" in r][0]
        assert rec["config.capture.reason"] == "shrank_vs_last_good"
        assert int(rec["config.capture.prev_bytes"]) == len(big.encode())


class TestSteadyStateFetch:

    def test_the_second_poll_fetches_rather_than_re_cloning(self, tmp_path, ag):
        """A sentinel inside the mirror is the discriminator: _clone_fresh rmtree's the mirror
        and renames a replacement over it, so a sentinel that SURVIVES proves the update came
        from a fetch. Re-cloning every poll would work and would be wrong — it re-downloads the
        entire history on every interval."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        mirror = _mirror_path(ag)
        (mirror / "sentinel").write_text("poll-1")

        _push(src, {"outpost": _named(REAL_FASTPATH, "outpost-renamed")})
        ext2 = _ext(remoteUrl=_url(src))
        ext2.poll()

        assert (mirror / "sentinel").exists(), "the mirror was re-cloned instead of fetched"
        assert {r["host.name"] for r in _controls(ext2)} == {"outpost-renamed"}, \
            "the fetch did not bring the new revision across"

    def test_a_deleted_upstream_tag_stops_resolving_locally(self, tmp_path, ag):
        """--prune-tags is load-bearing, not tidiness. Without it a `golden` tag deleted
        upstream keeps resolving in the mirror forever and drift keeps reporting "matches
        golden" against a baseline that no longer exists — a fifth route into this codebase's
        recurring false all-clear."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _git(src, "tag", "golden", "main")
        ext = _ext(remoteUrl=_url(src))
        ext.poll()
        mirror = _mirror_path(ag)
        assert _git(mirror, "rev-parse", "--verify", "golden", check=False).returncode == 0

        _git(src, "tag", "-d", "golden")
        ext2 = _ext(remoteUrl=_url(src))
        ext2.poll()

        assert _git(mirror, "rev-parse", "--verify", "golden", check=False).returncode != 0
        assert [r["config.drift_from_golden"] for r in _drift(ext2)] == ["unknown"], \
            "with the baseline gone, drift must be UNKNOWN — never 'matches'"

    def test_a_force_pushed_remote_is_followed_without_force(self, tmp_path, ag):
        """The mirror refspec is +refs/*:refs/*, so a rewound history is already handled. No
        --force anywhere in this design, deliberately."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        work = src.parent / ("_work_" + src.name.replace(".", "_"))
        _git(work, "reset", "-q", "--hard", "HEAD")
        (work / "outpost").write_text(_named(REAL_FASTPATH, "rewritten"))
        _git(work, "add", "-A")
        _git(work, "commit", "-q", "--amend", "-m", "rewritten history")
        _git(work, "push", "-q", "--force", str(src), "main:main")

        ext2 = _ext(remoteUrl=_url(src))
        ext2.poll()
        assert {r["host.name"] for r in _controls(ext2)} == {"rewritten"}


# ══════════════════════════════════════════════════════════════════════════════════════════
# Requirement 3 — staleness is NEVER silent
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestRemoteUnreachableWithAWarmMirror:
    """The failure mode holding a mirror CREATES. Serving it silently would be the defect."""

    def test_devices_are_still_graded_and_the_staleness_is_reported(self, tmp_path, ag):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()

        src.rename(tmp_path / "src.git.gone")          # the remote goes away
        ext = _ext(remoteUrl=url)
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}, \
            "refusing to grade a mirror inside the limit recreates the device-goes-silent bug"
        assert _drift(ext), "drift is still a fact worth reporting off last-good data"

        stale = _archive_records(ext)
        assert len(stale) == 1, "exactly one archive-scoped record, not one per device"
        assert stale[0]["compliance.status"] == "archive_stale"
        assert stale[0]["config.capture.reason"] == "archive_stale"
        assert stale[0]["severity"] == "WARN"

    def test_warn_not_error_so_the_dead_archive_alert_keeps_its_meaning(self, tmp_path, ag):
        """dt.source == "cno-config" and severity == "ERROR" is the low-cardinality alert
        trigger this module established, and it must keep meaning "grading stopped". A
        transient hiccup must not fire the same alert as a dead archive."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        src.rename(tmp_path / "gone.git")

        ext = _ext(remoteUrl=url)
        ext.poll()
        assert [r for r in ext.emitted if r["severity"] == "ERROR"] == []

    def test_every_record_carries_the_freshness_dimensions(self, tmp_path, ag):
        """Requirement 3, positively: freshness rides on records that already exist, so it is
        never inferred from silence. The stated consumer contract is that refreshed == "no"
        means UNKNOWN, not healthy — including on the drift records, where a stale "no" would
        otherwise paint "on intended config" over a device that has since drifted."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        src.rename(tmp_path / "gone.git")

        ext = _ext(remoteUrl=url)
        ext.poll()

        assert len(ext.emitted) > 5
        for r in ext.emitted:
            assert r["config.archive.refreshed"] == "no"
            assert r["config.archive.source"] == "remote"
            assert r["config.archive.url"] == url
            assert int(r["config.archive.age_seconds"]) >= 0
            assert r["config.archive.last_refresh"].startswith("20")

    def test_a_recovered_remote_goes_back_to_fresh(self, tmp_path, ag):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        src.rename(tmp_path / "gone.git")
        _ext(remoteUrl=url).poll()

        (tmp_path / "gone.git").rename(src)
        ext = _ext(remoteUrl=url)
        ext.poll()

        assert _archive_records(ext) == []
        assert all(r["config.archive.refreshed"] == "yes" for r in ext.emitted)


class TestRemoteUnreachableWithNoMirror:

    def test_one_error_record_and_nothing_else(self, tmp_path, ag):
        ext = _ext(remoteUrl=_url(tmp_path / "does-not-exist.git"))
        ext.poll()

        assert len(ext.emitted) == 1, "zero records is the failure this module exists to remove"
        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_unreachable"
        assert rec["config.capture.reason"] == "archive_unreachable"
        assert rec["severity"] == "ERROR"
        assert rec["dt.source"] == "cno-config"
        assert rec["log.source"] == "network.compliance"
        assert CAPTURE_REASONS["archive_unreachable"] in rec["content"]
        assert _controls(ext) == [] and _drift(ext) == []

    def test_it_says_coverage_is_zero_rather_than_clean(self, tmp_path, ag):
        ext = _ext(remoteUrl=_url(tmp_path / "nope.git"))
        ext.poll()
        assert "ZERO" in ext.emitted[0]["content"]
        assert ext.emitted[0]["config.archive.refreshed"] == "no"

    def test_no_writable_base_is_reported_not_swallowed(self, tmp_path, ag):
        """An ActiveGate with nowhere to put the mirror must say so, not go quiet."""
        ext = _ext(remoteUrl="https://gitlab.example.invalid/net/oxidized.git")
        ext._mirror_base = lambda: ""
        ext.poll()

        assert len(ext.emitted) == 1
        assert ext.emitted[0]["config.capture.reason"] == "archive_unreachable"
        assert "no writable directory" in ext.emitted[0]["content"]


class TestStalenessIsNeverSilent:
    """Past the limit, grading STOPS. The module already argues why: a stale dashboard number
    "is not merely incomplete, it is stale and wrong, and decays hourly"."""

    def test_beyond_the_limit_nothing_is_graded_and_one_error_says_so(self, tmp_path, ag):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        mirror = _mirror_path(ag)
        src.rename(tmp_path / "gone.git")
        _age_back(mirror, STALE_FLOOR_SECONDS + 60)

        ext = _ext(remoteUrl=url)
        ext.poll()

        assert len(ext.emitted) == 1
        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_stale_refused"
        assert rec["severity"] == "ERROR"
        assert _controls(ext) == [] and _drift(ext) == []
        assert CAPTURE_REASONS["archive_stale_refused"] in rec["content"]
        assert int(rec["config.archive.stale_limit_seconds"]) == STALE_FLOOR_SECONDS

    def test_the_mirror_is_kept_so_recovery_needs_no_re_clone(self, tmp_path, ag):
        """Refusing to SERVE stale data is not the same as destroying it."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        mirror = _mirror_path(ag)
        src.rename(tmp_path / "gone.git")
        _age_back(mirror, STALE_FLOOR_SECONDS + 60)
        _ext(remoteUrl=url).poll()

        assert mirror.is_dir()
        assert _git(mirror, "rev-parse", "-q", "--verify", "HEAD^{commit}",
                    check=False).returncode == 0

    def test_just_inside_the_limit_still_grades(self, tmp_path, ag):
        """The boundary is asserted from both sides, because an off-by-one here is the
        difference between a working capability and a blank dashboard."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        mirror = _mirror_path(ag)
        src.rename(tmp_path / "gone.git")
        _age_back(mirror, STALE_FLOOR_SECONDS - 600)

        ext = _ext(remoteUrl=url)
        ext.poll()
        assert _controls(ext), "just inside the limit must still grade"
        assert _archive_records(ext)[0]["compliance.status"] == "archive_stale"

    def test_a_mirror_that_was_never_verified_is_refused(self, tmp_path, ag):
        """A usable-looking directory with no refresh marker cannot PROVE when it last reached
        the remote. Unprovable freshness is refused, which is the only direction consistent
        with requirement 3."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        mirror = _mirror_path(ag)
        os.remove(mirror / "cno-last-refresh")
        src.rename(tmp_path / "gone.git")

        ext = _ext(remoteUrl=url)
        ext.poll()
        assert len(ext.emitted) == 1
        assert ext.emitted[0]["compliance.status"] == "archive_stale_refused"
        assert "never been successfully refreshed" in ext.emitted[0]["content"]

    def test_the_limit_never_drops_below_a_legal_poll_interval(self, tmp_path, ag):
        """The floor is IMPLIED, not chosen: intervalSeconds ships with "maximum": 86400, so a
        limit below that would make a legally-configured 24-hour poll declare itself stale
        between its own polls. The 2x multiplier means one missed refresh never blanks the view
        at any cadence."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url, intervalSeconds=86400).poll()
        mirror = _mirror_path(ag)
        src.rename(tmp_path / "gone.git")
        _age_back(mirror, 100000)                      # > the floor, < 2 x the interval

        ext = _ext(remoteUrl=url, intervalSeconds=86400)
        ext.poll()
        assert _controls(ext), "at a 24h poll, a 100000s-old mirror is ONE missed refresh"
        assert int(_archive_records(ext)[0]["config.archive.stale_limit_seconds"]) == 172800

    def test_a_failed_fetch_does_not_advance_the_freshness_marker(self, tmp_path, ag):
        """The measurement that forced this module to own a marker at all. On the ActiveGate's
        git 2.34.1, FETCH_HEAD's mtime ADVANCES on a failed fetch (rc 128), so reusing it would
        report a dead archive as freshly refreshed."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        marker = _mirror_path(ag) / "cno-last-refresh"
        before = marker.stat().st_mtime

        src.rename(tmp_path / "gone.git")
        _ext(remoteUrl=url).poll()

        assert marker.stat().st_mtime == before, \
            "the marker is written ONLY after a fetch that returned 0 and verified"

    def test_a_healthy_but_unchanged_archive_is_never_called_stale(self, tmp_path, ag):
        """Oxidized commits only on CHANGE, so a stable fleet's HEAD commit can be weeks old.
        The freshness signal is "when did we last reach the remote", never the commit date —
        otherwise a perfectly working network alarms."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        old = time.time() - 90 * 86400
        for root, _dirs, files in os.walk(src):
            for f in files:
                os.utime(os.path.join(root, f), (old, old))
        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        assert _archive_records(ext) == []
        assert all(r["config.archive.refreshed"] == "yes" for r in ext.emitted)


# ══════════════════════════════════════════════════════════════════════════════════════════
# Recovery paths
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestCorruptMirrorRecovery:

    @staticmethod
    def _corrupt(mirror):
        packs = [p for p in (mirror / "objects" / "pack").iterdir() if p.suffix == ".pack"]
        assert packs, "clone --mirror should produce a packfile"
        pk = packs[0]
        pk.chmod(0o644)
        pk.write_bytes(b"X" * pk.stat().st_size)

    def test_the_probe_catches_what_is_bare_repository_misses(self, tmp_path, ag):
        """The obvious probe is the wrong one, and picking it would make the recovery below
        unreachable. Re-measured here against a mirror whose packfile has been overwritten:

            rev-parse --is-bare-repository      rc 0, prints "true"   <- DOES NOT DETECT IT
            rev-parse -q --verify HEAD^{commit} rc 1                   <- detects it
            ls-tree -r HEAD                     rc 128
            show HEAD:outpost                   rc 128
        """
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=_url(src))
        ext.poll()
        mirror = _mirror_path(ag)
        self._corrupt(mirror)

        bare = _git(mirror, "rev-parse", "--is-bare-repository", check=False)
        assert (bare.returncode, bare.stdout.strip()) == (0, "true")
        assert _git(mirror, "ls-tree", "-r", "HEAD", check=False).returncode != 0
        assert ext._mirror_usable(str(mirror)) is False

    def test_a_corrupt_mirror_is_re_cloned_and_the_devices_come_back(self, tmp_path, ag):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _ext(remoteUrl=_url(src)).poll()
        mirror = _mirror_path(ag)
        self._corrupt(mirror)

        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert _archive_records(ext) == []
        assert all(r["config.archive.refreshed"] == "yes" for r in ext.emitted)

    def test_a_corrupt_mirror_with_a_dead_remote_is_unreachable_not_stale(self, tmp_path, ag):
        """There is nothing safe to serve, so it must not be dressed up as last-good data."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        url = _url(src)
        _ext(remoteUrl=url).poll()
        self._corrupt(_mirror_path(ag))
        src.rename(tmp_path / "gone.git")

        ext = _ext(remoteUrl=url)
        ext.poll()
        assert len(ext.emitted) == 1
        assert ext.emitted[0]["compliance.status"] == "archive_unreachable"

    def test_a_partial_directory_left_by_a_killed_clone_does_not_wedge_the_mirror(self, tmp_path, ag):
        """Measured asymmetry: a FAILED clone removes its own destination, but a KILLED clone —
        exactly what a timeout produces — leaves a partial directory that clone can then never
        reuse ("destination path already exists and is not an empty directory"). <mirror>.new
        is therefore removed before AND after every attempt."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        base = ag / "extensions" / MIRROR_DIRNAME
        base.mkdir(parents=True, exist_ok=True)
        leftover = base / (CONFIG_ID + ".git.new")
        leftover.mkdir()
        (leftover / "half-downloaded").write_text("x")

        ext = _ext(remoteUrl=_url(src))
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert not leftover.exists(), "the staging directory must not survive a successful swap"

    def test_a_failed_clone_never_destroys_the_last_good_mirror(self, tmp_path, ag):
        """This is what makes the staleness contract real rather than nominal: a re-clone that
        fails because the network is down must not destroy the last-good data.

        The URL-change path is used because it is the only one where a clone runs while a GOOD
        mirror is already on disk — steps 1 and 4 of _refresh_mirror only clone when there is
        nothing worth keeping. The mirror must survive intact and readable, and the staging
        directory must not be left behind to wedge the next attempt.
        """
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _ext(remoteUrl=_url(src)).poll()
        mirror = _mirror_path(ag)
        head = _git(mirror, "rev-parse", "HEAD").stdout.strip()

        _ext(remoteUrl=_url(tmp_path / "unreachable.git")).poll()

        assert _git(mirror, "rev-parse", "HEAD").stdout.strip() == head
        assert _git(mirror, "cat-file", "-e", head, check=False).returncode == 0, \
            "the objects must survive, not just the ref"
        assert not (mirror.parent / (CONFIG_ID + ".git.new")).exists()


class TestChangedRemoteUrl:

    def test_pointing_at_a_new_remote_re_clones_rather_than_re_pointing(self, tmp_path, ag):
        """`git remote set-url` was rejected on measurement. On git 2.34.1 — the ActiveGate's
        version — repointing a mirror whose HEAD is refs/heads/master at a remote whose default
        branch is `main` and fetching gives rc 0 and leaves HEAD on the now-deleted master
        ("fatal: Not a valid object name HEAD"). It would also keep the previous remote's
        objects, serving them by SHA."""
        a = _remote(tmp_path, {"outpost": REAL_FASTPATH}, name="a.git")
        b = _remote(tmp_path, {"branch-sw1": _named(REAL_FASTPATH, "branch-sw1")},
                    name="b.git", branch="master")
        _ext(remoteUrl=_url(a)).poll()
        mirror = _mirror_path(ag)
        old_head = _git(mirror, "rev-parse", "HEAD").stdout.strip()
        (mirror / "sentinel").write_text("from-a")

        ext = _ext(remoteUrl=_url(b))
        ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"branch-sw1"}
        assert not (mirror / "sentinel").exists(), "a set-url + fetch would have kept this"
        assert _git(mirror, "cat-file", "-e", old_head, check=False).returncode != 0, \
            "the previous remote's objects must not still be servable by SHA"
        assert _git(mirror, "config", "--get",
                    "remote.origin.url").stdout.strip() == _url(b)

    def test_a_url_change_whose_clone_fails_is_unavailable_never_stale(self, tmp_path, ag):
        """The mirror on disk answers a DIFFERENT repository. Serving it under the new URL —
        which is the URL stamped on every record — would be an affirmative lie, not merely old
        data. It is kept on disk so the next poll can retry without re-downloading."""
        a = _remote(tmp_path, {"outpost": REAL_FASTPATH}, name="a.git")
        _ext(remoteUrl=_url(a)).poll()
        mirror = _mirror_path(ag)

        ext = _ext(remoteUrl=_url(tmp_path / "never-existed.git"))
        ext.poll()

        assert len(ext.emitted) == 1
        rec = ext.emitted[0]
        assert rec["compliance.status"] == "archive_unreachable"
        assert "different repository" in rec["content"].lower()
        assert mirror.is_dir(), "the old mirror is kept for a cheap retry"
        assert _controls(ext) == []
        assert "config.archive.last_refresh" not in rec, \
            "the marker's timestamp belongs to the PREVIOUS remote, not this url"


# ══════════════════════════════════════════════════════════════════════════════════════════
# Requirement 4 — no token in any log, record, exception, argv, or on disk
# ══════════════════════════════════════════════════════════════════════════════════════════

def _tree_text(root):
    """Every byte under a directory, as one searchable blob."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            try:
                out.append(open(os.path.join(dirpath, f), "rb").read().decode("utf-8", "replace"))
            except OSError:
                pass
    return "\n".join(out)


class TestTheTokenNeverLeaks:

    def test_a_password_pasted_into_the_url_is_written_to_disk_by_git(self, tmp_path, ag):
        """The reproduction, before any assertion about the fix. Measured 2026-08-02 and
        reproduced here hermetically over file://: git stores the URL VERBATIM, credential and
        all, in <mirror>/config."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        leaky = f"file://oauth2:{TOKEN}@{src}"
        subprocess.run(["git", "clone", "--mirror", "--quiet", "--", leaky,
                        str(tmp_path / "leaked.git")], check=True, capture_output=True)
        assert TOKEN in (tmp_path / "leaked.git" / "config").read_text()

    def test_the_extension_stores_a_sanitised_url_instead(self, tmp_path, ag, caplog):
        """Prevented STRUCTURALLY: no command in this design is ever handed a URL containing a
        password, so there is nothing for git to write."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=f"file://oauth2:{TOKEN}@{src}")
        with caplog.at_level(logging.DEBUG):
            ext.poll()

        mirror = _mirror_path(ag)
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}, "it still works"
        assert TOKEN not in (mirror / "config").read_text()
        assert TOKEN not in _tree_text(mirror)
        assert TOKEN not in caplog.text
        assert TOKEN not in json.dumps(ext.emitted)
        assert _git(mirror, "config", "--get", "remote.origin.url").stdout.strip() \
            == f"file://oauth2@{src}"

    def test_the_operator_is_told_to_move_it_to_the_secret_field(self, tmp_path, ag, caplog):
        """Used rather than refused — it is unambiguously the credential they supplied, and
        refusing would break them without un-exposing anything already stored in the tenant —
        but never quietly."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=f"file://oauth2:{TOKEN}@{src}")
        with caplog.at_level(logging.WARNING):
            ext.poll()
        assert "secret field" in caplog.text and TOKEN not in caplog.text

    def test_the_secret_field_wins_when_both_are_supplied(self, tmp_path, ag, caplog):
        """An operator mid-migration can have both. The secret field is authoritative, and
        neither value may reach a log."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        other = "glpat-STALE-URL-PASSWORD"
        ext = _ext(remoteUrl=f"file://oauth2:{other}@{src}", remoteToken=TOKEN)
        with caplog.at_level(logging.DEBUG):
            ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert "the secret field wins" in caplog.text
        for secret in (TOKEN, other):
            assert secret not in caplog.text
            assert secret not in json.dumps(ext.emitted)
            assert secret not in _tree_text(_mirror_path(ag))

    def test_nothing_leaks_when_the_remote_is_unreachable(self, tmp_path, ag, caplog):
        """The failure path is the one that carries git's own stderr into a RECORD, so it is
        the path most likely to leak."""
        ext = _ext(remoteUrl=f"file://oauth2:{TOKEN}@{tmp_path}/nope.git")
        with caplog.at_level(logging.DEBUG):
            ext.poll()

        assert ext.emitted[0]["compliance.status"] == "archive_unreachable"
        assert TOKEN not in json.dumps(ext.emitted)
        assert TOKEN not in caplog.text
        assert ext.emitted[0]["config.archive.url"] == f"file://oauth2@{tmp_path}/nope.git"

    def test_a_secret_field_token_reaches_no_file_in_the_mirror(self, tmp_path, ag, caplog):
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        ext = _ext(remoteUrl=_url(src), remoteToken=TOKEN)
        with caplog.at_level(logging.DEBUG):
            ext.poll()

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert TOKEN not in _tree_text(_mirror_path(ag))
        assert TOKEN not in caplog.text and TOKEN not in json.dumps(ext.emitted)

    def test_sanitize_remote_handles_the_shapes_the_three_providers_document(self):
        for raw, clean, user, pw in [
            (f"https://oauth2:{TOKEN}@gitlab.example.com/net/oxidized.git",
             "https://oauth2@gitlab.example.com/net/oxidized.git", "oauth2", TOKEN),
            (f"https://x-token-auth:{TOKEN}@bitbucket.org/team/oxidized.git",
             "https://x-token-auth@bitbucket.org/team/oxidized.git", "x-token-auth", TOKEN),
            # username-only is the documented no-secret shape and must survive untouched
            ("https://oauth2@gitlab.example.com/net/oxidized.git",
             "https://oauth2@gitlab.example.com/net/oxidized.git", "oauth2", ""),
            ("https://git.example.com/net/oxidized.git",
             "https://git.example.com/net/oxidized.git", "", ""),
            ("file:///var/lib/oxidized/configs.git",
             "file:///var/lib/oxidized/configs.git", "", ""),
        ]:
            assert _sanitize_remote(raw) == (clean, user, pw)

    def test_a_percent_encoded_credential_is_decoded_the_way_git_decodes_it(self):
        clean, user, pw = _sanitize_remote("https://o%40uth:se%2Fcret@git.example.com/x.git")
        assert clean == "https://o%40uth@git.example.com/x.git"
        assert (user, pw) == ("o@uth", "se/cret")

    def test_redact_covers_the_base64_form_as_well_as_the_raw_token(self):
        """A redactor that only looked for the raw token would miss the form that actually
        travels on the wire, which is the one a proxy can echo back in an error body."""
        import base64
        header = base64.b64encode(f"oauth2:{TOKEN}".encode()).decode()
        text = f"fatal: proxy rejected 'Authorization: Basic {header}' for {TOKEN}"
        out = _redact(text, TOKEN, header)
        assert TOKEN not in out and header not in out and out.count("***") == 2


@pytest.fixture
def fake_git(tmp_path, monkeypatch):
    """A `git` on PATH that records its argv and environment instead of talking to anything.

    This is the only way to observe the two channels a file:// remote cannot reach: what lands
    in argv (world-readable via `ps -eo args` — measured 2026-08-02) and what the child process
    actually inherits.
    """
    bin_dir, out = tmp_path / "fakebin", tmp_path / "gitcall"
    bin_dir.mkdir()
    out.mkdir()
    script = bin_dir / "git"
    script.write_text("#!/bin/sh\n"
                      f'printf "%s\\n" "$@" > "{out}/argv"\n'
                      f'env > "{out}/env"\n'
                      "exit 0\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return out


class TestTheTokenTravelsInTheEnvironmentNotArgv:

    URL = "https://gitlab.example.com/net/oxidized.git"

    def _run(self, tmp_path, fake_git, **kw):
        ext = _ext()
        ok, err = ext._git_net(["clone", "--mirror", "--quiet", "--", self.URL,
                                str(tmp_path / "m.git")], token=TOKEN, url=self.URL,
                               timeout=30, **kw)
        argv = (fake_git / "argv").read_text()
        env = dict(l.split("=", 1) for l in (fake_git / "env").read_text().splitlines()
                   if "=" in l)
        return ok, err, argv, env

    def test_the_token_is_absent_from_argv_and_present_in_the_environment(self, tmp_path, fake_git):
        import base64
        ok, _err, argv, env = self._run(tmp_path, fake_git)
        assert ok
        assert TOKEN not in argv, "`-c` values are visible to any local user via ps -eo args"
        header = base64.b64encode(f"oauth2:{TOKEN}".encode()).decode()
        assert env["GIT_CONFIG_KEY_0"] == f"http.{self.URL}.extraHeader"
        assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {header}"
        assert int(env["GIT_CONFIG_COUNT"]) == 5

    def test_the_hardening_configuration_is_all_present(self, tmp_path, fake_git):
        _ok, _err, _argv, env = self._run(tmp_path, fake_git)
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        assert pairs["credential.helper"] == "", "resets any system-wide `store` helper"
        assert pairs["http.followRedirects"] == "false", \
            "git's default carries the extraHeader to the REDIRECT TARGET"
        assert pairs["http.lowSpeedLimit"] == "1000" and pairs["http.lowSpeedTime"] == "10"
        assert env["GIT_TERMINAL_PROMPT"] == "0", "a credential prompt is an infinite hang"
        assert env["GCM_INTERACTIVE"] == "never"

    def test_header_dumping_trace_variables_are_deleted_from_the_child(self, tmp_path,
                                                                       fake_git, monkeypatch):
        """GIT_TRACE_CURL and GIT_CURL_VERBOSE dump request HEADERS, and the Authorization
        header is where the token lives. An operator debugging something unrelated must not be
        able to put a customer PAT into the extension log."""
        for var in ("GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_TRACE", "GIT_TRACE_PACKET",
                    "GIT_ASKPASS", "SSH_ASKPASS"):
            monkeypatch.setenv(var, "1")
        monkeypatch.setenv("CNO_UNRELATED", "keep-me")

        _ok, _err, _argv, env = self._run(tmp_path, fake_git)
        for var in ("GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_TRACE", "GIT_TRACE_PACKET",
                    "GIT_ASKPASS", "SSH_ASKPASS"):
            assert var not in env
        assert env["CNO_UNRELATED"] == "keep-me", "only the dangerous ones are dropped"

    def test_no_header_is_injected_for_a_transport_that_cannot_use_one(self, tmp_path, fake_git):
        ext = _ext()
        ext._git_net(["clone", "--mirror", "--", "file:///tmp/x.git", str(tmp_path / "m.git")],
                     token=TOKEN, url="file:///tmp/x.git", timeout=30)
        env = dict(l.split("=", 1) for l in (fake_git / "env").read_text().splitlines()
                   if "=" in l)
        assert int(env["GIT_CONFIG_COUNT"]) == 4
        assert not any("extraHeader" in v for v in env.values())
        assert TOKEN not in (fake_git / "env").read_text()


class TestATimeoutKillsTheWholeProcessGroup:
    """subprocess.run(timeout=) kills ONLY the direct child, and `git fetch` over https spawns
    git-remote-https. Measured 2026-08-02: `sh -c 'sleep 30 & wait'` with timeout=2 raised
    TimeoutExpired and left "99593 1 sleep 30" running; the same call with
    start_new_session=True plus os.killpg(SIGKILL) left 0 survivors. Without this the extension
    would leak a transport helper holding a socket on EVERY POLL."""

    def test_the_background_transport_helper_does_not_survive(self, tmp_path, monkeypatch):
        bin_dir, out = tmp_path / "slowbin", tmp_path / "slowcall"
        bin_dir.mkdir()
        out.mkdir()
        script = bin_dir / "git"
        script.write_text("#!/bin/sh\n"
                          "sleep 20 &\n"
                          f'echo $! > "{out}/childpid"\n'
                          "wait\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

        ext = _ext()
        ok, err = ext._git_net(["fetch", "--", "origin"], token="", url="https://x.invalid/a.git",
                               timeout=1)

        assert ok is False and "timed out after 1s" in err
        pid = int((out / "childpid").read_text().strip())
        for _ in range(40):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"orphaned helper {pid} survived the timeout")


# ══════════════════════════════════════════════════════════════════════════════════════════
# Requirement 2 — local-path mode is unchanged
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestLocalPathModeIsUnchanged:

    def test_a_plain_directory_still_reads_with_no_remote_configured(self, tmp_path, ag):
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        ext = _ext(configPath=str(tmp_path))
        ext.poll()
        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}

    def test_an_empty_remote_url_is_local_mode_not_an_error(self, tmp_path, ag):
        """A nullable text property arrives as "" or None, and neither may switch modes."""
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        for value in ("", "   ", None):
            ext = _ext(configPath=str(tmp_path), remoteUrl=value)
            ext.poll()
            assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
            assert all(r["config.archive.source"] == "local" for r in ext.emitted)

    def test_local_mode_claims_no_remote_it_does_not_have(self, tmp_path, ag):
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        ext = _ext(configPath=str(tmp_path))
        ext.poll()
        for r in ext.emitted:
            assert r["config.archive.refreshed"] == "yes"
            assert r["config.archive.age_seconds"] == "0"
            assert "config.archive.url" not in r
            assert "config.archive.last_refresh" not in r

    def test_no_mirror_is_created_in_local_mode(self, tmp_path, ag):
        (tmp_path / "outpost.cfg").write_text(REAL_FASTPATH)
        _ext(configPath=str(tmp_path)).poll()
        assert not (ag / "extensions" / MIRROR_DIRNAME).exists()

    def test_a_foreign_owned_local_archive_still_gets_its_narrow_trust_grant(self, tmp_path, ag,
                                                                             caplog):
        """The safe.directory handling exists for LOCAL mode and must not have been removed
        along with the reason remote mode does not need it."""
        bare = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        os.environ["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
        try:
            ext = _ext(configPath=str(bare))
            with caplog.at_level(logging.WARNING):
                ext.poll()
        finally:
            os.environ.pop("GIT_TEST_ASSUME_DIFFERENT_OWNER", None)

        assert {r["host.name"] for r in _controls(ext)} == {"outpost"}
        assert "safe.directory=" in caplog.text
        assert all(r["config.archive.source"] == "local" for r in ext.emitted)


# ══════════════════════════════════════════════════════════════════════════════════════════
# Where the mirror lives, and how it is keyed
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestMirrorPlacement:

    def test_the_runtime_dir_is_derived_from_the_measured_tmpdir_shape(self, monkeypatch):
        """Verbatim from /proc/<pid>/environ on the lab ActiveGate 2026-08-02, double slash
        included — which is why this cuts on a marker rather than counting path segments."""
        monkeypatch.setenv(
            "TMPDIR", "/var/lib/dynatrace/remotepluginmodule/agent//runtime/datasources/"
                      "working_directories/ds4711770000000000/tmp")
        assert _ag_runtime_dir() == \
            "/var/lib/dynatrace/remotepluginmodule/agent//runtime"

    @pytest.mark.parametrize("tmpdir", ["", "/tmp", "/var/folders/xy/T/pytest-1"])
    def test_a_non_eec_tmpdir_yields_no_runtime_dir(self, monkeypatch, tmpdir):
        monkeypatch.setenv("TMPDIR", tmpdir)
        assert _ag_runtime_dir() == ""

    def test_the_mirror_lands_in_the_agent_runtime_not_the_working_directory(self, tmp_path, ag):
        """The datasource CWD is .../working_directories/<dsid><epoch_ms> — a name the
        extension cannot predict or rediscover after a restart, which is why the SDK's own
        CWD-relative convention is unusable here."""
        src = _remote(tmp_path, {"outpost": REAL_FASTPATH})
        _ext(remoteUrl=_url(src)).poll()
        assert _mirror_path(ag).is_dir()

    def test_the_last_resort_base_names_its_own_cost(self, tmp_path, monkeypatch, caplog):
        """On a stock ActiveGate /usr/lib/tmpfiles.d/tmp.conf is "D /tmp 1777 root root -", so
        /tmp is EMPTIED at every boot and its parent is world-traversable. Usable, but the
        operator is told what it costs."""
        monkeypatch.setenv("TMPDIR", "/nowhere-eec-shaped")
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "systmp"))
        ext = _ext()
        with caplog.at_level(logging.WARNING):
            base = ext._mirror_base()

        assert base == str(tmp_path / "systmp" / MIRROR_DIRNAME)
        assert "re-cloned after a reboot" in caplog.text
        assert oct(os.stat(base).st_mode & 0o777) == "0o700"

    def test_no_activegate_tree_is_invented_on_a_machine_that_has_none(self, tmp_path,
                                                                       monkeypatch):
        """Both ActiveGate candidates require their parent to already exist, so a developer
        machine cannot end up with a plausible-looking /var/lib/dynatrace that no ActiveGate
        owns."""
        monkeypatch.setenv("TMPDIR", "/nowhere-eec-shaped")
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "systmp"))
        _ext()._mirror_base()
        assert not os.path.exists("/var/lib/dynatrace/remotepluginmodule/agent/runtime/"
                                  "extensions/" + MIRROR_DIRNAME)

    def test_two_monitoring_configurations_never_share_a_mirror(self):
        a = _mirror_root("/base", "config-aaa", "https://git.example.com/x.git")
        b = _mirror_root("/base", "config-bbb", "https://git.example.com/x.git")
        assert a != b and a.endswith("config-aaa.git")

    def test_editing_the_url_of_one_configuration_reuses_its_directory(self):
        """Deliberate: it is what forces the URL-changed case to be handled explicitly instead
        of silently accumulating one orphaned mirror per URL edit."""
        assert _mirror_root("/base", "cfg-1", "https://a.example.com/x.git") \
            == _mirror_root("/base", "cfg-1", "https://b.example.com/y.git")

    def test_a_hostile_configuration_id_cannot_escape_the_base(self):
        got = _mirror_root("/base", "../../etc/cron.d/evil", "https://git.example.com/x.git")
        assert got.startswith("/base/") and ".." not in got

    def test_with_no_configuration_id_the_url_is_the_key(self):
        a = _mirror_root("/base", "", "https://git.example.com/x.git")
        b = _mirror_root("/base", None, "https://git.example.com/y.git")
        assert a != b and a.startswith("/base/") and a.endswith(".git")


class TestBudgetsComeFromThePropertyThatAlreadyExists:
    """A fetchTimeoutSeconds property was considered and rejected — its only sane value is a
    function of intervalSeconds, which already ships."""

    @pytest.mark.parametrize("interval,fetch,clone", [
        (900, 300, 1200),      # the schema default
        (60, 60, 240),         # the schema minimum
        (86400, 300, 1200),    # the schema maximum
        (240, 80, 320),
    ])
    def test_budgets(self, interval, fetch, clone):
        assert _budgets(interval) == (fetch, clone)

    def test_a_fetch_can_never_outrun_the_poll_interval(self):
        for interval in (60, 120, 900, 3600, 86400):
            assert _budgets(interval)[0] <= max(60, interval)

    @pytest.mark.parametrize("cfg,want", [
        ({}, 900), ({"intervalSeconds": 300}, 300), ({"intervalSeconds": "300"}, 300),
        ({"intervalSeconds": None}, 900), ({"intervalSeconds": ""}, 900),
        ({"intervalSeconds": "nonsense"}, 900),
    ])
    def test_the_interval_helper_never_raises(self, cfg, want):
        assert _interval_seconds(cfg) == want


# ══════════════════════════════════════════════════════════════════════════════════════════
# Requirement 5 + 7 — the schema, and the surface it adds
# ══════════════════════════════════════════════════════════════════════════════════════════

class TestTheActivationSchema:

    @staticmethod
    def _props():
        return json.load(open(SCHEMA))["types"]["pythonRemote"]["properties"]

    def test_no_nullable_property_carries_a_default(self):
        """Learned from a REJECTED UPLOAD on 2026-08-02: a property with "nullable": true must
        not also carry a "default" — the upload fails outright. A clean `dt-sdk build` proves
        nothing; only an upload does, so this is asserted here instead."""
        offenders = [n for n, p in self._props().items()
                     if p.get("nullable") is True and "default" in p]
        assert offenders == []

    def test_remote_mode_adds_exactly_two_properties(self):
        """Requirement 7. remoteUsername was rejected (the URL already has a slot for it and
        all three providers document that syntax), mirrorPath was rejected (operator-provisioned
        scaffolding is what this change exists to delete), branch/ref was rejected (clone
        --mirror adopts the remote's HEAD and goldenRef already exists), fetchTimeoutSeconds was
        rejected (derived from intervalSeconds) and caCertPath/insecureSkipVerify were rejected
        (the ActiveGate trust store already exists, and an insecure-TLS toggle is a finding
        waiting to be written up in a customer audit)."""
        assert set(self._props()) == {"configPath", "remoteUrl", "remoteToken", "goldenRef",
                                      "deviceGlob", "intervalSeconds"}

    def test_the_token_is_a_secret_and_the_url_is_not(self):
        p = self._props()
        assert p["remoteToken"]["type"] == "secret"
        assert p["remoteUrl"]["type"] == "text"
        assert p["remoteUrl"]["nullable"] is True and p["remoteToken"]["nullable"] is True

    def test_config_path_is_untouched(self):
        """Requirement 2 is met by NOT TOUCHING IT: same type, same nullable, same default.

        The description is pinned by its OWN literal, not by
        self._props()["configPath"]["description"] — which is what this assertion used to
        compare against, i.e. itself. A tautology cannot fail, so the description was the one
        part of "untouched" the test could not actually see, while reading as though it could.
        configPath's wording is load-bearing (it is the only place the three supported archive
        shapes are described to the operator) and in remote mode it silently becomes the
        FALLBACK, so a drive-by edit here is exactly the change worth catching.
        """
        assert self._props()["configPath"] == {
            "displayName": "Config archive path",
            "description": (
                "Where Oxidized stores its archive on this ActiveGate. Three shapes all work: "
                "a plain directory of config files (file backend); a Git checkout; or — the "
                "shape Oxidized's own git output backend produces, and the one the deployment "
                "guide recommends — a BARE repository such as /var/lib/oxidized/configs.git, "
                "which has no files on disk and stores each device as a blob named after the "
                "node. Git-backed paths also enable drift."),
            "type": "text", "nullable": False, "maxLength": 500,
            "default": "/var/lib/oxidized/configs"}

    def test_device_glob_lost_its_default_and_that_is_a_third_schema_change(self):
        """Disclosed, not smuggled. deviceGlob was nullable:true AND default:"" at HEAD, which
        violates the upload rule the suite asserts one test above — so the property could not
        have uploaded as committed. Removing the default is required and correct, but it is a
        change to a PRE-EXISTING property that arrived alongside remote mode's two new ones and
        was reported as "2 new properties". Pinned here so the schema diff is three items and
        the audit above is not quietly passing because someone fixed the violation in passing.

        Runtime impact is nil in both directions, which is why it went unnoticed: query() reads
        str(c.get("deviceGlob", AUTO_GLOB) or AUTO_GLOB), and "" , None and absent all collapse
        to AUTO_GLOB. Monitoring configurations that already persisted "" keep working.
        """
        glob = self._props()["deviceGlob"]
        assert glob["nullable"] is True
        assert "default" not in glob, "nullable:true + default is rejected at upload"
        assert ComplianceExtension._cfg_glob({"deviceGlob": ""}) == AUTO_GLOB
        assert ComplianceExtension._cfg_glob({"deviceGlob": None}) == AUTO_GLOB
        assert ComplianceExtension._cfg_glob({}) == AUTO_GLOB
        assert ComplianceExtension._cfg_glob({"deviceGlob": "*.cfg"}) == "*.cfg"

    def test_nothing_ssh_shaped_was_added(self):
        """Out of scope by decision, and the schema is where that decision would erode first.

        SSH is allowed to be MENTIONED — the operator has to be told it is unsupported and what
        to do instead — but nothing SSH-shaped may be configurable. A second auth path would
        drag in key files, key permissions, known_hosts and a StrictHostKeyChecking security
        decision for a mechanism that is not how a SERVICE reads GitLab / GitHub Enterprise /
        Bitbucket.
        """
        blob = open(SCHEMA).read().lower()
        for word in ("ssh://", "git@", "known_hosts", "privatekey", "private key", "keyfile",
                     "id_rsa", "stricthostkeychecking"):
            assert word not in blob
        for name in self._props():
            assert "ssh" not in name.lower() and "key" not in name.lower()
        assert "ssh urls are not supported" in blob, \
            "the scope cut must be stated to the operator, not left to be discovered"
