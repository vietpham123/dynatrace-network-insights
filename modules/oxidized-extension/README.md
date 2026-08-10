# CNO Compliance / config-change extension — `custom:cno.network.compliance`

Remote (ActiveGate) Python extension. **Ports the on-prem capture cron's read/evaluate path** — reads
the device running-configs Oxidized captures into its Git archive, evaluates ISO-27001:2022 controls
against each, detects drift vs a golden baseline, and ships LOGS to Grail. No polling gap: run it on
a schedule, or trigger it on Oxidized's change hook.

## Emits (logs)
| log.source | Fields | Meaning |
|---|---|---|
| `network.compliance` | `compliance.control, compliance.status, compliance.control_name, host.name` | ISO-27001 pass/fail, one record per control per device |
| `network.compliance` | `compliance.status=capture_failed\|capture_partial, config.capture.reason, config.capture.bytes` | **capture health** — device-level, no `compliance.control` |
| `network.config` | `config.drift_from_golden, config.diff, host.name` | drift vs the golden baseline |

## Capture health (read this before trusting a compliance number)
Oxidized will store a CLI refusal as a device's config and still mark the node `success`.
Measured 2026-08-02 on the lab's Netgear GSM7248V2: `enable` was rejected, every command was
refused, and the "config" it committed was 272 bytes of `% Invalid input detected`. Nothing
reported a problem for 29 hours.

`assess_capture()` therefore runs **before** platform detection and grading, and classifies the
artefact by how much recognisable configuration it contains — deliberately *not* by file size,
because the repo's own smallest golden config (485B) is larger than the broken artefact and a
valid MikroTik export (223B) is smaller than it. There is no byte floor with full recall and
zero false positives; the measurements are in the `assess_capture` docstring.

| verdict | `compliance.status` | severity | grading | drift |
|---|---|---|---|---|
| `ok` | as before | — | normal | normal |
| `suspect` (partial/truncated) | `capture_partial` | `WARN` | skipped | suppressed¹ |
| `unusable` (not a config) | `capture_failed` | `ERROR` | skipped | suppressed |

¹ except `shrank_vs_last_good`, which still reports drift — see below.

`capture_failed` is **not** `not_assessed`, and the distinction is the point. `not_assessed`
means "good artefact, we have no rule set for its syntax" — our coverage gap, fixed by writing
predicates. `capture_failed` means "no usable artefact at all" — the customer's network ops
team, fixed by granting enable privilege or fixing credentials. It can also hit a device that
graded 12/12 yesterday, so the dashboard figure is not merely incomplete, it is stale and wrong.

Every reason carries an operator-facing remediation sentence (`CAPTURE_REASONS`) in the record
text, because the reason code is what a detector fires on but the sentence is what lands in the
ticket.

### The arms, and what corroborates each
Two principles run through all of them, and both were added after a measured false positive:

- **Corroboration, not keywords.** An error phrase counts only if its payload is `%`-prefixed,
  or the artefact is a command transcript *and* the line is not a comment. Banner and MOTD
  bodies are masked throughout — a security banner is the one place a real config legitimately
  says "Permission denied". The pager pattern is punctuation-shaped (`--More--`, `---(more`)
  and no longer matches prose: "Press any key to continue" and a bare `MORE:` were both
  measured firing on healthy IOS configs, and neither is a pager prompt on any supported vendor.
- **Recovery.** A defect only condemns a capture if the capture *stops* there. Twenty lines of
  configuration after it prove the session was alive, which turns "one auxiliary command this
  platform does not implement" back into a healthy capture. Without this, a Cisco device that
  does not support `show bootvar` never graded again — one error line beat 34 lines of config,
  on every poll, forever.

| reason | evidence | needs git |
|---|---|---|
| `no_content` / `cli_refused` / `mostly_command_echo` | the artefact is command echo and refusals | no |
| `stub_capture` | tiny, unfingerprinted **and carrying refusal markers** | no |
| `wrong_device_config` | the parsed hostname is another node's filename, **or** two nodes hold byte-identical text | no |
| `pager_truncation` | pager residue the capture did not recover from | no |
| `cli_error_mid_capture` | corroborated CLI error the capture did not recover from | no |
| `no_end_of_config_marker` | an IOS-family capture with no standalone `end` | no |
| `shrank_vs_last_good` | a fraction of this device's own last good capture | **yes** |
| `too_little_content_to_grade` | fingerprinted, but under 5 configuration statements | no |

Two nodes reporting the same device name but **different** configurations is a duplicate name,
not a mis-stored capture — a cloned template or a factory default left on `snmp-server sysname`.
That is `compliance.status=duplicate_device_name` at `WARN`, the device is **still graded**, and
`host.name` falls back to the Oxidized node name so the two stay distinguishable. Requiring that
positive evidence matters: without it the guard reported a healthy 5497-byte config as
`capture_failed` at ERROR with zero compliance records — the victim-goes-silent outcome the
guard exists to detect, manufactured by the guard.

`no_end_of_config_marker` is what actually closes the *partial capture that still fingerprints*
risk. A session that dies on a line boundary at 95% leaves no error text, no pager residue and
trips no size ratio, yet grades 7 controls FAIL that are configured on the device. `TERMINATORS`
is deliberately limited to `cisco-ios`, `arista-eos` and `frr`: brace vendors are legitimately
unterminated, and Oxidized has never successfully pulled a config off the lab's FASTPATH switch,
so claiming its terminator would be an untested vendor-doc assertion.

`shrank_vs_last_good` is the one arm with no in-file evidence of corruption — "the file got
smaller" is textually identical for a truncation and for an operator deleting 40 firewall rules
— so it is the one arm that still reports drift, and it is restricted to platforms we would
otherwise grade.

### Drift is never an affirmative all-clear
Four separate routes used to report `matches golden (0 lines)` at INFO for a device that had
never been compared to anything, and git exits **0** on three of them:

- no `golden` ref (the normal first-deployment state) — `fatal: bad revision`, rc 128;
- the file is not in the golden ref (a node Oxidized has just started capturing) — rc **0**,
  empty stdout, because a pathspec matching nothing is not an error;
- a nested `deviceGlob` such as `*/*.cfg` (what you get the moment Oxidized `groups:` is
  configured) — rc **0**, empty stdout, same reason;
- **the diff compared a different artefact than the one that was graded** — rc **0**, and the
  worst of the four because it can report `no` over a config that is genuinely drifted. Reading
  is disk-first, so in a **git checkout** (deployment shape #2 below) the graded bytes come
  from the working tree while `git diff golden HEAD` compares the last *commit*. With
  Oxidized's file backend nothing ever commits that directory, so it was permanent: measured
  2026-08-02, one poll reported `A.8.5`, `A.8.9` and `A.8.26` = **FAIL** and, on the same
  bytes, `config.drift_from_golden: "no"` at INFO. `HEAD` is now in the diff only when `HEAD`
  is what was read.

All four now report `config.drift_from_golden: "unknown"` (or the true diff). Paths are spelled
repository-root-relative — `<rev>:<path>` for object lookups and `:(top)<path>` for pathspecs —
so `configPath` may sit below the repository root and the bare case works, which `<rev>:./<path>`
did not (rc 128, "relative path syntax can't be used outside working tree").

## Tests
```bash
PYTHONPATH=. python -m pytest tests/ -q     # 350 tests
```
Same layout and runner as `modules/controlplane-extension`. `tests/conftest.py` stubs the SDK so
the suite needs no ActiveGate. The corpus in `tests/test_capture_health.py` is the artefact worth
preserving here, more than the thresholds it calibrates. Two classes hold it:

- `TestSmallButValidMustNeverBeFlagged` — every real config a naive size rule would have
  condemned (the three repo goldens, a minimal FRR, an unsupported-vendor MikroTik export, a
  Juniper `set` export, an SR Linux fragment, plus configs whose banners and ACL remarks contain
  literal CLI error phrases).
- `TestTheExtendedFalsePositiveCorpus` — the shapes that actually broke the gate: refused
  auxiliary commands, pager words in banners and SNMP locations, error vocabulary in engineer
  comments, and legitimate large deletions. The first class alone was not enough, because all
  eleven of its cases land in the fast path and none of them can reach an arm that fires.

`TestEveryArmIsReachableAndExplainsItself` is a structural guard: it asserts every verdict arm
has a fixture that reaches it and every reason has remediation text. Four arms had neither, and
three of those four turned out to be defective.

## Configure (AG monitoring configuration)
- **Config archive path** — where Oxidized keeps its archive on this AG. Three shapes work:
  a plain directory of files (file backend); a Git checkout; or a **bare repository**
  (`…/configs.git`) — what Oxidized's own `output: git` backend produces, and what
  [`docs/the app's Configuration page`](../../docs/the app's Configuration page) recommends. Git-backed paths enable drift.
- **Remote Git URL** — *leave blank when Oxidized runs on this AG.* Set it when the archive
  lives somewhere else, and the AG keeps its own mirror instead. See below.
- **Remote Git token / PAT** — read access for that URL. Blank for an unauthenticated remote.
- **Golden git ref** — the approved baseline tag/ref (default `golden`). Drift is skipped (compliance-only) if absent.
- **Device file pattern** — **leave blank** (auto-discover). Set one only to narrow a plain
  directory: `*.cfg`, or `*/*.cfg` when Oxidized `groups:` is configured.
- **Poll interval** — default 900s (15 min, matching the cron)

### Remote mode — when Oxidized is not on the ActiveGate
A local filesystem path was the only way to reach the archive, and in the deployment measured
2026-08-02 that one assumption forced Oxidized on `cno-svc`, the AG on `cno-ag`, an **NFS export
to bridge them**, a foreign-owned repo (uid 30000), `safe.directory` handling, and then
`--no-ext-diff/--no-textconv/core.fsmonitor=false` to close the command-execution hole
`safe.directory` opened. All of it scaffolding around one wrong assumption. The archive is a Git
repository; the AG can fetch it.

Set **Remote Git URL** and the AG clones its own `--mirror` under
`…/agent/runtime/extensions/cno-oxidized-mirrors/<monitoring-config-id>.git` (0700 — the mirror
holds running-configs with password hashes and SNMP communities) and refreshes it every poll.
A mirror **is** a bare repo, so it is read by the same reader described below — remote mode adds
no second read path, and drift, the golden ref and the history walk all work unchanged.
`clone --mirror` (never `init`+`fetch`, which manufactures a dangling `HEAD` when the AG's
`init.defaultBranch` differs from the remote's) brings tags across, so `goldenRef` needs no
extra refspec. This is also why the Oxidized **REST API** was not used: it returns only the
*current* config, and without history drift-vs-golden and change-to-impact both die.

**HTTPS + token only.** Put the username in the URL where the host wants one
(`https://oauth2@…` GitLab, `https://x-token-auth@…` Bitbucket). **SSH is out of scope** — no
schema field, no `GIT_SSH_COMMAND`, no `known_hosts` policy. For an ssh-only remote, use the
local path above. The token is sent as an HTTPS `Authorization` header via `GIT_CONFIG_*` in the
child environment: never in `argv` (measured world-readable via `ps -eo args`), never in
`<mirror>/config`, and every git stderr string that reaches a log or a record is redacted for
both the raw token and its base64 form. `http.followRedirects=false`, because git's default
carries that header to the redirect *target*.

**Staleness is never silent**, which is the failure mode holding a mirror creates:

| refresh | mirror age | graded? | record |
| --- | --- | --- | --- |
| ok | — | yes | none (freshness rides on every record as dimensions) |
| failed | ≤ limit | **yes** | one `archive_stale`, **WARN** |
| failed | > limit | **no** | one `archive_stale_refused`, **ERROR** |
| no usable mirror | — | no | one `archive_unreachable`, **ERROR** |

The limit is `max(86400, 2 × interval)`. The floor is *implied*, not chosen: `intervalSeconds`
already ships with `"maximum": 86400`, so anything lower would make a legal 24-hour poll declare
itself stale between its own polls. Freshness is "when did we last **reach** the remote", never
the commit date (Oxidized commits only on change — a healthy stable fleet's `HEAD` is weeks old)
and never `FETCH_HEAD`'s mtime, which was measured to **advance on a failed fetch**.

Every record carries `config.archive.refreshed` / `.age_seconds` / `.last_refresh` / `.url` /
`.source`. **Consumer contract: `refreshed == "no"` means UNKNOWN, not healthy.**
`ConfigChanges.tsx` implements it — a stale `drift="no"` renders "unknown — archive stale", not
"on intended config".

`age_seconds` and `last_refresh` are **omitted when the age is genuinely unknown**, rather than
defaulted. `archive_unreachable` used to publish `age_seconds="0"` — "refreshed 0 seconds ago"
stamped on the worst state the module can report, and a detector written as `age_seconds > limit`
could never fire on it. Absent now means unknown in both fields; the two states that legitimately
have an age of zero (local mode, and a remote refreshed this poll) set it explicitly.

### Why the pattern defaults to blank
Oxidized's git backend stores each device as a **blob named after the node, with no file
extension** (`outpost`, not `outpost.cfg`) inside a **bare** repo that has no working tree at
all. Measured on the lab AG 2026-08-02: `find … -name '*.cfg'` returned nothing and the
extension emitted **zero records** — not `not_assessed`, total silence — for the deployment
shape we document. Reading is now: **disk first** (any hit → plain-directory mode, git
untouched, `glob` semantics preserved *exactly*), **git `HEAD` only when disk yields nothing**.
An explicit pattern always means what it meant before, including `glob`'s own dot-file rule (a
dot-segment matches only a dot-leading pattern segment); auto-discovery adds a deny-list for
repository housekeeping by **filename** (`README.md`, `.gitignore`, `*.sample`, scripts).

Git's own storage is excluded by **shape** — a directory holding `HEAD` + `objects/` + `refs/`
is never walked — not by directory *name*. Names are not safe to deny: `logs`, `info` and
`modules` are ordinary Oxidized **group** names, and denying them removed every device in that
group with no record of any kind. Measured 2026-08-02 on a seven-group archive, five groups
were dropped silently. Tracked git blobs need no such guard at all, since git never commits its
own object store.

**Reading zero devices is now always an `ERROR` record** naming the cause and the fix. An absence
cannot be queried, so silence was the defect — and there were three separate routes into it, all
now closed:

| state | record | severity |
|---|---|---|
| the archive was read and matched nothing | `archive_empty` | ERROR |
| `configPath` is not a directory (**local mode**) | `archive_path_missing` | ERROR |
| the archive lists a device it cannot produce bytes for | `archive_unreadable_file`, **one per device** | ERROR |

`archive_path_missing` is deliberately not folded into `archive_unreachable`: a detector fires on
the code, and `archive_unreachable`'s remediation sends the operator to check a remote Git URL and
rotate a PAT, neither of which exists in local mode. The trigger here is a filesystem one — an NFS
export or bind mount dropping — which is precisely the deployment remote mode exists to replace.

`archive_unreadable_file` is the **partial** case, and it is per device on purpose. A fleet that
silently drops from 3 rows to 2 looks healthy; 2 healthy rows plus one ERROR naming `sw2` is a fact
somebody can alert on. `archive_empty` only ever fired when *nothing* loaded, so a damaged object
store that cost one device out of fifty was invisible.

**A missing golden baseline is never a green tick.** With no resolvable golden ref every device
reports `config.drift_from_golden = "unknown"`, and the poll emits one archive-scoped record
carrying `config.drift_status = "not_evaluated"` — **WARN** when a golden ref was explicitly
configured and does not resolve, **INFO** when the field was left blank (drift is a supported
opt-out, per the schema). It carries no `config.capture.*` fields, because nothing about any
capture failed; the captures are fine, the baseline is missing. Consumers must treat
`drift != "no"` as unknown: `ConfigChanges.tsx` rendered `"unknown"` as "✓ on intended config" and
counted those devices as having a baseline they did not have.

Foreign-owned archives are expected: the AG runs as a different user from Oxidized, so git
reports *dubious ownership*. The extension grants `safe.directory=<repo root>` **narrowly and
per-invocation** (never `*`, never your `--global` config), logs that it did, and stamps
`config.archive.ownership`. `git diff` is hardened with `--no-ext-diff --no-textconv`
(+`core.fsmonitor=false` everywhere) because a repo-supplied textconv was measured **executing
as the AG user**. Any git failure still degrades to drift `unknown`, never `matches`.

### Device identity
`host.name` / `device.address` are extracted with **platform-scoped** rules (mirroring
`PLATFORMS`, same `verified` discipline) and both carry a `device.identity.*_source` field, so
"parsed from the device" and "guessed from the filename" are separable in Grail.

The old `hostname` / `ip address` pair produced an **empty `device.address` for 100% of the
corpus** — including all three verified Cisco goldens — and the real FASTPATH capture has no
`hostname` line at all. Netgear now reads `snmp-server sysname` (the SNMP **sysName** object,
so `host.name` matches the SNMP extension's `sys_name` by construction, not by luck) and
`network parms`. An address is emitted only when it is unambiguously the **management**
address; when ambiguous it stays empty, because a plausible-but-wrong address mints a phantom
`network_device_<ip>` entity. `set prompt` is deliberately never a name source — on the real
GSM7248V2 it is the model number.

## Build → sign → deploy
Same flow as the NetBox extension:
```bash
pip install dt-extensions-sdk
dt-sdk gencerts        # once
dt-sdk build           # -> dist/custom_cno.network.compliance-0.0.1.zip
```
Upload your cert's public part to **Settings → Extensions → trusted certificates**, upload the `.zip`,
add a monitoring config.

## Retire the cron
Replaces the on-prem capture cron's check and compliance passes. The `--seed` / `--change` simulation path
is lab-only and stays on the VM (or is dropped) — it exists because snmpsim has no real running-config.

## Customize the controls
`COMPLIANCE` in `oxidized_extension/__main__.py` is a plain dict of `control -> (name, predicate)`.
Add, remove, or reword controls to match your standard; predicates are simple substring checks over
the running-config text.
