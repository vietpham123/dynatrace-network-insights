# Real artefacts from the lab's Oxidized archive (2026-08-02)

Both files came out of the live archive for the lab's **Netgear GSM7248V2 (FASTPATH)**. They
are here because a fix validated only against hand-written fixtures still fails in the lab —
`FASTPATH_VALID` in `test_capture_health.py` uses `hostname "lab-gsm7248"`, which is
**fabricated syntax**; real FASTPATH emits zero `hostname` lines.

| file | size | what it is |
|---|---|---|
| `gsm7248v2-fastpath-good.cfg` | 5506 B | A **successful** capture. Original 5494 B — see redactions below. |
| `gsm7248v2-refused.cfg` | 272 B | A **failed** capture, verbatim. Oxidized authenticated, had its `enable` rejected, had every command refused, stored the refusal text as the config, and marked the node `success`. Nothing said otherwise for 29 hours. |

## Redactions (good capture only)

This repository is a customer deliverable, so two things were removed. Nothing else was
touched, and the line count is unchanged:

1. The two distinct 128-hex password hashes → constant runs of `a`/`b` (+12 B, hence 5506).
2. The chassis serial number → `REDACTED-FOR-TEST-FIXTURE`.

**Every line the tests reason about is byte-identical to the archive:**

```
line 46   set prompt "GSM7248V2"                             <- the MODEL. A decoy, never a name source.
line 49   network parms 10.0.10.3 255.255.255.0 10.0.10.1    <- the management address
line 82   snmp-server sysname "outpost"                      <- the SNMP sysName object
```

Verified equivalent to the untouched original: same platform (`netgear`), same capture verdict
(`ok`), same `_meta` output — `('outpost', '10.0.10.3', 'snmp_sysname', 'network_parms')`.

Do **not** "tidy" these files. Their value is that they are what the device actually emitted.
