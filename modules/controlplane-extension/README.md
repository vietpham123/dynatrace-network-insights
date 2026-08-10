# CNO LLDP topology extension (`custom:cno.network.controlplane`)

Discovers Layer-2 neighbours over LLDP-MIB and ships them to Grail as logs, so the app can
draw device↔device topology and surface **unmanaged** neighbours.

## Why this is Python and not declarative SNMP

Because the declarative datasource **cannot** do it. It decodes binary `OCTET STRING`s as
UTF-8 and drops invalid bytes, which destroys the two fields the feature depends on. Measured
on a real Netgear GS752TP, then fixed here — same switch, same OIDs, same day:

| field | declarative datasource | this extension |
|---|---|---|
| own chassis id | `'_ڨ'` | `e4:f4:c6:da:a8:ec` |
| neighbour chassis id (the trunk) | `' N\x7fN'` | `20:4e:7f:4e:c3:e6` |
| neighbour capability `20 00` | `' '` | `['bridge']` |
| neighbour capability `28 00` | `'('` | `['bridge','router']` |
| neighbour port id | `'X_#!'` | `58:d6:1f:23:21:b2` |

The loss is not cosmetic: three distinct MACs sharing an OUI collapse to one string, and
same-vendor fleets differ exactly in the dropped trailing bytes — so a chassis-id join would
silently merge distinct switches into one node. There is no encoding option on that datasource
to work around it. Full write-up: `docs/docs/METRIC-CONTRACT.md` §L.

## What it emits

All records are logs with `log.source: network.lldp`, `dt.source: cno-lldp`.

| `lldp.record` | one per | key fields |
|---|---|---|
| `device` | polled device | `device.address`, `host.name`, `lldp.chassis_id` |
| `link` | neighbour heard | `lldp.local_port`, `lldp.remote_chassis_id`, `lldp.remote_port`, `lldp.remote_sys_name`, `lldp.remote_mgmt_address`, `lldp.remote_class`, `lldp.remote_capabilities` |
| `error` | device that failed | `device.address`, `lldp.error` |

Errors are **records, not a failed run**: one unreachable device must not blank the topology
or turn the whole monitoring configuration red (the declarative extension did exactly that —
§L7).

**Joining:** match `lldp.remote_chassis_id` on a `link` against `lldp.chassis_id` on a
`device`. A neighbour that matches nothing is **unmanaged** — surface it, don't drop it; an
unmanaged switch in the fabric is a finding.

`lldp.remote_mgmt_address` comes from `lldpRemManAddrTable`, where the address lives inside
the **OID index** rather than a column — which is another thing a declarative datasource
cannot reach. Treat it as a useful attribute, **not** the join key: joining topology on IP
inherits the overlapping-IP problem (DR pairs and K8s meshes legitimately reuse ranges).

## Endpoint exclusion — on by default, and honest about its limits

`excludeEndpoints` (default **on**) drops neighbours whose LLDP capability bitmap identifies
them as endpoints — `stationOnly` or `telephone`. Phones advertise `bridge`+`telephone`
because of their pass-through switch, so `telephone` wins over `bridge`; otherwise every desk
phone would land in the topology.

Two things it deliberately does **not** do:

- **It never drops `unknown`.** A neighbour that advertises no capabilities is kept. Under-
  filtering is recoverable; a switch missing from a topology view is not.
- **It only catches devices that identify themselves.** Measured in the lab: a Windows PC
  advertised capability `0x8000` (`other` only), so it classifies as `unknown` and is
  **kept** — the filter dropped 0 of 1 endpoints there. Real enterprise endpoints (IP phones,
  managed workstations) generally do advertise `telephone`/`stationOnly`, so this should
  behave better on a real fleet, but that is **not yet measured**. Do not promise a specific
  volume reduction.

To switch the walk off entirely, disable the monitoring configuration — that is the hard cost
control.

## Configuration

| field | default | notes |
|---|---|---|
| `deviceList` | — | management addresses, comma- or newline-separated, optional `:port` |
| `excludeEndpoints` | `true` | see above |
| `intervalSeconds` | `900` | topology changes on a work-order timescale |
| `version` | `v2c` | or `v3` (USM) |
| `community` | — | v2c only |
| `userName` / `securityLevel` / `authProtocol` / `authPassword` / `privProtocol` / `privPassword` | — | v3 only |
| `timeoutSeconds` / `retries` | `5` / `2` | |
| `maxRepetitions` | `10` | deliberately gentle — see below |

`maxRepetitions` defaults to 10 rather than the usual 25+. The lab's older Netgear GSM7248V2
returns a GetBulk timeout on the LLDP scalars to the declarative datasource (§L7, root cause
still unestablished), so mixed-age estates are safer starting low. Raise it for speed on
modern fleets.

## Build

```bash
pip install dt-extensions-sdk
dt-sdk gencerts                       # once — your developer cert
dt-sdk build -k <dev_fused.pem>       # -> dist/custom_cno.network.lldp-<v>.zip, signed
```

Upload the zip, activate it, then add a monitoring configuration scoped to your AG group.
**A clean build does not mean a deployable extension** — the tooling does not validate
activation-schema semantics. The upload is the test.

## Dependencies

`pysnmp==7.1.28` only (plus its transitive `pyasn1`). Both ship as **`py3-none-any`**
universal pure-Python wheels, so this extension carries no compiled artifacts and survives the
Python 3.10 → 3.14 runtime move untouched. **Preserve that property** — read
`docs/docs/METRIC-CONTRACT.md` §M before adding any dependency.

On package identity: after the original author died in 2022 the maintained fork (lextudio)
became `pysnmp` on PyPI again, and 7.x is that line. `pysnmplib` and `pysnmp-lextudio` are
dead ends — don't "fix" it to one of those.

## Tests

```bash
PYTHONPATH=. python -m pytest tests/ -q     # 41 tests
```

`tests/test_codec.py` is built around the exact bytes captured from real hardware. It pins the
defect rather than the happy path — including a case that caught a genuine bug during
development: `DE AD` is *valid* UTF-8 (`U+07AD`) and passes an `isprintable()` check, so a
subtype that declares binary must never reach text decoding at all.

## Validation status

- ✅ 41 unit tests, green on Python 3.14.3 and on Python 3.10.12 (the AG runtime version)
- ✅ Live poll against real hardware (Netgear GS752TP, 10.0.10.2) — every previously mangled
  field decodes correctly; the trunk neighbour resolves to `10.0.10.3`, the other monitored switch
- ✅ Builds and signs; all three bundled wheels are `py3-none-any`
- ✅ Uploaded to a tenant — activation schema accepted (HTTP 201)
- ⬜ **Not yet activated against a monitoring configuration**, so end-to-end ingest into Grail
  and the app-side topology join are not yet proven
