# Custom EF2.0 SNMP interface extension (`custom:cno.network.interfaces`)

The **monitoring** layer stock generic SNMP extensions don't provide (see
`docs/docs/METRIC-CONTRACT.md`): polls IF-MIB/ifXTable per device → interface up/down +
throughput metrics on the fleet.

## Metrics (per interface, dims: `if_index`, `if_descr`)
`cno.if.oper_status` (1=up 2=down) · `cno.if.admin_status` · `cno.if.high_speed`
(Mbps) · `cno.if.in_octets.count` / `cno.if.out_octets.count` (ifHC*, 64-bit).

## Feature sets — v0.0.14 (⚠️ breaking; read before upgrading)
Everything except `cno.device.uptime` is now **opt-in per monitoring configuration**. A config
with no `featureSets` collects uptime and nothing else — **and reports status OK while doing
it**. Select per device class:

| set | gates | enable on |
|---|---|---|
| `Interfaces` | `interfaces` group (ifTable/ifXTable) | switches, routers, firewalls, APs |
| `Cisco device health` | `device-health/health` (Cisco enterprise OIDs) | Cisco only |
| `UPS power` | `power/ups` | a UPS — **never** with `Interfaces` |
| `PDU power` | `power/pdu` | ServerTech PDU *(unverified against real hardware)* |
| `UPS battery voltage` | that one metric | only a UPS confirmed to answer `upsBatteryVoltage` |
| `LLDP topology` | `lldp` group | nothing — see the group comment, it ships off |
| *(implicit `default`)* | `device-health/system` → `cno.device.uptime` | always on, not selectable |

Each set carries a `displayName` and a `description` via the top-level `featureSetsMetadata`
block, so this guidance reaches the operator in the monitoring-configuration UI instead of
living only in YAML comments. `isRecommended` is `true` for `Interfaces` alone.

**Upgrading from ≤0.0.13 is a migration, not an upload.** Feature sets are strictly additive
opt-in and an existing `"featureSets": []` is never re-derived, so activating 0.0.14 silently
stops `cno.if.*`, `cno.device.cpu_usage`/`memory_*` and `cno.power.*` on every existing config.
The full per-config procedure, every measurement behind these boundaries, and the risks left
explicitly unverified are in the header comment of `extension/extension.yaml`; the
operator-facing version is in `docs/the app's Configuration page` (Tier 1) and
`docs/the app's Configuration page` §3 step 4a. Three things that are easy to get wrong:

- **Probe one metric per feature set** in the pre-flight query — there are five gates. A
  four-probe query misses `UPS battery voltage` (ungated and therefore *live* under ≤0.0.13 on
  any UPS that implements it) and the memory half of `Cisco device health` (IOS-XE and stacks
  frequently answer the memory-pool OIDs but not `cpmCPUTotal1minRev`).
- **The before/after diff is a regression test only.** It cannot tell you the fix worked:
  `cno.power.*` reads zero both before *and* after a failed migration. Pair it with the two
  positive checks in the checklist.
- **`scripts/activate-ext-version.sh` refuses ≥0.0.14 for this extension** unless
  `CNO_MIGRATION_ACK=1` is set, so the bulk activation path cannot skip the pre-flight snapshot.

**`minDynatraceVersion` is 1.338.0 and `minEECVersion` is 1.333.0 as of 0.0.14** (raised from
1.295.0, which had no EEC floor at all). `UPS battery voltage` is gated by a **metric-level**
`featureSet` overriding its subgroup's — a construct Dynatrace's own
`com.dynatrace.extension.snmp-generic-device` 3.0.4 uses (subgroup `NIC status`/`Interfaces`
with metrics overriding to `Interfaces 32-bit` / `Interfaces 64-bit`) and which that extension
declares those same floors for. If an older EEC ignores the metric-level key, the OID rejoins
the `UPS power` batch and takes every other power metric down with it, silently, with the
config green — so refusing to load is the safer failure.

### Validate the YAML before uploading (offline, real platform schema)
```
curl -s -H "Authorization: Api-Token $TOK" "$DT_URL/api/v2/extensions/schemas/1.345.0" -o s.zip
unzip -q s.zip -d schemas          # dt ext schemas mis-fires as "Zip Bomb Attack"; curl instead
dt ext validate-schema --instance extension/extension.yaml \
    --schema-entrypoint schemas/extension.schema.json     # silent = valid; errors give line/col
```
Needs a token with `extensions.read`. **This checks structure, not activation-schema semantics
— only an upload is the real test.**

## Build / sign / upload (dt-cli)
```
dt ext assemble --source extension --output /tmp/ext.zip --force
dt ext sign --src /tmp/ext.zip --output /tmp/bundle.zip --key <dev_fused.pem>   # cert FIRST then key
dt ext upload --tenant-url <url> --api-token <tok> /tmp/bundle.zip
# then: activate env config version, POST monitoringConfigurations {scope:ag_group-<your-group>, value:{snmp:{devices:[...]}}}
```

## Signing certs (learned the hard way)
Sign with a dev cert whose CA is **trusted by the tenant** *and* healthy — the
`proxmox-ca` chain is broken (AG rejects: "checking signature failed"). Generate a
fresh project CA+dev cert (`dt ext gencerts`), upload the **CA** via the UI
(Settings → Credential vault → Certificate, scope Extensions) — the credentials
**API** rejects passwordless public certs (password required-but-any-value-fails).
Keys live in the gitignored `.secrets-ext/`.

## Deploy status — ✅ LIVE (2026-07-22/23)
Built, signed (project cert `cno-ext-signing-ca`), uploaded, activated **v0.0.2**,
configured (10 devices, `ag_group-<your-group>`, config `a591cefe`). **Polling all 10
devices** (`Endpoints OK: 10`), config status **OK**, **8 interfaces** monitored with
up/down + throughput — queryable in near-real-time via the AG metric path.

### The cert-trust saga + the fix that worked (important)
Signature verification failed for a long time: `SignatureVerifier: CMS routines:
unable to get local issuer certificate` — the AG's SignatureVerifier had loaded
**only built-in Dynatrace root CAs**; the custom signing CA never reached its trust
store (`conf/certificates` empty). Chain was fine (`openssl verify -CAfile ca.pem
dev.pem` = OK) and the CA was correctly in the vault. Root cause + fix:
- The **broken `proxmox-ca`** in the vault was poisoning the cluster→AG cert bundle
  sync, so **zero** custom CAs loaded. Deleted it.
- The AG (installed *earlier*, while the vault was poisoned) never recovered its
  trust store; restarts didn't fix it.
- **The fix: a clean AG uninstall + reinstall against the now-clean vault.** On first
  boot the fresh AG synced `cno-ext-signing-ca.pem` into `conf/certificates`, verified
  the extension, and went ERROR→OK. **Low blast radius** — entities, generator
  reconciliation, and OneAgent are all AG-independent and survived untouched.

### Verify
```
# metrics API (no dtctl):
curl -s -G -H "Authorization: Api-Token $TOK" \
  --data-urlencode 'metricSelector=cno.if.oper_status:splitBy(if_descr)' \
  --data-urlencode 'from=now-15m' "$DT_URL/api/v2/metrics/query"
# or DQL: timeseries s=avg(cno.if.oper_status), by:{if_descr}, from:-15m
```
