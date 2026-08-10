# CNO NetBox source extension — `custom:cno.network.netbox`

Remote (ActiveGate) Python extension. **Replaces the on-prem inventory/cabling crons** — reads NetBox and lands the device roster + declared cabling in Grail
as metrics, so in-tenant workflows never have to reach back to a private NetBox.

## Emits
| Metric | Dimensions | Value |
|---|---|---|
| `cno.inv.device` | `device.name, device.address, device.role, netbox.id` | 1 active / 0 inactive |
| `cno.inv.linked` | `device.name` | 1 if NetBox carries `dynatrace_entity_id` |
| `cno.dep.uses` | `device.address, upstream.address, link_type=power, …` | 1 |
| `cno.dep.uses` | `…, link_type=data, …` | 1 *(skipped if **emitDataLinks** is off)* |
| `cno.dep.uses_network` | `dt.entity.host, device.address, …` | 1 *(needs DT API token)* |

The declarative extension **`custom:cno.network.dependency`** turns `cno.dep.*` into
`network:device` Smartscape edges — **deploy both**.

## Configure (AG monitoring configuration)
- **NetBox URL** + **NetBox API token** (read on `/dcim`) — required
- **Dynatrace API URL** + **token** (`entities.read`) — optional; enables the host→device edges
  (`cno.dep.uses_network`), which need a host-entity lookup. Blank = skip them.
- **Emit device↔device data links from NetBox cabling** — **defaults ON.** There is no packaged,
  production-deployable live-LLDP extension today, so NetBox's declared cabling is the only
  production-ready source of device↔device topology. Turn this **OFF** only where a genuine
  live-LLDP source is already discovering these same devices (e.g. the internal lab's
  the LLDP collector) — NetBox derives the same edges' direction independently, from its own
  role-slug rank table rather than LLDP's hostname-derived guess, and running both against the
  same devices can disagree on which end depends on which. Power links (`link_type=power`) and
  host→device edges are unaffected; NetBox is the only source for those and always emits them.
- **Poll interval** — default 60s (matches the cron cadence)

## Build → sign → deploy (you control the cert)
```bash
pip install dt-extensions-sdk         # provides the dt-sdk CLI
dt-sdk gencerts                       # once: your developer cert (or reuse one you trust)
dt-sdk build                          # builds + signs -> dist/custom_cno.network.netbox-0.0.1.zip
```
1. Upload your dev cert's **public** part to **Settings → Extensions → trusted certificates** (one-time).
2. Upload `dist/*.zip` in **Extensions** (browse/upload), then add a monitoring configuration on your AG group with the fields above.
3. Verify: `cno.inv.device` / `cno.dep.uses` start flowing; the dependency extension lights up the Smartscape edges.

## Retire the crons
Once this is flowing, disable the VM crons it replaces:
the on-prem inventory and cabling crons (leave the others).

## SDK-version notes
Built against the `dt-extensions-sdk` `Extension` API (`report_metric`, `get_activation_config`,
`schedule`). If your SDK version differs, only two spots may need a tweak — the config access in
`_cfg()` and `self.logger`. Everything else is stdlib. If the `activationSchema.json` shape is
rejected at build, run `dt-sdk create` once to scaffold the skeleton for your SDK version and drop
`netbox_extension/__main__.py` into it.
