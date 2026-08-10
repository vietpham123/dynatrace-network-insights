# Network Insights

**Network observability for Dynatrace.** A Dynatrace app plus five extensions that give you device
health, interface throughput, NetFlow analysis, LLDP topology, power chain, and configuration
compliance — deployed into your own tenant, polling your own devices, signed with your own
certificates.

Nothing here is a hosted service. Everything runs in your environment.

> **This is not an official Dynatrace product.** It is an independent open-source project that runs
> on Dynatrace, licensed under Apache 2.0 and provided as-is. Dynatrace does not support, endorse or
> maintain it, and it is outside your Dynatrace support agreement — raising a Dynatrace support
> ticket about it will not get you anywhere. Issues and pull requests here are the route.

---

## Start here

You need three things, in this order. The first two are documents; after that the app guides you
itself.

| | Read | Why |
|---|---|---|
| **1** | [`docs/pre-deployment-brief.html`](docs/pre-deployment-brief.html) | Four decisions to make *before* installing anything. One of them cannot be undone. ~30 minutes, no tooling. |
| **2** | [`docs/customer-install-walkthrough.html`](docs/customer-install-walkthrough.html) | Installing the app, step by step, assuming you have never deployed one. ~5 minutes of actual work. |
| **3** | The app's **Configuration** page | Once installed, the app reads your tenant and shows what is set up and what is not. It is the deployment guide from here on. |

> **Why so little documentation?** Because the app can see your tenant and a document cannot. Rather
> than maintain a written procedure that silently drifts from the product, everything after install
> lives in the Configuration page next to the code that implements it. The two documents above cover
> the only phase where that is impossible — before the app exists.

Extension signing is the one procedure worth reading in advance:
[`docs/extensions-setup-walkthrough.html`](docs/extensions-setup-walkthrough.html).

---

## What's in here

```
network-insights-app/    the app — React + TypeScript UI, app functions in api/
modules/                 five extensions: two declarative (YAML), three Python
docs/                    the contract and the deployment guides
scripts/                 tooling that runs against a real estate
CLAUDE.md                orientation for an AI coding agent working in this repo
```

### The five extensions

| Extension | What it gives you |
|---|---|
| `custom:cno.network.interfaces` | Interface and device metrics — start here |
| `custom:cno.network.controlplane` | LLDP topology discovery — **produces** the edges |
| `custom:cno.network.dependency` | **Consumes** those edges into Smartscape topology |
| `custom:cno.network.compliance` | Config capture and golden-config drift |
| `custom:cno.network.netbox` | Inventory and power topology from NetBox |

Controlplane and dependency are two halves of one feature; deploying only one gives you an empty
topology page.

---

## Reviewing this before you deploy it

Everything is source. There are no compiled artifacts, no bundles and no binaries except the
Dynatrace logo. If you are assessing this for your estate, the shortest useful path:

1. **What can the app do?** — `network-insights-app/app.config.json`. The `scopes` array is the
   complete set of permissions the app holds, each with a comment saying why. Nothing outside that
   list is possible.
2. **What talks to your devices?** — `modules/`. All five extensions in full source. They run on
   your ActiveGate, and you sign them with your own certificate authority.
3. **What writes to your tenant?** — `network-insights-app/api/provision.function.ts`. Device
   onboarding, retirement, and anomaly detectors. It is the only component that writes.
4. **Where do credentials live?** — the Dynatrace Credential Vault. The app references entries by
   id and never reads a secret. There are no credentials in this repository.
5. **Dependencies** — `network-insights-app/package-lock.json` pins every version.

One generated file: `network-insights-app/ui/app/lib/extensionBundles.ts` is base64-encoded zips of
`modules/`, so the app can offer extension source as a download. It is reproducible — regenerate it
with `python3 scripts/bundle_extensions.py` and diff — and the source it encodes is in this repo.

---

## Extending it with your own data

**The app reads a metric model, not a specific extension.** Anything emitting the right keys and
dimensions appears in the app, whatever produced it — SNMP, a vendor API, or a script.

- [`docs/METRIC-CONTRACT.md`](docs/METRIC-CONTRACT.md) — the contract, in prose
- [`docs/contract.json`](docs/contract.json) — the same thing, machine-readable
- `scripts/api_bridge.py` — a complete worked example from a **non-SNMP** source

Check your work rather than guessing:

```bash
python3 scripts/verify_contract.py --context <ctx> --device 10.1.1.1
```

It reports which parts of the app your data satisfies and names the specific dimension that is
missing. The characteristic failure here is a metric that is present but missing one dimension: the
data is in Grail, the query returns rows, and the page is empty. Nothing errors.

The minimum to make a device appear at all is **one metric with two dimensions** —
`cno.device.uptime` with `device.address` and `sys_name`.

---

## Building

```bash
# app
cd network-insights-app
npm ci
npm run build
npm test
npx dt-app deploy --environment-url https://<your-tenant>.apps.dynatrace.com/

# extensions
pip install dt-cli dt-extensions-sdk
```

Bump `app.version` in `app.config.json` before every deploy — Dynatrace rejects re-uploading an
existing version. Full signing and upload procedure is in the extensions walkthrough.

---

## Contributing

Yes, please — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Note that most customisation needs no change
to this repository at all: if you are adding your own devices or data sources, you meet the contract
from your own code and never touch ours.

## Licence

Apache 2.0 — see [`LICENSE`](LICENSE).
