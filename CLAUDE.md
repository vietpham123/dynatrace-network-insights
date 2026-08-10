# Working in this repository

*This file orients an AI coding agent (Claude Code, Cursor, or similar) working in this
repository. It is also a fast orientation for a human. If you are an agent: read this first, then
read `docs/METRIC-CONTRACT.md` before writing any code that produces data.*

---

## What this is

**Network Insights** — a Dynatrace app for network observability, plus five extensions that feed
it. You deploy both into your own Dynatrace tenant. Nothing here is a SaaS service; it all runs in
your environment.

| Directory | What's in it |
|---|---|
| `network-insights-app/` | The app: React + TypeScript UI, plus app functions in `api/` |
| `modules/` | Five extensions. Two declarative (YAML), three Python |
| `docs/` | The contract, deployment guides, sizing |
| `scripts/` | Operational tooling that runs against a real estate |

## The one thing to understand before writing code

**The app reads a metric model, not a specific extension.** Anything emitting the keys and
dimensions in `docs/METRIC-CONTRACT.md` shows up in the app — SNMP, a vendor API, or a script.

This means **you extend it by meeting the contract, not by modifying the app.** If a customer asks
"can we bring our own extension", the answer is yes, and the contract is the interface.

- The spec, for humans: `docs/METRIC-CONTRACT.md`
- The same spec, machine-readable: `docs/contract.json`
- **A complete worked example from a non-SNMP source: `scripts/api_bridge.py`** — read this before
  writing your own. It maps an SD-WAN controller API into `cno.*` and the app cannot tell the
  difference.

## Check your work — do not guess

```bash
python3 scripts/verify_contract.py --context <ctx> --device <ip>
```

Reports each tier of the app as PASS or FAIL and names the specific dimension that is missing.
**Run this instead of assuming a change worked.** The characteristic failure here is a metric that
is present but missing one dimension: the data is in Grail, the query returns rows, and the page is
empty. Nothing errors.

Requires `dtctl auth login` first. Browser SSO grants the platform scopes needed to run DQL; API
tokens cannot.

## Commands

```bash
# app
cd network-insights-app
npm ci                 # once per machine
npm run build          # bundle without deploying — do this before any deploy
npm test               # vitest
npm run lint           # eslint
npx dt-app deploy --environment-url https://<tenant>.apps.dynatrace.com/

# extensions
pip install dt-cli dt-extensions-sdk
dt ext assemble --source extension --output /tmp/ext.zip --force    # declarative
dt ext sign --src /tmp/ext.zip --output /tmp/bundle.zip --key dev_fused.pem --force
dt-sdk build -k dev_fused.pem                                        # python
```

**Bump `app.version` in `app.config.json` before every deploy.** Dynatrace rejects re-uploading an
existing version.

## Hard rules

These are not style preferences. Each one has produced a silent, wrong answer in production.

1. **Never use a multi-aggregate `timeseries { a=count(X), b=count(Y) }`** when a metric might be
   empty. It inner-joins on the by-dimensions, so one empty metric erases every other column. Use
   `| append [ … ]`. This has bitten this codebase four times, including in the panel whose entire
   purpose was to report metrics with no data.

2. **Never conflate "no data" with "could not ask."** A failed query must not render as zero, down,
   or unconfigured. Every input's *absence* is treated as unknown rather than as a state, and new
   code must preserve that. If you add a signal, add its error path in the same change.

3. **Always set `featureSets` explicitly** on a monitoring configuration. An empty array is
   inherited silently across version changes and stops every gated metric while the configuration
   still reports status OK.

4. **Never enable the `Interfaces` feature set on a UPS or PDU.** Their management cards answer
   SNMP GetNext but never GetBulk, so it produces a permanent ERROR and no power data.

5. **`device.address` is identity and it is permanent.** Entities cannot be deleted (405) and never
   age out. Do not write code that assumes an entity can be cleaned up.

6. **Never hardcode a tenant URL, credential, or vault ID.** Credentials are referenced by vault id;
   the app never sees a secret.

## When you change something

- **After editing `modules/`**, run `python3 scripts/bundle_extensions.py` — the app serves
  extension source as downloads, generated from those folders. Skipping this ships stale source.
- **After changing what the app collects or displays**, re-read the Configuration page steps in
  `network-insights-app/ui/app/pages/Configuration.tsx`. They are the primary deployment guide, and
  they go stale silently.
- **Tests are the gate.** `npm test` must be green. Add tests before changing untested code.

## What an agent should not do alone

Not restrictions on capability — these need a human because they need secrets, physical access, or
an irreversible judgment call:

- **Signing extensions.** Needs the customer's own CA and private key.
- **Installing an ActiveGate.** Physical or VM provisioning in their network.
- **Deciding IP addressing.** If any part of the estate reuses IP space, that must be resolved
  before onboarding — and it cannot be undone afterwards.
- **Deploying to a production tenant.** Propose it; let a human run it.

## Style

Match the surrounding code. This codebase comments *why*, not *what* — most comments record a
measurement or a failure that produced the current design. Preserve them; they are the reason the
code is shaped the way it is. If you change behaviour a comment describes, update the comment in
the same edit.
