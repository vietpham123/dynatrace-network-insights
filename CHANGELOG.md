# Changelog

What changed in each release, and **what you need to do about it**.

Written for the person running this, not for its authors. Entries say what behaviour changed and
whether an upgrade needs an action beyond installing the app. Commit messages carry the engineering
detail; this file carries the consequences.

Versions follow the app version in `network-insights-app/app.config.json`. The RCA workflow is
versioned **with** the app, because the app bundles and deploys it — so a workflow change and an app
change always share a version number.

---

## 1.3.0 — 2026-08-11

**Retire moved to the device page.** It was an inline action on every row of the Devices table.
Retiring withdraws the monitoring configuration from every extension holding a device — polling
stops, the licence frees, and the undo is re-onboarding rather than a click. To retire something you
now open it first, so you have seen its name, address, site, role and state before deciding. The
confirmation is unchanged.

**The `hide` button is gone.** It wrote a *shared* acknowledgement, so one person hiding a device
removed it from Fleet, Overview and Topology for everyone — while the label implied a personal view
preference. Rather than leave a control whose behaviour contradicts its name, it is withdrawn until
there is a per-user preference to hang it on.

Nothing already hidden is stranded: **unhide remains** on the Devices page, and the acknowledgement
mechanism itself is untouched because retire depends on it — a device entity cannot be deleted, so
that flag is the only thing that takes a retired device off the live views.

*Upgrade action: none.*

---

## 1.2.2 — 2026-08-11

**Root-cause cards now name the real source of the dependency graph.** A card said "graph source:
NetBox declared cabling" regardless of what it had actually walked — text left over from when NetBox
was the only source of device-to-device topology. Cards now report the sources behind the specific
edges they used, e.g. LLDP neighbour discovery, NetBox declared cabling, or a controller API.

Sources are read from the data, not from a fixed list — if you emit topology with your own
`discovery` value, the card names it.

*Upgrade action: redeploy the RCA workflow from Configuration → Network RCA.*

---

## 1.2.1 — 2026-08-11

**A real app icon.** The launcher and navigation were showing an auto-generated "Ne" tile. Replaced
with a signal mark — a node with radiating arcs — as a white glyph on a cyan-to-blue tile, the same
construction Dynatrace uses for Workflows and Kubernetes, so it reads at 24px in the nav and holds up
on any background in either theme.

*Upgrade action: none.*

---

## 1.1.1 — 2026-08-11

**Fixes a crash on load in 1.1.0.** 1.1.0 failed to start with `B5e is not a function` — a circular
import between two library modules meant a shared helper was still undefined when it was first
called.

> **If you installed 1.1.0, upgrade.** It does not load.

*Upgrade action: install and reload.*

---

## 1.1.0 — 2026-08-11

⚠️ **Withdrawn — does not load. Use 1.1.1 or later.** The changes below are real and carried forward.

### Root-cause analysis now works for power failures and for cascades

Three defects meant the RCA either stayed silent or named the wrong device. All three are fixed.

**A PDU or UPS could never be identified as the root cause.** Anything deciding whether a device was
reporting asked only for `cno.if.oper_status` — an interface metric. Power devices have no interface
table and, since the extension's 0.0.14 feature-set change, are correctly no longer polled for one.
So they were invisible: a PDU failure was blamed on the highest affected switch, which was itself a
victim. Liveness is now the union of `cno.device.uptime` and `cno.if.oper_status`, which every
device emits one of.

**A cascade produced no problem at all.** The root test asks "is this device down, with no failed
device above it?" — but the topology graph contained the same links in both directions, so in a
multi-device failure every candidate had a failed neighbour above it and none qualified. A single
isolated failure worked; a real cascade was silent.

**Interface degradation fired constantly on healthy switches.** It flagged any device with an
admin-enabled port that was operationally down — which is the normal state of an unpatched access
port, and roughly two-thirds of a typical estate. It now requires a port that was **up recently and
is down now**, so a genuinely failed link is reported and an unused one is not.

### Consistency

"Is this device reporting?" was implemented in three places and fixed in one. The Devices page could
list a UPS while the lifecycle logic could not see it and the RCA could not observe it failing.
There is now a single definition all three use.

> **Upgrade action — required.** The app bundles the RCA workflow, so installing the app is not
> enough. Open **Configuration → Network RCA** and redeploy the workflow, or your tenant keeps
> running the previous one. See *Known issues* below.

---

## 1.0.0 — 2026-08-10

First customer-facing release. The app, five extensions, the `cno.*` metric contract, and the
deployment guides, extracted from the development repository into this one.

*Upgrade action: n/a.*

---

## Known issues

**Redeploying the RCA workflow is manual.** The app ships the workflow definition, but upgrading the
app does not update a workflow already deployed on your tenant. Until the app detects and warns
about this, check after any upgrade: the deployed workflow's description ends with the version that
produced it, e.g. `[Network Insights v1.3.0]`. If it does not match the app version in the sidebar,
redeploy from **Configuration → Network RCA**.

**RCA topology direction depends on NetBox roles.** The dependency graph is oriented using
`device.role` from NetBox inventory. With LLDP but no CMDB, or with role names outside the expected
vocabulary (`wan-edge`, `sdwan`, `spine`, `core`, `leaf`, `access`, `ap`), link direction falls back
to whatever the discovery source reported and root-cause selection may pick the wrong end.

**Problems close on a timer, not on recovery.** A device can be reporting again while its problem is
still open — measured at roughly seven minutes. This is Davis's event-timeout behaviour, not a
defect.
