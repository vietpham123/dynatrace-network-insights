import React, { useState } from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useNavigate } from "react-router-dom";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t } from "../theme";
import { Panel, QueryErr } from "../components/ui";
import { StepRow, Step } from "../components/StepRow";
import { Configure } from "./Configure";
import { ConfigureApi } from "./ConfigureApi";
import { RcaCapability } from "../components/RcaCapability";
import { NetboxApplyDownload } from "../components/NetboxApplyDownload";
import { NetflowModeSetup } from "../components/NetflowModeSetup";
import { ExtensionDownload } from "../components/ExtensionDownload";
import { DetectionCapability } from "../components/DetectionCapability";
import { useCapabilitySignals } from "../lib/data";

// ── The Configuration hub ────────────────────────────────────────────────────
// One place, N focused tracks — pick one at a time. Every step EXPANDS to the
// concrete how (what it is · the command/artifact · what "done right" looks like)
// and is tagged by who drives it (you / in NetBox / we automate / verify), so a
// junior engineer with zero context can actually follow it — not just a TOC.

type TrackId = "snmp" | "api" | "netbox" | "netflow" | "oxidized" | "activegate" | "topology";
type Status = "idle" | "active" | "done";
type Track = { id: TrackId; icon: string; tag: string; title: string; blurb: string; status: Status; time: string; steps: Step[]; link?: { to: string; label: string } };

const TRACKS: Track[] = [
  {
    id: "snmp", icon: "▤", tag: "Devices", title: "SNMP device", status: "active", time: "~5 min",
    blurb: "Switches, routers, firewalls, UPS/PDU polled over SNMP v2c/v3.",
    steps: [
      { text: "Pick the device type", d: { who: "you", what: "The type maps your device to the right Dynatrace extension — Cisco routers/switches and generic gear use the SNMP extension; Palo Alto has its own; UPS/PDU use the SNMP extension's power group.", how: "You don't install anything here — just choose in the form below so the correct OIDs get polled." } },
      { text: "Choose an SNMP credential (v2c or v3)", d: { who: "you", what: "How the ActiveGate authenticates to the device. Both are supported: v2c = a community string; v3 = a user + security level + auth/priv passphrases. Pick the version in the credential picker — for v3 the form only offers the fields your chosen security level actually permits, so it cannot submit an invalid combination. Security-conscious estates usually mandate v3, since v2c authenticates in cleartext.", how: "Create it once in Settings → Credential vault, then pick it by name here. The app references the id — it never sees the secret.", verify: "The credential shows in the dropdown below." } },
      { text: "Turn on the feature sets you need", key: true, d: { who: "you", what: "Feature sets are OPT-IN and ADDITIVE. A monitoring configuration with none selected polls only the default set (interfaces) — UPS power, UPS battery voltage, PDU power, and Cisco device health each have to be ticked, or their metrics simply never appear and the pages that need them look empty. LLDP topology is the exception — leave it OFF (see the Topology track).", how: "Select them on the monitoring configuration. Only enable what the device actually implements — on an all-or-nothing SNMPv1 agent one unsupported OID makes the WHOLE request fail, so a single wrong feature set can zero out an otherwise healthy device.", why: "Measured on a CyberPower UPS, 2026-08-02: a batch of 10 OIDs returned nothing at all; the same batch minus one unimplemented OID returned 9 of 9 in 9 ms. That is why UPS battery voltage is its own separate feature set rather than part of UPS power — it is optional in RFC 1628, and asking for it on a device that does not implement it kills every other power metric in the same request.", verify: "Power, topology and health tiles fill in. If a device polls interfaces fine but shows nothing else, the feature set is off — not the device." } },
      { text: "Add by IP, or discover a subnet", d: { who: "auto", what: "Either onboard one device (name + mgmt IP + credential) or point autodiscovery at a subnet and Dynatrace finds everything answering SNMP.", how: "Use the form below — single add is immediate; discovery runs under the SNMP autodiscovery extension." } },
      { text: "Verify it's polling", key: true, d: { who: "verify", what: "Confirmation the device is monitored.", verify: "Within ~1 min it appears in Devices with a green 'up' pill and a network:device entity is auto-created. If not: the community/IP is wrong, or the ActiveGate can't reach the device (firewall/routing)." } },
    ],
  },
  {
    id: "api", icon: "⇆", tag: "Devices", title: "API device", status: "active", time: "~5 min",
    blurb: "Controller-based gear via API — Cisco SD-WAN (vManage), Meraki, Catalyst Center.",
    steps: [
      { text: "Pick the platform / controller", d: { who: "you", what: "Unlike SNMP, each controller has a totally different API, so there's one extension per platform (vManage, Meraki, Catalyst Center).", how: "Install that platform's extension from the Dynatrace Hub if it isn't already, then select it." } },
      { text: "Enter the controller URL", d: { who: "you", what: "The controller's base API URL — one endpoint that reports ALL its managed devices (not per-device).", cmd: "https://vmanage.example.com" } },
      { text: "Store an API token in the vault", d: { who: "you", what: "A read-only API user on the controller.", how: "Create the user on the controller, put its token in Settings → Credential vault, reference it by id — same secure by-id pattern as SNMP." } },
      { text: "Test the connection", d: { who: "verify", verify: "The extension validates URL + token before polling. 401 = bad token; timeout = firewall/reachability to the controller." } },
      { text: "Select sites / fabrics", key: true, d: { who: "you", what: "Scope which sites or fabrics to onboard so you don't pull the entire global inventory at once." } },
    ],
  },
  {
    id: "topology", icon: "⚭", tag: "Topology", title: "LLDP topology — how devices connect", status: "active", time: "~10 min",
    blurb: "Live neighbour discovery. This is what draws the topology map and what RCA walks to find an upstream cause.",
    steps: [
      { text: "Use the controlplane extension — NOT the SNMP LLDP feature set", key: true, d: { who: "you", what: "There are two LLDP paths in this product and only one works. custom:cno.network.controlplane is a PYTHON extension that reads the LLDP tables itself. The SNMP extension also ships an 'LLDP topology' feature set — it is off by default and must stay off.", how: "The declarative SNMP datasource decodes binary OCTET STRINGs as text, and lldpRemChassisId is a MAC. 20 4E 7F 4E C3 E6 arrives as ' N_N', so the chassis-id join key — the entire point of the group — is destroyed. It is also expensive: one 48-port access switch can advertise 40+ neighbours every 15 minutes. Ticking it costs you money and returns mangled data." } },
      { text: "Build and sign BOTH extensions", d: { who: "you", what: "Same path as the SNMP and NetBox extensions — build each zip, sign it with your CA, upload, and activate. Both run on the same ActiveGate.", how: "Download both zips below — you need BOTH. controlplane produces the edges, the dependency extension turns them into Smartscape topology, and the consumer alone renders an empty page. Your signing CA must already be trusted in BOTH places (see the ActiveGate track) or the upload or the execution fails, with different errors." } },
      { text: "Point it at the same devices", d: { who: "you", what: "It takes a device list and SNMP credentials, exactly like the SNMP track. Anything you want to appear on the topology map has to be in here — an unpolled device can still be SEEN as a neighbour, but only devices you poll can report their own side of a link." } },
      { text: "Know what LLDP cannot see", key: true, d: { who: "you", what: "LLDP is a link-layer ADVERTISEMENT protocol, not a scan. A device that does not speak it, or has it switched off, is invisible no matter how healthy your polling is — in the reference lab the wireless AP never appears for exactly this reason.", how: "Where a neighbour is genuinely absent, model the link in NetBox instead: NetBox cabling produces the same cno.dep.uses edges, tagged discovery=netbox rather than discovery=lldp, so you can always tell a discovered link from a documented one. Power chains have no LLDP equivalent at all and are NetBox-only." } },
      { text: "Verify — edges are being produced", key: true, d: { who: "verify", verify: "Run: timeseries n=count(cno.dep.uses), by:{discovery}. A discovery=lldp row means it is working. No row means the extension is not running — upload alone does not move the ActiveGate onto a new version (see the ActiveGate track), so check pgrep on the AG rather than trusting the config's OK badge." } },
    ],
    link: { to: "/topology", label: "View Topology →" },
  },
  {
    id: "netbox", icon: "⇄", tag: "System of record", title: "NetBox → power & inventory", status: "idle", time: "~15 min",
    blurb: "Make NetBox your source of truth and light up the power chains LLDP physically can't see.",
    steps: [
      { text: "Deploy the NetBox source extension on your ActiveGate", d: { who: "you",
        what: "The extension reads your NetBox devices + cables and lands the roster and the dependency/power graph in Grail — it replaces the old on-prem bridge scripts, running on the AG so NetBox credentials never leave your network.",
        how: "Download the source below, build + sign it with your own cert, upload it, then add a monitoring config with your NetBox URL + API token. Deploy the companion dependency extension too — it maps the edges into Topology.",
        verify: "cno.inv.device and cno.dep.uses start appearing in Grail within a couple minutes of the first poll." } },
      { text: "Decide: emit device↔device data links? (default ON)", d: { who: "you",
        what: "The 'emitDataLinks' setting on the monitoring config. NetBox's declared cabling is currently the only production-ready source of device↔device topology, so it defaults ON and you should normally leave it.",
        how: "Turn it OFF only where a genuine live-LLDP source already discovers the same devices. Both derive edge DIRECTION independently — NetBox from its role-slug ranking, LLDP from the advertised capability bitmap (router > bridge > AP, tie-broken on the gateway-address convention; hostname inference was removed) — and when they disagree you get an edge in both directions, which breaks the RCA workflow's downstream-suppression walk.",
        verify: "Power edges are unaffected either way: NetBox is their only possible source, since there is no LLDP for power cabling." } },
      { text: "Model power in NetBox: Power Panel → Feed → PDU inlet → outlets", key: true, d: { who: "netbox",
        what: "This is the SUPPLY side. NetBox represents power as: a Power Panel → a Power Feed → a PDU (a device with an inlet power-port cabled to the feed) → the PDU's outlets.",
        how: "In NetBox: DCIM → Power Panels (create) → Power Feeds (create) → your PDU device with an inlet, cabled to the feed. You don't have to hand-build it — we ship a scaffold that creates the panel, feed and PDU inlet for you.",
        cmd: "python3 netbox_power_scaffold.py   # creates panel + feed + PDU inlet cabling" } },
      { text: "Cable each device's power-port to a PDU / UPS outlet", key: true, d: { who: "netbox",
        what: "This is the DEMAND side, and it's the whole point: each device (switch, AP, router) has a Power Port; you connect it to a PDU Outlet with a cable. THIS cabling is the ground truth that becomes the power dependency graph — which device dies if which PDU fails.",
        how: "In NetBox: open a device → Power Ports → Connect → choose the PDU outlet. Repeat per device (or extend the scaffold to auto-cable them). This is the one part only you know — which plug goes where in your racks." } },
      { text: "Inventory + power cabling land in Grail", d: { who: "auto",
        what: "The extension's next poll reads those cables and emits the dependency edges, including the power ones (device → its PDU → the UPS).",
        verify: "dtctl query 'timeseries sum(cno.dep.uses), by:{link_type}' shows a power row (not just data)." } },
      { text: "Power domain appears in Topology; UPS/PDU health on each device", key: true, d: { who: "verify",
        verify: "Open Topology — the PDU/UPS now connect to the devices they power (the power domain, drawn separate from the data path). Each device's detail page gains UPS/PDU health tiles. That's when you know the chain is live end-to-end." } },
    ],
    link: { to: "/topology", label: "View Topology →" },
  },
  {
    id: "netflow", icon: "⇋", tag: "Flow", title: "NetFlow → traffic", status: "idle", time: "~10 min",
    blurb: "Top talkers, conversations, egress-by-ASN — plus live collector health.",
    steps: [
      { text: "Enable flow export — and on ENOUGH devices", d: { who: "you",
        what: "SNMP counters give you volume per interface; they cannot show CONVERSATIONS. That needs a flow export. Two different protocol families, and they are not interchangeable: NetFlow v5/v9 and IPFIX (v10) share one collector on UDP 2055 — the decoder handles all three on that single port, so there is no per-version collector to choose. sFlow is a DIFFERENT protocol (packet sampling, XDR-encoded, no flow cache) on UDP 6343 and needs its own receiver. Routers and firewalls usually speak NetFlow/IPFIX; switches usually speak sFlow, so a real estate needs both.",
        cmd: "! Cisco IOS example\nflow exporter DT\n destination <collector-ip>\n transport udp 2055" } },
      { text: "Set up the OpenTelemetry collector", d: { who: "you",
        what: "An OpenTelemetry (OTel) Collector is a small vendor-neutral agent — receivers (telemetry in) → optional processors (shaping) → exporters (out, to Dynatrace) — wired by a service pipeline. The custom netflow_v9_collector.py feeds it and preserves the interface index the stock OTel receiver drops.",
        how: "Pick your export mode below (Full or Sampled) — the collector config updates and downloads to match. At scale, BindPlane pushes + version-manages that one config across a whole fleet of collectors (instead of SSH-ing each host)." } },
      { text: "Route to Dynatrace — flow arrives as logs", d: { who: "you",
        what: "Flow lands as LOGS, not metrics — the receiver has no metrics mode, so this is not a choice to make. Raw per-flow records are what make per-conversation and interface-level drill-down possible; aggregating them away would remove the reason to collect flow at all. Budget accordingly: a mid-size edge router can emit tens of thousands of flows per second, so plan exporter-side sampling or filtering rather than assuming an aggregate mode exists." } },
      { text: "Collector insights", key: true, d: { who: "verify",
        verify: "The collector reports its own throughput / drops / flows-per-second — watch it to confirm flow is actually arriving before you look in the app." } },
      { text: "Verify the views render", d: { who: "verify", verify: "Open NetFlow — the Sankey, top talkers, and per-interface drill-down populate with live data." } },
    ],
    link: { to: "/netflow", label: "View NetFlow →" },
  },
  {
    id: "oxidized", icon: "◨", tag: "Compliance", title: "Oxidized → config & compliance", status: "idle", time: "~15 min",
    blurb: "Archive device configs to Git and evaluate ISO-27001 controls on the captured config.",
    steps: [
      { text: "Deploy Oxidized", d: { who: "auto", what: "Oxidized is an open-source config-backup tool — the SolarWinds NCM replacement. It logs into your devices (SSH or telnet) and archives their running-config.", how: "Deploy it on a host that can reach your gear on SSH or telnet — older switches are frequently telnet-only. Dynatrace never touches device config directly (cloud-side + private devices); Oxidized is the on-prem puller." } },
      { text: "Point it at the device list + a PRIVILEGED account", d: { who: "you", what: "Oxidized's router.db lists devices and how to reach them. The account must be able to reach ENABLE / privileged mode — `show running-config` is a privileged command, and privilege is a property of the ACCOUNT, not of the password you supply.", how: "There is no read-only-but-privileged option on most platforms; budget for a write-level account, or use TACACS+ to authorise the login directly to privilege 15 and skip the enable step entirely. WATCH FOR THIS: a device may validate the enable secret BEFORE checking whether the account is authorised, so an authorisation failure is reported as 'Incorrect Password!'. Verified on Netgear FASTPATH 2026-08-02 — it cost a day of chasing the wrong cause. If credentials look right and enable still fails, check the account's privilege level." } },
      { text: "Choose a Git backend", d: { who: "you", what: "Configs commit to a Git repo — that IS your change history and diff engine (cheap, delta-based). Dynatrace ingests only the change events + verdicts, not raw configs wholesale." } },
      { text: "Schedule polls", d: { who: "you", verify: "Oxidized polls on a schedule; every config change becomes a new commit you can diff." } },
      { text: "Deploy the compliance extension on your ActiveGate", key: true, d: { who: "you", what: "The extension reads the running-configs Oxidized archives, evaluates the ISO-27001 A.8.x controls as predicates over the config text (login banner set, SSH-only VTY, encrypted secrets…), and detects drift vs a golden baseline.", how: "Download the source below, build + sign it, upload it, and point its config at the archive — either configPath for a co-located install, or remoteUrl for a Git remote the ActiveGate fetches (HTTPS + token), which is the usual enterprise shape when Oxidized runs elsewhere. Emits pass/fail per control per device + drift, as logs." } },
      { text: "Review diffs + control pass/fail", d: { who: "verify", verify: "Config & Compliance shows the change diffs and per-device control status; a failing control names the device inline." } },
    ],
    link: { to: "/config", label: "View Config & Compliance →" },
  },
  {
    id: "activegate", icon: "✦", tag: "Foundation", title: "ActiveGate", status: "done", time: "~10 min",
    blurb: "The on-prem gateway that does the polling and hosts your extensions. Set this up first.",
    steps: [
      { text: "Install an ActiveGate", d: { who: "you", what: "The ActiveGate is the on-prem component that reaches into your network — it polls SNMP, runs extensions, and relays to Dynatrace. Put it on a host that can reach your gear.", how: "Deploy Dynatrace → Install ActiveGate → copy the Linux command and run it. The installer bakes in your tenant + token, so it self-registers.", cmd: "sudo /bin/bash Dynatrace-ActiveGate.sh --set-group=<your-network-group>" } },
      { text: "Register to the tenant", d: { who: "auto", verify: "The installer auto-connects; the AG shows up under Deployment status → ActiveGates as Connected." } },
      { text: "Assign an EXPLICIT network group", d: { who: "you", what: "The group is how monitoring configs find this AG — each config is scoped to a group (e.g. ag_group-<name>). Devices in that scope route through this AG.", how: "agctl group set <name>, then restart the AG. Do not rely on the default: a fresh AG reports its group as bare 'default', which does NOT match a config scoped ag_group-default.", cmd: "sudo /opt/dynatrace/gateway/agctl group set <your-group> && sudo systemctl restart dynatracegateway", verify: "The AG shows your group name in Deployment status. If a monitoring config sits at UNKNOWN forever with no error, this is almost always why." } },
      { text: "Trust your signing CA — in TWO places", d: { who: "you", what: "The tenant Credential vault entry permits the UPLOAD; the ActiveGate's own trust store permits EXECUTION. They are separate, and only the first is obvious.", how: "Tenant: Credential vault → certificate, scope extension. ActiveGate: it should sync from the tenant — if it has not, drop the CA public cert into the AG cert directory and restart.", cmd: "sudo cp ca.pem /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/ && sudo systemctl restart dynatracegateway", verify: "Without this you get: Cannot extract extension ... checking signature failed, and the config stays UNKNOWN." } },
      { text: "Install the build tooling — once per machine", d: { who: "you", what: "Two tools, because there are two kinds of extension. Declarative extensions (SNMP interfaces, dependency) build with dt-cli; Python extensions (controlplane/LLDP, NetBox, compliance) build with dt-sdk. Each track below tells you which kind it hands you.", how: "Both are pip packages. You need them on whatever machine builds the extension — not on the ActiveGate.", cmd: "pip install dt-cli dt-extensions-sdk" } },
      { text: "Create your signing certificates — once per project", key: true, d: { who: "you", what: "Custom extensions must be signed, and you sign them with your OWN certificate authority — nothing runs in your environment that you did not sign. This produces a CA (which you will trust in the tenant) and a developer certificate (which does the signing).", how: "Generate once and keep them safe; every extension you build is signed with the same pair. The fused file concatenates the developer cert and key — CERTIFICATE FIRST, then key. That order is not cosmetic; reversing it fails later with an unhelpful error.", cmd: "dt ext gencerts --ca-cert ca.pem --ca-key ca.key \\\n  --dev-cert dev.pem --dev-key dev.key \\\n  --no-ca-passphrase --no-dev-passphrase\n\ncat dev.pem dev.key > dev_fused.pem", verify: "openssl verify -CAfile ca.pem dev.pem  →  dev.pem: OK", why: "Run that openssl check before chasing anything else. It separates a chain-packaging problem from a trust-distribution problem, and those two produce identical symptoms from the ActiveGate's side. One clean CA per project, and delete dead certificates from the vault — a broken or expired CA there can poison the whole cluster→ActiveGate certificate sync, after which the AG loads ZERO custom CAs and every custom extension fails signature at once." } },
      { text: "Build and sign an extension", d: { who: "you", what: "Turns a source folder into a signed .zip you can upload. The command depends on which kind of extension it is.", how: "Declarative (SNMP interfaces, dependency) — assemble then sign. Python (controlplane, NetBox, compliance) — dt-sdk build does both in one step. Run from inside the extension's source folder.", cmd: "# declarative\ndt ext assemble --source extension --output /tmp/ext.zip --force\ndt ext sign --src /tmp/ext.zip --output /tmp/bundle.zip --key dev_fused.pem --force\n\n# python\ndt-sdk build -k dev_fused.pem      # -> dist/custom_<name>-<version>.zip", verify: "A .zip exists, and its name carries the extension name and version." } },
      { text: "Upload it, then ACTIVATE the version", key: true, d: { who: "you", what: "Two separate actions. Uploading makes the version available in your tenant; it polls nothing until you activate it. The active version is one environment-wide setting per extension — activating moves every monitoring configuration of that extension at once, however many there are.", how: "Upload through the Extensions app in Dynatrace, or with dt ext upload. Then activate the version — in the Extensions app, or PUT the environment configuration.", cmd: "dt ext upload --tenant-url <url> --api-token <tok> /tmp/bundle.zip", verify: "The extension appears in the Extensions app showing the version you just activated." } },
      { text: "Rolling out a NEW extension version", key: true, phase: "day2", d: { who: "you", what: "Uploading a version and activating it in the environment configuration is NOT enough — the ActiveGate keeps running the OLD one. The monitoring configuration itself carries a version, and until that is updated the AG stays on the previous venv.", how: "Upload, activate the environment configuration, THEN read-modify-write the monitoring configuration with the new version (PUT /api/v2/extensions/{name}/monitoringConfigurations/{objectId}). Masked secrets round-trip through that PUT safely. You also cannot pre-pin a configuration to a version that is not yet active — it returns 404.", verify: "Check the RUNNING process on the ActiveGate, not the API: pgrep -af <extension> shows the venv path it is actually using.", why: "The API's active version and the version the ActiveGate is running can disagree indefinitely. An extension can sit active at one version in the environment while every device is still polled by an older one, because the monitoring configuration pins its own version — uploading a new bundle changes nothing on its own. After any upgrade, check each configuration rather than the environment." } },
      { text: "Verify — connected and polling", key: true, d: { who: "verify", verify: "AG = Connected, and your monitoring configs move from Pending → OK. Then SNMP metrics start flowing." } },
    ],
  },
];

// Live track status — derived from whether each track's data is actually in Grail (not hardcoded).
// "data present" is a truer health signal than a config's OK/pending flag: a config can read OK but
// silently stop producing data, whereas these queries only go green when data really arrives.
// APPEND, never a multi-aggregate `timeseries { a=.., b=.. }`. That form INNER-JOINS, so ONE empty
// member returns zero rows and every badge on this page silently reads "idle". Measured on the
// reference tenant 2026-08-03: api / inv / power were all empty, which erased snmp (17,262
// datapoints) and lldp (240) along with them — the page claimed nothing was configured while the
// fleet was polling normally. Fifth time this trap has bitten; see lib/data.ts and lib/netflow.ts.
//
// Windows differ per signal ON PURPOSE — SNMP polls every minute, but LLDP and NetBox run on much
// longer cycles and a 20-minute window makes them flap between done and idle.
// A signal with no data yields NO ROW rather than a zero, so the reader below defaults to 0.
const SIGNALS_Q = [
  ['snmp',  'count(cno.if.oper_status, filter:{isNull(source)})',        '-20m'],
  ['api',   'count(cno.if.oper_status, filter:{source=="sdwan-api"})',   '-20m'],
  ['lldp',  'count(cno.dep.uses, filter:{discovery=="lldp"})',           '-2h'],
  ['inv',   'count(cno.inv.device)',                                     '-2h'],
  ['power', 'count(cno.dep.uses, filter:{link_type=="power"})',          '-2h'],
].map(([k, agg, win], i) => {
  const leg = `timeseries n=${agg}, from:${win} | fields k="${k}", n=arraySum(n)`;
  return i === 0 ? leg : `| append [ ${leg} ]`;
}).join(" ") + " | summarize n=sum(n), by:{k}";
// flow.type is matched on PRESENCE, never on a specific wire version — an IPFIX exporter
// stamps "ipfix", v9 stamps "netflow_v9", and pinning either one turns this health tile red
// while flows are arriving perfectly. Same rule as lib/netflow.ts; see the note there.
const LOGS_SIGNAL_Q = `fetch logs, from:-2h | filter log.source == "network.config" or isNotNull(\`flow.type\`) | summarize cfg = countIf(log.source == "network.config"), flow = countIf(isNotNull(\`flow.type\`))`;

const SHORT: Record<TrackId, string> = { snmp: "SNMP", api: "API", netbox: "NetBox", netflow: "NetFlow", oxidized: "Compliance", activegate: "ActiveGate", topology: "Topology" };

// Cards in dependency order, numbered 1..8 so operators know the sequence to work through
// (foundation first, optional last). rca/detection are capabilities; the rest are setup tracks.
const CARD_ORDER: (TrackId | "rca" | "detection")[] = ["activegate", "snmp", "topology", "api", "netbox", "rca", "detection", "netflow", "oxidized"];

// Compact one-row card — icon + short label + a status dot; the full detail expands in the panel below.
function CompactCard(props: { n?: number; icon: string; label: string; on: boolean; onClick: () => void; dot?: string }) {
  return (
    <button onClick={props.onClick} title={props.n != null ? `${props.n}. ${props.label}` : props.label}
      style={{ textAlign: "left", cursor: "pointer", background: props.on ? t.emph : t.card, border: `1.5px solid ${props.on ? t.accent : t.border}`, borderRadius: 10, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
      <Flex justifyContent="space-between" alignItems="center">
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          {props.n != null ? <span style={{ fontSize: 12, fontWeight: 700, color: t.subtle, fontVariantNumeric: "tabular-nums" }}>{props.n}</span> : null}
          <span style={{ width: 30, height: 30, borderRadius: 8, display: "grid", placeItems: "center", background: props.on ? t.accent : t.cardSubtle, color: props.on ? "#fff" : t.ink, fontSize: 15, flex: "none" }}>{props.icon}</span>
        </span>
        {props.dot ? <span style={{ width: 8, height: 8, borderRadius: "50%", background: props.dot, flex: "none" }} /> : null}
      </Flex>
      <div style={{ fontSize: 13, fontWeight: 700, color: t.ink, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{props.label}</div>
    </button>
  );
}

const foundationPill: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 8, borderRadius: 999,
  padding: "5px 12px", fontSize: 13, fontWeight: 600, borderStyle: "solid", borderWidth: 1,
};

const ghostBtn: React.CSSProperties = { background: "none", color: t.accent, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 16px", fontSize: 14, fontWeight: 600, cursor: "pointer", alignSelf: "flex-start" };

export const Configuration = () => {
  const nav = useNavigate();
  const [sel, setSel] = useState<TrackId | "rca" | "detection">("snmp");
  const cur = TRACKS.find((x) => x.id === sel);

  // derive each track's badge from live data (see SIGNALS_Q / LOGS_SIGNAL_Q above)
  const sig = useDql({ query: SIGNALS_Q });
  const logsSig = useDql({ query: LOGS_SIGNAL_Q });
  const s: Record<string, number> = {};
  (((sig.data as any)?.records ?? []) as any[]).forEach((r) => { s[String(r.k)] = Number(r.n) || 0; });
  // Typed as a record rather than `any` so member access stays checked — agSignal reads the same
  // two fields a second time, and an `any` here spreads that unchecked access with every new use.
  const ls = (((logsSig.data as any)?.records?.[0] ?? {}) as Record<string, unknown>);
  const num = (v: any) => Number(v) || 0;
  // THE ACTIVEGATE HAS NO SIGNAL OF ITS OWN. There is no cno.* series meaning "the gateway is up",
  // which is why this track alone used to return a hardcoded "done" — every other track derives
  // from data, and this one asserted. On a fresh tenant, before the customer had installed
  // anything, the foundation step reported itself complete.
  //
  // It is inferable, and soundly in ONE direction: every signal on this page arrives THROUGH the
  // ActiveGate, so a single datapoint anywhere proves it is connected and polling. The inverse
  // does not hold — a healthy AG with nothing configured yet is equally silent — so zero means
  // "nothing observed", never "broken". That asymmetry is the whole reason this reads `idle`
  // rather than a failure state.
  const agSignal = num(s.snmp) + num(s.api) + num(s.lldp) + num(s.inv) + num(s.power)
                 + num(ls.flow) + num(ls.cfg);
  const live = (id: TrackId): Status =>
    id === "snmp" ? (num(s.snmp) > 0 ? "done" : "idle")
    : id === "api" ? (num(s.api) > 0 ? "done" : "idle")
    : id === "topology" ? (num(s.lldp) > 0 ? "done" : "idle")
    : id === "netbox" ? (num(s.power) > 0 ? "done" : num(s.inv) > 0 ? "active" : "idle")
    : id === "netflow" ? (num(ls.flow) > 0 ? "done" : "idle")
    : id === "oxidized" ? (num(ls.cfg) > 0 ? "done" : "idle")
    : id === "activegate" ? (agSignal > 0 ? "done" : "idle")
    : "idle";
  // A FAILED signal query must not read as "idle". Every badge on this page is derived from two
  // queries; if they error, `live()` sees zeros and reports the whole estate as unconfigured — the
  // same conflation of "no data" with "we could not ask" that the inner-join bug produced. Fall
  // back to the track's declared status and say so in the banner below.
  const sigFailed = !!(sig.error || logsSig.error);
  const statusOf = (tr: Track): Status =>
    (sig.isLoading || logsSig.isLoading || sigFailed ? tr.status : live(tr.id));

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1140 }}>
      <div>
        <Heading level={2}>Configuration</Heading>
        <Paragraph>One place to set everything up. Pick a track and we walk you through it end to end — one at a time. Click any step to expand the exact how (what it is · the command · how to know it worked).</Paragraph>
      </div>

      {/* The foundation claim is DERIVED, not decorative. This banner used to render
          "ActiveGate connected & polling" unconditionally — in green, with an up-dot — so a
          customer opening the page on a fresh tenant was told the foundation was ready before
          they had installed anything. Of everything on this page, the one state it must never
          invent is the one every other track depends on.
          While the signal queries are loading or have failed it renders NOTHING: the error
          banner below already says the badges are unmeasured, and a second claim here would be
          guessing in the gap. */}
      {!sig.isLoading && !logsSig.isLoading && !sigFailed && (
        <Flex>
          {agSignal > 0 ? (
            <span style={{ ...foundationPill, background: t.upBg, color: t.up, borderColor: t.up }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: t.up }} />
              Foundation ready · ActiveGate connected &amp; polling
            </span>
          ) : (
            <span style={{ ...foundationPill, background: t.card, color: t.subtle, borderColor: t.border }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: t.subtle }} />
              No telemetry observed yet · start with the ActiveGate track
            </span>
          )}
        </Flex>
      )}

      {sigFailed && (
        <div style={{ border: `1px solid ${t.down}`, borderRadius: 8, padding: "10px 14px", background: t.downBg }}>
          <QueryErr label="live setup status — the badges below show expected state, not measured state" />
        </div>
      )}

      <CapabilityPanel />

      {/* ── one-row compact cards — capabilities + setup tracks; the full detail expands below ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(118px, 1fr))", gap: 10 }}>
        {CARD_ORDER.map((c, i) => {
          const n = i + 1;
          if (c === "rca") return <CompactCard key="rca" n={n} icon="◎" label="Network RCA" on={sel === "rca"} onClick={() => setSel("rca")} dot={t.accent} />;
          if (c === "detection") return <CompactCard key="detection" n={n} icon="◈" label="Detectors" on={sel === "detection"} onClick={() => setSel("detection")} dot={t.subtle} />;
          const tr = TRACKS.find((x) => x.id === c)!;
          const st = statusOf(tr);
          const dot = st === "done" ? t.up : st === "active" ? t.warn : t.subtle;
          return <CompactCard key={tr.id} n={n} icon={tr.icon} label={SHORT[tr.id]} on={sel === tr.id} onClick={() => setSel(tr.id)} dot={dot} />;
        })}
      </div>

      {/* ── selected detail — the root-cause capability OR a setup track, same frame ── */}
      {sel === "rca" ? <RcaCapability /> : sel === "detection" ? <DetectionCapability /> : cur ? (
      <Panel>
        <Flex flexDirection="column" gap={16}>
          <Flex gap={12} alignItems="flex-start">
            <span style={{ width: 44, height: 44, borderRadius: 11, display: "grid", placeItems: "center", background: t.accent, color: "#fff", fontSize: 22, flex: "none" }}>{cur.icon}</span>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: t.accent }}>{cur.tag}</div>
              <Heading level={3}>{cur.title}</Heading>
            </div>
          </Flex>
          <Text style={{ color: t.subtle, fontSize: 14 }}>{cur.blurb}</Text>

          {/* First-run steps only. A day-2 operation sitting in the middle of a setup checklist
              reads as something you must do now, which is how an extension-upgrade procedure ended
              up between "install an ActiveGate" and "verify it is polling". */}
          <Flex flexDirection="column" gap={8}>
            {cur.steps.filter((s) => s.phase !== "day2").map((s, i) => <StepRow key={i} step={s} n={i + 1} />)}
          </Flex>

          {cur.steps.some((s) => s.phase === "day2") ? (
            <Flex flexDirection="column" gap={8} style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: t.subtle }}>Day-2 operations</div>
                <Text style={{ color: t.subtle, fontSize: 13 }}>Not part of first setup — come back to these when you upgrade or change something.</Text>
              </div>
              {cur.steps.filter((s) => s.phase === "day2").map((s, i) => <StepRow key={`d2-${i}`} step={s} n={i + 1} />)}
            </Flex>
          ) : null}

          {cur.id === "snmp" ? (
            <>
              <ExtensionDownload bundleKeys={["snmp-interfaces-extension"]}
                intro="The SNMP interface datasource — polls IF-MIB/ifXTable per device for up/down + throughput. Deploy this on your ActiveGate first (build + sign with your cert), then onboard devices below." />
              <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
                <Text style={{ color: t.subtle, fontSize: 13, marginBottom: 8, display: "block" }}>Live onboarding — add or retire devices below. Each add starts SNMP polling and auto-creates the <span style={{ color: t.ink }}>network:device</span> entity.</Text>
                <Configure embedded />
              </div>
            </>
          ) : cur.id === "api" ? (
            <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 16 }}>
              <Text style={{ color: t.subtle, fontSize: 13, marginBottom: 8, display: "block" }}>Live API onboarding — connect a controller and the on-prem executor polls its devices into the fleet.</Text>
              <ConfigureApi embedded />
            </div>
          ) : cur.id === "topology" ? (
            <>
              <ExtensionDownload bundleKeys={["controlplane-extension", "network-dependency-extension"]}
                intro="Two halves, useless apart. The controlplane extension PRODUCES the edges — it polls LLDP itself and emits cno.dep.uses with discovery=lldp. The declarative dependency extension CONSUMES them and materialises the Smartscape topology. Build and sign both, deploy both to the same ActiveGate. Deploying only the consumer gives you an empty topology page with nothing to blame." />
              {cur.link ? <button onClick={() => nav(cur.link!.to)} style={{ ...ghostBtn, marginTop: 4 }}>{cur.link.label}</button> : null}
            </>
          ) : cur.id === "netbox" ? (
            <>
              <ExtensionDownload bundleKeys={["netbox-extension", "network-dependency-extension"]}
                intro="Two extensions, deployed together: the NetBox source (reads devices + cables → cno.inv/dep) and the declarative dependency extension (maps those edges into Topology). They replace the on-prem bridge scripts." />
              <NetboxApplyDownload />
            </>
          ) : cur.id === "netflow" ? (
            <>
              <NetflowModeSetup />
              {cur.link ? <button onClick={() => nav(cur.link!.to)} style={{ ...ghostBtn, marginTop: 4 }}>{cur.link.label}</button> : null}
            </>
          ) : cur.id === "oxidized" ? (
            <>
              <ExtensionDownload bundleKeys={["oxidized-extension"]}
                intro="The Dynatrace-facing half of the config loop: reads the running-configs Oxidized archives, evaluates ISO-27001 controls + drift, and ships them as logs. Oxidized itself (or your existing NCM) stays where it is." />
              {cur.link ? <button onClick={() => nav(cur.link!.to)} style={{ ...ghostBtn, marginTop: 4 }}>{cur.link.label}</button> : null}
            </>
          ) : cur.link ? (
            <button onClick={() => nav(cur.link!.to)} style={ghostBtn}>{cur.link.label}</button>
          ) : null}
        </Flex>
      </Panel>
      ) : null}

    </Flex>
  );
};


/* ── what is switched on and producing nothing ──────────────────────────────
   Found independently on TWO tenants: cno.power.pdu.* has had zero datapoints for 30 days in this
   lab, and a customer's bespoke ServerTech extension — enabled, configured, iterated all the way to
   v0.0.17 — currently has zero entities across all ten of its types. Neither tenant said a word.

   An operator turns a capability on, gets silence, and cannot distinguish "I have no PDU" from
   "the OIDs are wrong for my model" from "the feature set never actually took". Identical symptom,
   and two of the three are faults.

   QUIET IS NOT REPORTED AS BROKEN. Most fleets legitimately have no PDU, and almost none expose CPU
   over SNMP. So this states what is quiet and why it might be, then leaves the judgement to whoever
   knows the estate — calling it an error would be the same overreach in the other direction. */
function CapabilityPanel() {
  const { rows, isLoading, error } = useCapabilitySignals();
  const quiet = rows.filter((r) => r.datapoints === 0);
  const flowing = rows.filter((r) => r.datapoints > 0);
  const pill = (on: boolean): React.CSSProperties => ({
    display: "inline-flex", alignItems: "center", gap: 7, borderRadius: 20, padding: "4px 11px",
    fontSize: 12.5, fontWeight: on ? 600 : 400,
    border: `1px solid ${on ? t.up : t.border}`, background: on ? t.upBg : "transparent", color: on ? t.up : t.subtle,
  });
  return (
    <Panel title="Collecting now" tag={<span style={{ fontSize: 12, color: t.subtle }}>last 6h</span>}>
      {error ? <QueryErr label="capability signals" />
       : isLoading ? <Text style={{ color: t.subtle }}>Loading…</Text> : (
        <>
          <Flex gap={8} flexWrap="wrap" style={{ marginBottom: quiet.length ? 12 : 0 }}>
            {flowing.map((r) => (
              <span key={r.id} style={pill(true)} title={`${r.datapoints.toLocaleString()} datapoints`}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: t.up }} />{r.label}
              </span>
            ))}
            {quiet.map((r) => (
              <span key={r.id} style={pill(false)}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: t.subtle }} />{r.label}
              </span>
            ))}
          </Flex>
          {quiet.length > 0 && (
            <Flex flexDirection="column" gap={6}>
              <Text style={{ fontSize: 13, color: t.subtle }}>
                <strong style={{ color: t.ink }}>{quiet.length} {quiet.length === 1 ? "capability is" : "capabilities are"} quiet.</strong>{" "}
                Not automatically a fault — but if you switched one on and expected data, this is where to look.
              </Text>
              {quiet.map((r) => (
                <Text key={r.id} style={{ fontSize: 12.5, color: t.subtle }}>
                  <strong style={{ color: t.ink }}>{r.label}</strong> — {r.hint}
                </Text>
              ))}
            </Flex>
          )}
        </>
      )}
    </Panel>
  );
}
