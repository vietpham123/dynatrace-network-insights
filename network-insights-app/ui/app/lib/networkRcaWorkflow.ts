// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: workflows/network_rca_workflow.json
// Regenerate: python3 scripts/gen_workflow_ts.py
//
// The unified network-RCA workflow the Configuration page offers to deploy. One classify pass
// routes each device: not reporting SNMP -> chain RCA (graph root, suppress downstream,
// power-domain aware); reporting but with ports that WENT down -> interface RCA.
//
// This was hand-maintained against a "keep in sync" comment until 2026-08-10, at which point four
// of its six tasks had drifted from the JSON — so the app offered a workflow that was not the one
// running on the tenant. Hence the generator.
export const NETWORK_RCA_WORKFLOW_VERSION = "1.3.0";

export const NETWORK_RCA_WORKFLOW: any = {
  "title": "CNO - Network RCA",
  "description": "Unified deterministic network reasoner. One classify pass routes each device: not reporting SNMP -> chain RCA (graph root + suppress downstream, power-domain aware); reporting but with admin-enabled interfaces oper-down -> interface RCA (one consolidated card, disabled ports excluded, no storm). Stable titles + entityId targeting so Davis renews one problem each; Davis CoPilot adds a narrative. Replaces the separate device (dependency-suppression) and interface (degradation) workflows. [Network Insights v1.3.0]",
  "isPrivate": false,
  "tasks": {
    "reach": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "timeseries upt=count(cno.device.uptime), by:{sys_name, `device.address`}, from:-2m | fields device=if(isNotNull(sys_name) and sys_name != \"n/a\" and sys_name != \"\", lower(sys_name), else: `device.address`), n=arraySum(upt) | append [ timeseries seen=count(cno.if.oper_status), by:{sys_name, `device.address`}, from:-2m | fields device=if(isNotNull(sys_name) and sys_name != \"n/a\" and sys_name != \"\", lower(sys_name), else: `device.address`), n=arraySum(seen) ] | summarize n=sum(n), by:{device} | fieldsAdd is_up=if(n>0,1,else:0) | fields device, is_up"
      },
      "name": "reach",
      "position": {
        "x": 0,
        "y": 1
      }
    },
    "edges": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "timeseries e=count(cno.dep.uses), by:{`device.name`, `device.address`, `upstream.name`, `upstream.address`, link_type, discovery}, from:-2h | fieldsAdd n=arraySum(e) | filter n>0 | fields a=if(isNotNull(`device.name`) and `device.name` != \"n/a\" and `device.name` != \"\", lower(`device.name`), else: `device.address`), b=if(isNotNull(`upstream.name`) and `upstream.name` != \"n/a\" and `upstream.name` != \"\", lower(`upstream.name`), else: `upstream.address`), link_type, discovery | lookup [ timeseries r=count(cno.inv.device), by:{`device.name`, `device.role`}, from:-2h | fieldsAdd rn=arraySum(r) | filter rn>0 | fields dn=lower(`device.name`), role=`device.role` ], sourceField:a, lookupField:dn, prefix:\"ra_\" | lookup [ timeseries r=count(cno.inv.device), by:{`device.name`, `device.role`}, from:-2h | fieldsAdd rn=arraySum(r) | filter rn>0 | fields dn=lower(`device.name`), role=`device.role` ], sourceField:b, lookupField:dn, prefix:\"rb_\" | fieldsAdd rank_a = if(ra_role==\"wan-edge\",6, else: if(ra_role==\"sdwan\",6, else: if(ra_role==\"spine\",5, else: if(ra_role==\"core\",5, else: if(ra_role==\"leaf\",3, else: if(ra_role==\"access\",3, else: if(ra_role==\"ap\",1, else: 0))))))), rank_b = if(rb_role==\"wan-edge\",6, else: if(rb_role==\"sdwan\",6, else: if(rb_role==\"spine\",5, else: if(rb_role==\"core\",5, else: if(rb_role==\"leaf\",3, else: if(rb_role==\"access\",3, else: if(rb_role==\"ap\",1, else: 0))))))) | filter not (link_type==\"data\" and rank_a == rank_b and rank_a > 0) | fieldsAdd flip = if(link_type==\"data\" and rank_a > rank_b, true, else: false) | fields downstream = if(flip, b, else: a), upstream = if(flip, a, else: b), link_type, discovery | dedup {downstream, upstream, link_type, discovery}"
      },
      "name": "edges",
      "position": {
        "x": 1,
        "y": 1
      }
    },
    "entities": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "timeseries upt=count(cno.device.uptime), by:{sys_name, `device.address`, `dt.entity.network:device`}, from:-2h | fields device=if(isNotNull(sys_name) and sys_name != \"n/a\" and sys_name != \"\", lower(sys_name), else: `device.address`), entityId=`dt.entity.network:device`, n=arraySum(upt) | append [ timeseries seen=count(cno.if.oper_status), by:{sys_name, `device.address`, `dt.entity.network:device`}, from:-2h | fields device=if(isNotNull(sys_name) and sys_name != \"n/a\" and sys_name != \"\", lower(sys_name), else: `device.address`), entityId=`dt.entity.network:device`, n=arraySum(seen) ] | summarize n=sum(n), by:{device, entityId} | filter n>0 | dedup device"
      },
      "name": "entities",
      "position": {
        "x": 2,
        "y": 1
      }
    },
    "classify": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "timeseries o = min(cno.if.oper_status), a = max(cno.if.admin_status), by:{sys_name, `device.address`, if_descr}, from:-24h, interval:1m | fieldsAdd oc = arrayRemoveNulls(o), ac = arrayRemoveNulls(a) | filter arraySize(oc) > 0 and arrayLast(ac) == 1 | fieldsAdd last = arrayLast(oc), everUp = arrayMin(oc), device = if(isNotNull(sys_name) and sys_name != \"n/a\" and sys_name != \"\", lower(sys_name), else: `device.address`) | summarize down_list = collectArray(if(last == 2 and everUp == 1, if_descr)), up = countIf(last == 1), down = countIf(last == 2 and everUp == 1), by:{device} | fieldsAdd down_list = arrayRemoveNulls(down_list) | filter up > 0 and down > 0 | sort down desc"
      },
      "name": "classify",
      "position": {
        "x": 3,
        "y": 1
      }
    },
    "evidence": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "fetch logs, from:-45m | filter `log.source` == \"network.config\" or `log.source` == \"cisco.syslog\" | sort timestamp desc | fields ts=formatTimestamp(timestamp, format:\"HH:mm:ss\"), src=`log.source`, dev=lower(`host.name`), msg=substring(content, from:0, to:150) | limit 40"
      },
      "name": "evidence",
      "position": {
        "x": 4,
        "y": 1
      }
    },
    "emit": {
      "action": "dynatrace.automations:run-javascript",
      "conditions": {
        "states": {
          "reach": "OK",
          "edges": "OK",
          "entities": "OK",
          "classify": "OK",
          "evidence": "OK"
        }
      },
      "input": {
        "script": "import { execution } from '@dynatrace-sdk/automation-utils';\nimport { eventsClient, EventIngestEventType } from '@dynatrace-sdk/client-classic-environment-v2';\nimport { httpClient } from '@dynatrace-sdk/http-client';\n\n// CNO Network RCA — one deterministic reasoner. A single pass routes every device:\n//   * NOT reporting SNMP (device down)                  -> chain RCA: graph root + suppress downstream\n//     symptoms; ONE card per root (power-domain / WAN-isolation / device-failure).\n//   * reporting but admin-ENABLED interfaces oper-down  -> interface RCA: ONE consolidated\n//     \"Interface degradation\" card (disabled ports excluded; no per-interface storm).\n// A down device has no interface data, so no device is in both lanes. Stable titles + entityId\n// targeting + timeout:8 renew one problem each. Davis CoPilot adds a best-effort narrative.\nexport default async function ({ executionId }) {\n  const ex = await execution(executionId);\n  const reach = await ex.result('reach');\n  const edgesR = await ex.result('edges');\n  const entsR = await ex.result('entities');\n  const evR = await ex.result('evidence');\n  const clsR = await ex.result('classify');\n  const norm = s => String(s || '').toLowerCase();\n\n  const entOf = {};\n  for (const r of (entsR.records || [])) { const d = norm(r['device']); if (d && r['entityId']) entOf[d] = r['entityId']; }\n\n  // Deterministic narrative is ALWAYS written first (so the card always has a readable story);\n  // Davis CoPilot then enriches it best-effort. CoPilot returns 403 on tenants where it isn't\n  // enabled/authorized — the deterministic narrative stands, and CoPilot auto-activates if enabled.\n  const narrate = async (prompt, deterministic, props) => {\n    props['cno.rca_narrative'] = deterministic;\n    try {\n      const _r = await httpClient.send({ url: '/platform/davis/copilot/v1/skills/conversations:message', method: 'POST', body: { text: prompt, context: [] }, headers: { 'Content-Type': 'application/json' } });\n      if (_r.status < 300) { const _b = await _r.body('json'); const _t = _b && _b.text; if (_t) { props['cno.rca_narrative'] = 'Davis CoPilot: ' + String(_t).slice(0, 1180); props['event.description'] = 'Davis CoPilot - ' + String(_t).replace(/\\n/g, ' ').slice(0, 460) + ' || ' + props['event.description']; } }\n    } catch (e) { /* best-effort; deterministic narrative stands */ }\n  };\n  const emit = async (title, entityId, props) => {\n    Object.keys(props).forEach(k => { if (!props[k]) delete props[k]; });\n    try { await eventsClient.createEvent({ body: { eventType: EventIngestEventType.AvailabilityEvent, title, entitySelector: entityId ? `entityId(\"${entityId}\")` : `type(\"network:device\")`, timeout: 8, properties: props } }); return true; }\n    catch (e) { return String(e); }\n  };\n\n  const out = { downDevices: 0, deviceRoots: [], interfaceDegraded: [] };\n\n  // ===== LANE B — device / chain RCA =====\n  const dev = {};\n  const edgeSrc = {};\n  const SRC_NAMES = { lldp: 'LLDP neighbour discovery', netbox: 'NetBox declared cabling',\n                      api: 'controller API', manual: 'manual assignment' };\n  for (const d of Object.keys(entOf)) dev[d] = { up: new Set(), powerUp: new Set(), entityId: entOf[d] || null, isUp: false };\n  const answering = new Set();\n  for (const r of (reach.records || [])) { const d = norm(r['device']); if (!dev[d]) continue; if (r['is_up'] === 1 || r['is_up'] === '1' || r['is_up'] === true) answering.add(d); }\n  for (const d of Object.keys(dev)) dev[d].isUp = answering.has(d);\n  for (const r of (edgesR.records || [])) {\n    const d = norm(r['downstream']); const u = norm(r['upstream']); if (!d || !u) continue;\n    dev[d] = dev[d] || { up: new Set(), powerUp: new Set(), entityId: entOf[d] || null, isUp: true };\n    dev[u] = dev[u] || { up: new Set(), powerUp: new Set(), entityId: entOf[u] || null, isUp: true };\n    dev[d].up.add(u);\n    // link_type was already selected by the edges query and then thrown away. A power edge\n    // is how we KNOW a failure is a power-domain failure, rather than guessing from a name.\n    if (String(r['link_type'] || '').toLowerCase() === 'power') dev[d].powerUp.add(u);\n    // PROVENANCE, NOT ASSUMPTION. The card used to claim \"graph source: NetBox declared\n    // edges\", hardcoded from when NetBox was the only device<->device source. It is not:\n    // data edges come from LLDP and NetBox supplies power. Record what each edge actually\n    // came from so the card can say so instead of guessing.\n    edgeSrc[`${d}|${u}`] = String(r['discovery'] || '').toLowerCase();\n  }\n  const isDown = d => dev[d] && dev[d].isUp === false;\n  out.downDevices = Object.values(dev).filter(n => n.isUp === false).length;\n  const roots = [];\n  for (const [d, n] of Object.entries(dev)) { if (!isDown(d)) continue; if (![...n.up].some(u => isDown(u))) roots.push(d); }\n  const descendantsOf = root => { const o = new Set(); const st = [root]; while (st.length) { const c = st.pop(); for (const [d, n] of Object.entries(dev)) if (n.up.has(c) && !o.has(d)) { o.add(d); st.push(d); } } return [...o].filter(isDown); };\n  for (const root of roots) {\n    const kids = descendantsOf(root);\n    const entityId = dev[root].entityId;\n    const _n = root.toLowerCase();\n    // CLASSIFY FROM THE GRAPH, NOT THE NAME. Devices that draw power from this root and are\n    // down make it a power-domain failure whatever the root is called. The hostname regexes\n    // remain only as a fallback for estates with no NetBox power cabling, and are the same\n    // naming-convention inference removed everywhere else (B1a) — a PDU called rack3-pwr-a\n    // was previously invisible to this check.\n    const _pwrVictims = Object.keys(dev).filter(k => dev[k].powerUp && dev[k].powerUp.has(root) && isDown(k));\n    const _srcs = [...new Set(kids.map(k => edgeSrc[`${k}|${root}`]).filter(Boolean))].sort();\n    // Friendly names for sources we know; ANY other value passes through unchanged, so a\n    // customer emitting discovery=\"servicenow\" or \"manual\" is described correctly with no\n    // code change. Nothing here decides which sources may exist.\n    const _srcLabel = _srcs.length\n      ? _srcs.map(s => SRC_NAMES[s] || s).join(' + ')\n      : 'no declared edges';\n    const _fault = _pwrVictims.length ? 'power-domain' : /pdu|ups/.test(_n) ? 'power-domain' : /sdwan|8200/.test(_n) ? 'wan-isolation' : 'device-failure';\n    const title = _fault === 'power-domain' ? `Power domain failure: ${root}` : _fault === 'wan-isolation' ? `Site isolated: WAN edge ${root} down` : `Device failure: ${root} down`;\n    const props = { 'event.description': `${root} is the causal failure (graph source: ${_srcLabel}). Suppressed downstream symptoms: ${kids.join(', ') || '(none)'}.`, 'cno.root_cause': root, 'cno.fault_type': _fault, 'cno.blast_radius': String(kids.length), 'cno.power_victims': String(_pwrVictims.length), 'cno.fault_evidence': _pwrVictims.length ? 'power edge (NetBox cabling)' : 'name heuristic', 'cno.suppressed': kids.join(',') || '(none)', 'cno.suppressed_count': String(kids.length), 'dt.event.group_label': `cno-root-cause-${root}` };\n    const _aff = new Set([root, ...kids].map(x => norm(x)));\n    const _chg = (evR.records || []).filter(r => r['src'] === 'network.config').slice(0, 6).map(r => `${r['ts']} config change on ${r['dev']}: ${r['msg']}`);\n    const _log = (evR.records || []).filter(r => r['src'] === 'cisco.syslog' && _aff.has(norm(r['dev']))).slice(0, 6).map(r => `${r['ts']} syslog ${r['dev']}: ${r['msg']}`);\n    const _ev = _chg.concat(_log).join('\\n');\n    const _det = `${root} (${_fault.replace(/-/g, ' ')}) is the root cause and is down` + (kids.length ? `, taking ${kids.length} downstream device(s) with it: ${kids.join(', ')}.` : ' with no downstream impact.') + (_chg.length ? ` A recent config change may be related (${_chg[0]}).` : '') + ` First check: ${_fault === 'power-domain' ? 'the PDU/UPS power feed to ' + root : _fault === 'wan-isolation' ? 'the WAN uplink at ' + root : 'reachability + recent changes on ' + root}.`;\n    await narrate(`Network NOC incident. Root cause: ${root} (fault type: ${_fault}) is DOWN. Blast radius: ${kids.length} downstream device(s) unreachable${kids.length ? ' - ' + kids.join(', ') : ''}.` + (_ev ? `\\n\\nRecent evidence (config changes + syslog from affected devices):\\n${_ev}` : '') + `\\n\\nIn 2-4 sentences: the root cause, the impact, whether a recent config change likely contributed, and one recommended first action.`, _det, props);\n    const r = await emit(title, entityId, props);\n    out.deviceRoots.push({ root, suppressed: kids, ok: r === true, err: r === true ? undefined : r });\n  }\n\n  // ===== LANE A — interface RCA (only for UP devices; down devices handled above) =====\n  for (const r of (clsR.records || [])) {\n    const device = norm(r['device']);\n    const down = Number(r['down'] || 0); const up = Number(r['up'] || 0);\n    const list = Array.isArray(r['down_list']) ? r['down_list'] : [];\n    if (!device || down < 1 || isDown(device)) continue;\n    const entityId = entOf[device] || null;\n    const title = `Interface degradation on ${device}`;\n    const props = { 'event.description': `${device} is UP but ${down} admin-enabled interface(s) are operationally down: ${list.join(', ') || '(unnamed)'}. ${up} enabled interface(s) still up. Disabled/admin-down ports excluded. Device reachable — no device-level outage.`, 'cno.device': device, 'cno.iface_down_count': String(down), 'cno.iface_down_list': list.join(',') || '(unnamed)', 'cno.iface_up_count': String(up), 'cno.severity_hint': down >= 3 ? 'high' : 'low', 'dt.event.group_label': `cno-iface-degradation-${device}` };\n    const _chg = (evR.records || []).filter(r2 => r2['src'] === 'network.config' && norm(r2['dev']) === device).slice(0, 6).map(r2 => `${r2['ts']} config change: ${r2['msg']}`);\n    const _log = (evR.records || []).filter(r2 => r2['src'] === 'cisco.syslog' && norm(r2['dev']) === device).slice(0, 8).map(r2 => `${r2['ts']} syslog: ${r2['msg']}`);\n    const _ev = _chg.concat(_log).join('\\n');\n    const _idet = `${device} is reachable, but ${down} admin-enabled interface(s) are operationally down (${list.join(', ')}); ${up} remain up — a partial port/link issue, not a device outage.` + (_chg.length ? ` A recent config change may be related (${_chg[0]}).` : '') + ` First check: cabling / SFP / far-end on ${list[0] || 'the affected port'}.`;\n    await narrate(`Network interface degradation. Device ${device} is UP and reachable via SNMP, but ${down} admin-enabled interface(s) are operationally down: ${list.join(', ')}. ${up} interface(s) remain up — a PARTIAL failure, NOT a device outage.` + (_ev ? `\\n\\nEvidence from ${device}:\\n${_ev}` : '') + `\\n\\nIn 2-3 sentences: the most likely cause (cabling / SFP / far-end / local port config), whether a recent config change contributed, and one first action. The device is reachable — do NOT describe it as down.`, _idet, props);\n    const rr = await emit(title, entityId, props);\n    out.interfaceDegraded.push({ device, down, up, ok: rr === true, err: rr === true ? undefined : rr });\n  }\n\n  return out;\n}\n"
      },
      "name": "emit",
      "position": {
        "x": 0,
        "y": 2
      },
      "predecessors": [
        "reach",
        "edges",
        "entities",
        "classify",
        "evidence"
      ]
    }
  },
  "trigger": {
    "schedule": {
      "filterParameters": {},
      "inputs": {},
      "isActive": false,
      "rule": null,
      "timezone": "UTC",
      "trigger": {
        "intervalMinutes": 3,
        "type": "interval"
      }
    }
  }
};
