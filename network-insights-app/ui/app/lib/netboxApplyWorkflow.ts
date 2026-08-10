// Clean, importable "CNO - Apply to Dynatrace (reconcile from NetBox intent)" workflow — the
// NetBox->Dynatrace provisioning baseline. Reads the declared roster from Grail (cno.inv.device,
// landed by the on-prem NetBox->Grail bridge) and makes Dynatrace reachability monitoring match.
// WRITES DYNATRACE ONLY (never NetBox). PREREQ: the NetBox->Grail bridge. Disabled by default;
// download-to-import (the app can't install workflows). Regenerate from the live workflow after edits.
export const NETBOX_APPLY_WORKFLOW: any = {
  "title": "CNO - Apply to Dynatrace (reconcile from NetBox intent)",
  "description": "Button 1 / read-only-to-NetBox. Reads the declared device roster from Grail (cno.inv.device, landed by the on-prem NetBox->Grail bridge) and makes Dynatrace's reachability monitoring match: creates monitors for new active devices, removes them for decommissioned ones. WRITES DYNATRACE ONLY \u2014 never touches NetBox.",
  "isPrivate": false,
  "tasks": {
    "intent": {
      "action": "dynatrace.automations:execute-dql-query",
      "conditions": {},
      "input": {
        "query": "timeseries act=avg(cno.inv.device), by:{`device.name`,`device.address`,`device.role`}, from:-15m, interval:1m | fieldsAdd active=arrayLast(act) | filter isNotNull(active) | fields name=`device.name`, address=`device.address`, role=`device.role`, active"
      },
      "name": "intent",
      "position": {
        "x": 0,
        "y": 1
      }
    },
    "reconcile": {
      "action": "dynatrace.automations:run-javascript",
      "conditions": {
        "states": {
          "intent": "OK"
        }
      },
      "input": {
        "script": "import { execution } from '@dynatrace-sdk/automation-utils';\nimport { businessEventsClient } from '@dynatrace-sdk/client-classic-environment-v2';\n\n// CNO \u2014 Apply to Dynatrace (reconcile from NetBox intent). WRITES DYNATRACE ONLY,\n// never NetBox. This is \"Button 1\": operator edits NetBox, clicks Apply, Dynatrace\n// self-configures its reachability monitoring to match the declared intent.\n//\n// Reads the intent roster from Grail (cno.inv.device \u2014 landed by the on-prem\n// NetBox->Grail bridge, so the workflow never reaches back to private NetBox):\n//   intended-active device with NO reachability monitor -> CREATE it\n//   monitor for a device NetBox marks 'decommissioned'   -> DELETE it\n//   monitor whose device vanished from intent entirely   -> report only (safe;\n//     a transient bridge gap must not delete real monitoring)\n// Every op is wrapped: a scope/permission failure is REPORTED, never thrown, so the\n// run completes and the summary event still fires.\n\nconst API = '/platform/classic/environment-api/v2/synthetic/monitors';\nconst LOCATIONS_API = '/platform/classic/environment-api/v1/synthetic/locations';\nlet LOCATION = null;   // resolved from THIS tenant at runtime - never a hardcoded id\nconst PREFIX = 'Reachability ';\n\nfunction monitorBody(name, ip) {\n  return {\n    name: PREFIX + name, type: 'MULTI_PROTOCOL', frequencyMin: 1,\n    locations: [LOCATION], enabled: true,\n    steps: [{\n      requestType: 'ICMP', targetList: [ip], properties: {},\n      constraints: [{ type: 'SUCCESS_RATE_PERCENT', properties: { value: '100', operator: '>=' } }],\n      requestConfigurations: [{ constraints: [{ type: 'ICMP_SUCCESS_RATE_PERCENT', properties: { value: '100', operator: '>=' } }] }],\n      name: 'ping ' + name,\n    }],\n    syntheticMonitorOutageHandlingSettings: { globalOutages: true, localOutages: false, globalConsecutiveOutageCountThreshold: 1, origin: 'DEFAULT' },\n    tags: [],\n  };\n}\n\nasync function api(path, opts) {\n  const res = await fetch(path, opts);\n  const txt = await res.text();\n  if (!res.ok) throw new Error(`${(opts && opts.method) || 'GET'} ${res.status}: ${txt.slice(0, 180)}`);\n  return txt ? JSON.parse(txt) : {};\n}\n\n// Resolve a synthetic location from THIS tenant. ICMP MULTI_PROTOCOL monitors need a\n// PRIVATE location (an ActiveGate running the synthetic module). This used to be a\n// hardcoded lab id, which silently failed on every other tenant.\nasync function resolveLocation() {\n  const list = await api(LOCATIONS_API, { method: 'GET' });\n  const all = list.locations || [];\n  const priv = all.filter((l) => l.type === 'PRIVATE' && (l.status || 'ENABLED') === 'ENABLED');\n  if (!priv.length) throw new Error('no ENABLED PRIVATE synthetic location on this tenant (saw ' + all.length + ' total); ICMP reachability needs an ActiveGate with the synthetic module');\n  return priv[0].entityId;\n}\n\nexport default async function ({ executionId }) {\n  const ex = await execution(executionId);\n  const intent = await ex.result('intent');\n  const rows = (intent.records || []).filter((r) => (r.role || '') !== 'server');\n\n  const created = [], deleted = [], inSync = [], wouldRemove = [], errors = [];\n\n  // Resolve up front. On failure REPORT and skip creates rather than POSTing monitors\n  // that reference a location this tenant does not have.\n  try { LOCATION = await resolveLocation(); }\n  catch (e) { errors.push('resolve synthetic location: ' + e.message); }\n\n  // current reachability monitors: deviceName -> monitorId\n  let byName = {};\n  try {\n    const list = await api(API + '?pageSize=1000', { method: 'GET' });\n    for (const m of (list.monitors || list.items || [])) {\n      const nm = m.name || '';\n      if (nm.startsWith(PREFIX)) byName[nm.slice(PREFIX.length)] = m.entityId || m.monitorId || m.id;\n    }\n  } catch (e) { errors.push(`list monitors: ${e.message}`); }\n\n  const intended = new Set();\n  for (const r of rows) {\n    const name = r.name, ip = r.address;\n    const active = Number(r.active) > 0.5;   // latest NetBox status: 1=active, 0=decommissioned\n    if (active) {\n      intended.add(name);\n      if (byName[name]) { inSync.push(name); continue; }\n      if (!LOCATION) { errors.push('skip create ' + name + ': no synthetic location resolved'); continue; }\n      try { await api(API, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(monitorBody(name, ip)) }); created.push(name); }\n      catch (e) { errors.push(`create ${name}: ${e.message}`); }\n    } else if (byName[name]) {\n      try { await api(API + '/' + byName[name], { method: 'DELETE' }); deleted.push(name); }\n      catch (e) { errors.push(`delete ${name}: ${e.message}`); }\n    }\n  }\n  for (const nm of Object.keys(byName)) if (!rows.find((r) => r.name === nm)) wouldRemove.push(nm);\n\n  // summary as a bizevent (businessEventsClient is proven; auditable in Grail:\n  //   fetch bizevents | filter event.type == \"cno.reconcile\")\n  try {\n    await businessEventsClient.ingest({\n      type: 'application/cloudevent+json',\n      body: {\n        specversion: '1.0', id: `cno-reconcile-${Date.now()}`,\n        source: 'cno-apply-to-dynatrace', type: 'cno.reconcile',\n        data: {\n          'cno.reconcile.created': created.join(',') || '(none)',\n          'cno.reconcile.deleted': deleted.join(',') || '(none)',\n          'cno.reconcile.in_sync_count': inSync.length,\n          'cno.reconcile.would_remove': wouldRemove.join(',') || '(none)',\n          'cno.reconcile.errors': errors.join(' | ') || '(none)',\n          'cno.reconcile.source': 'netbox-intent (writes Dynatrace only)',\n        },\n      },\n    });\n  } catch (e) { errors.push(`bizevent: ${e.message}`); }\n\n  return { created, deleted, in_sync: inSync, would_remove_report_only: wouldRemove, errors };\n}\n"
      },
      "name": "reconcile",
      "position": {
        "x": 0,
        "y": 2
      },
      "predecessors": [
        "intent"
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
        "intervalMinutes": 60,
        "type": "interval"
      }
    }
  }
};
