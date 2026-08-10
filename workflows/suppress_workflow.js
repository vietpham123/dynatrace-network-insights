import { execution } from '@dynatrace-sdk/automation-utils';
import { eventsClient, EventIngestEventType } from '@dynatrace-sdk/client-classic-environment-v2';

// CNO Network Dependency Suppression v3 — graph from NetBox-declared edges (cno.dep.uses),
// with the storm defect fixed. v2 emitted against the broad type("network:device") selector
// with a title that varied by suppressed-count, so Davis could not dedup and opened a NEW
// problem every poll (29 duplicates observed 2026-07-23). v3:
//   * resolves each root's SPECIFIC entityId (from a 2h name->entity map that survives the
//     outage) and targets entityId("CUSTOM_DEVICE-..") — the event lands ON the root device;
//   * uses a STABLE title per root ("Network root cause: X down") — suppression detail moves
//     to properties, which update the open problem instead of forking a new one;
//   * timeout tuned just above the poll interval so re-posting RENEWS one problem and it
//     auto-resolves ~timeout after recovery.
// Three DQL results in: reach (who answers), edges (the graph), entities (name->entityId).

export default async function ({ executionId }) {
  const ex = await execution(executionId);
  const reach = await ex.result('reach');
  const edgesR = await ex.result('edges');
  const entsR = await ex.result('entities');

  const ROSTER = ['lab-9300-1-1','lab-9300-1-2','lab-access-1','lab-sdwan-8200-1',
    'lab-sdwan-8200-2','lab-console-1','lab-pdu-1','lab-ups-1','lab-ap-01','lab-ap-02'];
  const norm = s => String(s || '').toLowerCase();

  // name -> entityId (2h window so a currently-down device still resolves from pre-outage data)
  const entOf = {};
  for (const r of (entsR.records || [])) {
    const d = norm(r['device']); if (d && r['entityId']) entOf[d] = r['entityId'];
  }

  const dev = {};
  for (const d of ROSTER) dev[d] = { up: new Set(), entityId: entOf[d] || null, isUp: false };
  const answering = new Set();
  for (const r of (reach.records || [])) {
    const d = norm(r['device']);
    if (!dev[d]) continue;
    if (r['is_up'] === 1 || r['is_up'] === '1' || r['is_up'] === true) answering.add(d);
  }
  for (const d of ROSTER) dev[d].isUp = answering.has(d);
  for (const r of (edgesR.records || [])) {
    const d = norm(r['downstream']); const u = norm(r['upstream']);
    if (!d || !u) continue;
    dev[d] = dev[d] || { up: new Set(), entityId: entOf[d] || null, isUp: true };
    dev[u] = dev[u] || { up: new Set(), entityId: entOf[u] || null, isUp: true };
    dev[d].up.add(u);
  }

  const isDown = d => dev[d] && dev[d].isUp === false;
  const roots = [], suppressed = [];
  for (const [d, n] of Object.entries(dev)) {
    if (!isDown(d)) continue;
    const anyUpstreamDown = [...n.up].some(u => isDown(u));
    if (anyUpstreamDown) suppressed.push(d); else roots.push(d);
  }

  const descendantsOf = root => {
    const out = new Set(); const stack = [root];
    while (stack.length) {
      const cur = stack.pop();
      for (const [d, n] of Object.entries(dev))
        if (n.up.has(cur) && !out.has(d)) { out.add(d); stack.push(d); }
    }
    return [...out].filter(isDown);
  };

  const results = [];
  for (const root of roots) {
    const kids = descendantsOf(root);
    const entityId = dev[root].entityId;
    const title = `Network root cause: ${root} down`;   // STABLE per root (dedup key)
    const props = {
      'event.description': `${root} is the causal failure (graph source: NetBox declared edges). ` +
        `Suppressed downstream symptoms: ${kids.join(', ') || '(none)'}.`,
      'cno.root_cause': root,
      'cno.suppressed': kids.join(',') || '(none)',
      'cno.suppressed_count': String(kids.length),
      'dt.event.group_label': `cno-root-cause-${root}`,   // stable correlation hint
    };
    Object.keys(props).forEach(k => { if (!props[k]) delete props[k]; });
    try {
      await eventsClient.createEvent({
        body: {
          eventType: EventIngestEventType.AvailabilityEvent,
          title,
          // target the SPECIFIC root device; fall back only if entity unresolved
          entitySelector: entityId ? `entityId("${entityId}")` : `type("network:device")`,
          timeout: 8,   // > 3-min poll -> re-post renews ONE problem; auto-resolves ~8m after recovery
          properties: props,
        },
      });
      results.push({ root, suppressed: kids, entityId: entityId || '(unresolved)' });
    } catch (e) {
      results.push({ root, error: String(e) });
    }
  }
  return { downCount: Object.values(dev).filter(n => n.isUp === false).length,
           roots, suppressed, emitted: results };
}
