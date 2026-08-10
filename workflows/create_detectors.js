// dtctl exec function — runs in AppEngine context with the user's OAuth.
// Creates the CNO Davis anomaly detectors from deploy/alerting/detectors.json.
// The settings API requires OAuth (not an Api-Token: it rejects with
// "request was not done using oAuth"). Run with:
//   dtctl exec function -f create_detectors.js --data @detectors.json --context <ctx>
//
// IDEMPOTENT: skips any detector whose title already exists, so re-running never
// stacks duplicates. (The earlier plain-POST version had no existence check — that
// is what produced the 9-for-4 duplicate set observed on the lab tenant.)
export default async function (payload) {
  const SCHEMA = "builtin:davis.anomaly-detectors";
  const want = Array.isArray(payload) ? payload : (payload?.detectors || []);
  if (!want.length) return { error: "no detectors in payload — pass --data @detectors.json" };

  // Titles that already exist on this tenant.
  const have = new Set();
  const cur = await fetch(
    `/platform/classic/environment-api/v2/settings/objects?schemaIds=${SCHEMA}&fields=value&pageSize=500`,
  );
  if (cur.ok) {
    const j = await cur.json();
    for (const o of (j.items || [])) if (o?.value?.title) have.add(o.value.title);
  }

  const todo = want.filter((d) => !have.has(d?.value?.title));
  const skipped = want.filter((d) => have.has(d?.value?.title)).map((d) => d?.value?.title);
  if (!todo.length) {
    return { created: 0, skipped: skipped.length, skippedTitles: skipped,
             note: "all detectors already present — nothing to do" };
  }

  const res = await fetch("/platform/classic/environment-api/v2/settings/objects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(todo),
  });
  const text = await res.text();
  return {
    status: res.status,
    created: res.ok ? todo.length : 0,
    createdTitles: todo.map((d) => d?.value?.title),
    skipped: skipped.length,
    skippedTitles: skipped,
    body: text.slice(0, 600),
  };
}
