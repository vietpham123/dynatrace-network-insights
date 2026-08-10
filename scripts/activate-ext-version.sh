#!/usr/bin/env bash
# activate-ext-version.sh — bulk-activate an EF2.0 extension version in ONE call.
#
# WHY THIS EXISTS
#   In Extensions 2.0 the "active version" is a single ENVIRONMENT-WIDE setting
#   (the environmentConfiguration). Every monitoring configuration of that
#   extension runs at whatever version is active — so the number of monitoring
#   configs is irrelevant: one PUT moves all of them at once. This is the bulk
#   alternative to clicking "update" on each config in the UI.
#
# USAGE
#   DT_ENV_URL=https://wem8433h.sprint.dynatracelabs.com \
#   DT_EXT_WRITE_TOKEN=dt0c01.XXXX \
#   ./activate-ext-version.sh custom:cno.network.interfaces 0.0.9
#
# TOKEN
#   Needs a classic Api-Token (dt0c01) with scope: environment-api:extensions:write
#   NOTE: the *platform* upload token (dt0s16) that POSTs the extension bundle does
#   NOT carry this scope — it's a different scope family. Mint a classic token with
#   environment-api:extensions:write (+ :read to see the before-state).
#
# DOMAIN
#   The classic /api/v2 surface lives on the ENVIRONMENT domain
#   (…​.dynatracelabs.com), NOT the apps domain (…​.apps.dynatracelabs.com).
set -euo pipefail

ENV_URL="${DT_ENV_URL:?set DT_ENV_URL (env domain, e.g. https://wem8433h.sprint.dynatracelabs.com — NOT .apps)}"
NAME="${1:?arg1 = extension name, e.g. custom:cno.network.interfaces}"
VER="${2:?arg2 = version, e.g. 0.0.9}"
: "${DT_EXT_WRITE_TOKEN:?set DT_EXT_WRITE_TOKEN (Api-Token dt0c01 with environment-api:extensions:write)}"

# ── BREAKING-CHANGE GUARD ─────────────────────────────────────────────────────
# This script is the single command that moves every monitoring configuration at once, which
# makes it also the single command that can silently break every one of them. Activating
# custom:cno.network.interfaces >= 0.0.14 stops all pre-existing configs collecting cno.if.*,
# cno.device.cpu_usage/memory_* and cno.power.* — because 0.0.14 introduced feature sets and a
# stored "featureSets": [] is never re-derived. Those configs keep reporting status OK.
# The checklist lives in another file; this is what actually gets reached for, so the warning
# has to be here. Set CNO_MIGRATION_ACK=1 once the pre-flight snapshot in step 1 is captured.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
if [ "$NAME" = "custom:cno.network.interfaces" ] && ver_ge "$VER" "0.0.14" && [ "${CNO_MIGRATION_ACK:-}" != "1" ]; then
  cat >&2 <<'WARN'
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  STOP — custom:cno.network.interfaces >= 0.0.14 IS A MIGRATION, NOT AN UPGRADE.      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
0.0.14 makes each OID group an opt-in feature set. Feature sets are strictly ADDITIVE
opt-in and activation does NOT re-derive a stored configuration value, so EVERY existing
monitoring configuration keeps its empty "featureSets" and STOPS COLLECTING:
    cno.if.*      cno.device.cpu_usage / memory_used / memory_free      cno.power.*
...while still reporting status OK. The status field is NOT the test.

BEFORE activating, capture the per-gate pre-flight snapshot (one probe PER FEATURE SET):

  timeseries dp=count(cno.if.oper_status), count(cno.device.cpu_usage),
                count(cno.device.memory_used), count(cno.power.ups.charge_pct),
                count(cno.power.ups.battery_voltage), count(cno.power.pdu.load),
             by:{device.address}, from:-24h

Then PUT each configuration with its featureSets array, and DIFF that query afterwards.
Any family with data before and none after is a regression. Full procedure + the two
branches for PUT ordering:
  modules/snmp-interfaces-extension/extension/extension.yaml  (header)
  docs/DEPLOYMENT-CHECKLIST.md                                (Tier 1)

Re-run with CNO_MIGRATION_ACK=1 once that snapshot is captured.
WARN
  exit 3
fi

base="$ENV_URL/api/v2/extensions/$NAME/environmentConfiguration"
auth=(-H "Authorization: Api-Token $DT_EXT_WRITE_TOKEN")

echo "Active version BEFORE:"
curl -sf --http1.1 "$base" "${auth[@]}" || echo "  (no active version yet)"
echo
echo "Activating $NAME -> $VER  (every monitoring config follows this in one shot)…"
curl -s --http1.1 -X PUT "$base" "${auth[@]}" \
  -H "Content-Type: application/json" \
  -d "{\"version\":\"$VER\"}" -w "\n[HTTP %{http_code}]\n"
echo
echo "Active version AFTER:"
curl -sf --http1.1 "$base" "${auth[@]}" || true
