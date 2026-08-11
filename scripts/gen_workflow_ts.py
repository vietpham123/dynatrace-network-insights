#!/usr/bin/env python3
"""
Generate the app's TypeScript workflow constant from the canonical JSON.

WHY THIS EXISTS
    The app ships a copy of the RCA workflow so the Configuration page can offer to deploy it.
    That copy used to be hand-maintained, with a "KEEP IN SYNC" comment as the only mechanism.

    It drifted. Measured 2026-08-10: four of six tasks differed between the TypeScript and the
    JSON — classify, edges, entities and reach — while emit and evidence happened to match. The
    JSON matched what was actually running on the tenant, so the app had been offering to deploy
    a workflow that was not the one in production.

    A comment is not a mechanism. This is: one source, generated output, and a diff in CI if
    anyone edits the generated file by hand.

USAGE
    python3 scripts/gen_workflow_ts.py            # regenerate
    python3 scripts/gen_workflow_ts.py --check    # exit 1 if the TS is stale (for CI)

    Run it after editing workflows/network_rca_workflow.json. Never edit the .ts directly.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "workflows", "network_rca_workflow.json")
APP_CFG = os.path.join(ROOT, "network-insights-app", "app.config.json")
OUT = os.path.join(ROOT, "network-insights-app", "ui", "app", "lib", "networkRcaWorkflow.ts")

HEADER = """// GENERATED FILE — DO NOT EDIT BY HAND.
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
"""


def build() -> str:
    with open(SRC) as fh:
        wf = json.load(fh)
    wf = wf if "tasks" in wf else wf.get("workflow", wf)

    # Strip server-assigned state. It describes a particular deployment, not the definition, and
    # shipping it invites the app to overwrite someone's schedule or claim an id that is not theirs.
    for k in ("id", "owner", "actor", "ownerType", "isDeployed", "version", "modificationInfo"):
        wf.pop(k, None)
    sched = (wf.get("trigger") or {}).get("schedule")
    if sched:
        for k in ("nextExecution", "isFaulty"):
            sched.pop(k, None)
        # Ships disabled. Enabling it is the operator's decision, and an app install should not
        # silently start creating problem cards on a tenant.
        sched["isActive"] = False

    # STAMP THE PROVENANCE. The workflow definition carries no version of its own, so a customer
    # who downloaded it had no way to tell which revision they were holding — and it changed three
    # times on 2026-08-11 alone. It is versioned WITH the app, because that is what ships it, so
    # the app version is the honest identifier. Rendered next to the download button, and written
    # into the description so it survives into the tenant even when the file is passed around.
    with open(APP_CFG) as fh:
        app_version = json.load(fh)["app"]["version"]
    wf["description"] = f"{wf.get('description','').rstrip()} [Network Insights v{app_version}]"

    body = json.dumps(wf, indent=2, ensure_ascii=False)
    return (f"{HEADER}export const NETWORK_RCA_WORKFLOW_VERSION = \"{app_version}\";\n\n"
            f"export const NETWORK_RCA_WORKFLOW: any = {body};\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if the generated file is stale")
    a = ap.parse_args()

    want = build()
    have = open(OUT).read() if os.path.exists(OUT) else ""

    if a.check:
        if want != have:
            print("STALE: networkRcaWorkflow.ts does not match workflows/network_rca_workflow.json")
            print("       run: python3 scripts/gen_workflow_ts.py")
            sys.exit(1)
        print("networkRcaWorkflow.ts is in sync with the JSON")
        return

    with open(OUT, "w") as fh:
        fh.write(want)
    print(f"wrote {os.path.relpath(OUT, ROOT)} ({len(want)} bytes)")


if __name__ == "__main__":
    main()
