#!/usr/bin/env python3
"""
Check a tenant against the cno.* contract and say exactly which pages will render.

WHY THIS EXISTS
    Documentation tells you what to emit. It cannot tell you whether you got it right, and a
    metric that is present but missing one dimension fails in the least helpful way available:
    the data is in Grail, the query returns rows, and the page is empty.

    This closes that loop. Point it at a tenant and it reports, per tier, PASS or FAIL and the
    specific dimension that is missing — which means an AI agent extending this can iterate to
    green on its own instead of asking someone to look at a screen.

USAGE
    # what will render for everything reporting
    python3 scripts/verify_contract.py --context <dtctl-context>

    # one device
    python3 scripts/verify_contract.py --context <ctx> --device 10.1.1.1

    # no tenant needed — print the DQL it would run
    python3 scripts/verify_contract.py --print-queries

REQUIREMENTS
    dtctl, authenticated:  dtctl auth login --context <ctx>
    Browser SSO grants the platform scopes. API tokens cannot run DQL.
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT = os.path.join(ROOT, "docs", "contract.json")

WINDOW = "-30m"          # long enough for a 15-minute poll cycle to have landed twice
TOPOLOGY_WINDOW = "-2h"  # LLDP defaults to 900s and topology changes slowly

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = RESET = ""


def q(dim: str) -> str:
    """Backtick any dimension carrying a dot — DQL needs it, and forgetting is a silent parse error."""
    return f"`{dim}`" if "." in dim else dim


def build_query(metric: str, dims: list, device: str | None, window: str) -> str:
    """
    One query per requirement. Counts series, and separately counts series where a required
    dimension came back null — because "the metric exists" and "the metric carries the
    dimensions the app groups by" are different facts, and only the second one renders a page.
    """
    by = ", ".join(q(d) for d in dims)
    null_test = " or ".join(f"isNull({q(d)})" for d in dims)
    dev = f" | filter {q('device.address')} == \"{device}\"" if device else ""
    return (
        f"timeseries n=count({metric}), from:{window}, by:{{{by}}}"
        f"{dev}"
        f" | fieldsAdd points=arraySum(n)"
        f" | filter points > 0"
        f" | fieldsAdd incomplete=({null_test})"
        f" | summarize series=count(), missingDims=countIf(incomplete)"
    )


class AuthFailure(Exception):
    """
    Raised on the FIRST unusable-credential response rather than per metric. Without this the tool
    prints the same OAuth error twenty times — once per requirement — and buries the one line that
    tells you what to do. An expired token is a property of the session, not of cno.if.oper_status.
    """


AUTH_MARKERS = ("invalid_grant", "refresh token", "unauthorized", "401", "not authenticated", "auth login")


def run_dql(query: str, context: str | None) -> dict:
    cmd = ["dtctl", "query", query, "-o", "json"]
    if context:
        cmd += ["--context", context]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "dtctl failed").strip()
        if any(m in err.lower() for m in AUTH_MARKERS):
            raise AuthFailure(err)
        return {"_error": err[:300]}
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"_error": f"could not parse dtctl output: {p.stdout[:200]}"}
    # dtctl wraps results in an envelope in agent mode and returns a bare list otherwise.
    if isinstance(out, dict):
        if out.get("ok") is False:
            return {"_error": str(out.get("error"))[:300]}
        out = out.get("result", out.get("records", out))
    if isinstance(out, list):
        return out[0] if out else {}
    return out if isinstance(out, dict) else {}


def check(req: dict, device, context, window, print_only):
    metric, dims = req["metric"], req["dimensions"]
    query = build_query(metric, dims, device, window)
    if print_only:
        print(f"\n{DIM}# {metric}{RESET}\n{query}")
        return None
    r = run_dql(query, context)
    if "_error" in r:
        return {"metric": metric, "state": "error", "detail": r["_error"]}
    series = int(r.get("series") or 0)
    missing = int(r.get("missingDims") or 0)
    if series == 0:
        return {"metric": metric, "state": "absent",
                "detail": f"no data in the last {window.lstrip('-')}"}
    if missing:
        return {"metric": metric, "state": "partial",
                "detail": f"{series} series, but {missing} are missing one of: {', '.join(dims)}"}
    return {"metric": metric, "state": "ok", "detail": f"{series} series"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", help="dtctl context (omit to use the current one)")
    ap.add_argument("--device", help="restrict to one management address")
    ap.add_argument("--print-queries", action="store_true", help="print the DQL and exit — no tenant needed")
    args = ap.parse_args()

    with open(CONTRACT) as fh:
        contract = json.load(fh)

    print(f"\n  cno.* contract {contract['contractVersion']} — verified against app "
          f"{contract['verifiedAgainst']['app']}")
    if args.device:
        print(f"  device: {args.device}")
    print()

    satisfied, failed = [], []
    try:
        _run_tiers(contract, args, satisfied, failed)
    except AuthFailure as e:
        ctx = f" --context {args.context}" if args.context else ""
        print(f"  {RED}Not authenticated.{RESET} dtctl could not get a usable token.\n")
        print(f"    dtctl auth login{ctx}\n")
        print(f"{DIM}  Browser SSO grants the platform scopes needed to run DQL; API tokens cannot.\n"
              f"  Underlying error: {str(e)[:160]}…{RESET}\n")
        sys.exit(2)

    if args.print_queries:
        print()
        return

    print(f"  {len(satisfied)} of {len(contract['tiers'])} tiers satisfied")
    if failed:
        print(f"  not yet: {', '.join(failed)}")
    print(f"\n{DIM}  Tiers are cumulative in usefulness, not in dependency — you can stop anywhere.\n"
          f"  'roster' alone is a legitimate landing point: the device appears, is counted,\n"
          f"  filters by site and role, and shows liveness.{RESET}\n")
    sys.exit(0 if "roster" in satisfied else 1)


def _run_tiers(contract, args, satisfied, failed):
    for tier in contract["tiers"]:
        window = TOPOLOGY_WINDOW if tier["id"] in ("topology", "inventory") else WINDOW
        reqs = tier["requires"]
        results_any = [check(r, args.device, args.context, window, args.print_queries)
                       for r in reqs.get("anyOf", [])]
        results_all = [check(r, args.device, args.context, window, args.print_queries)
                       for r in reqs.get("allOf", [])]
        if args.print_queries:
            continue

        # anyOf: one passing requirement carries the tier. allOf: every one must pass.
        ok = (any(r["state"] == "ok" for r in results_any) if results_any else True) and \
             (all(r["state"] == "ok" for r in results_all) if results_all else True)
        (satisfied if ok else failed).append(tier["id"])

        mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  {mark}  {tier['id']:<14} {DIM}{tier['unlocks']}{RESET}")
        for r in results_any + results_all:
            if r["state"] == "ok" and ok:
                continue
            colour = {"ok": GREEN, "partial": YELLOW, "absent": DIM, "error": RED}[r["state"]]
            print(f"          {colour}{r['state']:<8}{RESET} {r['metric']}  {DIM}{r['detail']}{RESET}")

        # Recommended metrics never fail a tier — they are the difference between a page that
        # renders and a page that renders WELL, and conflating those would make this tool cry
        # wolf on a deployment that is working exactly as intended.
        for r in [check(x, args.device, args.context, window, False)
                  for x in reqs.get("recommended", [])]:
            if r["state"] != "ok":
                print(f"          {DIM}optional  {r['metric']}  {r['detail']}{RESET}")
        print()

    if args.print_queries:
        print()


if __name__ == "__main__":
    main()
