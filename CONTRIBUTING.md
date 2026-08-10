# Contributing

Contributions are welcome. Please read the first section before opening a pull request — it will
save you effort.

## Most changes do not belong here

**The app reads a metric model, not a specific extension.** If you are adding your own devices, a
new data source, or vendor-specific collection, you do that by *meeting the contract* from your own
code — not by changing this repository.

- [`docs/METRIC-CONTRACT.md`](docs/METRIC-CONTRACT.md) — what to emit
- `scripts/api_bridge.py` — a worked example from a non-SNMP source
- `python3 scripts/verify_contract.py` — check your work

Your extension, your repository, your release cycle. The app cannot tell the difference between
your data and ours, and you never wait on us to merge anything.

This is the single most important thing to know here, and it covers the large majority of what
people want to do.

## What does belong here

- Bugs in the app or in one of the five extensions
- Corrections to the documentation, including the contract
- Support for a device or vendor quirk that belongs in a shipped extension
- Performance and accessibility fixes

Open an issue first for anything substantial. It is a short conversation that avoids a long
rewrite.

## Before you open a PR

```bash
cd network-insights-app
npm ci
npm run build      # must succeed
npm test           # must be green
npm run lint
```

**Tests are the gate.** If you are changing code that has no test, add one first. For extensions,
run the module's own test suite.

Some specifics that are easy to get wrong and hard to spot in review:

- **Never use a multi-aggregate `timeseries { a=count(X), b=count(Y) }`** where a metric might be
  empty — it inner-joins on the by-dimensions, so one empty metric erases every other column. Use
  `| append [ … ]`.
- **Never render "no data" and "could not ask" the same way.** A failed query must not appear as
  zero, down, or unconfigured.
- **Do not hardcode a tenant URL, credential, or vault id.**

`CLAUDE.md` has the full list with the reasoning behind each, and is worth reading whether or not
you use an AI assistant.

## How merging actually works — please read

**This repository is generated from a private source repository**, where the app is developed
alongside a hardware lab used to test it.

That has one consequence you should know before you spend time on a change:

> **Your PR is accepted as a proposal, not as a merge commit.** When we take a change, it is applied
> to the source repository and ships in the next release here. We close the PR referencing the
> release that contains it.

**Your change survives. Your commit hash does not.** You will not appear in `git log` for this
repository, and a `git blame` will not point at you.

We would rather tell you that up front than have you discover it after the work. If attribution
matters for your contribution, say so on the issue and we will find a way to credit it properly —
in the release notes, or in the file.

Issues, discussions and review comments work exactly as you would expect. It is only the merge
mechanics that differ.

## Reporting something sensitive

Please do not open a public issue for a suspected security problem. Raise it privately with the
maintainer.

## This is not a Dynatrace product

It runs on Dynatrace and is written by a Dynatrace employee, but it is an independent open-source
project provided as-is under Apache 2.0. Dynatrace does not support, endorse or maintain it, and it
sits outside your Dynatrace support agreement. Issues and pull requests here are the route.

## Licence

By contributing you agree that your contribution is licensed under Apache 2.0, the same licence as
this project.
