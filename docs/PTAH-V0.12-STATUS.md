# PTAH v0.12 status and upstream checkpoint

**Checkpoint date:** 2026-10-25  
**Package label:** engineering preview; not a standalone production release.

## Upstream checkpoint identified

The latest upstream `morluto/rea` `main` commit identified during this checkpoint is:

- Commit: [`97194c4b4808b2a9b79277c436ba9042c58b1b70`](https://github.com/morluto/rea/commit/97194c4b4808b2a9b79277c436ba9042c58b1b70)
- Commit date reported by GitHub: 2026-10-24 17:16:51 UTC
- Subject: `fix(ghidra): admit recordless MIPS-I legacy targets (#7014)`
- Change summary: admit legacy MIPS-I targets and bind MIPS profiles to the target.

**Important:** this is a recorded upstream reference, not proof that the commit has been merged into this archive. The working environment could not resolve `github.com` for a complete source fetch, so the PTAH overlay has not been rebased on this commit and conflict resolution has not been performed. Do not describe this archive as the latest merged upstream source.

## Validation performed on the supplied archive

The following dependency-free checks ran successfully with Node.js `v22.16.0`:

- `node scripts/tests/ptah.test.mjs` — 6/6 passing.
- `node scripts/tests/ptah-engine.test.mjs` — 28/28 passing.
- JavaScript syntax checks and ZIP integrity were previously recorded for v0.11.

These checks exercise PTAH-owned functionality only. They do **not** validate the complete REA monorepo build, TypeScript/Vitest suites, Python tests, or external-provider/platform integrations.

## Remaining release gates

1. Fetch a full Git checkout of upstream `main` at the recorded commit (or a newer reviewed commit).
2. Apply/rebase the PTAH overlay against real Git history; review conflicts in package metadata, README, generated metadata, and overlapping source files.
3. Install dependencies using a supported Node.js release (the repository requires `^22.19.0 || ^24.11.0 || >=26.0.0`; this runtime is Node `22.16.0`).
4. Run the complete upstream build, typecheck, lint, Vitest, Python and CI suites, plus PTAH-specific tests.
5. Commit the reviewed source into `owlvisions/PTAH`, then verify GitHub Actions and publish an archive from that committed tree.

## Repository publication status

`owlvisions/PTAH` exists, but it was found empty at this checkpoint. No source upload or commit is claimed by this status file. A ZIP archive alone does not establish shared Git ancestry with upstream; the upstream-sync workflow needs a real Git-based bootstrap before it can safely rebase and propose sync pull requests.
