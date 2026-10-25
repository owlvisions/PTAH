# PTAH v0.11 validation status

**Snapshot label:** PTAH v0.11 (upstream-sync bootstrap hardening). This is a project snapshot label, not an npm release. The package remains `rea-agents@6.7.0`; package/repository/MCP namespace ownership and release migration remain unresolved.

## Verified locally

- `npm run test:ptah`: 34 tests passed, 0 failed.
- `node --check` passed for the five PTAH JavaScript entrypoint/engine files and the PTAH test file.
- The ZIP-upload/no-common-history state is now detected before attempting a rebase. The workflow exits safely with bootstrap instructions instead of attempting an unrelated-history rebase.
- Upstream synchronization remains a reviewed PR workflow; it does not auto-merge.

## Not verified

- Full REA monorepo build, TypeScript/Vitest suite, Python suite, and platform/provider integration tests.
- A live sync run against the latest `morluto/rea/main`.
- A real GitHub Actions run on `owlvisions/PTAH`.
- Upload of this complete snapshot to GitHub.

The environment is Node.js 22.16.0, while the repository requires `^22.19.0 || ^24.11.0 || >=26.0.0`. A normal `npm ci` correctly stopped at the engine guard. An explicitly overridden install was attempted for diagnostics but timed out and must not be treated as a successful dependency installation.

## Required bootstrap for dynamic upstream tracking

Because a ZIP upload has no `.git` history, `owlvisions/PTAH` must first be rebuilt from an upstream clone or fork, then have the PTAH overlay reviewed and applied on top. Only after the default branch shares Git history with `morluto/rea` can the scheduled rebase workflow work as intended. See `docs/PTAH-UPSTREAM-SYNC.md`.
