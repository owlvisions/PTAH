# PTAH v0.10 validation status

This release candidate adds an explicit GitHub Actions validation lane alongside the reviewed upstream-sync workflow.

## Locally verified

- `npm run test:ptah`: 34 tests passed, 0 failed.
- `node --check` passed for `scripts/ptah.mjs`, `scripts/ptah-engine.mjs`, `scripts/ptah-mcp.mjs`, `scripts/ptah-ui.mjs`, `scripts/ptah-ui-server.mjs`, and `scripts/tests/ptah.test.mjs`.
- The validation workflow is covered by a PTAH test that checks the supported Node.js version, dependency-free tests, dependency install, CI check command, and read-only permissions.
- The upstream sync workflow remains review-only and does not auto-merge.
- The sync workflow now detects a ZIP-upload repository with unrelated Git
  history and exits with explicit bootstrap guidance rather than attempting a
  rebase that cannot succeed safely.

## CI workflows

- `.github/workflows/ptah-validation.yml` runs PTAH-native tests and JavaScript syntax checks on Node.js 22.19.0, then runs the upstream repository CI checks after installing locked dependencies.
- `.github/workflows/ptah-upstream-sync.yml` proposes reviewed sync pull requests against the latest upstream `main` on a 15-minute schedule. GitHub may delay scheduled workflows; this is not a real-time guarantee.

## Not verified locally

The current local runtime is Node.js 22.16.0, below the repository engine range (`^22.19.0 || ^24.11.0 || >=26.0.0`), and `node_modules` is not installed. Therefore the full upstream typecheck/lint/Python/build matrix has not been claimed as passing. The new workflow will execute that lane on GitHub Actions with the supported runtime and a clean dependency installation.

The archive's upstream overlay patch is based on the supplied REA snapshot. It has not been verified against a live checkout of today's upstream `main`; bootstrap on a newer commit may require reviewed conflict resolution.
