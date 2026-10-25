# PTAH v0.9 validation report

**Snapshot label:** PTAH v0.9 (upstream-tracking workflow checkpoint). This is a project snapshot label, not an npm release. The package remains `rea-agents@6.7.0`; package/repository/MCP namespace ownership and release migration are still unresolved.

## Checks performed in this environment

| Check                                       | Result            | Notes                                                                                                                                                    |
| ------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PTAH JavaScript syntax checks               | PASS              | CLI, engine, MCP server, UI launcher and UI server parsed successfully under Node.js v22.16.0                                                            |
| `npm run test:ptah`                         | PASS: 33 tests    | Includes the upstream-sync workflow contract test; dependency-free PTAH tests only                                                                       |
| Upstream sync workflow YAML parse           | PASS              | Parsed structurally with PyYAML; GitHub-hosted execution has not been run                                                                                |
| Overlay patch against supplied REA snapshot | PASS              | Patch applies to the exact `rea-main.zip` snapshot supplied with this work                                                                               |
| ZIP archive integrity                       | PASS              | `unzip -t` reported no errors in the generated archive                                                                                                   |
| Tests from a clean archive extraction       | PASS: 33 tests    | The extracted `PTAH-v0.9` directory passed the dependency-free test suite                                                                                |
| Live fetch of GitHub `main`                 | BLOCKED           | This execution environment could not resolve `github.com`; no claim is made that this archive includes upstream commits newer than its supplied baseline |
| Full monorepo build and test matrix         | BLOCKED / NOT RUN | Dependencies are absent and Node.js v22.16.0 is below the repository's declared v22.19.0 minimum                                                         |

## What the upstream-sync automation does

`.github/workflows/ptah-upstream-sync.yml` is an opt-in GitHub Actions workflow that polls `morluto/rea` `main` every 15 minutes, rebases PTAH commits in a bot-owned branch, runs PTAH-specific checks, and opens or updates a review PR. It never auto-merges or pushes directly to the default branch. If conflicts occur, it aborts and records recovery guidance.

The workflow is not active merely because it exists in a ZIP. It requires applying the PTAH overlay to a Git repository with upstream history, pushing that work to a repository the maintainer controls, enabling Actions, and allowing the built-in GitHub token to open pull requests. GitHub may delay scheduled runs; the 15-minute schedule is a polling target, not a real-time guarantee.

## Reproduction

```sh
node --check scripts/ptah.mjs
node --check scripts/ptah-engine.mjs
node --check scripts/ptah-mcp.mjs
node --check scripts/ptah-ui.mjs
node --check scripts/ptah-ui-server.mjs
npm run test:ptah
```

See [PTAH-UPSTREAM-SYNC.md](PTAH-UPSTREAM-SYNC.md) for bootstrap and review instructions. Full validation still requires the supported Node/npm versions, dependency installation, and the upstream CI/build/test matrix.
