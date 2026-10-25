# PTAH v0.8 snapshot validation report

**Snapshot label:** PTAH v0.8 (repository migration checkpoint). This label is not the npm package version; `package.json` intentionally remains `rea-agents@6.7.0` while package/repository ownership and release migration are unresolved.

## Checks performed

| Check | Result | Notes |
|---|---|---|
| `node --check scripts/ptah.mjs` | PASS | Current Node runtime parses the PTAH CLI |
| `node --check scripts/ptah-engine.mjs` | PASS | Current Node runtime parses the investigation engine |
| `node --check scripts/ptah-mcp.mjs` | PASS | Current Node runtime parses the MCP server |
| `node --check scripts/ptah-ui.mjs` | PASS | Current Node runtime parses the UI launcher |
| `node --check scripts/ptah-ui-server.mjs` | PASS | Current Node runtime parses the local UI server |
| `npm run test:ptah` | PASS: 32 tests | All dependency-free PTAH tests passed in the current workspace |
| `npm run build` | BLOCKED | `node_modules/.package-lock.json` is missing; `npm run deps:check` requests `npm ci` |
| Full TypeScript/Vitest suite | NOT RUN | Project dependencies are absent; current Node is v22.16.0, below declared Node 22.19.0 minimum |

## Scope of the 32 passing tests

Tests cover investigation schema/provenance validation, fingerprinting, target drift checks, evidence reports/graphs/planning, file-backed CLI flows, provider discovery and bounded opt-in probes, MCP stdio behavior, allow-listed static-analysis adapters, local workbench upload/report/export behavior and rejection cases, and the root brand-migration contract.

## Explicitly not verified

- Full monorepo build, typecheck, lint, format, Vitest, Python, and docs/CI checks.
- Runtime compatibility of every inherited REA provider.
- OS-level sandboxing of external analysis tools.
- Production-grade or multi-user GUI security/usability.
- Complete rebrand of translated docs, website, release automation, repository URL, npm package name, or MCP registry identity.
- A standalone PTAH package publication or ownership of new namespaces.

## Reproduction

Run the five `node --check` commands above and `npm run test:ptah` from the repository root. For full validation, use the declared supported Node/npm toolchain, install dependencies from the lockfile, then run the project's documented CI/check/test commands.
