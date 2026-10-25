# PTAH initial source audit

**Audit input:** `rea-main.zip` uploaded for this task. **Audit type:** source/configuration inventory; not a complete security audit and not an execution of every provider.

## Observed facts

- Package identity is `rea-agents`, version `6.7.0`, with ESM configuration.
- Existing executable names are `rea` and `rea-agents`, both dispatched through `scripts/rea.mjs`.
- The source tree contains 2,524 TypeScript files under `src` in this archive.
- The archive contains 1,955 files matching `*.test.ts` or `*.spec.ts`; 748 are under `src` and 1,207 under `tests`.
- Architecture already separates CLI/MCP entry points, application workflows, contracts, domain logic, providers, process supervision, and evaluation.
- Existing evidence-related components include `src/application/investigation/EvidenceLedger.ts`, `src/domain/evidence.ts`, `src/domain/evidenceBundle.ts`, native investigation graph code, and reconstruction-obligation ledgers.
- `package.json` declares Node.js `^22.19.0 || ^24.11.0 || >=26.0.0` and npm `11.16.0` as package manager metadata.

## Environment observed during this task

- Node.js available: `v22.16.0`, below the declared Node 22 minimum.
- npm available: `10.9.2`.
- `node_modules` was absent at inspection time.
- Therefore, the full TypeScript build, Vitest suite, and provider integrations were not run during the initial implementation slice.

## Initial risks / follow-up checks

- Measure real end-to-end analysis accuracy on pinned reference tasks; test counts alone do not establish correctness.
- Validate evidence provenance and stale-result invalidation across provider/tool version changes.
- Review process isolation and resource bounds for every dynamic-analysis provider.
- Audit external provider dependencies and platform-specific prerequisites.
- Establish baseline latency, output size, model/tool cost, and unsupported-target behavior before optimization.

## Scope limitations

This report records directly observed repository metadata and file inventory. It does not claim all features are reliable, all security properties are verified, or any benchmark superiority has been established.

## PTAH engine slice added after the initial audit

- Added `scripts/ptah-engine.mjs`: dependency-free validation for schema-v1 investigation documents, provenance-preserving evidence reports, a directed evidence graph, stale/cross-target digest rejection, and a deterministic next-action planner with call/cost budget checks.
- Added `ptah report --input FILE`, `ptah graph --input FILE`, and `ptah plan --input FILE [--max-calls N] [--max-cost N]` to the additive PTAH CLI.
- Added `examples/ptah-investigation.example.json` and `docs/PTAH-ENGINE-V1.md`.
- Added seven engine/CLI tests. The combined dependency-free suite now passes 10/10 tests on the available Node.js runtime.
- Smoke-tested both CLI commands against the example JSON. The report found 1 evidence item, 1 claim, and 1 unresolved question; the graph export contained 4 nodes and 2 edges; the planner selected the permitted runtime-trace action within the configured cost budget. This selection is planning only; no target was executed.
- Remaining gaps: no adapter to the existing REA Evidence Ledger, no persisted graph/cache, no actual provider invocation, no MCP integration for the new model, and no GUI. The full project build and original test suite remain unverified because the environment does not meet the repository's declared Node/npm requirements and dependencies are absent.

## Brand and release audit follow-up

The root README now presents PTAH as a migration preview and links to `docs/PTAH-BRAND-AUDIT.md`. The package description and keywords have been updated to PTAH, while `rea-agents`, the upstream repository URLs, MCP namespace, and legacy entry points remain unchanged until a coordinated release/ownership migration can be performed safely. A prior root README snapshot is retained in `docs/legacy/`. This repository is not yet release-ready as an independent PTAH package; see the brand audit release gate checklist.
