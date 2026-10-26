# PTAH: engineering roadmap

**Status:** migration preview. This roadmap describes intended work, not shipped capabilities.

## Product goal

PTAH is intended to become a multi-format program understanding and reverse-engineering platform with a standalone engine, CLI, MCP interface, and graphical interface. The existing REA implementation is the compatibility base until each replacement has passed parity and regression tests.

## Non-negotiable engineering rules

1. Preserve existing CLI/MCP behavior unless a documented migration explicitly changes it.
2. No capability is described as implemented until code and automated tests demonstrate it.
3. Every important conclusion must retain provenance to source evidence and expose uncertainty.
4. Treat inspected programs and artifacts as untrusted. Runtime analysis must be isolated, resource-bounded, and permission-aware.
5. Prefer measured accuracy and end-to-end task success over tool count, code size, or model confidence.
6. New provider integrations must have typed contracts, deterministic error behavior, lifecycle ownership, and tests for missing tools and failure paths.

## Phases

### Phase 0 — Baseline and compatibility entry point

- Add a dependency-free `ptah` entry point without replacing `rea` / `rea-agents`.
- Add a machine-readable environment self-check.
- Record architecture, runtime constraints, test inventory, and the current migration boundary.
- Validate the new entry point with Node's built-in test runner.

**Exit criteria:** PTAH help/info/self-check tests pass without installed dependencies; existing package metadata and REA dispatcher remain intact.

### Phase 1 — Evaluation baseline

- Select representative authorized fixtures for JavaScript/Electron, Android, managed code, native binaries, web captures, WASM, and firmware.
- Define reference answers and evidence requirements for each task.
- Record correctness, unsupported/unknown handling, latency, memory, token/cost estimates, and failure rates.
- Separate smoke tests from expensive external-provider integration tests.

**Exit criteria:** repeatable baseline reports are generated from pinned fixtures and tool versions.

### Phase 2 — Unified investigation and evidence model

**Implementation status (2026-10-22): initial dependency-free slice implemented.** `scripts/ptah-engine.mjs` validates versioned investigation documents, verifies target digests and evidence references, produces provenance-preserving claim reports, exports a directed evidence graph, rejects stale/cross-target evidence, and chooses one deterministic next action under call/cost budgets. CLI entry points are `ptah report --input FILE` and `ptah plan --input FILE`. These are additive primitives. A TypeScript interoperability adapter now maps PTAH summary records into REA EvidenceBundle records; its TypeScript/Vitest integration tests are authored but have not been executed in this environment.

- Define stable IDs for targets, artifacts, observations, hypotheses, claims, and verification results.
- Model relationships with provenance, tool/version, timestamps, content digests, and confidence rationale.
- Invalidate cached conclusions when relevant inputs or provider versions change.
- Preserve existing Evidence Ledger and reconstruction-obligation contracts through adapters rather than duplicating state.
- Add round-trip export/replay and invalidation tests before connecting the new model to legacy workflows.

**Exit criteria:** at least one existing workflow can export and replay a versioned investigation without losing evidence references.

### Phase 3 — Investigation planner

- Select next steps based on unresolved questions and expected information gain.
- Enforce budgets for wall time, tool calls, output bytes, and model context.
- Cache only deterministic, content-addressed results with explicit invalidation.
- Keep human approval gates for destructive or externally visible actions.

**Exit criteria:** measured improvement against the Phase 1 baseline without reduced answer correctness.

### Phase 4 — Verification and reconstruction

- Generate testable hypotheses from evidence.
- Support differential tests in controlled environments for authorized targets.
- Report matching behavior, mismatches, untested behavior, and confidence limitations separately.
- Never present approximate decompilation as original source code.

**Exit criteria:** verified reports link each claim to evidence and test results.

### Phase 5 — Product surfaces

- Keep CLI and MCP as stable interfaces over a shared application API.
- Design a GUI as a client of that API, not a second implementation of analysis logic.
- Add job state, cancellation, progress, and artifact navigation.
- Version public contracts and provide migration tests.

**Exit criteria:** one investigation can be started, monitored, and reviewed consistently through CLI/MCP and the first GUI slice.

### Phase 6 — Provider expansion and optimization

- Add or improve providers only where benchmarks show meaningful coverage gaps.
- Use capability discovery and explicit provider readiness diagnostics.
- Parallelize independent work with bounded concurrency and owned process cleanup.
- Compare quality, latency, and cost before and after every optimization.

**Exit criteria:** each provider has conformance tests, failure-mode coverage, and documented prerequisites.

## Initial metrics

- Evidence-backed claim precision and unsupported-claim rate.
- Task success rate on pinned reference cases.
- Differential behavior match rate for reconstruction tasks.
- Unknown detection quality (not only the number of unknowns).
- Median and p95 wall-clock time.
- Tool calls, output bytes, peak memory, and model cost per task.
- Reproducibility across repeated runs and provider versions.

No “hundreds of times better” claim should be made until a benchmark defines the dimension, baseline, and reproducible measurement.

## Delivery status update — v0.4

Completed and dependency-free tested: target fingerprinting, investigation initialization, evidence append with validation and atomic save, provider PATH discovery, report, graph, and bounded deterministic planning. See [PTAH-V0.3.md](./PTAH-V0.3.md) for exact commands and validation.

Still open: execute the TypeScript adapter Vitest tests in the supported build environment, persistent multi-step investigation orchestration, target-specific provider analysis with stronger OS-level isolation, a richer GUI and deeper legacy-app integration, and full monorepo compatibility verification. Do not mark these as complete until integration and end-to-end tests pass.

### Additional verified v0.4 scope

The dependency-free CLI now supports authoring evidence, claims, questions, and candidate actions into a versioned investigation file. A tested integration path runs `init -> add-evidence -> add-claim -> add-question -> add-action -> plan -> report`. These records are PTAH's portable schema. The new `PtahEvidenceAdapter.ts` provides an explicit, loss-aware conversion to the existing REA `EvidenceBundle` contract and preserves a PTAH-ID → REA semantic-ID crosswalk; it is not yet exposed by the dependency-free CLI, and its TypeScript tests still need to run in the supported build environment.

## Delivery status update — v0.6

Added `src/application/investigation/PtahEvidenceAdapter.ts` and `PtahEvidenceAdapter.test.ts`. The adapter uses REA's own `createEvidence`/`createEvidenceBundle` APIs, rejects stale target digests, duplicate PTAH evidence IDs, and dangling claim references, and clearly marks imported summaries as `analyst-inference` with limitations because the PTAH v1 schema does not preserve original raw provider output. Claims remain separate from evidence records. Dependency-free PTAH tests were green (19/19 at the v0.6 checkpoint); the adapter TypeScript/Vitest tests and the monorepo build are not claimed as run because this environment lacks installed project dependencies and uses Node 22.16.0 while the project requires Node 22.19.0 or newer supported lines.

### v0.6 — target drift verification

Added `ptah verify --input INVESTIGATION.json [--target FILE]`. Without `--target`, it validates the saved schema, evidence references, and provenance fields. With `--target`, it hashes the current file and compares its bytes to the investigation's original SHA-256. A mismatch returns exit code `2` and a machine-readable report with `valid: false`; malformed input or I/O errors return exit code `1`. This does not execute the target.

Example:

```sh
ptah init --target ./sample.wasm --output ./sample.investigation.json
ptah verify --input ./sample.investigation.json --target ./sample.wasm
```

## Delivery status update — v0.7

Added `scripts/ptah-mcp.mjs`, a dependency-free stdio MCP server exposing `ptah_fingerprint`, `ptah_verify`, `ptah_report`, `ptah_graph`, `ptah_plan`, `ptah_providers`, and the allow-listed `ptah_static_analyze`. It implements JSON-RPC initialization, tools/list, tools/call, ping, notifications, and structured tool errors. Added `ptah-mcp` package bin and included PTAH scripts in the npm package allowlist and lockfile bin metadata.

Added opt-in `ptah providers --probe` checks. Each provider uses a fixed version/help argument list, `shell: false`, a bounded timeout (maximum 10 seconds), and bounded captured output (maximum 64 KiB). Default `ptah providers` remains discovery-only and does not launch tools. These are environment/version checks, not proof that an analyzer can correctly analyze a target.

Validation on the current environment: `node --check` passed for `ptah.mjs`, `ptah-engine.mjs`, `ptah-mcp.mjs`, `ptah-ui.mjs`, and `ptah-ui-server.mjs`; 31 dependency-free Node tests passed, including timeout handling, MCP stdio calls, static analyzer adapter behavior, evidence recording, and loopback GUI API integration. A real `objdump` run against `/bin/true` completed successfully and confirmed the target was not executed or modified. The full monorepo build, the TypeScript EvidenceLedger adapter tests, a production-grade integrated GUI, and OS-level sandboxing are not claimed as complete.

## Static analyzer adapter — v0.7 follow-up

Added `ptah analyze --target FILE --provider objdump|llvm-objdump|wasm-tools` and the `ptah_static_analyze` MCP tool. The adapter uses fixed argv (`-f -h -- TARGET`), no shell, a bounded wall-clock timeout, capped stdout/stderr, and pre/post target SHA-256 checks. It rejects unlisted providers and reports a nonzero tool exit as failure. A successful run can be recorded into an existing PTAH investigation using `--investigation FILE --save-investigation FILE --evidence-id ID`; cross-target or failed analysis is rejected. Tests cover paths with spaces, provider allowlisting, missing tools, timeout handling, evidence provenance, and the fact that the target is not launched as a process. The objdump adapters extract object/file metadata and section headers; the wasm-tools adapter validates only files with a confirmed WebAssembly magic signature. These are focused adapters, not a complete reverse-engineering pipeline, and are not OS-sandboxed yet.

## Local workbench — v0.7 follow-up

Added `ptah ui` / `ptah-ui`, a dependency-free loopback-only browser workbench at `http://127.0.0.1:4177/` by default. It supports target upload to a private temporary workspace, investigation creation, evidence/claim/question/action entry, allow-listed static metadata analysis, report/graph/planner views, and JSON export. The server restricts binding to loopback, validates Host headers, applies a 128 MiB upload limit (configurable in server tests), uses restrictive temporary-file permissions, and deletes its workspace on normal shutdown. Tests exercise upload, evidence, report, export, oversized upload rejection, and refusal of non-loopback binding. This is a single-user local utility, not a production GUI, and OS-level analyzer isolation remains open.

## Brand migration checkpoint

The root README and package description/keywords now identify PTAH while explicitly labeling the codebase a migration preview. The previous README snapshot is retained at `docs/legacy/REA-README-upstream-snapshot.md`, and `docs/PTAH-BRAND-AUDIT.md` records what changed, what remains upstream-bound, and the release gates. The npm package name, `mcpName`, repository URLs, legacy executable names, translated docs, and upstream license references have deliberately not been renamed without an owner-controlled namespace and a coordinated compatibility plan. This is an intentional safety boundary, not a claim that all visible REA references have been migrated.

## Public roadmap metrics

Every roadmap claim is tied to a measurement produced by `ptah eval --suite examples/ptah-eval --json` (and compared with `--baseline`). Targets are stated so progress is checkable, not aspirational:

| Metric (eval report field)                   | Current (synthetic suite)                            | Target                  | Notes                                                                                   |
| -------------------------------------------- | ---------------------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------- |
| `metrics.checkPassRate`                      | 1.0                                                  | 1.0 on every merge      | Any drop is a regression and fails `--baseline`.                                        |
| `metrics.claimLabelPrecision`                | 1.0                                                  | ≥ 0.98                  | Support labels vs. analyst reference labels.                                            |
| `metrics.unsupportedClaimRate`               | 0.33 (by design: one inference-only reference claim) | report, never hide      | PTAH must surface inference-only claims, not suppress them.                             |
| `metrics.medianDurationMs` / `p95DurationMs` | < 20 ms                                              | report per host         | Wall-clock; compare only on the same machine.                                           |
| `npm run test:ptah`                          | 84 tests                                             | 100% pass before merge  | Dependency-free; includes 11 provider conformance suites and a validator mutation test. |
| Isolation coverage                           | bubblewrap + prlimit when present                    | honest report every run | `isolation.applied` is recorded in evidence sources.                                    |

Real-world accuracy figures will be added only when authorized fixtures with reference answers exist; the synthetic suite proves the harness, not analyst-grade accuracy.

## Delivery status update — backlog completion (2026-10-26)

Completed with tests (see `docs/PTAH-DEVELOPMENT-PROMPT.md` backlog numbering): freeze/unfreeze, tags, related-case links, same-target merge with conflict policy, migration registry (legacy→v1), Ed25519 case signing with `keygen`, AES-256-GCM case encryption via `PTAH_CASE_PASSPHRASE`, gzip bundles, `--quiet`; provider table with readelf/nm/file/rabin2/rz-bin/monodis/aapt2/wasm-objdump adapters, bubblewrap isolation and prlimit limits with honest fallback, cancellable background analyzer jobs, native ASAR and WASM parsers, embedded-signature carving; evaluation harness with pinned fixtures, reference labels, baseline regression detection, validator mutation test; workbench diff panel, SVG graph view, DOT/Mermaid downloads; `watch`, shell completion, MCP prompts and `--root` resources; VS Code integration skeleton (`integrations/vscode-ptah`, unpublished); Arabic getting-started guide; synthetic example case; PTAH responsible-disclosure policy in `SECURITY.md`.

Deliberately deferred: publishing an npm package under a PTAH name (owner decision: keep `rea-agents` identity until a coordinated rename), and native analyzers replacing REA adapters (requires parity benchmarks on authorized real targets).

## Delivery status update — PTAH-first increment (2026-10-26)

Shipped and covered by `npm run test:ptah` (50 dependency-free tests): PTAH-first README/help/info; Markdown reports; deterministic diff; hash-chained history on every CLI and workbench mutation; guarded `set-claim-status` and `resolve-question`; `lint` and `stats`; evidence artifact digests; ELF/PE/Mach-O header decoding and entropy (`fingerprint --inspect`); bounded `strings`; 12 additional magic signatures incl. tar; DOT/Mermaid graph export; multi-step planning; published JSON Schema with drift test; matching MCP tools; workbench lint/metrics/inspect/strings panels. Still open from the backlog in `docs/PTAH-DEVELOPMENT-PROMPT.md`: evaluation harness with pinned fixtures, provider conformance suite, OS-level analyzer isolation, workbench job state and graph visualization, bundle signatures, and native analyzers replacing REA adapters only where parity is proven.

## Upstream freshness and integration

- [x] Add an opt-in scheduled upstream sync workflow that proposes review PRs every 15 minutes.
- [x] Run PTAH-specific syntax checks and dependency-free tests before publishing an upstream-sync branch.
- [ ] Push this work to a maintainer-controlled GitHub fork and enable Actions PR permissions.
- [ ] Successfully rebase against a live upstream commit and review the resulting diff. The current execution environment could not resolve `github.com`, so this archive does not claim to contain the newest upstream source snapshot.
- [ ] Require full upstream CI/build/provider/platform checks before merging each sync PR.
