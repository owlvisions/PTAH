# PTAH — Program Understanding & Analysis Toolkit

PTAH is the emerging product identity for this codebase: a program-understanding and reverse-engineering toolkit with a dependency-free investigation engine, CLI, MCP interface, and early local workbench. This repository is a **migration preview**, not a completed replacement of every REA capability.

> **Status and compatibility:** the codebase still contains the upstream REA runtime and legacy identifiers. The npm package is intentionally still named `rea-agents` until a verified owner-controlled package namespace and coordinated release migration exist. Do not treat this checkout or its PTAH additions as an official upstream release merely because the original implementation is present.

## Current PTAH-native features

- **Investigation engine:** target SHA-256 fingerprinting, file-signature hints, schema/provenance validation, evidence reports (JSON and Markdown) and graphs, deterministic investigation diff, deterministic bounded planning, target-drift verification, and corruption-checked portable case bundles.
- **CLI:** `ptah` commands for `info`, `self-check`, `providers`, `fingerprint`, `init`, `add-evidence`, `add-claim`, `add-question`, `add-action`, `verify`, `export-case`, `verify-case`, `import-case`, `report [--format json|markdown]`, `diff`, `graph`, `plan`, and bounded `analyze` operations.
- **MCP:** `ptah-mcp` exposes PTAH investigation, report, diff, and portable case operations over stdio using JSON-RPC/MCP.
- **Local workbench:** `ptah ui` launches an early loopback-only interface for investigations, evidence, reports (including Markdown download), graphs, planning, case export, and verified case import.
- **Compatibility:** `rea` and `rea-agents` remain as legacy entry points while feature parity is evaluated.

These features are deliberately scoped. Static adapters for `objdump`, `llvm-objdump`, and `wasm-tools` provide bounded metadata/validation operations; they are not a universal decompiler. External tools are not OS-sandboxed by this migration slice, and the workbench is a local single-user utility rather than a production multi-user application.

## Quick start from a source checkout

Requirements for the full legacy project are declared in `package.json` (Node.js `^22.23.4 || ^24.22.1 || >=26.12.1` and npm `11.16.0`). The lightweight PTAH-native commands do not require installing project dependencies, but the legacy runtime does.

```sh
node scripts/ptah.mjs help
node scripts/ptah.mjs info
node scripts/ptah.mjs self-check --json
node --test scripts/tests/ptah.test.mjs scripts/tests/ptah-engine.test.mjs
```

Create an investigation bound to a target file:

```sh
node scripts/ptah.mjs fingerprint --target ./sample.bin
node scripts/ptah.mjs init --target ./sample.bin --output ./sample.investigation.json
node scripts/ptah.mjs report --input ./sample.investigation.json
node scripts/ptah.mjs verify --input ./sample.investigation.json --target ./sample.bin
node scripts/ptah.mjs export-case --input ./sample.investigation.json --output ./sample.ptah-case.json
node scripts/ptah.mjs verify-case --input ./sample.ptah-case.json --target ./sample.bin
node scripts/ptah.mjs import-case --input ./sample.ptah-case.json --output ./restored.investigation.json --target ./sample.bin
node scripts/ptah.mjs report --input ./sample.investigation.json --format markdown > ./sample-report.md
node scripts/ptah.mjs diff --base ./sample.ptah-case.json --head ./restored.investigation.json
```

`report --format markdown` renders the same provenance-preserving report as the JSON output for humans: claims with support labels, cited evidence tables, and open questions. `diff` compares two investigations or verified case bundles and prints added/removed/changed evidence, claims, questions, and actions, claim status transitions, resolved or reopened questions, and whether both sides refer to the same target bytes; it exits `3` when differences exist, `0` when identical, and `1` on invalid input or a tampered case.

Case bundles contain the investigation and a SHA-256 corruption checksum, not the target file. The checksum is not a signature and does not authenticate the bundle author. Supply `--target` during verification/import to confirm the local target bytes still match the recorded digest.

Start the local workbench with `node scripts/ptah.mjs ui`. It binds to loopback by default; do not expose it to an untrusted network.

## Validation

Run the dependency-free PTAH suite with:

```sh
npm run test:ptah
```

A passing PTAH suite does **not** establish that the entire upstream monorepo builds or that every inherited provider works. The full project build and test suite require the declared Node.js version and installed dependencies. See [the current source audit](PTAH-AUDIT.md), [architecture](PTAH-ARCHITECTURE.md), [engine schema](PTAH-ENGINE-V1.md), [MCP guide](PTAH-MCP.md), [workbench notes](PTAH-UI.md), [roadmap](PTAH-ROADMAP.md), and [brand migration audit](PTAH-BRAND-AUDIT.md), [v0.8 validation report](PTAH-V0.8-VALIDATION.md), [v0.9 validation report](PTAH-V0.9-VALIDATION.md), [v0.10 validation report](PTAH-V0.10-VALIDATION.md), [v0.11 validation report](PTAH-V0.11-VALIDATION.md), and [upstream sync guide](PTAH-UPSTREAM-SYNC.md).

## Branding and provenance

This is a staged migration. The root README and PTAH-owned documentation use the PTAH identity, while upstream attribution, licensing, existing REA integrations, package identifiers, generated metadata, translations, and release links require careful coordinated review. The prior README snapshot is retained at [`docs/legacy/REA-README-upstream-snapshot.md`](legacy/REA-README-upstream-snapshot.md) for provenance and comparison. Review [PTAH-BRAND-AUDIT.md](PTAH-BRAND-AUDIT.md) before describing the project as fully rebranded or publishing a new package.

## License

The repository's existing `LICENSE` and `THIRD_PARTY_NOTICES.md` continue to apply. Rebranding does not change upstream copyright, third-party licenses, or attribution obligations.

## Keeping up with upstream REA

See [PTAH-UPSTREAM-SYNC.md](PTAH-UPSTREAM-SYNC.md) for the scheduled upstream polling and reviewed sync PR workflow.
