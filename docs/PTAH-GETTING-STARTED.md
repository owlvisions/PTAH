# PTAH — Program Understanding & Analysis Toolkit

PTAH is the emerging product identity for this codebase: a program-understanding and reverse-engineering toolkit with a dependency-free investigation engine, CLI, MCP interface, and early local workbench. This repository is a **migration preview**, not a completed replacement of every REA capability.

> **Status and compatibility:** the codebase still contains the upstream REA runtime and its source identifiers. The npm package is `@owlvisions/ptah` (`npx @owlvisions/ptah help`); the `rea` and `rea-agents` executables remain compatibility aliases. This is not an official REA (`morluto/rea`) release; REA itself continues to be published as `rea-agents`. `@owlvisions/ptah` is not yet on npm; until it is, use the source-checkout commands below.

## Current PTAH-native features

- **Investigation engine:** target SHA-256 fingerprinting with 25+ signatures, ELF/PE/Mach-O header details and entropy, bounded string extraction, schema/provenance validation with a published JSON Schema, hash-chained history, evidence artifact digests, reports (JSON and Markdown), graphs (JSON, DOT, Mermaid), deterministic diff/lint/stats, single- and multi-step bounded planning, target-drift verification, and corruption-checked portable case bundles.
- **CLI:** `ptah` commands for `info`, `self-check`, `providers`, `fingerprint [--inspect]`, `strings`, `init`, `add-evidence [--artifact]`, `add-claim`, `add-question`, `add-action`, `set-claim-status`, `resolve-question`, `verify`, `lint`, `stats`, `history`, `schema`, `export-case`, `verify-case`, `import-case`, `report [--format json|markdown]`, `diff`, `graph [--format json|dot|mermaid]`, `plan [--steps N]`, and bounded `analyze` operations.
- **MCP:** `ptah-mcp` exposes inspection, strings, investigation, report, diff, lint, stats, schema, planning, and portable case operations over stdio using JSON-RPC/MCP.
- **Local workbench:** `ptah ui` launches an early loopback-only interface for investigations, evidence, reports (including Markdown download), graphs, planning, lint, metrics, format/entropy inspection, strings, case export, and verified case import; every change is recorded in the hash-chained history.
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

### Protecting and sharing cases

```sh
node scripts/ptah.mjs export-case --input ./sample.investigation.json --output ./sample.ptah-case.json.gz --gzip
node scripts/ptah.mjs keygen --output-dir ./keys
node scripts/ptah.mjs sign-case --input ./sample.ptah-case.json.gz --key ./keys/ptah-case-signing.key --output ./sample.signed.json
node scripts/ptah.mjs verify-case --input ./sample.signed.json --public-key ./keys/ptah-case-signing.pub --require-signature --target ./sample.bin
PTAH_CASE_PASSPHRASE='a long passphrase' node scripts/ptah.mjs encrypt-case --input ./sample.signed.json --output ./sample.enc.json
```

Signatures (Ed25519) authenticate the holder of the signing key; encryption (AES-256-GCM, scrypt-derived key) protects confidentiality at rest. The passphrase is read only from `PTAH_CASE_PASSPHRASE`. `verify-case` and `import-case` accept gzip-compressed and encrypted inputs transparently.

### Governance of an investigation

`freeze` locks evidence, claims, questions, and actions behind a content digest (history can still grow); `unfreeze` releases it. `set-claim-status` refuses `verified` without observed evidence; `resolve-question` requires a reason. `link-case` records a cross-reference to another verified case; `merge` unions two investigations of the same target and demands `--prefer base|other` on conflicts. `migrate` upgrades legacy documents. `watch --target` re-verifies when the file changes. `eval` runs the pinned suite in `examples/ptah-eval`.

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
