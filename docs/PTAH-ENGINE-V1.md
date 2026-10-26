# PTAH Engine v1: dependency-free investigation primitives

This first engine slice is intentionally small and deterministic. It does not execute target programs and does not replace the existing REA Evidence Ledger.

## Commands

```bash
node scripts/ptah.mjs report --input examples/ptah-investigation.example.json
node scripts/ptah.mjs plan --input examples/ptah-investigation.example.json --max-calls 1 --max-cost 5
node scripts/ptah.mjs graph --input examples/ptah-investigation.example.json
npm run test:ptah
```

`report` validates a versioned JSON investigation and emits a claim report with source evidence references. A claim is not considered verified merely because a model says it is; the explicit `verified` status must be supplied by a workflow that has actually performed verification.

`graph` exports a directed JSON graph linking the target to evidence, evidence to claims, and relevant evidence to questions. It also records missing required evidence kinds per question. Evidence whose target digest does not match the investigation target is rejected to prevent accidental cross-target/stale evidence reuse.

`plan` chooses one deterministic action that can address the highest-priority unresolved question's missing evidence kinds. It respects `--max-calls` and `--max-cost`; it does not itself invoke tools. `blocked`, `budget-exhausted`, and `no-action-needed` are explicit outcomes rather than fabricated progress.

## Portable case bundles

Export an investigation as a portable JSON case, verify it, then restore the ordinary investigation document:

```bash
ptah export-case --input ./sample.investigation.json --output ./sample.ptah-case.json
ptah verify-case --input ./sample.ptah-case.json --target ./sample.bin
ptah import-case --input ./sample.ptah-case.json --output ./restored.investigation.json --target ./sample.bin
```

The versioned `ptah-investigation-case` envelope includes the validated investigation and a SHA-256 checksum over its canonical JSON payload. Import refuses invalid schemas, checksum mismatches, and—when `--target` is supplied—a target whose current bytes do not match the recorded digest. The target file itself is never embedded or executed. The checksum detects accidental corruption; it is not a digital signature and does not authenticate who created or modified a bundle.

The MCP server exposes matching `ptah_case_export`, `ptah_case_verify`, and `ptah_case_import` tools. The local workbench download now emits the same portable case format.

## Schema v1

- `target`: stable identifier and SHA-256 digest of the analyzed target.
- `evidence`: source-linked observations, each with a kind and confidence (`observed`, `derived`, `inferred`).
- `claims`: statements that cite one or more existing evidence IDs.
- `questions`: unresolved questions, priorities from 0 to 100, and required evidence kinds.
- `actions`: candidate operations and the evidence kinds they may produce, with a relative positive cost.

## Current limitations

- This schema is not yet wired into existing REA workflows or MCP tools.
- The planner is rule-based and uses evidence kinds, not semantic information-gain estimates.
- `verified` is a caller-supplied status, not independently attested by this module.
- The v1 digest is supplied by the caller; this module does not hash target files itself.
- The graph is an in-memory export only; persistence, incremental updates, and adapters to the existing ledger are not implemented yet.
- No dynamic analysis is performed. Any future runtime provider must add isolation, permission gates, and bounded resource use.
