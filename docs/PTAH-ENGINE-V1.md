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

## Markdown reports and investigation diff

`report --format markdown` renders the JSON report for human review. Support labels (`evidence-backed`, `derived-support`, `inference-only`, `verified`) are computed from cited evidence confidence exactly as in the JSON output; table cells are escaped and the rendering is byte-stable for the same input.

`diff --base FILE --head FILE` accepts investigations or verified case bundles on either side (a bundle with a checksum mismatch is refused). The result lists added, removed, and changed items by ID for evidence, claims, questions, and actions, claim status transitions, resolved and reopened questions, and a `target.sameTarget` flag; evidence is never treated as transferable between different target digests. The MCP equivalents are `ptah_report` with `format` and `ptah_diff`.

## Target inspection without execution

`fingerprint --inspect` (MCP `ptah_inspect`) adds `formatDetails` and `entropy` to the fingerprint. ELF headers yield class, endianness, OS ABI, type, and machine; `MZ` files are confirmed as PE only when `e_lfanew` points at a valid `PE\0\0` signature, and then yield machine, section count, DLL/executable flags, and PE32/PE32+; Mach-O yields endianness and CPU; universal (fat) binaries are distinguished from Java class files. Entropy is Shannon entropy in bits per byte over a bounded read (default 64 MiB) with a coarse hint (high entropy suggests compression, encryption, or packing). `strings` (MCP `ptah_strings`) extracts printable ASCII and UTF-16LE runs with byte offsets under `minLength`, `maxResults`, and `maxBytes` limits and reports `truncated` when any limit was hit. Neither operation launches the target or any external tool.

## History, claim status, and question resolution

Every CLI and workbench mutation appends an entry to `history`: `{ seq, action, at, …details, previousEntrySha256, entrySha256 }`. `entrySha256` is the SHA-256 of the canonical JSON of the entry (without itself) and therefore covers the previous digest, so editing, reordering, or dropping entries fails validation. `ptah history` prints and verifies the chain.

`set-claim-status` changes a claim to `hypothesis`, `supported`, `verified`, or `rejected` and records the transition. Setting `verified` is refused unless at least one cited evidence item is `observed`. `resolve-question` marks a question resolved with a required `reason` and optional supporting `evidenceIds` (which must exist); `--reopen` clears the resolution. Both are recorded in history.

## Lint and stats

`lint` (MCP `ptah_lint`) returns deterministic, advisory findings sorted by severity, code, and subject: `status-exceeds-evidence` (error), `duplicate-evidence-summary`, `inference-only-claim`, `resolved-without-reason`, `unreachable-question` (warning), and `orphan-evidence`, `observed-without-artifact`, `question-without-requirements` (info). The CLI exits `2` when any error exists. `stats` (MCP `ptah_stats`) reports evidence counts by confidence and kind, cited and artifact ratios, claim counts by support label, evidence-backed and inference-only ratios, question resolution metrics, and history length. Ratios are `null` when the denominator is zero.

## Evidence artifacts

`add-evidence --artifact FILE` records `{ sha256, sizeBytes, name }` of a raw output file (for example saved analyzer output) alongside the evidence item without embedding the file. This lets a reviewer confirm the exact bytes behind an observation.

## Multi-step planning and graph formats

`plan --steps N` runs the single-step planner greedily up to `N` times under a shared `--max-cost`, simulating that each selected action yields its listed evidence kinds; it reports every step, total estimated cost, and why it stopped (`step-limit`, `no-action-needed`, `blocked`, or `budget-exhausted`). Nothing is executed. `graph --format dot|mermaid` renders the evidence graph as Graphviz DOT or Mermaid with escaped labels.

## JSON Schema

`ptah schema` (MCP `ptah_schema`) prints the JSON Schema (draft 2020-12) for investigation documents; the committed copy at `docs/schema/ptah-investigation.schema.json` is tested against the engine so it cannot drift.

## Portable case bundles

Export an investigation as a portable JSON case, verify it, then restore the ordinary investigation document:

```bash
ptah export-case --input ./sample.investigation.json --output ./sample.ptah-case.json
ptah verify-case --input ./sample.ptah-case.json --target ./sample.bin
ptah import-case --input ./sample.ptah-case.json --output ./restored.investigation.json --target ./sample.bin
```

The versioned `ptah-investigation-case` envelope includes the validated investigation and a SHA-256 checksum over its canonical JSON payload. Import refuses invalid schemas, checksum mismatches, and—when `--target` is supplied—a target whose current bytes do not match the recorded digest. The target file itself is never embedded or executed. The checksum detects accidental corruption; it is not a digital signature and does not authenticate who created or modified a bundle.

The MCP server exposes matching `ptah_case_export`, `ptah_case_verify`, and `ptah_case_import` tools. The local workbench downloads this portable format and can import it after the matching target bytes have been uploaded; an invalid checksum or target mismatch leaves the current investigation unchanged.

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
- The graph export has no incremental update mode; adapters to the existing REA ledger remain a separate TypeScript module.
- `history` is tamper-evident, not tamper-proof: a party who can rewrite the whole file can rewrite the whole chain. Pair it with case checksums kept outside the file or with a future signature scheme.
- No dynamic analysis is performed. Any future runtime provider must add isolation, permission gates, and bounded resource use.
