# PTAH v0.6 — file-backed investigation workflow

This release is an additive, dependency-free layer over the existing REA codebase. It is not yet a replacement for the existing analysis runtime and does not claim that the complete PTAH product is finished.

## Implemented and tested

- `ptah fingerprint --target FILE`: streams the file to calculate SHA-256, reads only a small header for basic signature recognition, and reports size/path/mtime. It does not execute or modify the target.
- `ptah init --target FILE --output FILE [--id ID]`: creates a schema-v1 investigation whose target digest is calculated from the actual target bytes.
- `ptah add-evidence --input FILE --output FILE --id ID --kind KIND --summary TEXT --source REF [--confidence observed|derived|inferred]`: appends source-linked evidence, binds it to the investigation's target digest, validates the full document, and saves it atomically.
- `ptah report`, `ptah graph`, and `ptah plan`: validate and report on the versioned investigation document.
- `ptah providers [--json]`: checks for selected external analysis tools in `PATH`. It only checks for executable presence and does not run them or prove their version/license/readiness.

## Example workflow

```bash
node scripts/ptah.mjs providers --json
node scripts/ptah.mjs fingerprint --target ./sample.wasm
node scripts/ptah.mjs init --target ./sample.wasm --output ./case.json
node scripts/ptah.mjs add-evidence \
  --input ./case.json --output ./case.with-evidence.json \
  --id ev-001 --kind static-analysis \
  --summary "Found exported function" --source "sample.wasm:exports" \
  --confidence observed
node scripts/ptah.mjs report --input ./case.with-evidence.json
node scripts/ptah.mjs graph --input ./case.with-evidence.json
```

## Validation performed for this release

```bash
node --test scripts/tests/ptah.test.mjs scripts/tests/ptah-engine.test.mjs
```

The dependency-free PTAH test suite currently contains 18 tests. The test suite exercises input validation, evidence provenance, stale-target rejection, graph output, deterministic planning, file fingerprinting, initialization, provider discovery, and a file-backed init/add-evidence/report workflow.

## Known gaps — not represented as completed

- The investigation graph is not yet adapted to REA's full existing Evidence Ledger.
- The planner chooses one deterministic action from declared evidence kinds; it does not execute providers or use model-based information gain.
- `providers` is PATH presence detection only, not provider health checks or end-to-end analysis validation.
- There is no PTAH GUI in this release.
- No new native-analysis, Android, or runtime instrumentation engine is implemented by these commands; existing REA workflows remain the compatibility backend.
- The full monorepo build and legacy test suite have not been run in this environment because the available Node.js version is below the package engine requirement and dependencies are not installed.

## Additional file-backed authoring commands

The investigation can now be built up through validated CLI commands, without hand-editing JSON:

```bash
node scripts/ptah.mjs add-claim --input ./case.with-evidence.json --output ./case.with-claim.json \
  --id claim-001 --text "The module exports x" --evidence-ids ev-001 --status supported
node scripts/ptah.mjs add-question --input ./case.with-claim.json --output ./case.with-question.json \
  --id q-runtime --text "Does x change at runtime?" --priority 90 \
  --required-evidence-kinds runtime-observation
node scripts/ptah.mjs add-action --input ./case.with-question.json --output ./case.ready.json \
  --id runtime-trace --name "Run a permitted runtime trace" \
  --produces runtime-observation --cost 2
node scripts/ptah.mjs plan --input ./case.ready.json --max-calls 1 --max-cost 3
```

The full file-backed flow (init, evidence, claim, question, action, planner) is covered by an integration test. Fingerprinting also checks for common file changes during the operation and refuses a result when the target appears to change while being read.
