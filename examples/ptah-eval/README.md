# PTAH evaluation suite

Pinned, synthetic, non-executable fixtures with reference answers. Run:

```sh
node scripts/ptah.mjs eval --suite examples/ptah-eval
node scripts/ptah.mjs eval --suite examples/ptah-eval --json > eval-report.json
node scripts/ptah.mjs eval --suite examples/ptah-eval --baseline eval-report.json
```

Each case directory contains `case.json` (target path, expectations, optional investigation and reference claim labels) and the target bytes. `expect` entries support exact values and the operators `$regex`, `$gte`, `$lte`, `$includes`, `$length`. Metrics reported: check pass rate, claim label precision against the reference, unsupported (inference-only) claim rate, and median/p95 wall-clock latency. `--baseline` compares against a previous report and exits nonzero on regression.

Regenerate the fixture bytes with `node examples/ptah-eval/generate-fixtures.mjs`; the digests in `case.json` pin the exact content. These fixtures are hand-built headers, not real programs, and establish the harness; add authorized real-world targets locally without committing them.
