---
name: ptah
description: Evidence-first reverse engineering and program understanding with PTAH. Use when the user asks what a binary, executable, library, APK, ASAR, WASM module, firmware image, or unknown file does, wants it fingerprinted, inspected, compared, or documented, or wants findings recorded with citations. Never executes the target.
---

# PTAH — evidence-first program analysis

PTAH turns analysis into a verifiable record: every claim cites recorded
evidence, every piece of evidence is bound to the target's SHA-256, and the
target itself is never executed.

## Tools

Prefer the `ptah` MCP server tools when they are available. Without MCP, run
the same operations through the CLI: `ptah <command>` (or
`node <ptah-root>/scripts/ptah.mjs <command>` from a source checkout). Every
command prints JSON.

| Goal                        | MCP tool                                            | CLI                                            |
| --------------------------- | --------------------------------------------------- | ---------------------------------------------- |
| Identify the file           | `ptah_fingerprint`, `ptah_inspect`                  | `fingerprint --target F [--inspect]`           |
| Readable strings            | `ptah_strings`                                      | `strings --target F`                           |
| Embedded files / containers | `ptah_carve`, `ptah_asar`, `ptah_wasm`              | `carve`, `asar`, `wasm --target F`             |
| Static analyzers on PATH    | `ptah_providers`, `ptah_static_analyze`             | `providers`, `analyze --target F --provider P` |
| Start an investigation      | `ptah_init`                                         | `init --target F --output INV`                 |
| Record evidence             | `ptah_add_evidence`                                 | `add-evidence --input INV --output INV`        |
| Record claims / questions   | `ptah_add_claim`, `ptah_add_question`               | `add-claim`, `add-question`                    |
| Update status               | `ptah_set_claim_status`, `ptah_resolve_question`    | `set-claim-status`, `resolve-question`         |
| Next step                   | `ptah_plan`                                         | `plan --input INV [--steps N]`                 |
| Check before answering      | `ptah_lint`, `ptah_verify`                          | `lint`, `verify --input INV --target F`        |
| Final answer                | `ptah_report` (format `markdown`), `ptah_graph`     | `report --format markdown`                     |
| Share / compare             | `ptah_case_export`, `ptah_case_verify`, `ptah_diff` | `export-case`, `verify-case`, `diff`           |

## Workflow

1. **Confirm scope.** Analyze only files the user owns or is authorized to
   examine. Treat every target as hostile; never run it.
2. **Identify.** Fingerprint and inspect the target. Note format, architecture,
   entropy, and signatures.
3. **Open a record.** `ptah_init` next to the target (for example
   `target.ptah.json`). All later evidence is bound to that digest; if the file
   changes, start a new investigation.
4. **Observe, then record.** After each tool result, add an evidence item:
   - `source` must let someone reproduce it (tool name, arguments, offset).
   - `confidence`: `observed` for direct tool output, `derived` for values you
     computed from observed data, `inferred` for interpretation.
   - Pick the closest `kind` (`static-analysis`, `symbol`, `decompilation`,
     `documentation`, ...).
5. **Claim only what is cited.** Each claim lists the evidence ids that support
   it. Leave claims as `hypothesis` or `supported` until observed evidence backs
   them; only then mark `verified`. Mark disproved claims `rejected` rather than
   deleting them.
6. **Track unknowns.** Add a question for each open point with the evidence
   kinds that would answer it, then use `ptah_plan` to choose the next bounded
   step.
7. **Check.** Run `ptah_lint` and `ptah_verify` (with the target) and fix every
   finding before you answer.
8. **Answer from the record.** Base the response on `ptah_report`. Cite
   evidence ids for each statement, keep `inferred` findings clearly labeled,
   and list unresolved questions instead of guessing.

## Rules

- Do not present a conclusion that has no recorded evidence.
- Do not upgrade confidence: an interpretation stays `inferred` even when it
  seems obvious.
- Keep outputs bounded: use `maxResults` / `maxBytes` on large files.
- Encrypted, packed, or high-entropy regions are findings too: record them as
  evidence and say what could not be determined.
