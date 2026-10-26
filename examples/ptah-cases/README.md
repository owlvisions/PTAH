# PTAH example cases

Walkthrough cases built only from synthetic, non-executable fixtures committed in this repository (`examples/ptah-eval`). They show the full PTAH workflow — fingerprint, evidence, claims with honest support labels, lint, portable case export with checksum — without distributing any third-party binary.

| Case                        | Target                                      | What it demonstrates                                                                                                                               |
| --------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `synthetic-elf-walkthrough` | `../ptah-eval/elf-aarch64-shared/target.so` | Header-derived observed evidence, an inference-only claim kept honest, a hash-chained history, and a verified case bundle (`case.ptah-case.json`). |

Verify a case against its target:

```sh
node scripts/ptah.mjs verify-case --input examples/ptah-cases/synthetic-elf-walkthrough/case.ptah-case.json --target examples/ptah-eval/elf-aarch64-shared/target.so
node scripts/ptah.mjs report --input examples/ptah-eval/elf-aarch64-shared/investigation.json --format markdown
```

Real-world cases must use targets you are authorized to analyse; keep them local and export only case bundles whose evidence summaries do not disclose proprietary content.
