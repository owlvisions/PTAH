# PTAH integration checkpoint — 2026-10-26

## Source and history

- Existing PTAH work branch: `db6225f41b3301206a5083790aef51c03c2b9ae9`.
- REA upstream main fetched and verified: `1173c0a9dc1b352a60943a491462294db8f353ae` (6.8.0).
- Applied the existing PTAH overlay to the real upstream checkout. Resolved README and package conflicts explicitly, retaining upstream scripts, dependencies, packaged environment helper and runtime changes. Preserved the latest upstream README as a provenance snapshot and retained its runtime instructions in the root README.
- The integration tree is recorded with both revisions as parents. Existing PTAH history is retained; no unrelated-history conflict was resolved by blindly selecting a side, and no default branch rewrite is needed.
- Old unpushed Copilot/Codespaces changes were not used.

## Implemented changes

- PTAH engine, CLI, MCP, UI and Evidence adapter retained on latest fetched REA.
- Fixed strict TypeScript fixture typing in the Evidence adapter tests.
- Upstream automation merges into a review branch rather than rebasing published PTAH history. Conflicts abort; publication uses a lease and new PRs are drafts. A local Git scenario verified preservation of both parents and repeat-run no-op behavior.
- Validation follows `.nvmrc`; obsolete `npm run check` invocations use `check:ci`. Legacy bootstrap is manual and no longer force-pushes its branch.
- Updated Zod 4.4.3 → 4.6.7 and fast-uri 3.1.8 → 3.1.9. Preserved the historical datetime acceptance oracle independently of Zod's newly tightened seconds requirement; production datetime semantics are unchanged.
- Regenerated error schema, dependency inventory and runtime notice metadata. Verified that both updated packages retain the license text already preserved in the notices.
- Upstream release entry jobs are gated to `morluto/rea` while PTAH still retains its legacy npm/MCP identifiers. This integration does not publish an npm/MCP release.

## Executed validation

| Check                                                                            | Observed result                                                                                                                                  |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Locked dependency installation                                                   | Passed on Node 24.22.1; npm 11.9.0 (package manager declares 11.16.0)                                                                            |
| Runtime build (`build:cached`)                                                   | Passed; bundler emitted non-fatal dynamic-import warnings                                                                                        |
| Typecheck and ordinary lint (`check:fast`)                                       | Passed                                                                                                                                           |
| CI static tasks, architecture guards, discovery, Python, production reachability | Completed successfully before the final typed-lint stage                                                                                         |
| PTAH native suite                                                                | 34 passed                                                                                                                                        |
| PTAH Evidence adapter                                                            | 3 passed                                                                                                                                         |
| Python                                                                           | 42 bridge tests + 93 analysis-efficiency tests passed                                                                                            |
| Domain/services/conformance selection                                            | 579 files passed, 2 failed; 11,047 passed, 49 failed, 12 skipped, before datetime oracle correction                                              |
| Datetime follow-up                                                               | All 52 passed after correcting the historical test oracle                                                                                        |
| Remaining source failure comparison                                              | `decompileAll.test.ts`: identical 48 failed / 2 passed on integrated and pristine REA source with the same installed dependencies                |
| Representative MCP failure comparison                                            | Same test failed on both integrated and pristine REA; diagnostic reported `ps` ownership inspection failure (`fatal library error, lookup self`) |
| README consistency                                                               | 9 passed                                                                                                                                         |
| Documentation generation and `docs:check`                                        | Passed after updating schema and verified notices                                                                                                |
| npm audit                                                                        | 0 vulnerabilities reported                                                                                                                       |
| Full `npm test`                                                                  | Attempted, then interrupted after repeated process-ownership environment failures; no complete pass claimed                                      |
| Full typed lint                                                                  | Native process received SIGKILL; memory-limited retry reached about 5 GB RSS and was interrupted; complete `check:ci` is not green               |

The post-update datetime follow-up does not constitute a fresh complete source-suite run. The baseline worktree shared the installed dependencies with the integrated worktree; it isolates source changes, not dependency changes. Real external providers, all platforms, all client integrations and OS sandboxing were not verified here.

## Remaining requirements

- Run complete acceptance tests and typed lint on a host with working process ownership inspection and sufficient resources, then review and merge the integration normally.
- GitHub Actions account restriction remains external; local checks do not prove scheduled runs or PR creation on GitHub.
- npm/MCP namespace migration, provider parity, production integration of the standalone Evidence adapter, and production UI readiness remain open. Existing compatibility identifiers are intentional; do not describe this as a finished universal analyzer or complete rebrand.

## Rollback

Before merging, discard the review branch to leave the default branch unchanged. After a normal merge, revert the integration merge with the appropriate first parent; do not force-push or erase retained history. Preserve local investigations and Evidence independently of source rollback.
