# PTAH brand migration audit

**Status: package identity migrated to `@owlvisions/ptah`; inherited runtime identifiers retained.** Earlier revisions were not release-ready as a standalone PTAH package; the package name, MCP registry name, repository URLs, installer, release tag component (`ptah-<version>`), and generated metadata now identify PTAH. This audit distinguishes verified source changes from work that still requires coordinated ownership, release, and integration decisions.

## Original vs current state

| Area                   | Original REA base                             | Current PTAH state                                                                                                                                                 | Remaining work                                                                                                          |
| ---------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| Root product messaging | REA: Reverse Engineer Anything                | Root README now presents PTAH and clearly labels this a migration preview                                                                                          | Review the site, social links, docs landing pages, screenshots, and localized READMEs                                   |
| Package metadata       | `rea-agents`, REA description and keywords    | Package is `@owlvisions/ptah`, `mcpName` `io.github.owlvisions/ptah`, repository `owlvisions/PTAH`; lockfile, `server.json`, installer, and release config updated | Publish each release to npm and the MCP registry from `owlvisions/PTAH`; keep `rea`/`rea-agents` executables as aliases |
| CLI                    | `rea` / `rea-agents` dispatch                 | PTAH-native `ptah` CLI is additive; legacy dispatch is preserved                                                                                                   | Prove command parity and deprecation/alias policy before removing old entry points                                      |
| Investigation model    | Existing REA workflows and evidence contracts | PTAH schema, fingerprinting, evidence graph/report, bounded planner and verification                                                                               | Wire the adapter into production workflows and run its TypeScript tests under the supported toolchain                   |
| MCP                    | Existing REA MCP runtime                      | Separate `ptah-mcp` stdio server for PTAH-native operations                                                                                                        | Decide official MCP registry namespace and test full client interoperability/release metadata                           |
| GUI                    | Existing REA surfaces                         | Early loopback-only PTAH workbench                                                                                                                                 | Accessibility, usability, session/CSRF review as applicable, packaging, and broader end-to-end tests                    |
| Analysis               | Many inherited REA providers                  | Bounded static adapters for `objdump`, `llvm-objdump`, and `wasm-tools`                                                                                            | Provider-by-provider parity, resource limits, OS isolation, accuracy corpus, and unsupported-format reporting           |
| Documentation          | REA docs and translations                     | PTAH architecture, engine, audit, roadmap, MCP and UI docs; original README snapshot retained                                                                      | Review every translated/generated page and remove stale links only after confirming replacement destinations            |
| Licensing/provenance   | Upstream REA license and third-party notices  | Existing license/notices retained; snapshot preserved                                                                                                              | Recheck SBOM, third-party notices, generated assets, copyright, and release provenance before publication               |
| Validation             | Upstream monorepo build/test system           | PTAH dependency-free Node tests can run independently                                                                                                              | Full build, TypeScript/Vitest tests, Python tests, website/docs checks and CI on supported Node/npm                     |

## Upstream synchronization

The repository now includes `.github/workflows/ptah-upstream-sync.yml`, which polls `morluto/rea` main every 15 minutes and proposes a review pull request after a successful rebase and PTAH-specific test run. It is an opt-in automation template: it becomes active only after this project is pushed to a repository controlled by the maintainer, GitHub Actions is enabled, and the repository permits the built-in token to open pull requests. It does not make the already-created ZIP track upstream by itself and does not auto-merge changes. Conflicts stop the proposed sync without modifying the default branch. See `docs/PTAH-UPSTREAM-SYNC.md`.

## Identifiers deliberately not renamed yet

The following are release and compatibility identifiers, not merely visible branding. Renaming them without a confirmed owner and migration plan could break installs or send users to the wrong place:

- npm package `@owlvisions/ptah` and package version `6.8.0`;
- `mcpName` value `io.github.morluto/rea`;
- repository, homepage, bug tracker, website, and community URLs that point to the upstream REA project;
- legacy executables `rea` and `rea-agents`, source/bridge identifiers, existing translations, generated metadata, and upstream license/copyright references.

Do not publish the package as an independent PTAH product until ownership of the target repository/domain/package/MCP namespace is established and all release automation is updated consistently.

## Reproducible checks

From the repository root:

```sh
node --check scripts/ptah.mjs
node --check scripts/ptah-engine.mjs
node --check scripts/ptah-mcp.mjs
node --check scripts/ptah-ui.mjs
node --check scripts/ptah-ui-server.mjs
npm run test:ptah
```

These checks cover PTAH-owned JavaScript and dependency-free tests only. They are not substitutes for the full monorepo build/test matrix. The package currently requires Node.js `^22.23.4 || ^24.22.1 || >=26.12.1`; run full validation with a supported runtime and the lockfile-compatible package manager (`npm@11.16.0`).

## Release gate checklist

- [x] Confirm ownership and availability of repository and npm package name (`@owlvisions/ptah` was unpublished before this migration); MCP registry namespace `io.github.owlvisions` follows the GitHub owner.
- [ ] Update package metadata, lockfile, bin names, docs, install commands, CI/release workflows, and generated metadata in one reviewed migration.
- [ ] Run full build, typecheck, lint, format, Vitest, Python tests, docs checks, and architecture guards under supported Node/npm.
- [ ] Run the PTAH-to-REA evidence adapter tests and end-to-end round-trip tests.
- [ ] Audit each external provider for execution policy, timeout, output bounds, cleanup, and OS-level isolation needs.
- [ ] Test the UI across supported browsers, large uploads, malformed inputs, local-network threat model, and shutdown cleanup.
- [ ] Verify third-party notices, SBOM/dependency inventory, licenses, source attribution, and generated assets.
- [ ] Build a release archive; inspect its file list, run archive integrity checks, and smoke-test from a clean extraction.
- [ ] Publish release notes that clearly separate verified capabilities from preview/roadmap items.
