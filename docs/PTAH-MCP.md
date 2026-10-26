# PTAH MCP server

PTAH includes a dependency-free Model Context Protocol (MCP) stdio server at `scripts/ptah-mcp.mjs`. It can run before the REA TypeScript runtime has been built.

## Run locally

```sh
node scripts/ptah-mcp.mjs
```

When installed as an npm package, the executable is `ptah-mcp`. Configure your MCP client to launch that executable using stdio transport. For clients that require an explicit command, use `node` with the absolute path to `scripts/ptah-mcp.mjs` as its sole argument.

## Tools

- `ptah_fingerprint`: hash and identify a regular file without executing it.
- `ptah_verify`: validate an investigation and optionally re-hash its target.
- `ptah_case_export`: write a portable investigation case bundle with a SHA-256 corruption checksum.
- `ptah_case_verify`: validate a case bundle and optionally re-hash its target.
- `ptah_case_import`: verify a case bundle and atomically restore its investigation JSON.
- `ptah_report`: return a provenance-aware report as JSON (default) or Markdown (`format: "markdown"`).
- `ptah_diff`: deterministically compare two investigations or verified case bundles (`base`, `head`).
- `ptah_graph`: return the directed evidence graph.
- `ptah_plan`: select one deterministic next action under call/cost budgets.
- `ptah_providers`: discover provider commands on `PATH` without executing them.
- `ptah_static_analyze`: run allow-listed `objdump`, `llvm-objdump`, or `wasm-tools` file/object metadata inspection or WebAssembly validation (which requires a confirmed WebAssembly signature) with a bounded timeout and output cap; this does not execute the target program.

Tools accepting file paths operate with the permissions of the local MCP server process. Only connect clients and files you trust. The server does not accept arbitrary shell commands and does not run analyzed targets. Case checksums detect accidental corruption but do not authenticate bundle authors. Provider version probes remain an explicit CLI opt-in (`ptah providers --probe`) rather than an MCP tool. Static metadata analysis does launch the selected analyzer against the file; the adapter does not yet provide OS-level CPU/memory/filesystem sandboxing.

## Protocol and tests

The server implements JSON-RPC over newline-delimited stdio messages and advertises protocol version `2024-11-05`. It handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`. Regression tests are in `scripts/tests/ptah-engine.test.mjs` and run with `npm run test:ptah` (the tests themselves use Node's built-in test runner).

## Limitations

This server is intentionally a narrow, dependency-free entry point; it does not replace the existing REA MCP server. Target-specific analyzer execution, process-level resource isolation, a production-grade GUI integration, and full monorepo build verification remain separate milestones.
