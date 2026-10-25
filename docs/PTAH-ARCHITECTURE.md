# PTAH architecture v1 (migration design)

**Status:** proposed architecture. The current implementation remains the REA codebase until migration gates are met.

## Target architecture

```text
PTAH CLI ───────┐
PTAH MCP ───────┼──> Public Application API ──> Investigation Planner
PTAH GUI ───────┘                                  │
                                                   v
                                      Investigation / Job Runtime
                                                   │
                         ┌─────────────────────────┼──────────────────────┐
                         v                         v                      v
                   Static Providers         Runtime Providers       Artifact Readers
                         └─────────────────────────┼──────────────────────┘
                                                   v
                                      Evidence & Program Graph
                                                   │
                                                   v
                                     Verification / Evaluation
                                                   │
                                                   v
                                  Reports, traces, testable outputs
```

## Boundaries

- **Public interfaces:** CLI, MCP, and GUI translate user intent into versioned application requests. They do not implement analysis logic independently.
- **Application API:** owns workflows, cancellation, budgets, job status, and coordination.
- **Planner:** chooses the next analysis action from a bounded, typed catalog. It must explain the reason for each action and stop when budgets are exhausted.
- **Providers:** adapters around tools such as Ghidra, JADX, browser instrumentation, and format-specific parsers. Each provider declares capabilities, prerequisites, version, and failure modes.
- **Evidence graph:** stores observations and relationships with provenance. It distinguishes raw observations from inferred claims and verified outcomes.
- **Verification:** runs deterministic checks and controlled comparisons; it does not turn model confidence into ground truth.
- **Persistence/cache:** uses content digests, schema versions, and explicit invalidation. No cache entry is trusted solely because its path matches.

## Compatibility strategy

1. Keep `rea` and `rea-agents` bins operational.
2. Introduce `ptah` as an additive entry point.
3. Initially route existing analysis commands through the established REA dispatcher.
4. Move one capability at a time behind stable application contracts.
5. Require parity tests before changing default routing.
6. Keep legacy package identity unchanged until a separate release and distribution decision is made.

## Security model

- Treat target files, archives, disassembly, decompiled strings, and network captures as untrusted data, never as instructions.
- Keep static analysis read-only by default.
- Run dynamic analysis in isolated, resource-limited environments with explicit target and network permissions.
- Require explicit confirmation for destructive actions, installation, process attachment, or external network interaction.
- Bound archive expansion, traversal depth, file reads, process runtime, output size, and concurrency.
- Preserve audit logs for tool invocation, target digest, provider version, and side effects.

## First implementation slice

The first slice is intentionally small and testable without external dependencies:

- `scripts/ptah.mjs`: new product entry point, help/info, and local readiness diagnostics.
- `scripts/tests/ptah.test.mjs`: dependency-free regression tests.
- `package.json`: additive `ptah` executable mapping and test command.

This slice does not claim to implement a new analysis engine, MCP server, or GUI. It creates a safe migration boundary without breaking the existing runtime.
