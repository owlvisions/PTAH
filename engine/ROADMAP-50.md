# PTAH Engine — 50 improvements to surpass the baseline analyzer and every similar tool

Each item is executed in a **tested batch**: real code plus a test that passes
before moving on. Nothing is marked done without a test. Status: `planned`
until its batch lands. Grouped by theme; ordered roughly by impact.

Legend: ☐ planned · ☑ done (with test) · ◐ partial.

## A. Deeper static analysis (1–10)

1. ☐ Cross-reference graph (xrefs) per symbol, merged across providers.
2. ☐ Call graph export (DOT/Mermaid/JSON) from Ghidra + radare2, reconciled.
3. ☐ Control-flow graph per function with basic blocks.
4. ☐ Type/struct recovery surfaced from Ghidra decompilation into evidence.
5. ☐ String cross-reference: which function references each string.
6. ☐ Constant and crypto-constant detection (AES S-box, SHA IV, base64 tables).
7. ☐ Import resolution across libraries (which dylib/so exports a symbol).
8. ☐ Entry-point and init/fini array recovery for ELF/PE/Mach-O.
9. ☐ Section entropy map with packed-region flagging per offset window.
10. ☐ Symbol demangling (Itanium C++, Rust, Swift) in PTAH's own code.

## B. Dynamic analysis in a consented sandbox (11–20)

11. ☐ bubblewrap/container sandbox runner with no network by default.
12. ☐ Syscall tracing (strace/seccomp) with an allow/deny policy, as evidence.
13. ☐ Network capture during a run, linked back to static endpoints.
14. ☐ Filesystem/registry write observation during a run.
15. ☐ Frida instrumentation scripts shipped, consent-gated, sandbox-only.
16. ☐ Unicorn function-level emulation: call a function with inputs, record I/O.
17. ☐ angr symbolic execution to reach a target block / solve a branch.
18. ☐ Anti-debug / anti-VM detection reported (never bypassed).
19. ☐ Dynamic↔static cross-validation: which recovered functions actually ran.
20. ☐ Screenshot/behavior timeline for GUI targets, as evidence artifacts.

## C. Application mapping & reconstruction (21–30)

21. ☐ Full app map: screens, features, APIs, each with cited evidence.
22. ☐ OpenAPI export from observed/recovered HTTP endpoints.
23. ☐ Data-model recovery (entities/relations) from storage + API shapes.
24. ☐ JavaScript/Electron module reconstruction from ASAR/bundles.
25. ☐ Source↔binary mapping when debug info or sourcemaps exist.
26. ☐ Spec generation (original, our words) from the app map.
27. ☐ Scaffold an original reimplementation project from the spec.
28. ☐ Feature-parity matrix: original vs reimplementation, per feature.
29. ☐ Auto-generated tests asserting behavioral parity.
30. ☐ Fresh-eyes review pass by a separate agent over the reconstruction.

## D. Intelligence & detection (31–38)

31. ☐ YARA rule _bundles_ shipped (malware families, packers, compilers).
32. ☐ CVE scanning with an offline, versioned advisory database + updater.
33. ☐ SBOM export (CycloneDX / SPDX) from the dependency inventory.
34. ☐ Capability-to-ATT&CK mapping with confidence and evidence links.
35. ☐ Similarity/clustering: fuzzy hashes (ssdeep/TLSH) across a corpus.
36. ☐ Diffing two versions: added/removed/changed functions and strings.
37. ☐ License detection from embedded notices and dependency metadata.
38. ☐ Secret validation hooks (opt-in, user-authorized scope only).

## E. Performance, scale & correctness (39–44)

39. ☐ Persistent on-disk cache keyed by SHA-256 across runs.
40. ☐ Parallel multi-target analysis with a work queue and progress events.
41. ☐ Incremental analysis: reuse unchanged-region results on a new version.
42. ☐ Deterministic, byte-stable reports verified by a golden-file test.
43. ☐ Ed25519-signed, portable case bundles with a tamper-evident chain.
44. ☐ Streaming/bounded memory for very large targets.

## F. Surfaces & experience (45–50)

45. ☑ Wire the engine into the `ptah` CLI (every provider reachable). — `ptah engine` (task/matrix/benchmark/providers/crossvalidate), tested.
46. ☐ Expose engine providers as MCP tools for agents.
47. ☐ A graphical workbench better than peers: evidence graph, hex+entropy,
    provider matrix, timeline, side-by-side diff, dark/light.
48. ☐ HTML and SARIF reports with navigation and evidence drill-down.
49. ☐ A plugin API so third parties add providers without forking.
50. ☐ Benchmark suite + public capability matrix vs named peers, reproducible.

## Execution rule

A batch lands only when `node --test engine/test/*.test.mjs` is green, lint and
format pass, and the capability matrix / README reflect the change. Beyond-the baseline analyzer
items are additive; nothing removes a working capability.
