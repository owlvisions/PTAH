# PTAH — Program Understanding & Analysis Toolkit

<div align="center">

**بتاح · PTAH** — evidence-first reverse engineering for binaries, applications, and runtime behavior.

**Every claim cites its evidence. Targets are never executed. Results are portable, checksummed, and diffable.**

`ptah` CLI · `ptah-mcp` MCP server · `ptah ui` local workbench · inherited REA analyzers underneath

</div>

PTAH is the primary product in this repository. It owns the investigation model, the CLI and MCP contracts, the local workbench, and the documentation. The REA runtime it inherited is retained as an internal compatibility layer: PTAH calls REA's analyzers through bounded adapters and keeps the `rea` / `rea-agents` entry points working for existing automation while PTAH-native capabilities grow.

## Why PTAH

Most reverse-engineering assistants return answers. PTAH returns **investigations**: versioned, provenance-checked records that can be verified, exported, imported, compared, and reported without trusting the tool or the model that produced them.

| PTAH guarantee                  | What it means in practice                                                                                                                                                                                                                          |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Evidence first**              | Every claim must cite recorded evidence with a confidence level (`observed`, `derived`, `inferred`). Reports label claims `evidence-backed`, `derived-support`, or `inference-only`; `verified` appears only when a workflow actually verified it. |
| **Bound to target bytes**       | Investigations and every evidence item carry the target's SHA-256. Stale or cross-target evidence is rejected; `ptah verify --target` detects drift when the file changes.                                                                         |
| **No target execution**         | Fingerprinting, metadata analysis, and WebAssembly validation launch the analyzer against the file with fixed argv, no shell, a wall-clock timeout, and output caps. The target itself is never run.                                               |
| **Portable, checksummed cases** | `export-case` wraps an investigation in a `ptah-investigation-case` envelope with a canonical-JSON SHA-256. `import-case` refuses corruption, schema violations, and target mismatch.                                                              |
| **Deterministic**               | Reports, graphs, plans, and diffs are byte-stable for the same input, so they can be reviewed, committed, and compared across time.                                                                                                                |
| **Honest planning**             | The bounded planner returns `planned`, `blocked`, `budget-exhausted`, or `no-action-needed` — never fabricated progress.                                                                                                                           |
| **Local by default**            | The workbench binds to loopback only, validates Host headers, stores uploads in a private temp workspace with restrictive permissions, and deletes them on shutdown.                                                                               |

## Quick start with PTAH

PTAH-native commands run from a source checkout without installing project dependencies. Use a supported Node.js (`^22.23.4 || ^24.22.1 || >=26.12.1`).

```sh
node scripts/ptah.mjs help
node scripts/ptah.mjs self-check --json
node scripts/ptah.mjs fingerprint --target ./sample.bin --inspect     # format details + entropy, no execution
node scripts/ptah.mjs strings --target ./sample.bin --min-length 8     # bounded printable strings with offsets
node scripts/ptah.mjs init --target ./sample.bin --output ./sample.investigation.json
node scripts/ptah.mjs add-evidence --input ./sample.investigation.json --output ./sample.investigation.json \
  --id ev-1 --kind static-analysis --summary "Exports a login handler" --source "objdump -h" \
  --confidence observed --artifact ./objdump-output.txt
node scripts/ptah.mjs add-claim --input ./sample.investigation.json --output ./sample.investigation.json \
  --id c-1 --text "The binary exposes a login handler" --evidence-ids ev-1
node scripts/ptah.mjs set-claim-status --input ./sample.investigation.json --output ./sample.investigation.json \
  --id c-1 --status verified --reason "handler symbol observed in section table"
node scripts/ptah.mjs lint --input ./sample.investigation.json
node scripts/ptah.mjs stats --input ./sample.investigation.json
node scripts/ptah.mjs history --input ./sample.investigation.json
node scripts/ptah.mjs report --input ./sample.investigation.json --format markdown
node scripts/ptah.mjs graph --input ./sample.investigation.json --format mermaid
node scripts/ptah.mjs plan --input ./sample.investigation.json --steps 3
node scripts/ptah.mjs export-case --input ./sample.investigation.json --output ./sample.ptah-case.json
node scripts/ptah.mjs diff --base ./yesterday.ptah-case.json --head ./sample.ptah-case.json
node scripts/ptah.mjs ui
```

Run the dependency-free test suite with `npm run test:ptah`. Full instructions, including the MCP registration for `ptah-mcp`, are in `docs/PTAH-GETTING-STARTED.md` and `docs/PTAH-MCP.md`.

## What PTAH does today

- **Investigation engine** (`scripts/ptah-engine.mjs`, `scripts/ptah-analysis.mjs`, `scripts/ptah-case-tools.mjs`): fingerprinting with 25+ magic signatures, ELF/PE/Mach-O header decoding, Shannon entropy, bounded ASCII/UTF-16LE strings, embedded-signature carving, native Electron ASAR and WebAssembly section parsing, schema and provenance validation with a published JSON Schema, hash-chained history, freeze/unfreeze, tags, evidence artifact digests, related-case links, same-target merge with conflict policy, legacy migration, reports (JSON and Markdown), graphs (JSON, DOT, Mermaid), deterministic diff, lint and metrics, target-drift verification and `watch`, single- and multi-step bounded planning, checksummed case bundles with optional gzip, Ed25519 signatures, and AES-256-GCM encryption.
- **Analyzers** (`ptah analyze`): allow-listed `objdump`, `llvm-objdump`, `readelf`, `nm`, `file`, `rabin2`, `rz-bin`, `monodis`, `aapt2`, `wasm-objdump`, `wasm-tools` with fixed argv, no shell, timeout, output cap, pre/post target digests, optional bubblewrap isolation (`--isolation auto|required|none`) and prlimit CPU/memory limits — applied when available and reported honestly when not. Every adapter has a conformance test (missing tool, nonzero exit, timeout, output cap, wrong format, paths with spaces).
- **Evaluation** (`ptah eval`): pinned synthetic fixtures with reference answers in `examples/ptah-eval`; reports check pass rate, claim-label precision, unsupported-claim rate, median/p95 latency, and `--baseline` regression detection.
- **CLI** (`ptah`): 40+ commands including `info`, `self-check`, `providers`, `isolation`, `fingerprint --inspect`, `strings`, `carve`, `asar`, `wasm`, `init`, `add-evidence`, `add-claim`, `add-question`, `add-action`, `set-claim-status`, `resolve-question`, `freeze`, `unfreeze`, `verify`, `lint`, `stats`, `history`, `schema`, `migrate`, `export-case`, `verify-case`, `import-case`, `sign-case`, `keygen`, `encrypt-case`, `decrypt-case`, `link-case`, `merge`, `report`, `diff`, `graph`, `plan`, `analyze`, `eval`, `watch`, `completion`, and `ui`; `--quiet` everywhere. Any other command is routed to the inherited REA CLI.
- **MCP server** (`ptah-mcp [--root DIR]`): 20 tools (`ptah_fingerprint`, `ptah_inspect`, `ptah_strings`, `ptah_carve`, `ptah_asar`, `ptah_wasm`, `ptah_verify`, `ptah_report`, `ptah_diff`, `ptah_lint`, `ptah_stats`, `ptah_schema`, `ptah_graph`, `ptah_plan`, `ptah_providers`, `ptah_isolation`, `ptah_static_analyze`, `ptah_eval`, `ptah_case_export`, `ptah_case_verify`, `ptah_case_import`), three workflow prompts, and root-bounded investigation resources.
- **Workbench** (`ptah ui`): upload a target, build the investigation (every change in hash-chained history), run analyzers now or as cancellable background jobs, compare with an uploaded case, inspect reports/graphs/plans/lint/metrics/format/strings/carving/ASAR/WASM, view the evidence graph as SVG, and download Markdown reports, DOT/Mermaid graphs, and verified case bundles.
- **Integrations**: `integrations/vscode-ptah` (unpublished VS Code skeleton), `ptah completion bash|zsh|fish`, Arabic guide `docs/PTAH-GETTING-STARTED.ar.md`, example case in `examples/ptah-cases`, PTAH disclosure policy in `SECURITY.md`.
- **Inherited analyzers** (REA layer): native binaries via Hopper, Ghidra, or IDA; JavaScript and Electron applications; .NET assemblies; Android; WebAssembly; firmware; and web captures. These run beneath PTAH and are documented in the collapsed section below.

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│  PTAH surfaces      ptah CLI · ptah-mcp (MCP) · ptah ui      │
├──────────────────────────────────────────────────────────────┤
│  PTAH engine        investigations · evidence · claims       │
│                     verify · report · graph · plan · diff    │
│                     checksummed portable cases               │
├──────────────────────────────────────────────────────────────┤
│  Bounded adapters   objdump · llvm-objdump · wasm-tools      │
│                     fixed argv · no shell · timeout · caps   │
├──────────────────────────────────────────────────────────────┤
│  Inherited REA runtime (compatibility layer)                 │
│  Hopper/Ghidra/IDA bridges · JS/Electron · .NET · Android …  │
└──────────────────────────────────────────────────────────────┘
```

PTAH never forks REA state: it adapts REA evidence into its own provenance model (`src/application/investigation/PtahEvidenceAdapter.ts`) and replaces inherited analyzers only when parity tests pass.

## PTAH documentation

| Topic                                          | Location                                            |
| ---------------------------------------------- | --------------------------------------------------- |
| Getting started, commands, limits              | `docs/PTAH-GETTING-STARTED.md`                      |
| Engine schema and case bundles                 | `docs/PTAH-ENGINE-V1.md`                            |
| MCP server and tools                           | `docs/PTAH-MCP.md`                                  |
| Local workbench                                | `docs/PTAH-UI.md`                                   |
| Architecture and roadmap                       | `docs/PTAH-ARCHITECTURE.md`, `docs/PTAH-ROADMAP.md` |
| Development prompt for agents and contributors | `docs/PTAH-DEVELOPMENT-PROMPT.md`                   |
| Brand migration status and release gates       | `docs/PTAH-BRAND-AUDIT.md`                          |
| Upstream REA sync policy                       | `docs/PTAH-UPSTREAM-SYNC.md`                        |

## Status and honesty notes

- This repository is a **migration preview**. PTAH is the product identity and the primary interface; the npm package is still published as `rea-agents`, and `mcpName`, repository URLs, and legacy executables remain unchanged until an owner-controlled namespace and coordinated release migration exist (see `docs/PTAH-BRAND-AUDIT.md`).
- Case checksums detect corruption; they are not signatures and do not authenticate authors.
- Analyzer adapters apply bubblewrap isolation and prlimit limits only when those tools are present; each run records whether isolation was applied. Treat every analyzed target as hostile regardless.
- Case signatures authenticate a key holder, not a person; encryption protects confidentiality only. The history chain is tamper-evident, not tamper-proof.
- Capability claims above are backed by `npm run test:ptah`, CI checks, and Git history. Nothing is described as implemented without tests.

## Licensing

PTAH-authored and REA-authored code are licensed under MIT; see the inherited section below for third-party notices and commercial-tool terms.

<details>
<summary><strong>Inherited REA runtime documentation</strong> — analyzers, setup, showcases, and FAQ for the compatibility layer beneath PTAH (click to expand)</summary>

## REA compatibility runtime — upstream documentation

### One MCP for reverse engineering across binaries, applications, and runtime behavior.

**See a feature you like. Understand how it works, down to the binary level.**

[![npm version](https://img.shields.io/npm/v/rea-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/rea-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-contracts.md#generated-catalog)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#what-you-can-analyze)
[![skills.sh](https://skills.sh/b/morluto/rea?style=flat-square)](https://skills.sh/morluto/rea/reverse-engineer-anything)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Discord](https://img.shields.io/discord/1556595354999332884?logo=discord&logoColor=white&label=Discord&color=5865F2)](https://discord.gg/GkcryMnJDM)

<a href="https://trendshift.io/repositories/82054?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-82054" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/82054" alt="morluto%2Frea | Trendshift" width="250" height="55"/></a>

**[Website](https://rea.tools/) · [Guides](https://rea.tools/guides/) · [Showcases](https://rea.tools/showcase/)**

[Quick start](#quick-start) · [How REA works](#how-rea-works) · [What you can analyze](#what-you-can-analyze) · [Showcases](#showcases) · [Build RL environments](#build-rl-environments) · [FAQ](#faq) · [Documentation](#documentation)

<code>npx rea-agents setup</code>

</div>

> [!IMPORTANT]
> Get REA from [morluto/rea](https://github.com/morluto/rea),
> [rea.tools](https://rea.tools/), or the [rea-agents npm package](https://www.npmjs.com/package/rea-agents).
> Follow the installation and release links from these official sources. A similar
> repository name or copied README does not establish that a download is official.

<div align="center">

<br />

<img src="docs/assets/rea-hopper-analysis.png" alt="REA launching its analysis bridge inside Hopper while inspecting a native binary" width="1200" />

<br /><br />

<table aria-label="REA community">
<tr>
<td align="center" width="360">
  <a href="https://discord.gg/GkcryMnJDM">
    <img src="docs/assets/discord.svg" height="42" alt="Discord" /><br />
    <strong>Join the Reverse Engineering Community</strong>
  </a><br />
  <sub>Discord · Q&amp;A · Show and Tell</sub>
</td>
</tr>
</table>

<br />

</div>

---

See a feature in an app that you want in your own product? Ask your agent to investigate it with REA. It can inspect the app without its source code, explain how the feature works, show the evidence, and build a version for your project.

REA connects your agent to tools for inspecting native binaries, JavaScript and Electron apps, .NET assemblies, and websites. You can also use the same tools from your terminal. Analysis runs locally, and results include the evidence and limitations behind each conclusion.

Setup registers REA with your agent and installs matching workflow instructions. Native analysis can use an existing Hopper, Ghidra, or IDA installation; setup can optionally install Hopper with approval. Static JavaScript analysis needs no native analysis engine.

> **[Visit the REA website](https://rea.tools/)** for setup instructions, illustrated guides, and real case studies.

## Quick start

On Linux, Ghidra, JADX, firmware tool launches and static JavaScript/Electron
analysis require a procps-compatible `ps` on REA's `PATH` for process ownership
checks. Recovery steps are in `docs/installation.md` under
"Linux owned-process prerequisite".

### Set up your agent

With Node.js and npm installed, run:

```bash
npx rea-agents setup
```

Choose your agents, review the proposed changes, and approve them. Setup adds
REA's MCP server and matching workflow instructions, with backups of existing
configuration. Restart your agent afterward.

Setup supports Claude Code, Codex, Cursor, Gemini CLI, Grok Build and
[other agents](docs/installation.md#supported-agents). See
[installation and setup](docs/installation.md) for provider configuration and
manual MCP registration.

MCP uses compact input schemas by default to reduce context overhead. Set
`REA_MCP_INPUT_SCHEMA_PROFILE=full` in your MCP registration when you need the
complete advertised field guidance and nested validation details. Both profiles
keep the full tool set and canonical server validation. See
"Compact input schema profile" in the MCP contracts guide.

### Ask your agent

```text
Understand how search works in the Notes app, show me the evidence, and build a
similar feature for my project.
```

Replace Notes with your target app and the feature you want to understand.

### Use the terminal

Inspect an extracted JavaScript/Electron app directory or ASAR:

```bash
npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json
```

The result includes modules, imports, Electron boundaries and their evidence.
Replace the path with your target, such as `"D:/apps/example"` on Windows.

To install the `rea` command for regular use:

```bash
npm install --global rea-agents
rea --help
```

For native analysis, configure a provider first. See the
[CLI and Evidence guide](docs/cli.md) for native commands, provider selection,
snapshots and scripting.

### Update REA

REA changes quickly, and new releases include frequent bug fixes. Keep your
installation up to date.

For a CLI installed with `npm install --global` or `bun add --global`:

```bash
rea update
```

`rea --update` is an alias for this verified workflow and accepts the same global
output flags. Use `rea update` when combining it with other command controls.

Updater commands retain at most 4 MiB of stdout and stderr combined. Oversized
metadata replies are rejected after the command exits; verbose installs continue
with bounded diagnostics. Human progress output respects terminal backpressure
and waits for submitted writes to finish.

Bun global updates require Bun 1.2.17 or later. With an older Bun release,
upgrade Bun manually before running `rea update`.

To refresh your agent registrations and skill, run the setup command printed
by the update.

If you use `npx`, update your agent setup with:

```bash
npx rea-agents@latest setup
```

Review the setup changes and restart your agent. For one-off CLI commands,
use `npx rea-agents@latest` followed by the command. With Bun, use
`bunx rea-agents@latest` in place of `npx rea-agents@latest`.

## How REA works

Your agent calls REA through MCP to inspect the target and trace relevant code.
REA returns findings with their evidence. The agent uses them to ask follow-up
questions, explain the behavior, or write and test an implementation.
CLI commands use the same workflows.

![REA investigation flow: your agent asks about a local target, REA inspects and traces it using analysis tools, and the agent uses the returned code, references and unknowns to explain, implement and test.](website/public/assets/figures/rea-investigation-flow.svg)

[Open the full-size figure](website/public/assets/figures/rea-investigation-flow.svg).

<a id="current-status"></a>

## What you can analyze

REA requires Node.js 22.x (>=22.23.4), 24.x (>=24.22.1), or 26.12.1+, plus npm.
Additional tools and host support depend on the target:

| Target                  | What REA returns                                                                                  | Requirements and guide                                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Desktop installations   | Runtime candidates, supporting files, component markers and next probes                           | Built-in bounded directory/header inspection; [desktop applications](docs/desktop-applications.md)                                    |
| Native binaries         | Pseudocode, assembly, strings, symbols, calls and references                                      | Hopper, Ghidra or IDA; [native analysis](docs/native-investigation.md)                                                                |
| Offline ELF layout      | Sections, segments, original symbols/relocations and static mitigation candidates                 | Caller-supplied pwntools on Linux x64; [binary diagnostics](docs/binary-diagnostics.md)                                               |
| Go binaries             | Embedded compiler version, modules, replacements and build settings                               | Built-in static ELF/PE/thin Mach-O inspection; no Go installation required                                                            |
| GPU code objects        | CUDA/HIP targets, selected kernel parameters and resources, retained PTX text                     | Built-in static ELF/PE/fatbin/CUBIN/PTX inspection; [GPU code objects](docs/gpu-code-objects.md)                                      |
| Model artifacts         | GGUF / safetensors metadata, tensor declarations and derived totals                               | Built-in header inspection; optional full-file hash; [model files](docs/model-artifacts.md)                                           |
| IL2CPP metadata         | Unity global-metadata.dat assembly images, type and method names and index ranges                 | Built-in static decoding of versions 24, 27, 29, 31 and 39; no Unity required                                                         |
| Godot PCK               | Archive inventory and extraction, original header/directory facts and selected content identities | Built-in static formats 2, 3 and 4; no Godot required                                                                                 |
| Rust binaries           | Embedded cargo-auditable crate names, versions, sources and dependency edges                      | Built-in static ELF/PE/thin Mach-O inspection; [Rust binaries](docs/rust-binaries.md)                                                 |
| PE certificates         | Authenticode WIN_CERTIFICATE entries and PKCS#7 signer/X.509 identity fields                      | Built-in static PE inspection; [PE certificates](docs/pe-certificates.md)                                                             |
| PE imports              | Import and delay-load DLL names, ordinals, IAT RVAs and pefile import hash                        | Built-in static PE inspection; [PE imports](docs/pe-imports.md)                                                                       |
| ELF notes               | PT_NOTE/SHT_NOTE owners, types, GNU build-id and ABI-tag fields                                   | Built-in static ELF inspection; [ELF notes](docs/elf-notes.md)                                                                        |
| Apple IPS crashes       | .ips metadata, threads, images, registers and documented crash classes                            | Built-in static JSON inspection; [Apple IPS](docs/apple-ips.md)                                                                       |
| Linux kernel modules    | .modinfo keys, __versions CRCs, this_module presence, and signature trailer                       | Built-in static ELF inspection; [kernel modules](docs/kernel-modules.md)                                                              |
| Erlang BEAM             | IFF chunks, atoms, exports, imports, lambdas and the Code header                                  | Built-in static BEAM inspection; [Erlang BEAM](docs/erlang-beam.md)                                                                   |
| WASM artifact           | Validation, sections, exact import/export WAT forms and decoded WAT                               | Caller-supplied WABT 1.0.42; `inspect_wasm_artifact`                                                                                  |
| EVM bytecode            | Dispatch selectors, byte offsets, inferred arguments and mutability                               | Local raw/hex carrier on Linux x64; [offline EVM guide](docs/evm-bytecode.md)                                                         |
| SQLite databases        | Tables, columns, indexes, views, triggers and selected ordinary-table rows                        | Local database/WAL snapshot; Node.js 24.x >=24.15 or 26+ with native SQLite limits                                                    |
| Recorded Linux crashes  | Raw notes, every recorded thread's registers/signals and optional mapping candidates              | Caller-supplied pwntools on Linux x64; optional GDB/pwndbg; [recorded crashes](docs/recorded-crashes.md)                              |
| JavaScript / Electron   | Modules, imports, source maps, routes, IPC and native add-on relationships                        | Node.js and npm; Linux: procps-compatible `ps`; [application analysis](docs/javascript-application-workflows.md)                      |
| Websites                | Page structure, scripts, network observations and requested screenshots                           | A Chrome-family browser; [browser analysis](docs/browser-observation.md)                                                              |
| Saved network captures  | Requests, responses, exposed payloads and source locations                                        | HAR or Fiddler Everywhere SAZ; mitmdump on Linux for native mitmproxy; [capture guide](docs/web-network-captures.md)                  |
| .NET assemblies         | Metadata, CIL instructions, declared native dependencies and build comparisons                    | None (static only); [managed-code guide](docs/managed-code-analysis.md)                                                               |
| Android APKs            | Manifest declarations, classes, decompiled methods and references                                 | Headless JADX and a full JDK on Linux/macOS/Windows x64; [Android guide](docs/android-analysis.md)                                    |
| APK signatures          | v1/v2/v3/v3.1 signers, certificate fingerprints, key rotation and digest self-consistency         | None (static only); `inspect_apk_signature`                                                                                           |
| Android devices         | Devices, packages, processes, logs, dumps, screen captures, and APK/file transfers                | Caller-supplied adb (emulator or hardware); [ADB guide](docs/adb-device-analysis.md)                                                  |
| JEB projects            | Engine-backed project units, artifact digests and type/method pseudo-code                         | A caller-started JEB client serving MCP, selected with REA_JEB_MCP_URL; [JEB guide](docs/jeb-analysis.md)                             |
| Android resources       | Decoded manifest, string tables, locales and version facts                                        | Caller-supplied Apktool launcher; [resource guide](docs/apktool-resource-analysis.md)                                                 |
| Flutter apps            | Dart snapshot hash, per-ABI library digests and engine build provenance                           | None (static APK parsing); [Flutter guide](docs/flutter-analysis.md)                                                                  |
| Firmware                | Regions, extraction results and native-analysis handoffs                                          | Binwalk / Unblob on Linux; [firmware guide](docs/firmware-analysis.md)                                                                |
| Recorded packets        | Selected fields, repeated values, filters and decode-as rules                                     | Linux: TShark 4.x + prlimit; [capture guide](docs/packet-captures.md)                                                                 |
| Packet summaries        | Endpoints, DNS, TLS SNI, protocol distribution and HTTP requests                                  | Caller-supplied tshark and capinfos (Linux-verified); [pcap guide](docs/pcap-analysis.md)                                             |
| Recorded logic signals  | Decoder annotations, sample ranges and diagnostics                                                | Linux: sigrok-cli 0.7.2 + prlimit; [signal recordings](docs/signal-recordings.md)                                                     |
| Packages and resources  | File inventories, digests, plists, Apple bundle anatomy and extracted resources                   | [Artifact and JavaScript guide](docs/javascript-artifact-reconstruction.md), [Apple applications](docs/apple-application-analysis.md) |
| Process behavior        | Terminal output, interactions, exit and filesystem observations, and run comparisons              | Linux/macOS with a native PTY; [process capture](docs/process-capture.md)                                                             |
| PyInstaller executables | CArchive members, Python version, entry scripts and extracted bytecode                            | None (static only); [Python packaged applications](docs/python-packaged-applications.md)                                              |

Static JavaScript and .NET inspection read the supplied files without running
the application. Runtime capture runs or interacts with the selected target
using your user permissions; each runtime guide describes its effects.

For offline native-binary inspection, REA also supports caller-supplied GNU
objdump and Rizin. See the [reverse-engineering tools guide](docs/reverse-engineering-tools.md)
for provider setup, CLI commands, and Evidence limitations. REA does not install
or update either provider.

<a id="choosing-a-deep-analysis-provider"></a>

Native formats and host support vary by provider. See
[Hopper and Ghidra setup](docs/installation.md#hopper), the
[IDA guide](docs/ida-provider.md) (including an optional native MCP bridge), the
[Kuna decompiler guide](docs/kuna-provider.md), and
[experimental Windows Ghidra support](docs/windows-ghidra-p0.md).
Ghidra also supports [16-bit DOS analysis](docs/ghidra-dos.md).
For large binaries, raise the provider's startup deadline with
`REA_GHIDRA_STARTUP_TIMEOUT_MS` or `REA_HOPPER_STARTUP_TIMEOUT_MS`.
For provider selection, see the [CLI guide](docs/cli.md#choose-a-provider).
Check [release availability](docs/installation.md#released-package-and-main)
for features added since the latest npm release.

## Showcases

<a href="https://rea.tools/showcase/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/rea-showcases-dark.svg" />
    <img alt="Illustrations of the DX-Ball sound-pan, Notion clipboard-bridge, and TH04 bullet-ring showcases" src="docs/assets/rea-showcases.svg" />
  </picture>
</a>

### DX-Ball: reconstruct a sound-pan calculation

Follow a sound call into its position-to-pan helper, inspect the instructions,
and turn incomplete pseudocode into C. The reconstruction passes 3,205
original-x86 cases and reproduces all 63 compiled function bytes.

[Read the case study](https://rea.tools/showcase/dx-ball/) ·
[Reconstruction repository](https://github.com/N0zoM1z0/dx-ball)

### Notion: trace the Electron clipboard bridge

Find the renderer's clipboard API, follow it through preload and IPC into the
main process, and inspect the rich clipboard format.

[Read the case study](https://rea.tools/showcase/notion/)

### TH04: recover a DOS bullet-ring calculation

Inspect the original PC-98 game's 16-bit instructions, recover the fixed and
aimed angle calculations, and compare the reconstructed C++ with the
historical compiler output.

[Read the case study](https://rea.tools/showcase/th04/) ·
[Reconstruction repository](https://github.com/N0zoM1z0/th04)

### Build RL environments with REA

Record a web app session, turn its API into tools, and export an environment an AI agent can use. Run it with AgentEnv, then add tasks and reward checks for RL training or evaluation.

[Read the guide](https://rea.tools/guides/rl-environments/) ·
[Watch the video](https://x.com/reatools/status/2112574822584918075?s=20)

If you've used REA on something interesting, we'd love to see it. Share your
case in an [issue](https://github.com/morluto/rea/issues) or a
[pull request](https://github.com/morluto/rea/pulls), including the target,
your question, how REA helped, and what you found.

## Build RL environments

Give an AI agent a local environment to practice tasks such as finding an issue or creating a folder, without running the original app. Use it for reinforcement learning (RL) or to test how well an agent completes tasks.

REA turns recorded API requests and responses into tools the agent can call. The environment uses the recorded data and supports changes only when the recording confirms their effects.

With REA set up in your agent, replace the example URL and folder tasks below with your own:

```text
Use REA to build an RL environment from my test web app at
http://127.0.0.1:3000.
Cover listing, creating, renaming, and deleting folders. You may create and
remove test folders. Leave existing data unchanged.
Save it in a folder named my-env. Check which operations work and tell me
how to run it.
```

<details>
<summary>Use the command line instead</summary>

Use these commands if you already have a file containing the app’s recorded browser requests and responses. Running the result also requires AgentEnv and Docker.

```sh
rea environment-build ./session.har ./my-env --name my-env --json
agent-env run ./my-env
```

</details>

REA exports a runnable environment with a basic test to check that it starts and responds. Use it with your RL framework to define task goals, add reward checks, and run training.

[Build an environment](https://rea.tools/guides/rl-environments/) ·
[Environment reference](docs/agent-environments.md) ·
[Watch the demo on X](https://x.com/reatools/status/2112574822584918075?s=20)

## FAQ

<details>
<summary><strong>Which agents can use REA?</strong></summary>

Any agent that supports local MCP servers. Setup configures the
[supported agents](docs/installation.md#supported-agents); other clients can use
[manual MCP registration](docs/installation.md#mcp-registry).

</details>

<details>
<summary><strong>Do I need Hopper, Ghidra or IDA?</strong></summary>

Deep native analysis uses one of them. Static JavaScript and .NET inspection
work without a native analysis engine. Setup can install Hopper after approval;
Ghidra and IDA use your existing installations. See [provider setup](docs/installation.md#hopper).

</details>

<details>
<summary><strong>Do I need to start Hopper first?</strong></summary>

REA starts Hopper when an operation needs it. On macOS, a first-run dialog may
ask you to choose demo mode or activate your license. Complete that prompt in the
same user session before your first CLI/MCP operation or unattended job. Open
Hopper manually if needed. See
[Hopper startup and troubleshooting](docs/installation.md#launcher-paths-and-troubleshooting).

</details>

<details>
<summary><strong>What does installing the skill from skills.sh do?</strong></summary>

The skill supplies investigation instructions for your agent. Use `npx rea-agents setup`
to register REA's MCP server and install the matching instructions, then restart
your agent. See [skill-only installation](docs/installation.md#skill-only-installation).

</details>

<details>
<summary><strong>What code does REA return?</strong></summary>

Native analysis returns pseudocode and assembly. JavaScript/Electron analysis
recovers modules and their relationships. Your agent uses these findings to
write and test an implementation; the [showcases](#showcases) give worked examples.

</details>

<details>
<summary><strong>Does REA upload my app?</strong></summary>

REA analyzes targets locally. Your agent receives the tool results, and its
model provider has its own data policy.

</details>

<details>
<summary><strong>What should I do if I hit a bug?</strong></summary>

Update first; a recent release may already fix it.

For a CLI installed with `npm install --global` or `bun add --global`:

```bash
rea update
```

For agent setup through `npx`:

```bash
npx rea-agents@latest setup
```

If you're using an agent, complete the [setup refresh](#update-rea) and restart
it. Retry the same task. If the problem persists, [open an issue](https://github.com/morluto/rea/issues)
with your REA version, target type, steps to reproduce and error output.

</details>

## Documentation

Start with the website's [worked guides](https://rea.tools/guides/).
For exact options, prerequisites and result contracts:

- [Installation and setup](docs/installation.md): agent registration, provider configuration, updates and uninstall.
- [Readiness and troubleshooting](docs/installation.md#check-readiness-for-your-task): diagnose one agent or analysis engine.
- [CLI and Evidence](docs/cli.md): commands, provider selection, snapshots, import/export and exit statuses.
- [MCP contracts](docs/mcp-contracts.md) and [agent prompts](docs/mcp-prompts.md): tool results, sessions and guided investigations.
- [Tool catalog](docs/mcp-contracts.md#generated-catalog): generated inventory of tools, providers and CLI commands.
- [Roadmap](docs/roadmap.md): planned work and capability trackers.

Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Star history

🎉 **300,000 GitHub stars — thank you!**

Thanks to everyone using REA, reporting bugs, requesting features, testing builds, and contributing fixes.

<a href="https://www.star-history.com/?repos=morluto%2Frea&amp;type=date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date&amp;theme=dark&amp;legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
    <img alt="REA GitHub star history" src="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
  </picture>
</a>

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance.

The project's position on illegal or unauthorized use covers all REA versions,
distribution channels, and platforms; each copy retains its applicable licenses.

REA is for lawful research, education, interoperability, software preservation,
and analysis of software you own or are authorized to examine.

## Contributing

We'd love your help with REA! [Open an issue](https://github.com/morluto/rea/issues) to
report a bug or suggest a feature, or [send a pull request](https://github.com/morluto/rea/pulls)
to improve the code or docs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and checks,
[testing](docs/testing.md) for verification lanes, and the
[architecture map](docs/architecture.mermaid) for selected layers and dependency paths.

## License

[MIT](LICENSE)

REA-authored code is licensed under MIT. Third-party material retains its own
licenses and copyright notices; see
[Third-party notices](THIRD_PARTY_NOTICES.md) for the dependency inventory,
preserved license texts, and external-tool terms.

**You must legally obtain and be authorized to use commercial tools**, including
IDA Pro / Hex-Rays decompilers, Hopper, and JEB, under their applicable
licenses. REA grants no tool license, key, or activation entitlement. Trials and
demos remain subject to vendor terms, including user, feature, automation, and
output sharing restrictions. Cracked copies, stolen keys, unauthorized key
sharing, and bypassing license restrictions are not authorized. This guidance
does not amend MIT or third-party licenses.

</details>
