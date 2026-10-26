# PTAH Engine

A self-contained, evidence-first analysis core. It has no runtime
dependencies and imports nothing outside this directory (enforced by
`test/core.test.mjs`); external analysis tools are called directly through
PTAH's own adapters.

## Layers

```mermaid
flowchart TB
  subgraph Surfaces["Surfaces (unchanged): ptah CLI · ptah-mcp · ptah ui"]
  end
  Surfaces --> Session
  subgraph Core["PTAH Engine core"]
    Session["Session<br/>attestation · drift guard · evidence log"]
    Policy["Policy<br/>ownership + purpose allow-lists · target checks"]
    Registry["Capability Registry<br/>probe · format→task routing · fallback · degrade · SHA-256 cache"]
    Evidence["Evidence model<br/>content-addressed ids · confidence · status · provenance"]
    Target["Target identity<br/>SHA-256 · format detection"]
  end
  Session --> Policy
  Session --> Target
  Session --> Registry
  Registry --> Contract
  Contract["AnalysisProvider contract<br/>capabilities · isAvailable · disassemble · decompile · strings · symbols · importsExports · resources · manifest · sections"]
  subgraph Adapters["Adapters (anti-corruption layer: tool output → evidence)"]
    Builtin["Built-in inspectors"]
    Tools["Tool adapters<br/>readelf · objdump · nm · …"]
    Engines["Engine adapters<br/>Ghidra · radare2 · user-licensed IDA/Hopper/JEB · …"]
  end
  Contract --> Builtin
  Contract --> Tools
  Contract --> Engines
  Tools --> Exec["Bounded exec<br/>fixed argv · no shell · timeout · output cap · process-group kill"]
  Engines --> Exec
  Evidence -.-> Registry
```

## Guarantees enforced in code

| Guarantee                                                                                     | Where                              | Test                                 |
| --------------------------------------------------------------------------------------------- | ---------------------------------- | ------------------------------------ |
| No analysis without recorded ownership and an allow-listed purpose                            | `src/policy.mjs`, `src/engine.mjs` | `core.test.mjs`                      |
| Organization target checks can refuse a target                                                | `evaluateTarget`                   | `core.test.mjs`                      |
| Evidence is bound to the target SHA-256; drift aborts the session                             | `src/engine.mjs`                   | `core.test.mjs`                      |
| Evidence ids are content-derived; edited evidence is rejected                                 | `src/evidence.mjs`                 | `core.test.mjs`                      |
| Byte-stable output: canonical JSON, code-point ordering, machine paths replaced by `<target>` | `src/canonical.mjs`, adapters      | `core.test.mjs`, `binutils.test.mjs` |
| Tools run with fixed argv, no shell, timeout, capped output                                   | `src/exec.mjs`                     | `core.test.mjs`                      |
| Best available provider, automatic fallback, `unavailable` evidence instead of crashes        | `src/registry.mjs`                 | `core.test.mjs`, `binutils.test.mjs` |
| No REA dependency                                                                             | whole package                      | `core.test.mjs`                      |

## Usage

```js
import { createDefaultRegistry, createEngine } from "@owlvisions/ptah-engine";

const engine = createEngine({ registry: createDefaultRegistry() });
const session = await engine.open("/path/to/target", {
  ownership: "owner", // owner | licensed | authorized | open-source
  purpose: "interoperability", // see PURPOSES in src/policy.mjs
  statement: "Our own release build",
});
const { evidence, provider, attempts } = await session.run("importsExports");
```

## Provider status

| Provider     | Kind   | Formats                        | Tasks                                                             | License                    | Status                                           |
| ------------ | ------ | ------------------------------ | ----------------------------------------------------------------- | -------------------------- | ------------------------------------------------ |
| readelf      | tool   | elf                            | manifest, sections, symbols, importsExports                       | GPL-3.0-or-later           | tested live                                      |
| objdump      | tool   | elf, pe                        | disassemble, sections                                             | GPL-3.0-or-later           | tested live (ELF)                                |
| nm           | tool   | elf, pe                        | symbols, importsExports                                           | GPL-3.0-or-later           | tested live (ELF)                                |
| aapt2        | tool   | apk                            | manifest                                                          | Apache-2.0                 | tested live                                      |
| apktool      | tool   | apk, aab                       | manifest, resources                                               | Apache-2.0                 | tested live                                      |
| jadx         | tool   | apk, aab, dex, jar, java-class | decompile, strings                                                | Apache-2.0                 | tested live                                      |
| wasm-objdump | tool   | wasm                           | sections, importsExports, disassemble                             | Apache-2.0                 | tested live                                      |
| monodis      | tool   | dotnet                         | manifest, symbols, importsExports, disassemble                    | MIT                        | tested live                                      |
| binwalk      | tool   | unknown, bin                   | resources                                                         | MIT                        | tested live                                      |
| unblob       | tool   | unknown, bin                   | resources                                                         | MIT                        | tested live                                      |
| tshark       | tool   | pcap, pcapng                   | resources                                                         | GPL-2.0-or-later           | tested live                                      |
| radare2      | engine | elf, pe, macho, dex            | manifest, sections, symbols, importsExports, strings, disassemble | LGPL-3.0-only              | tested live (ELF)                                |
| rizin        | engine | elf, pe, macho, dex            | same as radare2, one priority lower (fallback)                    | LGPL-3.0-only              | tested live (ELF)                                |
| ghidra       | engine | elf, pe, macho, dex            | decompile, symbols                                                | Apache-2.0                 | tested live (ELF)                                |
| ida          | engine | elf, pe, macho                 | decompile, symbols                                                | commercial (user-licensed) | adapter; PTAH_IDA_BINARY + PTAH_IDA_SCRIPT       |
| hopper       | engine | elf, pe, macho                 | decompile                                                         | commercial (user-licensed) | adapter; PTAH_HOPPER_BINARY + PTAH_HOPPER_SCRIPT |
| jeb          | engine | apk, aab, dex                  | decompile                                                         | commercial (user-licensed) | adapter; PTAH_JEB_BINARY + PTAH_JEB_SCRIPT       |
| kuna         | engine | elf, pe, macho                 | symbols                                                           | user-provided              | adapter; PTAH_KUNA_BINARY                        |

Commercial engines (IDA, Hopper, JEB, Binary Ninja) are never bundled; their
adapters, when added, call the user's own licensed installation.

Run the tests with `node --test test/*.test.mjs` from this directory.
