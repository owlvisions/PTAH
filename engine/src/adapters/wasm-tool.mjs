/**
 * WebAssembly adapter over wasm-objdump (WABT): section headers, imports and
 * exports, and a bounded instruction disassembly.
 */
import { ToolProvider } from "./tool-provider.mjs";

/** wasm-objdump -x: "Section[n]:" blocks with " - ..." detail lines. */
export function parseWasmObjdumpDetails(text) {
  const sections = [];
  const imports = [];
  const exports = [];
  let current;
  for (const line of text.split("\n")) {
    const header = /^(\w+)\[(\d+)\]:$/u.exec(line);
    if (header) {
      current = { name: header[1], count: Number(header[2]) };
      sections.push(current);
      continue;
    }
    const importMatch =
      /^\s*-\s*(func|table|memory|global)\[\d+\].*<-\s*(\S+)\.(\S+)$/u.exec(
        line,
      );
    if (importMatch)
      imports.push({
        kind: importMatch[1],
        module: importMatch[2],
        name: importMatch[3],
      });
    const exportMatch =
      /^\s*-\s*(func|table|memory|global)\[\d+\](?:\s*<[^>]*>)?\s*->\s*"([^"]*)"$/u.exec(
        line,
      );
    if (exportMatch)
      exports.push({ kind: exportMatch[1], name: exportMatch[2] });
  }
  return { sections, imports, exports };
}

/** wasm-objdump -d: "nnnnnn func[i] <name>:" then indented instruction lines. */
export function parseWasmDisassembly(text, maxInstructions = Infinity) {
  const functions = [];
  let current;
  let count = 0;
  let truncated = false;
  for (const line of text.split("\n")) {
    const header = /^[0-9a-f]+ func\[(\d+)\](?:\s*<([^>]*)>)?:/u.exec(line);
    if (header) {
      current = {
        index: Number(header[1]),
        name: header[2] ?? null,
        instructions: [],
      };
      functions.push(current);
      continue;
    }
    const instruction = /^\s*[0-9a-f]+:\s+[0-9a-f ]+\|\s*(.*)$/u.exec(line);
    if (!instruction || !current) continue;
    if (count >= maxInstructions) {
      truncated = true;
      break;
    }
    current.instructions.push(instruction[1].trim());
    count += 1;
  }
  return {
    functions: functions.filter((fn) => fn.instructions.length),
    instructionCount: count,
    truncated,
  };
}

export class WasmObjdumpProvider extends ToolProvider {
  id = "wasm-objdump";
  name = "wasm-objdump (WABT)";
  license = "Apache-2.0";
  executables = ["wasm-objdump"];
  capabilities() {
    return {
      formats: ["wasm"],
      tasks: {
        sections: { priority: 6 },
        importsExports: { priority: 6 },
        disassemble: { priority: 6 },
      },
    };
  }
  async sections(target, context) {
    const run = await this.execute(target, ["-x", "{target}"], context);
    const { sections } = parseWasmObjdumpDetails(run.stdout);
    return [
      this.evidence("sections", target, run, {
        summary: `${sections.length} sections: ${sections.map((s) => `${s.name}(${s.count})`).join(", ")}`,
        data: { sections },
      }),
    ];
  }
  async importsExports(target, context) {
    const run = await this.execute(target, ["-x", "{target}"], context);
    const { imports, exports } = parseWasmObjdumpDetails(run.stdout);
    return [
      this.evidence("importsExports", target, run, {
        summary: `${imports.length} imports (${[...new Set(imports.map((i) => i.module))].join(", ") || "none"}), ${exports.length} exports`,
        data: { imports, exports },
      }),
    ];
  }
  async disassemble(target, context = {}) {
    const max = context.options?.maxInstructions ?? 20_000;
    const run = await this.execute(target, ["-d", "{target}"], context);
    const listing = parseWasmDisassembly(run.stdout, max);
    return [
      this.evidence("disassemble", target, run, {
        summary: `${listing.instructionCount} instructions in ${listing.functions.length} functions`,
        data: listing,
        partial: listing.truncated,
      }),
    ];
  }
}

export const wasmProviders = () => [new WasmObjdumpProvider()];
