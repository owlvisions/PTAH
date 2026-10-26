/**
 * GNU binutils adapters: readelf, objdump, and nm. Each mapper turns one
 * output format into PTAH data; providers declare which tasks they serve and
 * how strongly (priority) so the registry can choose and fall back.
 */
import { compareCodePoints } from "../canonical.mjs";
import { ToolFailure, ToolProvider } from "./tool-provider.mjs";

const hex = (value) => Number.parseInt(value, 16);
const splitVersion = (name) => {
  const match = /^([^@]+)(@@?)(.+)$/u.exec(name);
  return match
    ? { name: match[1], version: match[3], defaultVersion: match[2] === "@@" }
    : { name, version: null, defaultVersion: false };
};

/** `readelf -h -W`: "Key: value" lines. */
export function parseReadelfHeader(text) {
  const header = {};
  for (const line of text.split("\n")) {
    const match = /^\s{2}([^:]+):\s+(.*)$/u.exec(line);
    if (match) header[match[1].trim()] = match[2].trim();
  }
  if (!header.Class)
    throw new ToolFailure("readelf", "no ELF header in output");
  return header;
}

/** `readelf -S -W`: the section header table. */
export function parseReadelfSections(text) {
  const sections = [];
  const pattern =
    /^\s*\[\s*(\d+)\]\s+(\S*)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([A-Za-z]*)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/u;
  for (const line of text.split("\n")) {
    const match = pattern.exec(line);
    if (!match || match[3] === "NULL") continue;
    sections.push({
      index: Number(match[1]),
      name: match[2],
      type: match[3],
      address: hex(match[4]),
      offset: hex(match[5]),
      size: hex(match[6]),
      flags: match[8],
      executable: match[8].includes("X"),
      writable: match[8].includes("W"),
    });
  }
  return sections;
}

/** `readelf -s` / `--dyn-syms`: every symbol table in the output. */
export function parseReadelfSymbols(text) {
  const tables = {};
  let current;
  for (const line of text.split("\n")) {
    const heading = /^Symbol table '([^']+)'/u.exec(line);
    if (heading) {
      current = tables[heading[1]] = [];
      continue;
    }
    const match =
      /^\s*\d+:\s+([0-9a-f]+)\s+(0x[0-9a-f]+|\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s*(.*)$/u.exec(
        line,
      );
    if (!match || !current) continue;
    const raw = match[7].replace(/\s+\(\d+\)$/u, "").trim();
    if (!raw) continue;
    current.push({
      ...splitVersion(raw),
      value: hex(match[1]),
      size: match[2].startsWith("0x") ? hex(match[2]) : Number(match[2]),
      type: match[3],
      binding: match[4],
      visibility: match[5],
      defined: match[6] !== "UND",
      section: match[6],
    });
  }
  return tables;
}

/** `readelf -d`: needed libraries, soname, and search paths. */
export function parseReadelfDynamic(text) {
  const libraries = [];
  let soname = null;
  const paths = [];
  for (const line of text.split("\n")) {
    const match = /\((NEEDED|SONAME|RPATH|RUNPATH)\)\s+[^[]*\[([^\]]*)\]/u.exec(
      line,
    );
    if (!match) continue;
    if (match[1] === "NEEDED") libraries.push(match[2]);
    else if (match[1] === "SONAME") soname = match[2];
    else paths.push({ kind: match[1].toLowerCase(), value: match[2] });
  }
  return { libraries, soname, searchPaths: paths };
}

/** Imports and exports from dynamic symbols. */
export function importsExportsFromSymbols(symbols) {
  const imports = new Map();
  const exports = new Map();
  for (const symbol of symbols) {
    if (!symbol.name) continue;
    if (!symbol.defined)
      imports.set(symbol.name, {
        name: symbol.name,
        version: symbol.version,
        weak: symbol.binding === "WEAK",
      });
    else if (
      (symbol.binding === "GLOBAL" || symbol.binding === "WEAK") &&
      (symbol.type === "FUNC" || symbol.type === "OBJECT")
    )
      exports.set(symbol.name, {
        name: symbol.name,
        version: symbol.version,
        type: symbol.type,
      });
  }
  const byName = (left, right) => compareCodePoints(left.name, right.name);
  return {
    imports: [...imports.values()].sort(byName),
    exports: [...exports.values()].sort(byName),
  };
}

/** `objdump -d --no-show-raw-insn -w`: functions and instructions. */
export function parseObjdumpDisassembly(text, maxInstructions = Infinity) {
  const functions = [];
  let current;
  let count = 0;
  let truncated = false;
  for (const line of text.split("\n")) {
    const start = /^([0-9a-f]+) <(.+)>:$/u.exec(line);
    if (start) {
      current = { name: start[2], address: hex(start[1]), instructions: [] };
      functions.push(current);
      continue;
    }
    const instruction = /^\s*([0-9a-f]+):\t(.*)$/u.exec(line);
    if (!instruction || !current) continue;
    if (count >= maxInstructions) {
      truncated = true;
      break;
    }
    const body = instruction[2].trim();
    const [mnemonic, ...rest] = body.split(/\s+/u);
    current.instructions.push({
      address: hex(instruction[1]),
      mnemonic,
      operands: rest.join(" "),
    });
    count += 1;
  }
  const format = /file format (\S+)/u.exec(text)?.[1] ?? null;
  return {
    format,
    functions: functions.filter((fn) => fn.instructions.length),
    instructionCount: count,
    truncated,
  };
}

/** `objdump -h -w`: sections with flags. */
export function parseObjdumpSections(text) {
  const sections = [];
  for (const line of text.split("\n")) {
    const match =
      /^\s*(\d+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+2\*\*(\d+)\s*(.*)$/u.exec(
        line,
      );
    if (!match) continue;
    const flags = match[8]
      .split(",")
      .map((flag) => flag.trim())
      .filter(Boolean);
    sections.push({
      index: Number(match[1]),
      name: match[2],
      size: hex(match[3]),
      address: hex(match[4]),
      offset: hex(match[6]),
      alignment: 2 ** Number(match[7]),
      flags,
      executable: flags.includes("CODE"),
      writable: !flags.includes("READONLY") && flags.includes("ALLOC"),
    });
  }
  return sections;
}

/** `nm` output: address (absent for undefined), type letter, name. */
export function parseNm(text) {
  const symbols = [];
  for (const line of text.split("\n")) {
    const match = /^\s*([0-9a-f]+)?\s+([A-Za-z?-])\s+(\S+)$/u.exec(line);
    if (!match) continue;
    symbols.push({
      ...splitVersion(match[3]),
      address: match[1] ? hex(match[1]) : null,
      type: match[2],
      defined:
        !/^[Uvw]$/u.test(match[2]) || (match[2] === "w" && Boolean(match[1])),
    });
  }
  return symbols;
}

const SAFE_SYMBOL = /^[\w.$@:<>~-]{1,256}$/u;

export class ReadelfProvider extends ToolProvider {
  id = "readelf";
  name = "GNU readelf";
  license = "GPL-3.0-or-later";
  executables = ["readelf", "eu-readelf"];
  capabilities() {
    return {
      formats: ["elf"],
      tasks: {
        manifest: { priority: 6 },
        sections: { priority: 6 },
        symbols: { priority: 6 },
        importsExports: { priority: 6 },
      },
    };
  }
  async manifest(target, context) {
    const run = await this.execute(target, ["-h", "-W", "{target}"], context);
    const header = parseReadelfHeader(run.stdout);
    return [
      this.evidence("manifest", target, run, {
        summary: `${header.Class} ${header.Type} for ${header.Machine}, entry ${header["Entry point address"]}`,
        data: { header },
      }),
    ];
  }
  async sections(target, context) {
    const run = await this.execute(target, ["-S", "-W", "{target}"], context);
    const sections = parseReadelfSections(run.stdout);
    return [
      this.evidence("sections", target, run, {
        summary: `${sections.length} sections; executable: ${
          sections
            .filter((s) => s.executable)
            .map((s) => s.name)
            .join(", ") || "none"
        }`,
        data: { sections },
      }),
    ];
  }
  async symbols(target, context) {
    const run = await this.execute(
      target,
      ["--dyn-syms", "-s", "-W", "{target}"],
      context,
    );
    const tables = parseReadelfSymbols(run.stdout);
    const counts = Object.entries(tables)
      .map(([name, items]) => `${name}: ${items.length}`)
      .join(", ");
    return [
      this.evidence("symbols", target, run, {
        summary: `Symbol tables ${counts || "none"}`,
        data: { tables },
        limitations: tables[".symtab"]
          ? []
          : [
              "No .symtab: the binary is stripped; only dynamic symbols are listed.",
            ],
      }),
    ];
  }
  async importsExports(target, context) {
    const run = await this.execute(
      target,
      ["-d", "-W", "--dyn-syms", "{target}"],
      context,
    );
    const dynamic = parseReadelfDynamic(run.stdout);
    const { imports, exports } = importsExportsFromSymbols(
      parseReadelfSymbols(run.stdout)[".dynsym"] ?? [],
    );
    return [
      this.evidence("importsExports", target, run, {
        summary: `Needs ${dynamic.libraries.join(", ") || "no libraries"}; ${imports.length} imported and ${exports.length} exported symbols`,
        data: { ...dynamic, imports, exports },
      }),
    ];
  }
}

export class ObjdumpProvider extends ToolProvider {
  id = "objdump";
  name = "GNU objdump";
  license = "GPL-3.0-or-later";
  executables = ["objdump"];
  capabilities() {
    return {
      formats: ["elf", "pe"],
      tasks: { disassemble: { priority: 5 }, sections: { priority: 4 } },
    };
  }
  /**
   * context.options: { symbol?: string, maxInstructions?: number }. Without a
   * symbol the whole text is disassembled up to the instruction limit.
   */
  async disassemble(target, context = {}) {
    const { symbol, maxInstructions = 5000 } = context.options ?? {};
    if (symbol !== undefined && !SAFE_SYMBOL.test(symbol))
      throw new ToolFailure(
        this.id,
        "symbol name contains unsupported characters",
      );
    const args = [
      "-d",
      "--no-show-raw-insn",
      "-w",
      ...(symbol ? [`--disassemble=${symbol}`] : []),
      "{target}",
    ];
    const run = await this.execute(target, args, context);
    const listing = parseObjdumpDisassembly(run.stdout, maxInstructions);
    // Either cap (captured bytes or instruction count) makes the listing partial.
    return [
      this.evidence("disassemble", target, run, {
        partial: listing.truncated,
        summary: `${listing.instructionCount} instructions in ${listing.functions.length} functions${symbol ? ` for ${symbol}` : ""} (${listing.format})`,
        data: listing,
        limitations: listing.truncated
          ? [
              `Stopped after ${maxInstructions} instructions; request a symbol for a focused listing.`,
            ]
          : [],
      }),
    ];
  }
  async sections(target, context) {
    const run = await this.execute(target, ["-h", "-w", "{target}"], context);
    const sections = parseObjdumpSections(run.stdout);
    return [
      this.evidence("sections", target, run, {
        summary: `${sections.length} sections; code: ${
          sections
            .filter((s) => s.executable)
            .map((s) => s.name)
            .join(", ") || "none"
        }`,
        data: { sections },
      }),
    ];
  }
}

export class NmProvider extends ToolProvider {
  id = "nm";
  name = "GNU nm";
  license = "GPL-3.0-or-later";
  executables = ["nm"];
  capabilities() {
    return {
      formats: ["elf", "pe"],
      tasks: { symbols: { priority: 3 }, importsExports: { priority: 3 } },
    };
  }
  async symbols(target, context) {
    const run = await this.execute(target, ["-D", "{target}"], context);
    const symbols = parseNm(run.stdout);
    return [
      this.evidence("symbols", target, run, {
        summary: `${symbols.length} dynamic symbols`,
        data: { tables: { dynamic: symbols } },
      }),
    ];
  }
  async importsExports(target, context) {
    const defined = await this.execute(
      target,
      ["-D", "--defined-only", "{target}"],
      context,
    );
    const undefinedRun = await this.execute(
      target,
      ["-D", "-u", "{target}"],
      context,
    );
    const exports = parseNm(defined.stdout)
      .filter((s) => /^[TDBRVW]$/u.test(s.type))
      .map(({ name, version, type }) => ({ name, version, type }));
    const imports = parseNm(undefinedRun.stdout).map(
      ({ name, version, type }) => ({
        name,
        version,
        weak: type === "w" || type === "v",
      }),
    );
    const run = {
      ...undefinedRun,
      provider: {
        ...undefinedRun.provider,
        argv: [...defined.provider.argv, "&&", ...undefinedRun.provider.argv],
      },
      rawSha256: undefinedRun.rawSha256,
    };
    return [
      this.evidence("importsExports", target, run, {
        summary: `${imports.length} imported and ${exports.length} exported symbols`,
        data: { libraries: [], imports, exports },
        limitations: ["nm does not report needed libraries; readelf does."],
      }),
    ];
  }
}

export const binutilsProviders = () => [
  new ReadelfProvider(),
  new ObjdumpProvider(),
  new NmProvider(),
];
