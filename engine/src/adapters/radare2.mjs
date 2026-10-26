/**
 * radare2 / rizin engine adapter. Both expose the same scriptable command
 * interface, so one adapter serves both: fixed `-q -c '<cmds>' -e scr.color=0`
 * invocations whose JSON commands (ij, iSj, isj, iij, iEj, izj, pdfj) map into
 * PTAH evidence. Analysis runs in-process; the target is never executed.
 */
import { ToolProvider } from "./tool-provider.mjs";

const SEP = "---PTAH-SEP---";
const SAFE_SYMBOL = /^[\w.$@:<>]{1,256}$/u;

/** Parse one JSON blob; returns fallback on empty or invalid output. */
function json(text, fallback) {
  const trimmed = text.trim();
  if (!trimmed) return fallback;
  try {
    return JSON.parse(trimmed);
  } catch {
    return fallback;
  }
}

/** Map `ij` (file info) into a manifest. */
export function mapInfo(info) {
  const bin = info?.bin ?? {};
  return {
    format: bin.bintype ?? null,
    arch: bin.arch ?? null,
    bits: bin.bits ?? null,
    endian: bin.endian ?? null,
    os: bin.os ?? null,
    type: info?.core?.type ?? null,
    stripped: bin.stripped ?? null,
    pic: bin.pic ?? null,
    canary: bin.canary ?? null,
    nx: bin.nx ?? null,
    relocs: bin.relocs ?? null,
    language: bin.lang ?? null,
    compiler: bin.compiler || null,
  };
}

const EXPORT_TYPES = new Set(["FUNC", "OBJ", "IFUNC"]);

export class Radare2Provider extends ToolProvider {
  id = "radare2";
  name = "radare2";
  kind = "engine";
  license = "LGPL-3.0-only";
  executables = ["r2", "radare2"];
  versionArgs = ["-v"];
  capabilities() {
    return {
      formats: ["elf", "pe", "macho", "dex"],
      tasks: {
        manifest: { priority: 4 },
        sections: { priority: 3 },
        symbols: { priority: 4 },
        importsExports: { priority: 4 },
        strings: { priority: 5 },
        disassemble: { priority: 4 },
      },
    };
  }

  /** Run one or more r2 commands separated by SEP; returns the JSON parts. */
  async #commands(
    target,
    commands,
    context,
    { analysis = false, timeoutMs } = {},
  ) {
    const script = commands.join(`;?e ${SEP};`);
    const run = await this.execute(
      target,
      ["-q", "-e", "scr.color=0", "-c", script, "{target}"],
      {
        ...context,
        timeoutMs: timeoutMs ?? (analysis ? 120_000 : 30_000),
      },
    );
    const parts = run.stdout.split(`${SEP}`);
    return { run, parts };
  }

  async manifest(target, context) {
    const { run, parts } = await this.#commands(target, ["ij"], context);
    const info = mapInfo(json(parts[0], {}));
    return [
      this.evidence("manifest", target, run, {
        summary: `${info.format ?? "?"} ${info.arch ?? ""} ${info.bits ?? ""}-bit, ${info.stripped ? "stripped" : "not stripped"}`,
        data: info,
      }),
    ];
  }
  async sections(target, context) {
    const { run, parts } = await this.#commands(target, ["iSj"], context);
    const sections = (json(parts[0], []) ?? []).map((s) => ({
      name: s.name,
      size: s.size,
      address: s.vaddr,
      offset: s.paddr,
      permissions: s.perm ?? null,
      executable: typeof s.perm === "string" && s.perm.includes("x"),
    }));
    return [
      this.evidence("sections", target, run, {
        summary: `${sections.length} sections`,
        data: { sections },
      }),
    ];
  }
  async symbols(target, context) {
    const { run, parts } = await this.#commands(target, ["isj"], context);
    const symbols = (json(parts[0], []) ?? []).map((s) => ({
      name: s.realname ?? s.name,
      address: s.vaddr,
      type: s.type,
      binding: s.bind,
      defined: s.vaddr !== undefined && s.vaddr !== 0,
      size: s.size ?? 0,
    }));
    return [
      this.evidence("symbols", target, run, {
        summary: `${symbols.length} symbols`,
        data: { tables: { symbols } },
      }),
    ];
  }
  async importsExports(target, context) {
    const { run, parts } = await this.#commands(
      target,
      ["iij", "iEj"],
      context,
    );
    const imports = (json(parts[0], []) ?? []).map((i) => ({
      name: i.name,
      type: i.type,
      binding: i.bind,
      library: i.libname ?? null,
    }));
    const exports = (json(parts[1], []) ?? [])
      .filter((e) => EXPORT_TYPES.has(e.type))
      .map((e) => ({
        name: e.realname ?? e.name,
        type: e.type,
        address: e.vaddr,
      }));
    return [
      this.evidence("importsExports", target, run, {
        summary: `${imports.length} imports, ${exports.length} exports`,
        data: {
          libraries: [
            ...new Set(imports.map((i) => i.library).filter(Boolean)),
          ],
          imports,
          exports,
        },
      }),
    ];
  }
  async strings(target, context) {
    const { run, parts } = await this.#commands(target, ["izj"], context);
    const strings = (json(parts[0], []) ?? []).map((s) => ({
      value: s.string,
      offset: s.paddr,
      section: s.section ?? null,
      encoding: s.type ?? null,
    }));
    return [
      this.evidence("strings", target, run, {
        summary: `${strings.length} strings in data sections`,
        data: { strings },
      }),
    ];
  }
  async disassemble(target, context = {}) {
    const symbol = context.options?.symbol;
    if (symbol !== undefined && !SAFE_SYMBOL.test(symbol))
      throw new Error("symbol name contains unsupported characters");
    const seek = symbol ? `s sym.${symbol}` : "s entry0";
    const { run, parts } = await this.#commands(
      target,
      ["aa", "aflj", `${seek};pdfj`],
      context,
      { analysis: true },
    );
    const funcs = (json(parts[1], []) ?? []).map((f) => ({
      name: f.name,
      address: f.offset,
      size: f.size,
      instructions: f.ninstrs,
      calls: f.cc,
    }));
    const focused = json(parts[2], {});
    const ops = (focused?.ops ?? []).map((op) => ({
      address: op.offset,
      mnemonic: (op.disasm ?? "").split(/\s+/u)[0],
      text: op.disasm,
      type: op.type,
    }));
    return [
      this.evidence("disassemble", target, run, {
        summary: `${funcs.length} functions; ${ops.length} instructions at ${symbol ?? "entry0"}`,
        data: {
          functions: funcs,
          focus: { symbol: symbol ?? "entry0", instructions: ops },
        },
      }),
    ];
  }
}

export class RizinProvider extends Radare2Provider {
  id = "rizin";
  name = "rizin";
  license = "LGPL-3.0-only";
  executables = ["rizin"];
  capabilities() {
    // One below radare2 at each task, so it is the automatic fallback.
    const base = super.capabilities();
    return {
      formats: base.formats,
      tasks: Object.fromEntries(
        Object.entries(base.tasks).map(([task, { priority }]) => [
          task,
          { priority: priority - 1 },
        ]),
      ),
    };
  }
}

export const radare2Providers = () => [
  new Radare2Provider(),
  new RizinProvider(),
];
