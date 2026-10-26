/**
 * Mach-O inspector (thin and fat): header, load commands, segments and
 * sections, linked dylibs (imports), and a bounded symbol table. Written from
 * scratch over the bounded Reader. No external tool.
 */
import { Reader } from "../../bytes.mjs";
import { compareCodePoints } from "../../canonical.mjs";
import { BuiltinInspector } from "./base.mjs";

const MAGIC = {
  0xfeedface: { bits: 32, le: false },
  0xfeedfacf: { bits: 64, le: false },
  0xcefaedfe: { bits: 32, le: true },
  0xcffaedfe: { bits: 64, le: true },
};
const CPU = {
  7: "x86",
  0x01000007: "x86_64",
  12: "arm",
  0x0100000c: "arm64",
  0x0200000c: "arm64_32",
};
const FILETYPE = {
  1: "object",
  2: "executable",
  3: "fixed-vm-lib",
  4: "core",
  5: "preload",
  6: "dylib",
  7: "dylinker",
  8: "bundle",
  10: "dsym",
};
const LC = {
  SEGMENT: 0x1,
  SYMTAB: 0x2,
  SEGMENT_64: 0x19,
  LOAD_DYLIB: 0xc,
  LOAD_WEAK_DYLIB: 0x80000018,
  ID_DYLIB: 0xd,
  MAIN: 0x80000028,
  UUID: 0x1b,
  RPATH: 0x8000001c,
};
const MAX_COMMANDS = 4096;
const MAX_SECTIONS = 4096;
const MAX_SYMBOLS = 50_000;

/** Read one LC_SEGMENT(_64) and its sections into the accumulators. */
function readSegment(r, wide, segments, sections) {
  const name = r.ascii(16).replace(/\0+$/u, "");
  const vmaddr = wide ? r.u64() : r.u32();
  const vmsize = wide ? r.u64() : r.u32();
  const fileoff = wide ? r.u64() : r.u32();
  const filesize = wide ? r.u64() : r.u32();
  r.u32();
  r.u32();
  const nsects = r.u32();
  r.u32();
  segments.push({ name, vmaddr, vmsize, fileoff, filesize });
  for (let s = 0; s < Math.min(nsects, MAX_SECTIONS); s += 1) {
    const sectName = r.ascii(16).replace(/\0+$/u, "");
    const segName = r.ascii(16).replace(/\0+$/u, "");
    const addr = wide ? r.u64() : r.u32();
    const sectSize = wide ? r.u64() : r.u32();
    const offset = r.u32();
    r.u32();
    r.u32();
    r.u32();
    const flags = r.u32();
    r.u32();
    r.u32();
    if (wide) r.u32();
    sections.push({
      segment: segName,
      name: sectName,
      address: addr,
      size: sectSize,
      offset,
      executable:
        segName === "__TEXT" &&
        (sectName === "__text" || (flags & 0x80000400) !== 0),
    });
  }
}

function parseThin(bytes, base = 0) {
  const magic = bytes.readUInt32BE(base);
  const spec = MAGIC[magic] ?? MAGIC[bytes.readUInt32LE(base)];
  if (!spec) throw new RangeError("not a Mach-O magic");
  const r = new Reader(bytes, { littleEndian: spec.le, offset: base });
  r.u32();
  const cpuType = r.u32();
  r.u32();
  const fileType = r.u32();
  const ncmds = r.u32();
  r.u32();
  r.u32();
  if (spec.bits === 64) r.u32();
  const header = {
    bits: spec.bits,
    arch: CPU[cpuType] ?? `cpu-${cpuType}`,
    fileType: FILETYPE[fileType] ?? `type-${fileType}`,
  };
  const segments = [];
  const sections = [];
  const dylibs = [];
  const anomalies = [];
  let symtab;
  let entry = null;
  let uuid = null;
  for (let index = 0; index < Math.min(ncmds, MAX_COMMANDS); index += 1) {
    const start = r.pos;
    const cmd = r.u32();
    const size = r.u32();
    if (size < 8 || start + size > bytes.length) {
      anomalies.push(`load command ${index} has bad size ${size}`);
      break;
    }
    if (cmd === LC.SEGMENT || cmd === LC.SEGMENT_64) {
      readSegment(r, cmd === LC.SEGMENT_64, segments, sections);
    } else if (
      cmd === LC.LOAD_DYLIB ||
      cmd === LC.LOAD_WEAK_DYLIB ||
      cmd === LC.ID_DYLIB
    ) {
      const name = new Reader(bytes).cstringAt(start + r.u32(), size);
      if (cmd !== LC.ID_DYLIB)
        dylibs.push({ name, weak: cmd === LC.LOAD_WEAK_DYLIB });
    } else if (cmd === LC.SYMTAB) {
      symtab = {
        symoff: r.u32(),
        nsyms: r.u32(),
        stroff: r.u32(),
        strsize: r.u32(),
      };
    } else if (cmd === LC.MAIN) {
      entry = r.u64();
    } else if (cmd === LC.UUID) {
      uuid = [...r.bytesOf(16)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    r.seek(start + size);
  }
  return {
    header,
    segments,
    sections,
    dylibs,
    symtab,
    entry,
    uuid,
    anomalies,
    reader: r,
    spec,
  };
}

/** Symbols from the SYMTAB nlist table (bounded). */
function parseSymbols(bytes, parsed) {
  if (!parsed.symtab) return [];
  const { bits, le } = parsed.spec;
  const width = bits === 64 ? 16 : 12;
  const r = new Reader(bytes, { littleEndian: le });
  const symbols = [];
  const count = Math.min(parsed.symtab.nsyms, MAX_SYMBOLS);
  for (let index = 0; index < count; index += 1) {
    const at = parsed.symtab.symoff + index * width;
    if (at + width > bytes.length) break;
    r.seek(at);
    const strx = r.u32();
    const type = r.u8();
    const sect = r.u8();
    r.u16();
    const value = bits === 64 ? r.u64() : r.u32();
    const name = new Reader(bytes).cstringAt(parsed.symtab.stroff + strx, 1024);
    if (!name) continue;
    const external = (type & 0x01) !== 0;
    const defined = (type & 0x0e) !== 0x00 || sect !== 0;
    symbols.push({ name, value, external, defined });
  }
  return symbols;
}

function parseFatOrThin(bytes) {
  const magic = bytes.readUInt32BE(0);
  if (magic === 0xcafebabe || magic === 0xbebafeca) {
    const r = new Reader(bytes, { littleEndian: false });
    r.u32();
    const count = r.u32();
    const slices = [];
    for (let index = 0; index < Math.min(count, 32); index += 1) {
      const cpuType = r.u32();
      r.u32();
      const offset = r.u32();
      r.u32();
      r.u32();
      slices.push({ arch: CPU[cpuType] ?? `cpu-${cpuType}`, offset });
    }
    const first = slices[0] ? parseThin(bytes, slices[0].offset) : null;
    return { fat: true, slices, thin: first };
  }
  return { fat: false, thin: parseThin(bytes, 0) };
}

export class MachoInspector extends BuiltinInspector {
  id = "macho-inspector";
  name = "PTAH Mach-O inspector";
  capabilities() {
    return {
      formats: ["macho"],
      tasks: {
        manifest: { priority: 7 },
        sections: { priority: 7 },
        importsExports: { priority: 7 },
        symbols: { priority: 5 },
      },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const parsed = parseFatOrThin(bytes);
      const thin = parsed.thin;
      return {
        summary: parsed.fat
          ? `Fat Mach-O, ${parsed.slices.length} architectures: ${parsed.slices.map((s) => s.arch).join(", ")}`
          : `Mach-O ${thin.header.bits}-bit ${thin.header.fileType} for ${thin.header.arch}`,
        data: {
          fat: parsed.fat,
          slices: parsed.slices,
          header: thin?.header,
          uuid: thin?.uuid,
          entry: thin?.entry,
        },
        anomalies: thin?.anomalies,
      };
    });
  }
  async sections(target, context) {
    return this.inspect("sections", target, context, (bytes) => {
      const { thin } = parseFatOrThin(bytes);
      return {
        summary: `${thin.segments.length} segments, ${thin.sections.length} sections`,
        data: { segments: thin.segments, sections: thin.sections },
        anomalies: thin.anomalies,
      };
    });
  }
  async importsExports(target, context) {
    return this.inspect("importsExports", target, context, (bytes) => {
      const { thin } = parseFatOrThin(bytes);
      const symbols = parseSymbols(bytes, thin);
      const exports = symbols
        .filter((s) => s.external && s.defined)
        .map((s) => ({ name: s.name }))
        .sort((a, b) => compareCodePoints(a.name, b.name));
      const undefinedImports = symbols
        .filter((s) => s.external && !s.defined)
        .map((s) => ({ name: s.name }))
        .sort((a, b) => compareCodePoints(a.name, b.name));
      return {
        summary: `Links ${thin.dylibs.length} dylibs; ${undefinedImports.length} imported and ${exports.length} exported symbols`,
        data: {
          libraries: thin.dylibs.map((d) => d.name),
          imports: undefinedImports,
          exports,
        },
        anomalies: thin.anomalies,
      };
    });
  }
  async symbols(target, context) {
    return this.inspect("symbols", target, context, (bytes) => {
      const { thin } = parseFatOrThin(bytes);
      const symbols = parseSymbols(bytes, thin);
      return {
        summary: `${symbols.length} symbols`,
        data: { tables: { symtab: symbols } },
        anomalies: thin.anomalies,
      };
    });
  }
}

export const machoProviders = () => [new MachoInspector()];
