/**
 * Native, bounds-checked ELF and PE structure parsing: sections with entropy,
 * imports, exports, linked libraries, imphash, and packer hints.
 *
 * Targets are hostile: every offset is checked against the buffer, every
 * table has a count cap, and malformed structures are reported as anomalies
 * rather than thrown, so partial facts survive.
 */
import { createHash } from "node:crypto";
import { open, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { shannonEntropy } from "./ptah-analysis.mjs";

export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;
const MAX_SECTIONS = 4096;
const MAX_ENTRIES = 20_000;
const MAX_NAME = 512;

/** Read a regular file up to `maxBytes`; returns the bytes and whether it was truncated. */
export async function readTargetBytes(filePath, maxBytes = DEFAULT_MAX_BYTES) {
  const path = resolve(filePath);
  const info = await stat(path);
  if (!info.isFile()) throw new TypeError("target must be a regular file");
  const length = Math.min(info.size, maxBytes);
  const handle = await open(path, "r");
  try {
    const bytes = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const { bytesRead } = await handle.read(bytes, read, length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    return {
      path,
      bytes: bytes.subarray(0, read),
      size: info.size,
      truncated: info.size > length,
    };
  } finally {
    await handle.close();
  }
}

/** Bounds-checked little/big-endian reader over one buffer. */
function reader(bytes, littleEndian = true) {
  const fits = (offset, width) =>
    Number.isSafeInteger(offset) &&
    offset >= 0 &&
    offset + width <= bytes.length;
  const need = (offset, width) => {
    if (!fits(offset, width))
      throw new RangeError(`read past end at ${offset}`);
  };
  return {
    fits,
    u8: (o) => (need(o, 1), bytes[o]),
    u16: (o) => (
      need(o, 2),
      littleEndian ? bytes.readUInt16LE(o) : bytes.readUInt16BE(o)
    ),
    u32: (o) => (
      need(o, 4),
      littleEndian ? bytes.readUInt32LE(o) : bytes.readUInt32BE(o)
    ),
    u64: (o) => {
      need(o, 8);
      const value = littleEndian
        ? bytes.readBigUInt64LE(o)
        : bytes.readBigUInt64BE(o);
      if (value > BigInt(Number.MAX_SAFE_INTEGER))
        throw new RangeError(`value too large at ${o}`);
      return Number(value);
    },
    cstring: (o, max = MAX_NAME) => {
      if (!fits(o, 1)) return "";
      const end = bytes.indexOf(0, o);
      const stop = Math.min(end < 0 ? bytes.length : end, o + max);
      return bytes.toString("latin1", o, stop);
    },
  };
}

const round = (value) => Math.round(value * 1000) / 1000;
const sectionEntropy = (bytes, offset, size) =>
  size > 0 && offset >= 0 && offset < bytes.length
    ? round(
        shannonEntropy(
          bytes.subarray(offset, Math.min(bytes.length, offset + size)),
        ),
      )
    : null;

const SHT = {
  NULL: 0,
  SYMTAB: 2,
  STRTAB: 3,
  DYNAMIC: 6,
  NOBITS: 8,
  DYNSYM: 11,
};

function elfLayout(r, is64) {
  return is64
    ? {
        shoff: r.u64(0x28),
        shentsize: r.u16(0x3a),
        shnum: r.u16(0x3c),
        shstrndx: r.u16(0x3e),
      }
    : {
        shoff: r.u32(0x20),
        shentsize: r.u16(0x2e),
        shnum: r.u16(0x30),
        shstrndx: r.u16(0x32),
      };
}

function elfSectionHeader(r, at, is64) {
  return is64
    ? {
        nameOffset: r.u32(at),
        type: r.u32(at + 4),
        flags: r.u64(at + 8),
        addr: r.u64(at + 16),
        offset: r.u64(at + 24),
        size: r.u64(at + 32),
        link: r.u32(at + 40),
        entsize: r.u64(at + 56),
      }
    : {
        nameOffset: r.u32(at),
        type: r.u32(at + 4),
        flags: r.u32(at + 8),
        addr: r.u32(at + 12),
        offset: r.u32(at + 16),
        size: r.u32(at + 20),
        link: r.u32(at + 24),
        entsize: r.u32(at + 36),
      };
}

function elfSymbols({ r, is64, anomalies }, section, strtab) {
  const width = is64 ? 24 : 16;
  const count = Math.min(Math.floor(section.size / width), MAX_ENTRIES);
  const imports = [];
  const exports = [];
  for (let index = 1; index < count; index += 1) {
    const at = section.offset + index * width;
    if (!r.fits(at, width)) {
      anomalies.push(`${section.name} truncated at symbol ${index}`);
      break;
    }
    const nameOffset = r.u32(at);
    const info = is64 ? r.u8(at + 4) : r.u8(at + 12);
    const shndx = is64 ? r.u16(at + 6) : r.u16(at + 14);
    const name = strtab ? r.cstring(strtab.offset + nameOffset) : "";
    if (!name) continue;
    const binding = info >> 4;
    const type = info & 0xf;
    if (shndx === 0) imports.push(name);
    else if ((binding === 1 || binding === 2) && (type === 1 || type === 2))
      exports.push(name);
  }
  return { imports, exports };
}

function elfNeeded(r, dynamic, strtab, is64) {
  const width = is64 ? 16 : 8;
  const needed = [];
  let soname = null;
  const count = Math.min(Math.floor(dynamic.size / width), MAX_ENTRIES);
  for (let index = 0; index < count; index += 1) {
    const at = dynamic.offset + index * width;
    if (!r.fits(at, width)) break;
    const tag = is64 ? r.u64(at) : r.u32(at);
    const value = is64 ? r.u64(at + 8) : r.u32(at + 4);
    if (tag === 0) break;
    if (tag === 1 && strtab) needed.push(r.cstring(strtab.offset + value));
    if (tag === 14 && strtab) soname = r.cstring(strtab.offset + value);
  }
  return { needed, soname };
}

/** Parse ELF sections, dynamic dependencies, and symbols. */
export function parseElf(bytes) {
  const anomalies = [];
  const is64 = bytes[4] === 2;
  const r = reader(bytes, bytes[5] !== 2);
  const layout = elfLayout(r, is64);
  const sections = [];
  if (layout.shnum > MAX_SECTIONS)
    anomalies.push(`section count ${layout.shnum} exceeds ${MAX_SECTIONS}`);
  for (
    let index = 0;
    index < Math.min(layout.shnum, MAX_SECTIONS);
    index += 1
  ) {
    const at = layout.shoff + index * layout.shentsize;
    if (!r.fits(at, is64 ? 64 : 40)) {
      anomalies.push(`section header ${index} lies outside the file`);
      break;
    }
    sections.push(elfSectionHeader(r, at, is64));
  }
  const names = sections[layout.shstrndx];
  for (const section of sections)
    section.name = names ? r.cstring(names.offset + section.nameOffset) : "";
  const result = {
    format: "ELF",
    bits: is64 ? 64 : 32,
    sections: sections
      .filter((section) => section.type !== SHT.NULL)
      .map((section) => ({
        name: section.name,
        type: section.type,
        offset: section.offset,
        size: section.size,
        executable: (section.flags & 0x4) !== 0,
        entropy:
          section.type === SHT.NOBITS
            ? null
            : sectionEntropy(bytes, section.offset, section.size),
      })),
    libraries: [],
    imports: [],
    exports: [],
    soname: null,
    anomalies,
  };
  const symbolTable =
    sections.find((section) => section.type === SHT.DYNSYM) ??
    sections.find((section) => section.type === SHT.SYMTAB);
  if (symbolTable) {
    const symbols = elfSymbols(
      { r, is64, anomalies },
      symbolTable,
      sections[symbolTable.link],
    );
    result.imports = [...new Set(symbols.imports)].sort();
    result.exports = [...new Set(symbols.exports)].sort();
  }
  const dynamic = sections.find((section) => section.type === SHT.DYNAMIC);
  if (dynamic)
    Object.assign(
      result,
      (({ needed, soname }) => ({ libraries: needed, soname }))(
        elfNeeded(r, dynamic, sections[dynamic.link], is64),
      ),
    );
  return result;
}

function peSections(r, start, count) {
  const sections = [];
  for (let index = 0; index < Math.min(count, 96); index += 1) {
    const at = start + index * 40;
    if (!r.fits(at, 40)) break;
    sections.push({
      name: r.cstring(at, 8),
      virtualSize: r.u32(at + 8),
      virtualAddress: r.u32(at + 12),
      rawSize: r.u32(at + 16),
      offset: r.u32(at + 20),
      characteristics: r.u32(at + 36),
    });
  }
  return sections;
}

function rvaResolver(sections) {
  return (rva) => {
    const section = sections.find(
      (item) =>
        rva >= item.virtualAddress &&
        rva < item.virtualAddress + Math.max(item.virtualSize, item.rawSize),
    );
    return section ? rva - section.virtualAddress + section.offset : undefined;
  };
}

function peImports({ r, toOffset, pe32Plus, anomalies }, directory) {
  const imports = [];
  let at = toOffset(directory.rva);
  for (
    let descriptor = 0;
    at !== undefined && descriptor < 4096;
    descriptor += 1, at += 20
  ) {
    if (!r.fits(at, 20)) {
      anomalies.push("import directory runs past the end of the file");
      break;
    }
    const lookup = r.u32(at) || r.u32(at + 16);
    const nameRva = r.u32(at + 12);
    if (lookup === 0 && nameRva === 0) break;
    const nameOffset = toOffset(nameRva);
    const library = nameOffset === undefined ? "" : r.cstring(nameOffset);
    const functions = [];
    let thunk = toOffset(lookup);
    const width = pe32Plus ? 8 : 4;
    for (
      let index = 0;
      thunk !== undefined && index < MAX_ENTRIES && r.fits(thunk, width);
      index += 1, thunk += width
    ) {
      const high = pe32Plus ? r.u32(thunk + 4) : r.u32(thunk);
      const low = r.u32(thunk);
      if (low === 0 && (!pe32Plus || high === 0)) break;
      const byOrdinal = pe32Plus
        ? (high & 0x80000000) !== 0
        : (low & 0x80000000) !== 0;
      if (byOrdinal) functions.push(`ord${low & 0xffff}`);
      else {
        const hint = toOffset(low & 0x7fffffff);
        functions.push(hint === undefined ? "?" : r.cstring(hint + 2));
      }
    }
    imports.push({ library, functions });
  }
  return imports;
}

function peExports(r, directory, toOffset) {
  const at = toOffset(directory.rva);
  if (at === undefined || !r.fits(at, 40)) return { name: null, functions: [] };
  const nameOffset = toOffset(r.u32(at + 12));
  const count = Math.min(r.u32(at + 24), MAX_ENTRIES);
  const names = toOffset(r.u32(at + 32));
  const functions = [];
  for (
    let index = 0;
    names !== undefined && index < count && r.fits(names + index * 4, 4);
    index += 1
  ) {
    const offset = toOffset(r.u32(names + index * 4));
    if (offset !== undefined) functions.push(r.cstring(offset));
  }
  return {
    name: nameOffset === undefined ? null : r.cstring(nameOffset),
    functions,
  };
}

/** pefile-compatible imphash for name imports; ordinals use `ord<N>`. */
export function imphash(imports) {
  const parts = [];
  for (const { library, functions } of imports) {
    const lib = library.toLowerCase().replace(/\.(dll|ocx|sys)$/u, "");
    for (const fn of functions) parts.push(`${lib}.${fn.toLowerCase()}`);
  }
  return parts.length
    ? createHash("md5").update(parts.join(",")).digest("hex")
    : null;
}

/** Parse PE sections, imports, exports, and imphash. */
export function parsePe(bytes) {
  const anomalies = [];
  const r = reader(bytes);
  const pe = r.u32(0x3c);
  if (!r.fits(pe, 24) || bytes.toString("latin1", pe, pe + 4) !== "PE\0\0")
    throw new TypeError("not a PE image (missing PE signature)");
  const sectionCount = r.u16(pe + 6);
  const optionalSize = r.u16(pe + 20);
  const optional = pe + 24;
  const pe32Plus = r.u16(optional) === 0x20b;
  const directoryStart = optional + (pe32Plus ? 112 : 96);
  const directoryCount = Math.min(r.u32(optional + (pe32Plus ? 108 : 92)), 16);
  const directory = (index) =>
    index < directoryCount && r.fits(directoryStart + index * 8, 8)
      ? {
          rva: r.u32(directoryStart + index * 8),
          size: r.u32(directoryStart + index * 8 + 4),
        }
      : { rva: 0, size: 0 };
  const sections = peSections(r, optional + optionalSize, sectionCount);
  if (sectionCount > 96)
    anomalies.push(`section count ${sectionCount} exceeds the PE limit of 96`);
  const toOffset = rvaResolver(sections);
  const importDirectory = directory(1);
  const exportDirectory = directory(0);
  const imports = importDirectory.rva
    ? peImports({ r, toOffset, pe32Plus, anomalies }, importDirectory)
    : [];
  const exported = exportDirectory.rva
    ? peExports(r, exportDirectory, toOffset)
    : { name: null, functions: [] };
  return {
    format: "PE",
    bits: pe32Plus ? 64 : 32,
    sections: sections.map((section) => ({
      name: section.name,
      offset: section.offset,
      size: section.rawSize,
      virtualSize: section.virtualSize,
      executable: (section.characteristics & 0x20000000) !== 0,
      entropy: sectionEntropy(bytes, section.offset, section.rawSize),
    })),
    libraries: imports.map((item) => item.library),
    imports: imports.flatMap((item) =>
      item.functions.map((fn) => `${item.library}!${fn}`),
    ),
    importsByLibrary: imports,
    exports: exported.functions,
    exportName: exported.name,
    imphash: imphash(imports),
    anomalies,
  };
}

const PACKER_SECTIONS = [
  [/^UPX\d?$/iu, "UPX"],
  [/^\.aspack$|^\.adata$/iu, "ASPack"],
  [/^\.MPRESS\d$/iu, "MPRESS"],
  [/^\.themida$|^\.winlice$/iu, "Themida/WinLicense"],
  [/^\.vmp\d$/iu, "VMProtect"],
  [/^\.petite$/iu, "Petite"],
  [/^\.nsp\d$/iu, "NsPack"],
  [/^\.enigma\d$/iu, "Enigma"],
];

/** Heuristic packer/obfuscation hints; each hint names the observation behind it. */
export function packerHints(structure, bytes) {
  const hints = [];
  for (const section of structure.sections)
    for (const [pattern, packer] of PACKER_SECTIONS)
      if (pattern.test(section.name))
        hints.push({ packer, reason: `section named ${section.name}` });
  if (bytes.includes("UPX!"))
    hints.push({ packer: "UPX", reason: "UPX! marker present" });
  for (const section of structure.sections)
    if (section.executable && section.entropy !== null && section.entropy > 7.2)
      hints.push({
        packer: "unknown",
        reason: `executable section ${section.name || "(unnamed)"} has entropy ${section.entropy}`,
      });
  const imports = structure.imports.map((name) => name.split("!").at(-1));
  if (
    structure.format === "PE" &&
    imports.length > 0 &&
    imports.length <= 6 &&
    imports.some((name) => /^(LoadLibrary|GetProcAddress)/u.test(name))
  )
    hints.push({
      packer: "unknown",
      reason: `only ${imports.length} imports, including dynamic API resolution`,
    });
  return hints;
}

/** Parse the structure of an ELF or PE target, with packer hints. */
export async function analyzeStructure(filePath, options = {}) {
  const { path, bytes, size, truncated } = await readTargetBytes(
    filePath,
    options.maxBytes,
  );
  const elf =
    bytes.length >= 64 &&
    bytes[0] === 0x7f &&
    bytes.toString("latin1", 1, 4) === "ELF";
  const pe = bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  if (!elf && !pe)
    throw new TypeError("structure analysis supports ELF and PE targets");
  let structure;
  try {
    structure = elf ? parseElf(bytes) : parsePe(bytes);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    // A header pointing outside the file is itself a finding about the target.
    structure = {
      format: elf ? "ELF" : "PE",
      sections: [],
      libraries: [],
      imports: [],
      exports: [],
      anomalies: [`malformed header: ${error.message}`],
    };
  }
  return {
    path,
    size,
    truncated,
    ...structure,
    packerHints: packerHints(structure, bytes),
  };
}
