/**
 * Dependency-free, execution-free binary inspection primitives for PTAH.
 * Everything here reads bytes; nothing launches the target or any tool.
 */
import { createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { resolve } from "node:path";

const ELF_MACHINES = new Map([
  [0x03, "x86"],
  [0x08, "MIPS"],
  [0x14, "PowerPC"],
  [0x15, "PowerPC64"],
  [0x28, "ARM"],
  [0x2a, "SuperH"],
  [0x32, "IA-64"],
  [0x3e, "x86-64"],
  [0xb7, "AArch64"],
  [0xf3, "RISC-V"],
  [0xf7, "BPF"],
  [0x102, "LoongArch"],
]);

const ELF_TYPES = new Map([
  [1, "relocatable"],
  [2, "executable"],
  [3, "shared-object"],
  [4, "core"],
]);

const PE_MACHINES = new Map([
  [0x014c, "x86"],
  [0x0200, "IA-64"],
  [0x01c0, "ARM"],
  [0x01c4, "ARMv7 Thumb-2"],
  [0xaa64, "ARM64"],
  [0x8664, "x86-64"],
  [0x5032, "RISC-V 32"],
  [0x5064, "RISC-V 64"],
]);

const MACHO_CPU = new Map([
  [0x07, "x86"],
  [0x01000007, "x86-64"],
  [0x0c, "ARM"],
  [0x0100000c, "ARM64"],
  [0x12, "PowerPC"],
  [0x01000012, "PowerPC64"],
]);

/** Shannon entropy in bits per byte (0..8) over the supplied buffer. */
export function shannonEntropy(bytes) {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

function elfDetails(header) {
  if (header.length < 20) return { format: "ELF", truncated: true };
  const is64 = header[4] === 2;
  const littleEndian = header[5] === 1;
  const read16 = (offset) =>
    littleEndian ? header.readUInt16LE(offset) : header.readUInt16BE(offset);
  return {
    format: "ELF",
    class: is64 ? "ELF64" : header[4] === 1 ? "ELF32" : "unknown",
    endianness: littleEndian ? "little" : header[5] === 2 ? "big" : "unknown",
    osAbi: header[7],
    type: ELF_TYPES.get(read16(16)) ?? `unknown(${read16(16)})`,
    machine:
      ELF_MACHINES.get(read16(18)) ?? `unknown(0x${read16(18).toString(16)})`,
  };
}

async function peDetails(handle, size, header) {
  if (header.length < 0x40)
    return { format: "DOS MZ header (PE format not confirmed)" };
  const peOffset = header.readUInt32LE(0x3c);
  if (peOffset + 24 > size || peOffset < 0x40)
    return { format: "DOS MZ header (PE format not confirmed)", peOffset };
  const buffer = Buffer.alloc(24);
  const { bytesRead } = await handle.read(buffer, 0, 24, peOffset);
  if (bytesRead < 24 || buffer.readUInt32LE(0) !== 0x00004550)
    return { format: "DOS MZ header (PE format not confirmed)", peOffset };
  const machine = buffer.readUInt16LE(4);
  const characteristics = buffer.readUInt16LE(22);
  const optionalMagicBuffer = Buffer.alloc(2);
  const optional = await handle.read(optionalMagicBuffer, 0, 2, peOffset + 24);
  const optionalMagic =
    optional.bytesRead === 2 ? optionalMagicBuffer.readUInt16LE(0) : 0;
  return {
    format: "PE",
    peOffset,
    machine: PE_MACHINES.get(machine) ?? `unknown(0x${machine.toString(16)})`,
    sectionCount: buffer.readUInt16LE(6),
    isDll: (characteristics & 0x2000) !== 0,
    isExecutableImage: (characteristics & 0x0002) !== 0,
    optionalHeader:
      optionalMagic === 0x20b
        ? "PE32+"
        : optionalMagic === 0x10b
          ? "PE32"
          : "unknown",
  };
}

function machoDetails(header) {
  if (header.length < 16) return { format: "Mach-O", truncated: true };
  const magic = header.readUInt32BE(0);
  const littleEndian = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const cpu = littleEndian ? header.readUInt32LE(4) : header.readUInt32BE(4);
  return {
    format: is64 ? "Mach-O 64-bit" : "Mach-O 32-bit",
    endianness: littleEndian ? "little" : "big",
    cpu: MACHO_CPU.get(cpu) ?? `unknown(0x${cpu.toString(16)})`,
  };
}

/** Extract structural details for known executable formats from a 64-byte header. */
export async function describeFormat(filePath) {
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const handle = await open(absolutePath, "r");
  try {
    const header = Buffer.alloc(64);
    const { bytesRead } = await handle.read(header, 0, 64, 0);
    const bytes = header.subarray(0, bytesRead);
    if (bytes.length >= 4 && bytes.readUInt32BE(0) === 0x7f454c46)
      return elfDetails(bytes);
    if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a)
      return await peDetails(handle, fileStat.size, bytes);
    if (bytes.length >= 4) {
      const magic = bytes.readUInt32BE(0);
      if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic))
        return machoDetails(bytes);
      if (magic === 0xcafebabe && bytes.length >= 8) {
        const count = bytes.readUInt32BE(4);
        return count < 0x40
          ? { format: "Mach-O universal (fat) binary", architectures: count }
          : { format: "Java class", majorVersion: bytes.readUInt16BE(6) };
      }
    }
    return { format: null };
  } finally {
    await handle.close();
  }
}

/** Compute whole-file entropy with a bounded read. */
export async function fileEntropy(filePath, options = {}) {
  const maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const counts = new Uint32Array(256);
  let scanned = 0;
  for await (const chunk of createReadStream(absolutePath, {
    end: Math.min(fileStat.size, maxBytes) - 1,
  })) {
    for (const byte of chunk) counts[byte] += 1;
    scanned += chunk.length;
  }
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / scanned;
    entropy -= p * Math.log2(p);
  }
  return {
    bitsPerByte: Number(entropy.toFixed(4)),
    scannedBytes: scanned,
    truncated: scanned < fileStat.size,
    hint:
      entropy > 7.2
        ? "high entropy: likely compressed, encrypted, or packed"
        : entropy < 1
          ? "very low entropy: mostly repeated bytes"
          : "typical for code or mixed data",
  };
}

const isPrintable = (byte) => byte >= 0x20 && byte <= 0x7e;

/**
 * Extract printable ASCII and UTF-16LE strings with byte offsets.
 * Bounded by minLength, maxResults, and maxBytes; never executes the target.
 */
export async function extractStrings(filePath, options = {}) {
  const minLength = options.minLength ?? 6;
  const maxResults = options.maxResults ?? 500;
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024;
  if (!Number.isInteger(minLength) || minLength < 2)
    throw new TypeError("minLength must be an integer >= 2");
  if (!Number.isInteger(maxResults) || maxResults < 1)
    throw new TypeError("maxResults must be a positive integer");
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const results = [];
  let scanned = 0;
  let ascii = { start: 0, bytes: [] };
  let wide = { start: 0, bytes: [], expectNull: false };
  let truncatedResults = false;
  const push = (encoding, start, text) => {
    if (text.length < minLength) return;
    if (results.length >= maxResults) {
      truncatedResults = true;
      return;
    }
    results.push({ offset: start, encoding, length: text.length, text });
  };
  const flushAscii = () => {
    if (ascii.bytes.length)
      push("ascii", ascii.start, String.fromCharCode(...ascii.bytes));
    ascii = { start: 0, bytes: [] };
  };
  const flushWide = () => {
    if (wide.bytes.length)
      push("utf-16le", wide.start, String.fromCharCode(...wide.bytes));
    wide = { start: 0, bytes: [], expectNull: false };
  };
  for await (const chunk of createReadStream(absolutePath, {
    end: Math.min(fileStat.size, maxBytes) - 1,
  })) {
    for (let index = 0; index < chunk.length; index += 1) {
      const byte = chunk[index];
      const offset = scanned + index;
      if (isPrintable(byte)) {
        if (ascii.bytes.length === 0) ascii.start = offset;
        ascii.bytes.push(byte);
      } else flushAscii();
      if (wide.expectNull) {
        if (byte === 0) wide.expectNull = false;
        else {
          flushWide();
          if (isPrintable(byte)) {
            wide.start = offset;
            wide.bytes.push(byte);
            wide.expectNull = true;
          }
        }
      } else if (isPrintable(byte)) {
        if (wide.bytes.length === 0) wide.start = offset;
        wide.bytes.push(byte);
        wide.expectNull = true;
      } else flushWide();
      if (truncatedResults) break;
    }
    scanned += chunk.length;
    if (truncatedResults) break;
  }
  flushAscii();
  flushWide();
  results.sort(
    (a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding),
  );
  return {
    path: absolutePath,
    sizeBytes: fileStat.size,
    scannedBytes: Math.min(scanned, fileStat.size),
    minLength,
    count: results.length,
    truncated: truncatedResults || scanned < fileStat.size,
    executed: false,
    strings: results,
  };
}

const EMBEDDED_SIGNATURES = [
  { format: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { format: "PE/MZ", bytes: [0x4d, 0x5a] },
  { format: "Mach-O 64-bit", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { format: "ZIP", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { format: "gzip", bytes: [0x1f, 0x8b, 0x08] },
  { format: "xz", bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { format: "zstd", bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { format: "7-Zip", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { format: "bzip2", bytes: [0x42, 0x5a, 0x68] },
  { format: "PNG", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { format: "PDF", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { format: "SQLite", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20] },
  {
    format: "WebAssembly",
    bytes: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
  },
  { format: "Java class", bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { format: "DEX", bytes: [0x64, 0x65, 0x78, 0x0a, 0x30] },
  { format: "squashfs", bytes: [0x68, 0x73, 0x71, 0x73] },
  { format: "cpio (newc)", bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31] },
  { format: "LZMA", bytes: [0x5d, 0x00, 0x00] },
];

/**
 * Scan a file for embedded signatures at any offset (carving hints). Offset 0
 * is skipped because it is the container's own signature. Bounded and read-only.
 */
export async function findEmbeddedSignatures(filePath, options = {}) {
  const maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
  const maxResults = options.maxResults ?? 200;
  const minimumLength = options.minimumSignatureLength ?? 4;
  if (!Number.isInteger(maxResults) || maxResults < 1)
    throw new TypeError("maxResults must be a positive integer");
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const signatures = EMBEDDED_SIGNATURES.filter(
    (sig) => sig.bytes.length >= minimumLength,
  ).map((sig) => ({ ...sig, buffer: Buffer.from(sig.bytes) }));
  const longest = Math.max(...signatures.map((sig) => sig.buffer.length));
  const hits = [];
  let carry = Buffer.alloc(0);
  let scanned = 0;
  let truncated = false;
  for await (const chunk of createReadStream(absolutePath, {
    end: Math.min(fileStat.size, maxBytes) - 1,
  })) {
    const window = Buffer.concat([carry, chunk]);
    const base = scanned - carry.length;
    for (const sig of signatures) {
      let index = window.indexOf(sig.buffer, 0);
      while (index !== -1) {
        const offset = base + index;
        if (offset > 0) {
          if (hits.length >= maxResults) {
            truncated = true;
            break;
          }
          if (
            !hits.some(
              (hit) => hit.offset === offset && hit.format === sig.format,
            )
          )
            hits.push({
              offset,
              format: sig.format,
              signatureLength: sig.buffer.length,
            });
        }
        index = window.indexOf(sig.buffer, index + 1);
      }
      if (truncated) break;
    }
    scanned += chunk.length;
    carry = window.subarray(Math.max(0, window.length - (longest - 1)));
    if (truncated) break;
  }
  hits.sort((a, b) => a.offset - b.offset || a.format.localeCompare(b.format));
  return {
    path: absolutePath,
    sizeBytes: fileStat.size,
    scannedBytes: Math.min(scanned, fileStat.size),
    truncated: truncated || scanned < fileStat.size,
    count: hits.length,
    executed: false,
    note: "Signature hits are carving hints, not proof of a valid embedded object; MZ and short signatures produce false positives.",
    embedded: hits,
  };
}

/**
 * Parse an Electron ASAR archive header natively: 8-byte pickle (header size)
 * + 8-byte pickle (JSON string size) + JSON directory. Returns the file list
 * without extracting anything.
 */
export async function parseAsarHeader(filePath, options = {}) {
  const maxHeaderBytes = options.maxHeaderBytes ?? 16 * 1024 * 1024;
  const maxEntries = options.maxEntries ?? 5000;
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const handle = await open(absolutePath, "r");
  try {
    const prefix = Buffer.alloc(16);
    const { bytesRead } = await handle.read(prefix, 0, 16, 0);
    if (bytesRead < 16)
      throw new TypeError("file is too small to be an ASAR archive");
    const pickleSize = prefix.readUInt32LE(0);
    const headerSize = prefix.readUInt32LE(4);
    const stringPickleSize = prefix.readUInt32LE(8);
    const jsonLength = prefix.readUInt32LE(12);
    if (
      pickleSize !== 4 ||
      headerSize !== stringPickleSize + 4 ||
      jsonLength > stringPickleSize
    )
      throw new TypeError(
        "not a valid ASAR header (pickle sizes are inconsistent)",
      );
    if (jsonLength > maxHeaderBytes)
      throw new TypeError(`ASAR header JSON exceeds ${maxHeaderBytes} bytes`);
    if (16 + jsonLength > fileStat.size)
      throw new TypeError("ASAR header extends past end of file");
    const json = Buffer.alloc(jsonLength);
    await handle.read(json, 0, jsonLength, 16);
    let header;
    try {
      header = JSON.parse(json.toString("utf8"));
    } catch {
      throw new TypeError("ASAR header JSON is not parseable");
    }
    if (!header || typeof header.files !== "object")
      throw new TypeError("ASAR header lacks a files directory");
    const dataOffset = 8 + headerSize;
    const entries = [];
    let truncated = false;
    const walk = (node, prefixPath) => {
      for (const [name, value] of Object.entries(node.files ?? {})) {
        if (entries.length >= maxEntries) {
          truncated = true;
          return;
        }
        const path = prefixPath ? `${prefixPath}/${name}` : name;
        if (value && typeof value.files === "object") {
          entries.push({ path, type: "directory" });
          walk(value, path);
        } else {
          const size = Number(value?.size ?? 0);
          const offset =
            value?.offset !== undefined ? Number(value.offset) : null;
          entries.push({
            path,
            type: value?.link ? "link" : "file",
            sizeBytes: size,
            dataOffset: offset === null ? null : dataOffset + offset,
            unpacked: value?.unpacked === true,
            executable: value?.executable === true,
            ...(value?.link ? { link: value.link } : {}),
            ...(value?.integrity?.hash
              ? {
                  integrity: {
                    algorithm: value.integrity.algorithm,
                    hash: value.integrity.hash,
                  },
                }
              : {}),
          });
        }
      }
    };
    walk(header, "");
    const files = entries.filter((entry) => entry.type === "file");
    return {
      path: absolutePath,
      sizeBytes: fileStat.size,
      format: "Electron ASAR",
      headerBytes: jsonLength,
      dataOffset,
      entryCount: entries.length,
      fileCount: files.length,
      directoryCount: entries.filter((entry) => entry.type === "directory")
        .length,
      totalFileBytes: files.reduce((sum, entry) => sum + entry.sizeBytes, 0),
      truncated,
      executed: false,
      entries,
    };
  } finally {
    await handle.close();
  }
}

const WASM_SECTION_NAMES = [
  "custom",
  "type",
  "import",
  "function",
  "table",
  "memory",
  "global",
  "export",
  "start",
  "element",
  "code",
  "data",
  "datacount",
  "tag",
];

function readLeb128(buffer, offset) {
  let result = 0;
  let shift = 0;
  let position = offset;
  for (;;) {
    if (position >= buffer.length)
      throw new TypeError("truncated LEB128 value");
    const byte = buffer[position];
    position += 1;
    result += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 35) throw new TypeError("LEB128 value too large");
  }
  return { value: result, next: position };
}

function readName(buffer, offset) {
  const { value: length, next } = readLeb128(buffer, offset);
  if (next + length > buffer.length) throw new TypeError("truncated name");
  return {
    value: buffer.subarray(next, next + length).toString("utf8"),
    next: next + length,
  };
}

/** Parse WebAssembly module sections natively, with import/export names when bounded. */
export async function parseWasmSections(filePath, options = {}) {
  const maxBytes = options.maxBytes ?? 32 * 1024 * 1024;
  const maxNames = options.maxNames ?? 500;
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  if (fileStat.size > maxBytes)
    throw new TypeError(`module exceeds ${maxBytes} bytes`);
  const handle = await open(absolutePath, "r");
  let bytes;
  try {
    bytes = Buffer.alloc(fileStat.size);
    await handle.read(bytes, 0, fileStat.size, 0);
  } finally {
    await handle.close();
  }
  if (bytes.length < 8 || bytes.readUInt32BE(0) !== 0x0061736d)
    throw new TypeError("not a WebAssembly module (magic mismatch)");
  const version = bytes.readUInt32LE(4);
  const sections = [];
  const imports = [];
  const exports_ = [];
  const customNames = [];
  let offset = 8;
  let truncatedNames = false;
  while (offset < bytes.length) {
    const id = bytes[offset];
    const { value: size, next } = readLeb128(bytes, offset + 1);
    if (next + size > bytes.length)
      throw new TypeError(`section ${id} extends past end of module`);
    const body = bytes.subarray(next, next + size);
    const name = WASM_SECTION_NAMES[id] ?? `unknown(${id})`;
    const section = { id, name, offset, sizeBytes: size };
    if (id === 0) {
      const custom = readName(body, 0);
      section.customName = custom.value;
      customNames.push(custom.value);
    }
    if (id === 2 || id === 7) {
      const { value: count, next: start } = readLeb128(body, 0);
      section.count = count;
      let cursor = start;
      for (let index = 0; index < count && cursor < body.length; index += 1) {
        if ((id === 2 ? imports : exports_).length >= maxNames) {
          truncatedNames = true;
          break;
        }
        if (id === 2) {
          const module = readName(body, cursor);
          const field = readName(body, module.next);
          const kind = body[field.next];
          imports.push({
            module: module.value,
            name: field.value,
            kind:
              ["function", "table", "memory", "global", "tag"][kind] ??
              `unknown(${kind})`,
          });
          cursor = field.next + 1;
          const skip = readLeb128(body, cursor);
          cursor = kind === 1 ? cursor + 1 : kind === 2 ? cursor : skip.next;
          if (kind === 1 || kind === 2) {
            const flags = body[cursor];
            cursor += 1;
            cursor = readLeb128(body, cursor).next;
            if (flags & 1) cursor = readLeb128(body, cursor).next;
          } else if (kind === 3) cursor += 1;
        } else {
          const field = readName(body, cursor);
          const kind = body[field.next];
          const indexValue = readLeb128(body, field.next + 1);
          exports_.push({
            name: field.value,
            kind:
              ["function", "table", "memory", "global", "tag"][kind] ??
              `unknown(${kind})`,
            index: indexValue.value,
          });
          cursor = indexValue.next;
        }
      }
    } else if ([1, 3, 4, 5, 6, 9, 10, 11].includes(id)) {
      section.count = readLeb128(body, 0).value;
    }
    sections.push(section);
    offset = next + size;
  }
  return {
    path: absolutePath,
    sizeBytes: fileStat.size,
    format: "WebAssembly",
    version,
    sectionCount: sections.length,
    sections,
    imports,
    exports: exports_,
    customSections: customNames,
    hasStart: sections.some((section) => section.id === 8),
    truncatedNames,
    executed: false,
    note: "Structural parse only; use wasm-tools validate for specification conformance.",
  };
}
