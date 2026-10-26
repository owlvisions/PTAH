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
