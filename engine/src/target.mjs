/**
 * Target identity: content digest, size, and format detected from magic
 * bytes (and, for ZIP containers, from their central directory). Format ids
 * are what providers declare support for.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";

const HEADER_BYTES = 4096;
const ZIP_TAIL_BYTES = 66_000;
const MAGIC = [
  [[0x7f, 0x45, 0x4c, 0x46], "elf"],
  [[0x00, 0x61, 0x73, 0x6d], "wasm"],
  [[0xcf, 0xfa, 0xed, 0xfe], "macho"],
  [[0xce, 0xfa, 0xed, 0xfe], "macho"],
  [[0xfe, 0xed, 0xfa, 0xcf], "macho"],
  [[0xfe, 0xed, 0xfa, 0xce], "macho"],
  [[0xca, 0xfe, 0xba, 0xbe], "macho-fat-or-java-class"],
  [[0x64, 0x65, 0x78, 0x0a], "dex"],
  [[0x50, 0x4b, 0x03, 0x04], "zip"],
  [[0x50, 0x4b, 0x05, 0x06], "zip"],
  [[0xd4, 0xc3, 0xb2, 0xa1], "pcap"],
  [[0xa1, 0xb2, 0xc3, 0xd4], "pcap"],
  [[0x0a, 0x0d, 0x0d, 0x0a], "pcapng"],
  [[0x47, 0x47, 0x55, 0x46], "gguf"],
  [[0xaf, 0x1b, 0xb1, 0xfa], "il2cpp-metadata"],
  [[0x1f, 0x8b], "gzip"],
  [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], "xz"],
  [[0x28, 0xb5, 0x2f, 0xfd], "zstd"],
  [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], "7z"],
  [[0x42, 0x5a, 0x68], "bzip2"],
  [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], "rar"],
  [[0x47, 0x44, 0x50, 0x43], "godot-pck"],
  [[0x46, 0x4f, 0x52, 0x31], "beam"],
  [
    [
      0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61,
      0x74, 0x20, 0x33, 0x00,
    ],
    "sqlite",
  ],
];

/** Read the central-directory names of a ZIP to tell APK/JAR/IPA apart. */
async function zipEntryNames(handle, size) {
  const length = Math.min(size, ZIP_TAIL_BYTES);
  const tail = Buffer.alloc(length);
  await handle.read(tail, 0, length, size - length);
  const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0 || eocd + 22 > tail.length) return [];
  const count = Math.min(tail.readUInt16LE(eocd + 10), 65_535);
  const directorySize = tail.readUInt32LE(eocd + 12);
  const directoryOffset = tail.readUInt32LE(eocd + 16);
  if (
    directoryOffset + directorySize > size ||
    directorySize > 64 * 1024 * 1024
  )
    return [];
  const directory = Buffer.alloc(directorySize);
  await handle.read(directory, 0, directorySize, directoryOffset);
  const names = [];
  for (
    let at = 0, index = 0;
    index < count && at + 46 <= directory.length;
    index += 1
  ) {
    if (directory.readUInt32LE(at) !== 0x02014b50) break;
    const nameLength = directory.readUInt16LE(at + 28);
    const extra = directory.readUInt16LE(at + 30);
    const comment = directory.readUInt16LE(at + 32);
    names.push(
      directory.toString(
        "utf8",
        at + 46,
        Math.min(directory.length, at + 46 + nameLength),
      ),
    );
    at += 46 + nameLength + extra + comment;
  }
  return names;
}

function zipFlavor(names) {
  const has = (name) => names.includes(name);
  if (
    has("AndroidManifest.xml") &&
    names.some((name) => /^classes\d*\.dex$/u.test(name))
  )
    return "apk";
  if (
    has("BundleConfig.pb") ||
    names.some((name) => name.startsWith("base/manifest/"))
  )
    return "aab";
  if (names.some((name) => /^Payload\/[^/]+\.app\//u.test(name))) return "ipa";
  if (
    has("META-INF/MANIFEST.MF") ||
    names.some((name) => name.endsWith(".class"))
  )
    return "jar";
  return "zip";
}

function peFlavor(header) {
  const pe = header.length >= 0x40 ? header.readUInt32LE(0x3c) : 0;
  if (
    pe + 24 > header.length ||
    header.toString("latin1", pe, pe + 4) !== "PE\0\0"
  )
    return "dos-mz";
  const optional = pe + 24;
  const plus = header.readUInt16LE(optional) === 0x20b;
  const clr = optional + (plus ? 112 : 96) + 14 * 8;
  const managed = clr + 8 <= header.length && header.readUInt32LE(clr) !== 0;
  return managed ? "dotnet" : "pe";
}

function detect(header, names, name) {
  if (header[0] === 0x4d && header[1] === 0x5a) return peFlavor(header);
  if (header.toString("latin1", 0, 2) === "#!") return "script";
  if (header.toString("latin1", 0, 8) === "!<arch>\n") return "ar-archive";
  const match = MAGIC.find(([bytes]) =>
    bytes.every((byte, index) => header[index] === byte),
  );
  if (!match) {
    // Formats without a reliable magic are recognized by extension.
    const lower = name?.toLowerCase() ?? "";
    if (lower.endsWith(".safetensors")) return "safetensors";
    if (lower.endsWith(".asar")) return "asar";
    if (lower.endsWith(".ips")) return "ips";
    // CPython .pyc: bytes 2-3 are CR LF after the version magic.
    if (lower.endsWith(".pyc") && header[2] === 0x0d && header[3] === 0x0a)
      return "pyc";
    return "unknown";
  }
  if (match[1] === "zip") return zipFlavor(names);
  if (match[1] === "macho-fat-or-java-class")
    // Java class files carry a major version >= 45 here; fat Mach-O an arch count.
    return header.readUInt16BE(6) >= 45 ? "java-class" : "macho";
  return match[1];
}

async function digest(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/**
 * Identify a target file. The returned object is what providers receive.
 * @returns {Promise<{path: string, name: string, sizeBytes: number, sha256: string, format: string}>}
 */
export async function identifyTarget(filePath) {
  const path = resolve(filePath);
  const info = await stat(path);
  if (!info.isFile()) throw new TypeError("target must be a regular file");
  const handle = await open(path, "r");
  try {
    const header = Buffer.alloc(Math.min(HEADER_BYTES, info.size));
    await handle.read(header, 0, header.length, 0);
    const isZip = header[0] === 0x50 && header[1] === 0x4b;
    const names = isZip ? await zipEntryNames(handle, info.size) : [];
    return Object.freeze({
      path,
      name: basename(path),
      sizeBytes: info.size,
      sha256: await digest(path),
      format: detect(header, names, basename(path)),
    });
  } finally {
    await handle.close();
  }
}

/** Re-hash a target and report drift from a recorded identity. */
export async function checkDrift(target) {
  const current = await digest(target.path);
  return {
    drifted: current !== target.sha256,
    expected: target.sha256,
    actual: current,
  };
}
