/**
 * Parity inspectors closing the remaining REA format gaps: archives
 * (zip/jar/apk entry listing), Electron ASAR, Apple IPS crash reports, and
 * CPython .pyc. Written from scratch over the bounded Reader; no external tool.
 */
import { Reader } from "../../bytes.mjs";
import { compareCodePoints } from "../../canonical.mjs";
import { BuiltinInspector } from "./base.mjs";

const MAX_ENTRIES = 100_000;

/** ZIP central directory: name, size, compression, offset per entry. */
export function parseZipEntries(bytes) {
  const eocd = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new RangeError("no ZIP end-of-central-directory");
  // EOCD: +10 total records (u16), +12 CD size (u32), +16 CD offset (u32).
  const r = new Reader(bytes, { littleEndian: true, offset: eocd + 10 });
  const count = r.u16();
  const size = r.u32();
  const offset = r.u32();
  if (offset + size > bytes.length)
    throw new RangeError("central directory outside file");
  const entries = [];
  const dir = new Reader(bytes, { littleEndian: true, offset });
  for (let index = 0; index < Math.min(count, MAX_ENTRIES); index += 1) {
    if (dir.u32() !== 0x02014b50) break;
    dir.seek(dir.pos + 6);
    const method = dir.u16();
    dir.seek(dir.pos + 8);
    const compressedSize = dir.u32();
    const uncompressedSize = dir.u32();
    const nameLen = dir.u16();
    const extraLen = dir.u16();
    const commentLen = dir.u16();
    dir.seek(dir.pos + 8);
    const localOffset = dir.u32();
    const name = dir.ascii(nameLen);
    dir.seek(dir.pos + extraLen + commentLen);
    entries.push({
      name,
      method:
        method === 0 ? "store" : method === 8 ? "deflate" : `method-${method}`,
      compressedSize,
      size: uncompressedSize,
      offset: localOffset,
    });
  }
  return entries;
}

/** Electron ASAR: a Pickle-framed JSON header describing a virtual filesystem. */
export function parseAsar(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  if (r.u32() !== 4) throw new RangeError("not an ASAR header (pickle size)");
  const headerSize = r.u32();
  const stringSize = r.u32();
  const jsonLength = r.u32();
  if (
    headerSize !== stringSize + 4 ||
    jsonLength > stringSize ||
    16 + jsonLength > bytes.length
  )
    throw new RangeError("inconsistent ASAR pickle sizes");
  const header = JSON.parse(r.bytesOf(jsonLength).toString("utf8"));
  const files = [];
  const walk = (node, path) => {
    if (files.length >= MAX_ENTRIES) return;
    if (node.files)
      for (const [name, child] of Object.entries(node.files))
        walk(child, path ? `${path}/${name}` : name);
    else
      files.push({
        path,
        size: node.size ?? 0,
        offset: node.offset ?? null,
        executable: Boolean(node.executable),
        unpacked: Boolean(node.unpacked),
      });
  };
  walk(header, "");
  return {
    fileCount: files.length,
    files,
    javascript: files.filter((f) => f.path.endsWith(".js")).length,
  };
}

/** Apple IPS crash report: a JSON header line followed by a JSON body. */
export function parseIps(bytes) {
  const text = bytes.toString("utf8");
  const newline = text.indexOf("\n");
  const head = JSON.parse(text.slice(0, newline < 0 ? text.length : newline));
  let body = {};
  try {
    body = JSON.parse(text.slice(newline + 1));
  } catch {
    body = {};
  }
  return {
    app: head.app_name ?? head.procName ?? body.procName ?? null,
    version: head.app_version ?? body.version ?? null,
    bugType: head.bug_type ?? null,
    osVersion: body.osVersion?.train ?? head.os_version ?? null,
    exception: body.exception ?? null,
    faultingThread: body.faultingThread ?? null,
    binaryImages: Array.isArray(body.usedImages)
      ? body.usedImages.length
      : null,
  };
}

const PYC_MAGIC = {
  3310: "3.6",
  3379: "3.7",
  3394: "3.8",
  3425: "3.9",
  3439: "3.10",
  3495: "3.11",
  3531: "3.12",
  3571: "3.13",
};

/** CPython .pyc header: magic → version, bit-field flags, timestamp/size. */
export function parsePyc(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  const magic = r.u16();
  if (r.u16() !== 0x0a0d)
    throw new RangeError("not a .pyc file (missing CR LF)");
  const flags = r.u32();
  const hashBased = (flags & 0x1) !== 0;
  return {
    magicNumber: magic,
    pythonVersion: PYC_MAGIC[magic] ?? "unknown",
    hashBased,
    sourceHashValidation: hashBased && (flags & 0x2) !== 0,
  };
}

export class ArchiveInspector extends BuiltinInspector {
  id = "archive-inspector";
  name = "PTAH archive inspector";
  capabilities() {
    return {
      formats: ["zip", "jar", "apk", "aab", "ipa"],
      tasks: { resources: { priority: 3 } },
    };
  }
  async resources(target, context) {
    return this.inspect("resources", target, context, (bytes) => {
      const entries = parseZipEntries(bytes);
      const total = entries.reduce((sum, e) => sum + e.size, 0);
      return {
        summary: `${entries.length} archive entries, ${total} uncompressed bytes`,
        data: {
          files: entries
            .map(({ name, size, method }) => ({ path: name, size, method }))
            .sort((a, b) => compareCodePoints(a.path, b.path)),
        },
      };
    });
  }
}

export class AsarInspector extends BuiltinInspector {
  id = "asar-inspector";
  name = "PTAH Electron ASAR inspector";
  capabilities() {
    return {
      formats: ["asar"],
      tasks: { manifest: { priority: 7 }, resources: { priority: 7 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const a = parseAsar(bytes);
      return {
        summary: `Electron ASAR: ${a.fileCount} files (${a.javascript} JavaScript)`,
        data: { fileCount: a.fileCount, javascript: a.javascript },
      };
    });
  }
  async resources(target, context) {
    return this.inspect("resources", target, context, (bytes) => {
      const a = parseAsar(bytes);
      return {
        summary: `${a.fileCount} packaged files`,
        data: { files: a.files },
      };
    });
  }
}

export class IpsInspector extends BuiltinInspector {
  id = "ips-inspector";
  name = "PTAH Apple crash-report inspector";
  capabilities() {
    return { formats: ["ips"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const c = parseIps(bytes);
      return {
        summary: `IPS crash for ${c.app ?? "?"} ${c.version ?? ""} (${c.bugType ?? "crash"}); ${c.binaryImages ?? "?"} images`,
        data: c,
      };
    });
  }
}

export class PycInspector extends BuiltinInspector {
  id = "pyc-inspector";
  name = "PTAH Python bytecode inspector";
  capabilities() {
    return { formats: ["pyc"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const p = parsePyc(bytes);
      return {
        summary: `CPython ${p.pythonVersion} bytecode (magic ${p.magicNumber}${p.hashBased ? ", hash-based" : ""})`,
        data: p,
      };
    });
  }
}

export const formats2Providers = () => [
  new ArchiveInspector(),
  new AsarInspector(),
  new IpsInspector(),
  new PycInspector(),
];
