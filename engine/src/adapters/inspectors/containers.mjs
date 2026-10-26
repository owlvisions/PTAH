/**
 * Built-in inspectors for container and data formats: GGUF, safetensors,
 * SQLite, Godot PCK, and Erlang BEAM. Each parses headers and tables from the
 * bytes directly, with bounded counts. No external tool.
 */
import { Reader } from "../../bytes.mjs";
import { BuiltinInspector } from "./base.mjs";

const MAX_ENTRIES = 100_000;
const GGUF_TYPES = {
  0: "u8",
  1: "i8",
  2: "u16",
  3: "i16",
  4: "u32",
  5: "i32",
  6: "f32",
  7: "bool",
  8: "string",
  9: "array",
  10: "u64",
  11: "i64",
  12: "f64",
};

/** GGUF (llama.cpp model): magic, version, tensor/metadata counts, metadata keys. */
export function parseGguf(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  if (r.ascii(4) !== "GGUF") throw new RangeError("not a GGUF file");
  const version = r.u32();
  const tensorCount = r.u64();
  const kvCount = r.u64();
  const str = () => r.ascii(r.u64());
  const skipValue = (type) => {
    switch (type) {
      case 8:
        str();
        return;
      case 9: {
        const itemType = r.u32();
        const n = r.u64();
        for (let i = 0; i < Math.min(n, MAX_ENTRIES); i += 1)
          skipValue(itemType);
        return;
      }
      case 0:
      case 1:
      case 7:
        r.u8();
        return;
      case 2:
      case 3:
        r.u16();
        return;
      case 4:
      case 5:
      case 6:
        r.u32();
        return;
      case 10:
      case 11:
      case 12:
        r.u64();
        return;
      default:
        throw new RangeError(`unknown GGUF value type ${type}`);
    }
  };
  const metadata = {};
  for (let index = 0; index < Math.min(kvCount, MAX_ENTRIES); index += 1) {
    const key = str();
    const type = r.u32();
    if (type === 8) metadata[key] = str();
    else if (type >= 4 && type <= 6)
      metadata[key] = type === 6 ? "<f32>" : r.u32();
    else {
      metadata[key] = `<${GGUF_TYPES[type] ?? type}>`;
      if (type !== 4 && type !== 5) skipValue(type);
    }
  }
  return {
    version,
    tensorCount,
    metadataCount: kvCount,
    architecture: metadata["general.architecture"] ?? null,
    name: metadata["general.name"] ?? null,
    metadata,
  };
}

/** safetensors: 8-byte LE header length, then a JSON tensor dictionary. */
export function parseSafetensors(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  const headerLen = r.u64();
  if (headerLen > bytes.length - 8)
    throw new RangeError("safetensors header length exceeds file");
  const header = JSON.parse(r.ascii(headerLen));
  const tensors = Object.entries(header)
    .filter(([name]) => name !== "__metadata__")
    .map(([name, info]) => ({ name, dtype: info.dtype, shape: info.shape }));
  return {
    tensorCount: tensors.length,
    dtypes: [...new Set(tensors.map((t) => t.dtype))],
    metadata: header.__metadata__ ?? {},
    tensors: tensors.slice(0, 1000),
  };
}

const SQLITE_ENCODING = { 1: "utf-8", 2: "utf-16le", 3: "utf-16be" };

/** SQLite database header (first 100 bytes). */
export function parseSqlite(bytes) {
  const r = new Reader(bytes, { littleEndian: false });
  if (r.ascii(16) !== "SQLite format 3\0")
    throw new RangeError("not a SQLite database");
  const rawPageSize = r.u16();
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
  r.seek(56);
  const encoding = r.u32();
  r.seek(28);
  const pageCount = r.u32();
  return {
    pageSize,
    pageCount,
    sizeBytes: pageSize * pageCount,
    textEncoding: SQLITE_ENCODING[encoding] ?? `code-${encoding}`,
  };
}

/** Godot PCK package: magic, version, and the file table. */
export function parseGodotPck(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  if (r.u32() !== 0x43504447) throw new RangeError("not a Godot PCK (GDPC)");
  const formatVersion = r.u32();
  const engine = { major: r.u32(), minor: r.u32(), patch: r.u32() };
  r.seek(formatVersion >= 2 ? r.pos + 16 * 4 : r.pos);
  const fileCount = r.u32();
  const files = [];
  for (let index = 0; index < Math.min(fileCount, MAX_ENTRIES); index += 1) {
    const pathLen = r.u32();
    const path = r.ascii(pathLen).replace(/\0+$/u, "");
    const offset = r.u64();
    const size = r.u64();
    r.bytesOf(16);
    if (formatVersion >= 2) r.u32();
    files.push({ path, offset, size });
  }
  return {
    formatVersion,
    engineVersion: `${engine.major}.${engine.minor}.${engine.patch}`,
    fileCount,
    files: files.slice(0, 5000),
  };
}

/** Erlang BEAM: IFF "FOR1" container with "BEAM" type and named chunks. */
export function parseBeam(bytes) {
  const r = new Reader(bytes, { littleEndian: false });
  if (r.ascii(4) !== "FOR1") throw new RangeError("not a BEAM file");
  const totalSize = r.u32();
  if (r.ascii(4) !== "BEAM") throw new RangeError("missing BEAM form type");
  const chunks = [];
  const end = Math.min(bytes.length, 8 + totalSize);
  while (r.pos + 8 <= end && chunks.length < 1024) {
    const id = r.ascii(4);
    const size = r.u32();
    chunks.push({ id, size });
    r.seek(Math.min(end, r.pos + size + ((4 - (size % 4)) % 4)));
  }
  return {
    chunks,
    chunkNames: chunks.map((c) => c.id),
    hasCode: chunks.some((c) => c.id === "Code"),
    hasAtoms: chunks.some((c) => c.id === "AtU8" || c.id === "Atom"),
  };
}

export class GgufInspector extends BuiltinInspector {
  id = "gguf-inspector";
  name = "PTAH GGUF inspector";
  capabilities() {
    return { formats: ["gguf"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const g = parseGguf(bytes);
      return {
        summary: `GGUF v${g.version} model${g.architecture ? ` (${g.architecture})` : ""}: ${g.tensorCount} tensors, ${g.metadataCount} metadata keys`,
        data: g,
      };
    });
  }
}

export class SafetensorsInspector extends BuiltinInspector {
  id = "safetensors-inspector";
  name = "PTAH safetensors inspector";
  capabilities() {
    return { formats: ["safetensors"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const s = parseSafetensors(bytes);
      return {
        summary: `safetensors: ${s.tensorCount} tensors, dtypes ${s.dtypes.join(", ")}`,
        data: s,
      };
    });
  }
}

export class SqliteInspector extends BuiltinInspector {
  id = "sqlite-inspector";
  name = "PTAH SQLite inspector";
  capabilities() {
    return { formats: ["sqlite"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const s = parseSqlite(bytes);
      return {
        summary: `SQLite database: ${s.pageCount} pages of ${s.pageSize} bytes (${s.textEncoding})`,
        data: s,
      };
    });
  }
}

export class GodotPckInspector extends BuiltinInspector {
  id = "godot-pck-inspector";
  name = "PTAH Godot PCK inspector";
  capabilities() {
    return {
      formats: ["godot-pck"],
      tasks: { manifest: { priority: 7 }, resources: { priority: 7 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const p = parseGodotPck(bytes);
      return {
        summary: `Godot ${p.engineVersion} PCK (format ${p.formatVersion}): ${p.fileCount} files`,
        data: {
          formatVersion: p.formatVersion,
          engineVersion: p.engineVersion,
          fileCount: p.fileCount,
        },
      };
    });
  }
  async resources(target, context) {
    return this.inspect("resources", target, context, (bytes) => {
      const p = parseGodotPck(bytes);
      return {
        summary: `${p.fileCount} packaged resources`,
        data: { files: p.files },
      };
    });
  }
}

export class BeamInspector extends BuiltinInspector {
  id = "beam-inspector";
  name = "PTAH BEAM inspector";
  capabilities() {
    return {
      formats: ["beam"],
      tasks: { manifest: { priority: 7 }, sections: { priority: 7 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const b = parseBeam(bytes);
      return {
        summary: `Erlang BEAM module: ${b.chunks.length} chunks (${b.chunkNames.join(", ")})`,
        data: { chunkNames: b.chunkNames, hasCode: b.hasCode },
      };
    });
  }
  async sections(target, context) {
    return this.inspect("sections", target, context, (bytes) => {
      const b = parseBeam(bytes);
      return {
        summary: `${b.chunks.length} BEAM chunks`,
        data: { sections: b.chunks.map((c) => ({ name: c.id, size: c.size })) },
      };
    });
  }
}

export const containerProviders = () => [
  new GgufInspector(),
  new SafetensorsInspector(),
  new SqliteInspector(),
  new GodotPckInspector(),
  new BeamInspector(),
];
