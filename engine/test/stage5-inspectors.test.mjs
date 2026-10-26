import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  MachoInspector,
  createDefaultRegistry,
  createEngine,
  detectToolchains,
  identifyTarget,
  inspectorProviders,
  parseBeam,
  parseEvm,
  parseGguf,
  parseGodotPck,
  parseIl2cpp,
  parseSafetensors,
  parseSqlite,
} from "../src/index.mjs";

const attestation = { ownership: "owner", purpose: "interoperability" };

async function withTarget(bytes, name, fn) {
  const dir = await mkdtemp(join(tmpdir(), "ptah-s5-"));
  const path = join(dir, name);
  await writeFile(path, bytes);
  try {
    return await fn(path);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// --- fixture builders (PTAH's own synthetic samples) ---

/** A minimal 64-bit little-endian Mach-O dylib with one segment/section, a dylib, and a symbol. */
function macho64() {
  const strtab = Buffer.from("\0_main\0_malloc\0");
  const nlist = Buffer.alloc(32);
  // _main: defined, external (n_type 0x0f, n_sect 1)
  nlist.writeUInt32LE(1, 0);
  nlist.writeUInt8(0x0f, 4);
  nlist.writeUInt8(1, 5);
  nlist.writeBigUInt64LE(0x1000n, 8);
  // _malloc: undefined, external (n_type 0x01, n_sect 0)
  nlist.writeUInt32LE(7, 16);
  nlist.writeUInt8(0x01, 20);
  nlist.writeUInt8(0, 21);
  nlist.writeBigUInt64LE(0n, 24);

  const seg = Buffer.alloc(72 + 80);
  seg.writeUInt32LE(0x19, 0); // LC_SEGMENT_64
  seg.writeUInt32LE(72 + 80, 4);
  seg.write("__TEXT", 8, "latin1");
  seg.writeUInt32LE(1, 64); // nsects
  const sec = seg.subarray(72);
  sec.write("__text", 0, "latin1");
  sec.write("__TEXT", 16, "latin1");
  sec.writeUInt32LE(0x80000400, 64); // flags: pure instructions

  const dylibName = "/usr/lib/libSystem.B.dylib\0";
  const dylibSize = 24 + Math.ceil(dylibName.length / 4) * 4;
  const dylib = Buffer.alloc(dylibSize);
  dylib.writeUInt32LE(0xc, 0); // LC_LOAD_DYLIB
  dylib.writeUInt32LE(dylibSize, 4);
  dylib.writeUInt32LE(24, 8); // name offset
  dylib.write(dylibName, 24, "latin1");

  const header = Buffer.alloc(32);
  const loadCmds = Buffer.concat([seg, dylib]);
  const symtabCmdSize = 24;
  const symtab = Buffer.alloc(symtabCmdSize);
  const headerAndCmds = 32 + loadCmds.length + symtabCmdSize;
  const symoff = headerAndCmds;
  const stroff = symoff + nlist.length;
  symtab.writeUInt32LE(0x2, 0); // LC_SYMTAB
  symtab.writeUInt32LE(symtabCmdSize, 4);
  symtab.writeUInt32LE(symoff, 8);
  symtab.writeUInt32LE(2, 12); // nsyms
  symtab.writeUInt32LE(stroff, 16);
  symtab.writeUInt32LE(strtab.length, 20);

  header.writeUInt32LE(0xfeedfacf, 0); // 64-bit LE magic
  header.writeUInt32LE(0x0100000c, 4); // arm64
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(6, 12); // dylib
  header.writeUInt32LE(3, 16); // ncmds
  header.writeUInt32LE(loadCmds.length + symtabCmdSize, 20);
  return Buffer.concat([header, loadCmds, symtab, nlist, strtab]);
}

function gguf() {
  const parts = [Buffer.from("GGUF")];
  const u32 = (v) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
  };
  const u64 = (v) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(v));
    return b;
  };
  const str = (s) => {
    const b = Buffer.from(s);
    return Buffer.concat([u64(b.length), b]);
  };
  parts.push(u32(3), u64(0), u64(2)); // version 3, 0 tensors, 2 kv
  parts.push(str("general.architecture"), u32(8), str("llama"));
  parts.push(str("general.name"), u32(8), str("ptah-test-model"));
  return Buffer.concat(parts);
}

function safetensors() {
  const header = Buffer.from(
    JSON.stringify({
      weight: { dtype: "F32", shape: [2, 3], data_offsets: [0, 24] },
      __metadata__: { framework: "pt" },
    }),
  );
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(header.length));
  return Buffer.concat([len, header, Buffer.alloc(24)]);
}

function sqlite() {
  const b = Buffer.alloc(200);
  b.write("SQLite format 3\0", 0, "latin1");
  b.writeUInt16BE(4096, 16); // page size
  b.writeUInt32BE(3, 28); // page count
  b.writeUInt32BE(1, 56); // utf-8
  return b;
}

function godotPck() {
  const u32 = (v) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
  };
  const u64 = (v) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(v));
    return b;
  };
  const path = Buffer.from("res://main.tscn");
  const entry = Buffer.concat([
    u32(path.length),
    path,
    u64(100),
    u64(42),
    Buffer.alloc(16),
  ]);
  return Buffer.concat([
    u32(0x43504447),
    u32(1),
    u32(3),
    u32(5),
    u32(0),
    u32(1),
    entry,
  ]);
}

function beam() {
  const chunk = (id, data) => {
    const h = Buffer.alloc(8);
    h.write(id, 0, "latin1");
    h.writeUInt32BE(data.length, 4);
    const pad = (4 - (data.length % 4)) % 4;
    return Buffer.concat([h, data, Buffer.alloc(pad)]);
  };
  const body = Buffer.concat([
    Buffer.from("BEAM"),
    chunk("AtU8", Buffer.from("atoms")),
    chunk("Code", Buffer.from("bytecode")),
  ]);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(body.length);
  return Buffer.concat([Buffer.from("FOR1"), size, body]);
}

function il2cpp(version) {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0xfab11baf, 0);
  b.writeUInt32LE(version, 4);
  b.writeUInt32LE(0, 8);
  b.writeUInt32LE(5, 12);
  return b;
}

const evmHex = "6080604052348015600e575f80fd5b50"; // trivial constructor prologue

void test("Mach-O inspector parses header, sections, dylibs, and symbols from a synthetic binary", async () => {
  await withTarget(macho64(), "lib.dylib", async (path) => {
    const target = await identifyTarget(path);
    assert.equal(target.format, "macho");
    const inspector = new MachoInspector();
    const manifest = (await inspector.manifest(target, {}))[0];
    assert.equal(manifest.data.header.bits, 64);
    assert.equal(manifest.data.header.arch, "arm64");
    assert.equal(manifest.data.header.fileType, "dylib");
    const sections = (await inspector.sections(target, {}))[0];
    assert.ok(
      sections.data.sections.some((s) => s.name === "__text" && s.executable),
    );
    const ie = (await inspector.importsExports(target, {}))[0];
    assert.deepEqual(ie.data.libraries, ["/usr/lib/libSystem.B.dylib"]);
    assert.ok(ie.data.imports.some((s) => s.name === "_malloc"));
    assert.ok(ie.data.exports.some((s) => s.name === "_main"));
  });
});

void test("container inspectors parse GGUF, safetensors, SQLite, Godot PCK, and BEAM", () => {
  const g = parseGguf(gguf());
  assert.equal(g.version, 3);
  assert.equal(g.architecture, "llama");
  assert.equal(g.name, "ptah-test-model");
  const s = parseSafetensors(safetensors());
  assert.equal(s.tensorCount, 1);
  assert.deepEqual(s.dtypes, ["F32"]);
  assert.equal(s.metadata.framework, "pt");
  const db = parseSqlite(sqlite());
  assert.deepEqual(
    [db.pageSize, db.pageCount, db.textEncoding],
    [4096, 3, "utf-8"],
  );
  const pck = parseGodotPck(godotPck());
  assert.equal(pck.engineVersion, "3.5.0");
  assert.equal(pck.files[0].path, "res://main.tscn");
  const b = parseBeam(beam());
  assert.deepEqual(b.chunkNames, ["AtU8", "Code"]);
  assert.equal(b.hasCode, true);
});

void test("bytecode inspectors parse EVM and IL2CPP, and recognize known IL2CPP versions", () => {
  const evm = parseEvm(Buffer.from(evmHex));
  assert.ok(evm.instructions > 0);
  assert.equal(
    parseEvm(Buffer.from(`0x${evmHex}`)).byteLength,
    evmHex.length / 2,
  );
  for (const version of [24, 27, 29, 31, 39])
    assert.equal(
      parseIl2cpp(il2cpp(version)).recognizedVersion,
      true,
      `v${version}`,
    );
  assert.equal(parseIl2cpp(il2cpp(99)).recognizedVersion, false);
});

void test("the toolchain detector finds Go, Rust, Flutter, and PyInstaller markers", () => {
  const go = Buffer.concat([
    Buffer.from("\xff Go buildinf:", "latin1"),
    Buffer.alloc(16),
    Buffer.from("go1.22.3\0", "latin1"),
  ]);
  assert.equal(
    detectToolchains(go).find((t) => t.toolchain === "go").goVersion,
    "go1.22.3",
  );
  assert.ok(
    detectToolchains(Buffer.from("...rustc version 1.77.0 (...)...")).some(
      (t) => t.toolchain === "rust",
    ),
  );
  assert.ok(
    detectToolchains(Buffer.from("x libflutter.so kDartVmSnapshotData y")).some(
      (t) => t.toolchain === "flutter",
    ),
  );
  assert.ok(
    detectToolchains(
      Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e python3.11", "latin1"),
    ).some((t) => t.toolchain === "pyinstaller"),
  );
  assert.deepEqual(detectToolchains(Buffer.from("ordinary bytes")), []);
});

void test("built-in inspectors turn malformed input into an anomaly, not a crash", async () => {
  await withTarget(
    Buffer.from("GGUFXX not really"),
    "bad.gguf",
    async (path) => {
      const target = { ...(await identifyTarget(path)), format: "gguf" };
      const evidence = (
        await new (inspectorProviders().find(
          (p) => p.id === "gguf-inspector",
        ).constructor)().manifest(target, {})
      )[0];
      assert.equal(evidence.status, "partial");
      assert.ok(evidence.data.anomalies.length > 0);
    },
  );
});

void test("inspectors are always available and route through the engine by format", async () => {
  const registry = createDefaultRegistry();
  const table = await registry.probe();
  for (const id of [
    "macho-inspector",
    "gguf-inspector",
    "sqlite-inspector",
    "il2cpp-inspector",
  ])
    assert.equal(table.providers.find((p) => p.id === id).available, true, id);
  assert.ok(table.routes.gguf.manifest.includes("gguf-inspector"));
  assert.ok(table.routes.macho.importsExports.includes("macho-inspector"));

  await withTarget(gguf(), "m.gguf", async (path) => {
    const session = await createEngine({ registry }).open(path, attestation);
    assert.equal(session.target.format, "gguf");
    const result = await session.run("manifest");
    assert.equal(result.provider, "gguf-inspector");
    assert.equal(result.evidence[0].confidence, "observed");
    assert.equal(result.evidence[0].data.architecture, "llama");
  });

  await withTarget(il2cpp(29), "global-metadata.dat", async (path) => {
    const session = await createEngine({ registry }).open(path, attestation);
    assert.equal(session.target.format, "il2cpp-metadata");
    assert.equal((await session.run("manifest")).evidence[0].data.version, 29);
  });
});
