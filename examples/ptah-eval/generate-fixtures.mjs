#!/usr/bin/env node
/**
 * Regenerates the synthetic evaluation targets deterministically. Fixtures are
 * hand-constructed headers, not real programs; nothing here is executable.
 * Run: node examples/ptah-eval/generate-fixtures.mjs
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

function leb(value) {
  const bytes = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0);
  return Buffer.from(bytes);
}
const name = (text) =>
  Buffer.concat([leb(Buffer.byteLength(text)), Buffer.from(text)]);
const section = (id, body) =>
  Buffer.concat([Buffer.from([id]), leb(body.length), body]);

const fixtures = {
  "elf-aarch64-shared/target.so": () => {
    const elf = Buffer.alloc(256);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
    elf.writeUInt16LE(3, 16); // ET_DYN
    elf.writeUInt16LE(0xb7, 18); // AArch64
    elf.write("PTAH_SYNTHETIC_LIBRARY", 128, "ascii");
    elf.write("/lib/ld-linux-aarch64.so.1", 160, "ascii");
    return elf;
  },
  "pe-x64-dll/target.dll": () => {
    const pe = Buffer.alloc(512);
    pe.write("MZ", 0, "ascii");
    pe.writeUInt32LE(0x80, 0x3c);
    pe.write("PE\0\0", 0x80, "ascii");
    pe.writeUInt16LE(0x8664, 0x84);
    pe.writeUInt16LE(3, 0x86);
    pe.writeUInt16LE(0x2022, 0x80 + 22); // executable image + DLL
    pe.writeUInt16LE(0x20b, 0x80 + 24);
    pe.write("PtahSyntheticExport", 0x180, "ascii");
    return pe;
  },
  "wasm-module/target.wasm": () => {
    const type = section(1, Buffer.concat([leb(1), Buffer.from([0x60, 0, 0])]));
    const imports = section(
      2,
      Buffer.concat([
        leb(1),
        name("env"),
        name("log"),
        Buffer.from([0]),
        leb(0),
      ]),
    );
    const func = section(3, Buffer.concat([leb(1), leb(0)]));
    const exports = section(
      7,
      Buffer.concat([leb(1), name("run"), Buffer.from([0]), leb(1)]),
    );
    const code = section(
      10,
      Buffer.concat([leb(1), leb(2), Buffer.from([0, 0x0b])]),
    );
    const custom = section(
      0,
      Buffer.concat([name("producers"), Buffer.from("ptah")]),
    );
    return Buffer.concat([
      Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
      type,
      imports,
      func,
      exports,
      code,
      custom,
    ]);
  },
  "zip-with-embedded-png/target.zip": () => {
    const zipLocal = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      Buffer.alloc(26),
    ]);
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    return Buffer.concat([
      zipLocal,
      Buffer.from("README-INSIDE-ARCHIVE"),
      Buffer.alloc(40),
      png,
      Buffer.alloc(16),
    ]);
  },
};

for (const [relative, build] of Object.entries(fixtures)) {
  const path = join(root, relative);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, build());
  process.stdout.write(`${relative}\n`);
}
