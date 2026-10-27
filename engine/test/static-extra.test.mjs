/**
 * Tests for Batch A static-extra providers:
 * - #10 DemangledNmProvider / detectMangledLanguage / stripRustHash
 * - #6  CryptoInspector / detectCryptoConstants
 * - #9  EntropyInspector / shannonEntropy / entropyWindows
 * - #8  EntryPointInspector
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  detectCryptoConstants,
  detectMangledLanguage,
  entropyWindows,
  shannonEntropy,
  stripRustHash,
  createDefaultRegistry,
  createEngine,
  CryptoInspector,
  EntropyInspector,
  EntryPointInspector,
} from "../src/index.mjs";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const attestation = { ownership: "owner", purpose: "interoperability" };

// ── #10 demangling helpers ────────────────────────────────────────────────────

void test("detectMangledLanguage classifies C++, Rust, and unknown symbols", () => {
  assert.equal(detectMangledLanguage("_ZN3foo3barEv"), "c++");
  assert.equal(detectMangledLanguage("__ZN3foo3barEv"), "c++");
  assert.equal(
    detectMangledLanguage("_ZN4core3fmt5Write9write_fmtE17h1234567890abcdefE"),
    "rust",
  );
  assert.equal(detectMangledLanguage("_RNvNtCs1234_3foo3bar"), "rust");
  assert.equal(detectMangledLanguage("printf"), null);
  assert.equal(detectMangledLanguage("_start"), null);
});

void test("stripRustHash removes the trailing h<hex> hash from Rust symbols", () => {
  const demangled = "core::fmt::write::h1234567890abcdef";
  assert.equal(stripRustHash(demangled), "core::fmt::write");
  assert.equal(stripRustHash("no_hash"), "no_hash");
});

// ── #6 crypto constant detection ─────────────────────────────────────────────

void test("detectCryptoConstants finds AES S-box bytes", () => {
  const aesBytes = Buffer.from([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76,
  ]);
  const buf = Buffer.concat([Buffer.alloc(8), aesBytes, Buffer.alloc(8)]);
  const findings = detectCryptoConstants(buf);
  assert.ok(
    findings.some((f) => f.algo === "aes" && f.label.includes("S-box")),
  );
  assert.equal(findings[0].offset, 8);
});

void test("detectCryptoConstants finds base64 alphabet", () => {
  const table = Buffer.from(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  );
  const buf = Buffer.concat([Buffer.alloc(16), table]);
  const findings = detectCryptoConstants(buf);
  assert.ok(findings.some((f) => f.algo === "base64"));
});

void test("detectCryptoConstants returns empty for random-ish bytes", () => {
  const buf = Buffer.alloc(256, 0xaa);
  assert.equal(detectCryptoConstants(buf).length, 0);
});

void test("CryptoInspector runs on sample ELF and returns evidence", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(
    join(fixtures, "elf/sample.elf"),
    attestation,
  );
  const result = await session.run("resources", {
    provider: "crypto-inspector",
  });
  assert.ok(result.evidence[0].data.algorithmsDetected !== undefined);
  assert.ok(["ok", "partial"].includes(result.evidence[0].status));
});

// ── #9 entropy ────────────────────────────────────────────────────────────────

void test("shannonEntropy returns 0 for uniform buffer", () => {
  assert.equal(shannonEntropy(Buffer.alloc(256, 0x00)), 0);
});

void test("shannonEntropy returns ~8 for fully random-appearing bytes", () => {
  // Build a buffer with all 256 byte values represented equally
  const buf = Buffer.allocUnsafe(256);
  for (let i = 0; i < 256; i++) buf[i] = i;
  const h = shannonEntropy(buf);
  assert.ok(h > 7.99 && h <= 8, `entropy was ${h}`);
});

void test("entropyWindows produces windows for a typical binary", () => {
  const buf = Buffer.allocUnsafe(512);
  for (let i = 0; i < 512; i++) buf[i] = i % 256;
  const windows = entropyWindows(buf);
  assert.equal(windows.length, 2);
  for (const w of windows) {
    assert.ok(typeof w.offset === "number");
    assert.ok(typeof w.entropy === "number");
    assert.ok(typeof w.suspicious === "boolean");
    assert.ok(typeof w.packed === "boolean");
  }
});

void test("EntropyInspector runs on sample ELF and returns section entropy", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(
    join(fixtures, "elf/sample.elf"),
    attestation,
  );
  const result = await session.run("sections", {
    provider: "entropy-inspector",
  });
  const ev = result.evidence[0];
  assert.ok(typeof ev.data.overallEntropy === "number");
  assert.ok(Array.isArray(ev.data.windows));
  assert.ok(typeof ev.data.likelyPacked === "boolean");
});

// ── #8 entry-point inspector ──────────────────────────────────────────────────

void test("EntryPointInspector finds ELF entry point", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(
    join(fixtures, "elf/sample.elf"),
    attestation,
  );
  const result = await session.run("manifest", {
    provider: "entry-point-inspector",
  });
  const ev = result.evidence[0];
  // Entry point may be null for a stripped .so, but evidence must be returned
  assert.ok(["ok", "partial"].includes(ev.status));
  assert.ok("entryPoint" in ev.data);
});

void test("EntryPointInspector data.entryPoint is a hex string for ELF64", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(
    join(fixtures, "elf/sample.elf"),
    attestation,
  );
  const result = await session.run("manifest", {
    provider: "entry-point-inspector",
  });
  const ev = result.evidence[0];
  assert.ok(
    ev.data.entryPoint !== null,
    "ELF64 fixture should have a non-null entry point",
  );
  assert.match(ev.data.entryPoint, /^0x[0-9a-f]+$/);
});

// ── provider count regression ─────────────────────────────────────────────────

void test("adding static-extra providers increases total to >= 37", async () => {
  const registry = createDefaultRegistry();
  await registry.probe();
  assert.ok(
    registry.providers.length >= 37,
    `got ${registry.providers.length}`,
  );
});
