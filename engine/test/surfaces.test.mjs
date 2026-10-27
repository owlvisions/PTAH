/**
 * Tests for Batch C surfaces and performance:
 * - #39 DiskCache
 * - #48 renderHtmlReport / renderSarifReport
 * - #49 loadPlugin
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import test from "node:test";
import {
  DiskCache,
  renderHtmlReport,
  renderSarifReport,
  loadPlugin,
  createDefaultRegistry,
} from "../src/index.mjs";

const DUMMY_SHA = "a".repeat(64);

// ── #39 DiskCache ─────────────────────────────────────────────────────────────

void test("DiskCache set/get round-trips evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cache-"));
  try {
    const cache = new DiskCache(dir);
    const key = cache.cacheKey(DUMMY_SHA, "sections", "readelf");
    const fakeEvidence = [
      { id: "ev1", task: "sections", status: "ok", targetSha256: DUMMY_SHA },
    ];
    await cache.set(key, fakeEvidence);
    const result = await cache.get(key);
    assert.deepEqual(result, fakeEvidence);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("DiskCache returns undefined for missing keys", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cache-"));
  try {
    const cache = new DiskCache(dir);
    const result = await cache.get("nonexistent-key-" + DUMMY_SHA);
    assert.equal(result, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("DiskCache delete removes an entry", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cache-"));
  try {
    const cache = new DiskCache(dir);
    const key = cache.cacheKey(DUMMY_SHA, "manifest", "aapt2");
    await cache.set(key, [{ id: "ev1" }]);
    await cache.delete(key);
    assert.equal(await cache.get(key), undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("DiskCache persists across instances (on-disk)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-persist-"));
  try {
    const cache1 = new DiskCache(dir);
    const key = cache1.cacheKey(DUMMY_SHA, "symbols", "nm");
    const fakeEvidence = [{ id: "ev-persist", task: "symbols" }];
    await cache1.set(key, fakeEvidence);
    // New instance, no in-memory state
    const cache2 = new DiskCache(dir);
    const result = await cache2.get(key);
    assert.deepEqual(result, fakeEvidence);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── #48 HTML/SARIF report ─────────────────────────────────────────────────────

void test("renderHtmlReport produces a self-contained HTML page", () => {
  const target = {
    path: "/tmp/sample.elf",
    format: "elf",
    sha256: DUMMY_SHA,
    size: 1024,
  };
  const results = {
    sections: {
      provider: "readelf",
      evidence: [
        {
          status: "ok",
          confidence: "observed",
          summary: "5 sections",
          data: { sections: [] },
          limitations: [],
          provider: { id: "readelf" },
        },
      ],
    },
    manifest: {
      provider: "readelf",
      evidence: [
        {
          status: "partial",
          confidence: "derived",
          summary: "partial manifest",
          data: {},
          limitations: ["some limitation"],
          provider: { id: "readelf" },
        },
      ],
    },
  };
  const html = renderHtmlReport(target, results);
  assert.ok(html.includes("<!doctype html>"));
  assert.ok(html.includes("PTAH Report"));
  assert.ok(html.includes("sections"));
  assert.ok(html.includes("5 sections"));
  assert.ok(html.includes(DUMMY_SHA));
  assert.ok(html.includes("partial manifest"));
});

void test("renderHtmlReport escapes HTML-special characters in summaries", () => {
  const target = { path: "/tmp/t.bin", format: "elf", sha256: DUMMY_SHA };
  const results = {
    strings: {
      provider: "nm",
      evidence: [
        {
          status: "ok",
          confidence: "observed",
          summary: '<script>alert("xss")</script>',
          data: {},
          limitations: [],
          provider: { id: "nm" },
        },
      ],
    },
  };
  const html = renderHtmlReport(target, results);
  assert.ok(
    !html.includes('<script>alert("xss")'),
    "raw script tag must be escaped",
  );
  assert.ok(html.includes("&lt;script&gt;"));
});

void test("renderSarifReport returns valid SARIF 2.1 structure", () => {
  const target = { path: "/tmp/sample.elf", sha256: DUMMY_SHA };
  const results = {
    sections: {
      provider: "readelf",
      evidence: [
        {
          status: "failed",
          confidence: "observed",
          summary: "readelf failed",
          data: {},
          limitations: [],
          provider: { id: "readelf" },
        },
      ],
    },
    manifest: {
      provider: "aapt2",
      evidence: [
        {
          status: "ok",
          confidence: "observed",
          summary: "ok",
          data: {},
          limitations: [],
          provider: { id: "aapt2" },
        },
      ],
    },
  };
  const sarif = renderSarifReport(target, results);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.ok(sarif.runs[0].results.some((r) => r.level === "error"));
  // ok status should not produce a SARIF result
  assert.ok(
    !sarif.runs[0].results.some(
      (r) => r.ruleId === "ptah/manifest" && r.level === "note",
    ),
  );
});

// ── #49 Plugin API ────────────────────────────────────────────────────────────

void test("loadPlugin registers providers from a valid plugin module", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-plugin-"));
  try {
    const pluginPath = join(dir, "my-plugin.mjs");
    // Write a minimal valid plugin
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      pluginPath,
      `
import { AnalysisProvider } from ${JSON.stringify(new URL("../src/provider.mjs", import.meta.url).href)};
class TestProvider extends AnalysisProvider {
  id = "test-plugin-provider";
  name = "Test Plugin Provider";
  kind = "builtin";
  license = "MIT";
  capabilities() { return { formats: ["elf"], tasks: { strings: { priority: 1 } } }; }
  async isAvailable() { return { available: true }; }
  async strings() { throw new Error("not implemented"); }
  async disassemble() { throw new Error("not implemented"); }
  async decompile() { throw new Error("not implemented"); }
  async symbols() { throw new Error("not implemented"); }
  async importsExports() { throw new Error("not implemented"); }
  async resources() { throw new Error("not implemented"); }
  async manifest() { throw new Error("not implemented"); }
  async sections() { throw new Error("not implemented"); }
}
export function providers() { return [new TestProvider()]; }
`,
    );
    const registry = createDefaultRegistry();
    const before = registry.providers.length;
    const registered = await loadPlugin(
      registry,
      pathToFileURL(pluginPath).href,
    );
    assert.equal(registered.length, 1);
    assert.equal(registered[0], "test-plugin-provider");
    assert.equal(registry.providers.length, before + 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("loadPlugin throws when module has no providers() export", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-plugin-bad-"));
  try {
    const { writeFile } = await import("node:fs/promises");
    const pluginPath = join(dir, "bad-plugin.mjs");
    await writeFile(pluginPath, "export const version = 1;");
    const registry = createDefaultRegistry();
    await assert.rejects(
      () => loadPlugin(registry, pathToFileURL(pluginPath).href),
      /must export a providers\(\) function/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
