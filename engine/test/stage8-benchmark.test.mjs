import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  REA_FORMATS,
  benchmark,
  capabilityMatrix,
  coverageSummary,
  createDefaultRegistry,
  createEngine,
  renderBenchmarkMarkdown,
  renderMatrixMarkdown,
} from "../src/index.mjs";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

void test("the capability matrix covers every provider and marks parity vs beyond REA", async () => {
  const registry = createDefaultRegistry();
  await registry.probe();
  const rows = capabilityMatrix(registry);
  const summary = coverageSummary(registry);
  assert.ok(summary.providers >= 27);
  assert.deepEqual(summary.byKind, { tool: 11, engine: 7, builtin: 9 });
  assert.ok(summary.formatCount >= 20);
  // Every provider appears in at least one matrix row.
  const inMatrix = new Set(rows.flatMap((r) => r.providers));
  for (const provider of registry.providers)
    assert.ok(inMatrix.has(provider.id), `${provider.id} missing from matrix`);
  // Each row is classified, and parity rows are REA formats.
  for (const row of rows) {
    assert.ok(["parity", "beyond"].includes(row.comparison));
    assert.equal(row.comparison === "parity", REA_FORMATS.has(row.format));
  }
  const markdown = renderMatrixMarkdown(registry);
  assert.match(markdown, /# PTAH Engine capability matrix/);
  assert.match(markdown, /\| macho \| manifest \|/);
});

void test("the benchmark runs tasks over real fixtures and measures them", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const targets = [
    {
      path: join(fixtures, "wasm/sample.wasm"),
      tasks: ["sections", "importsExports"],
    },
    {
      path: join(fixtures, "dotnet/sample.dll"),
      tasks: ["manifest", "symbols"],
    },
    { path: join(fixtures, "android/sample.apk"), tasks: ["manifest"] },
  ];
  const report = await benchmark({ engine, targets });
  assert.ok(report.results.length > 0);
  assert.ok(report.totals.tasksRun >= 4);
  assert.ok(report.totals.succeeded >= 4, JSON.stringify(report.totals));
  assert.ok(report.totals.formatsCovered.includes("wasm"));
  assert.ok(report.totals.formatsCovered.includes("dotnet"));
  for (const row of report.results.filter((r) => !r.meta && !r.error)) {
    assert.equal(typeof row.ms, "number");
    assert.ok(row.ms >= 0);
    assert.ok(["ok", "partial", "unavailable", "failed"].includes(row.status));
  }
  assert.match(renderBenchmarkMarkdown(report), /# PTAH Engine benchmark/);
});

void test("the benchmark records fallbacks and never crashes on an unsupported task", async () => {
  const engine = createEngine({ registry: createDefaultRegistry() });
  const report = await benchmark({
    engine,
    targets: [
      {
        path: join(fixtures, "firmware/sample.bin"),
        tasks: ["decompile", "resources"],
      },
    ],
  });
  const decompile = report.results.find((r) => r.task === "decompile");
  assert.equal(
    decompile.status,
    "unavailable",
    "no decompiler claims firmware; degrades cleanly",
  );
  const resources = report.results.find((r) => r.task === "resources");
  assert.ok(["ok", "partial"].includes(resources.status));
});
