import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runEvaluationSuite, compareEvaluationReports } from "../ptah-eval.mjs";
import { validateInvestigation, fingerprintTarget } from "../ptah-engine.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const suite = join(root, "examples/ptah-eval");

void test("the committed evaluation suite passes and its fixtures match the generator", async () => {
  const report = await runEvaluationSuite(suite);
  assert.equal(
    report.failed,
    0,
    JSON.stringify(
      report.results.filter((r) => !r.passed),
      null,
      2,
    ),
  );
  assert.equal(report.cases, 4);
  assert.equal(report.metrics.checkPassRate, 1);
  assert.equal(report.metrics.claimLabelPrecision, 1);
  assert.equal(report.metrics.unsupportedClaimRate, Number((1 / 3).toFixed(4)));
  assert.equal(typeof report.metrics.medianDurationMs, "number");

  const scratch = await mkdtemp(join(tmpdir(), "ptah-eval-regen-"));
  try {
    const generator = await readFile(
      join(suite, "generate-fixtures.mjs"),
      "utf8",
    );
    const copy = join(scratch, "generate-fixtures.mjs");
    await writeFile(copy, generator);
    const run = spawnSync(process.execPath, [copy], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    for (const result of report.results) {
      const relative = result.observations.fingerprint.path.slice(
        suite.length + 1,
      );
      const regenerated = await fingerprintTarget(join(scratch, relative));
      assert.equal(
        regenerated.sha256,
        result.sha256,
        `${relative} drifted from generate-fixtures.mjs`,
      );
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

void test("evaluation detects wrong expectations, supports filters and operators, and flags regressions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-eval-custom-"));
  try {
    const caseDir = join(dir, "text-case");
    await (await import("node:fs/promises")).mkdir(caseDir);
    await writeFile(join(caseDir, "target.txt"), "hello evaluation harness");
    const digest = (await fingerprintTarget(join(caseDir, "target.txt")))
      .sha256;
    const manifest = (overrides) => ({
      schemaVersion: 1,
      id: "text-case",
      target: "target.txt",
      expect: {
        sha256: digest,
        detectedFormat: { $regex: "^Unknown" },
        inspect: { "entropy.bitsPerByte": { $gte: 3 }, formatDetails: null },
        strings: {
          options: { minLength: 5 },
          includes: ["hello evaluation harness"],
        },
        ...overrides,
      },
    });
    await writeFile(join(caseDir, "case.json"), JSON.stringify(manifest({})));
    const good = await runEvaluationSuite(dir);
    assert.equal(good.passed, 1);
    assert.equal(good.results[0].claimMetrics, null);
    await writeFile(
      join(caseDir, "case.json"),
      JSON.stringify(manifest({ detectedFormat: "ELF" })),
    );
    const bad = await runEvaluationSuite(dir);
    assert.equal(bad.failed, 1);
    assert.deepEqual(
      bad.results[0].checks.filter((c) => !c.pass).map((c) => c.name),
      ["detectedFormat"],
    );
    const comparison = compareEvaluationReports(good, bad);
    assert.equal(comparison.verdict, "regression");
    assert.deepEqual(comparison.regressions, [
      { id: "text-case", change: "now failing" },
    ]);
    assert.equal(
      compareEvaluationReports(bad, good).improvements[0].change,
      "now passing",
    );
    assert.equal(compareEvaluationReports(good, good).verdict, "no-regression");
    const precisionDrop = compareEvaluationReports(
      {
        cases: 1,
        results: [],
        metrics: { claimLabelPrecision: 1, unsupportedClaimRate: 0 },
      },
      {
        cases: 1,
        results: [],
        metrics: { claimLabelPrecision: 0.5, unsupportedClaimRate: 0.25 },
      },
    );
    assert.equal(precisionDrop.regressions.length, 2);
    const filtered = await runEvaluationSuite(dir, { only: ["nope"] });
    assert.equal(filtered.cases, 0);
    await assert.rejects(
      () => runEvaluationSuite(join(dir, "missing")),
      /ENOENT|no evaluation cases/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("validator rejects every single-field mutation of a valid document (mutation test)", () => {
  const digest = "f".repeat(64);
  const valid = {
    schemaVersion: 1,
    target: { id: "t", sha256: digest },
    evidence: [
      {
        id: "e",
        kind: "symbol",
        summary: "s",
        source: "nm",
        confidence: "observed",
        targetSha256: digest,
        artifact: { sha256: digest, sizeBytes: 1 },
        tags: ["a"],
      },
    ],
    claims: [
      {
        id: "c",
        text: "x",
        evidenceIds: ["e"],
        status: "supported",
        tags: ["b"],
      },
    ],
    questions: [
      {
        id: "q",
        text: "?",
        priority: 10,
        requiredEvidenceKinds: ["symbol"],
        resolved: true,
        resolution: { reason: "r", evidenceIds: ["e"] },
      },
    ],
    actions: [{ id: "a", name: "n", produces: ["symbol"], cost: 1 }],
  };
  validateInvestigation(valid);
  const mutations = [
    ["schemaVersion", 2],
    ["target.sha256", "zz"],
    ["target.id", ""],
    ["evidence.0.kind", "magic"],
    ["evidence.0.confidence", "certain"],
    ["evidence.0.targetSha256", "e".repeat(64)],
    ["evidence.0.summary", ""],
    ["evidence.0.artifact.sha256", "nope"],
    ["evidence.0.artifact.sizeBytes", -1],
    ["evidence.0.tags", ["a", "a"]],
    ["claims.0.evidenceIds", []],
    ["claims.0.evidenceIds", ["ghost"]],
    ["claims.0.status", "proven"],
    ["claims.0.text", 7],
    ["questions.0.priority", 101],
    ["questions.0.requiredEvidenceKinds", ["sorcery"]],
    ["questions.0.resolution.evidenceIds", ["ghost"]],
    ["questions.0.resolution.reason", ""],
    ["actions.0.cost", 0],
    ["actions.0.produces", ["sorcery"]],
    ["actions.0.name", undefined],
    [
      "frozen",
      { at: "2026-01-01T00:00:00.000Z", contentSha256: "0".repeat(64) },
    ],
    [
      "relatedCases",
      [{ payloadSha256: digest, targetSha256: digest, sameTarget: "yes" }],
    ],
    [
      "history",
      [
        {
          seq: 1,
          action: "x",
          at: "2026-01-01T00:00:00.000Z",
          previousEntrySha256: null,
          entrySha256: "0".repeat(64),
        },
      ],
    ],
  ];
  const setPath = (object, path, value) => {
    const keys = path.split(".");
    const clone = structuredClone(object);
    let cursor = clone;
    for (const key of keys.slice(0, -1)) cursor = cursor[key];
    if (value === undefined) delete cursor[keys.at(-1)];
    else cursor[keys.at(-1)] = value;
    return clone;
  };
  const survivors = [];
  for (const [path, value] of mutations) {
    try {
      validateInvestigation(setPath(valid, path, value));
      survivors.push(path);
    } catch {
      /* rejected as expected */
    }
  }
  assert.deepEqual(
    survivors,
    [],
    `validator accepted mutations: ${survivors.join(", ")}`,
  );
  const duplicateId = structuredClone(valid);
  duplicateId.evidence.push({ ...valid.evidence[0] });
  assert.throws(() => validateInvestigation(duplicateId), /duplicate id/);
});
