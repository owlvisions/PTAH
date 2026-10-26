/**
 * PTAH evaluation harness. Runs pinned fixtures through the dependency-free
 * engine, compares results with reference answers, and reports accuracy,
 * unsupported-claim rate, and latency. Nothing here executes a target.
 */
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import {
  buildEvidenceReport,
  fingerprintTarget,
  inspectTarget,
  lintInvestigation,
  investigationStats,
  validateInvestigation,
  verifyInvestigation,
} from "./ptah-engine.mjs";
import { extractStrings, parseWasmSections } from "./ptah-analysis.mjs";

export const EVAL_REPORT_VERSION = 1;

function deepGet(object, path) {
  return path.split(".").reduce((value, key) => value?.[key], object);
}

function compare(actual, expected) {
  if (expected && typeof expected === "object" && !Array.isArray(expected)) {
    if ("$regex" in expected)
      return new RegExp(expected.$regex, "u").test(String(actual));
    if ("$gte" in expected)
      return typeof actual === "number" && actual >= expected.$gte;
    if ("$lte" in expected)
      return typeof actual === "number" && actual <= expected.$lte;
    if ("$includes" in expected)
      return Array.isArray(actual) && actual.includes(expected.$includes);
    if ("$length" in expected)
      return Array.isArray(actual) && actual.length === expected.$length;
  }
  return JSON.stringify(actual) === JSON.stringify(expected);
}

async function loadCase(caseDir) {
  const manifest = JSON.parse(
    await readFile(join(caseDir, "case.json"), "utf8"),
  );
  if (manifest.schemaVersion !== 1)
    throw new TypeError(`${caseDir}: case.schemaVersion must be 1`);
  const targetPath = resolve(caseDir, manifest.target);
  if (!(await stat(targetPath)).isFile())
    throw new TypeError(`${caseDir}: target is not a file`);
  const investigation = manifest.investigation
    ? validateInvestigation(
        JSON.parse(
          await readFile(resolve(caseDir, manifest.investigation), "utf8"),
        ),
      )
    : null;
  return {
    id: manifest.id ?? basename(caseDir),
    dir: caseDir,
    manifest,
    targetPath,
    investigation,
  };
}

async function runCase(evalCase) {
  const started = performance.now();
  const observations = {};
  const checks = [];
  const check = (name, actual, expected) => {
    const pass = compare(actual, expected);
    checks.push({ name, pass, expected, actual });
    return pass;
  };
  const fingerprint = await fingerprintTarget(evalCase.targetPath);
  observations.fingerprint = fingerprint;
  const expectations = evalCase.manifest.expect ?? {};
  if (expectations.sha256 !== undefined)
    check("sha256", fingerprint.sha256, expectations.sha256);
  if (expectations.detectedFormat !== undefined)
    check(
      "detectedFormat",
      fingerprint.detectedFormat,
      expectations.detectedFormat,
    );
  if (expectations.inspect) {
    const inspected = await inspectTarget(evalCase.targetPath);
    observations.inspect = {
      formatDetails: inspected.formatDetails,
      entropy: inspected.entropy,
    };
    for (const [path, expected] of Object.entries(expectations.inspect))
      check(`inspect.${path}`, deepGet(inspected, path), expected);
  }
  if (expectations.strings) {
    const strings = await extractStrings(
      evalCase.targetPath,
      expectations.strings.options ?? {},
    );
    observations.strings = {
      count: strings.count,
      truncated: strings.truncated,
    };
    for (const text of expectations.strings.includes ?? [])
      check(
        `strings.includes:${text}`,
        strings.strings.some((s) => s.text === text),
        true,
      );
    for (const text of expectations.strings.excludes ?? [])
      check(
        `strings.excludes:${text}`,
        strings.strings.some((s) => s.text === text),
        false,
      );
  }
  if (expectations.wasm) {
    const wasm = await parseWasmSections(evalCase.targetPath);
    observations.wasm = {
      sectionCount: wasm.sectionCount,
      exports: wasm.exports.length,
    };
    for (const [path, expected] of Object.entries(expectations.wasm))
      check(`wasm.${path}`, deepGet(wasm, path), expected);
  }
  let claimMetrics = null;
  if (evalCase.investigation) {
    const verification = await verifyInvestigation(
      evalCase.investigation,
      evalCase.targetPath,
    );
    check("investigation.targetMatches", verification.targetMatches, true);
    const report = buildEvidenceReport(evalCase.investigation);
    const lint = lintInvestigation(evalCase.investigation);
    const stats = investigationStats(evalCase.investigation);
    observations.lint = lint.counts;
    observations.stats = stats.claims;
    if (expectations.lintOk !== undefined)
      check("lint.ok", lint.ok, expectations.lintOk);
    const referenceLabels = evalCase.manifest.reference?.claimLabels ?? {};
    let correct = 0;
    let labelled = 0;
    for (const claim of report.claims) {
      const expected = referenceLabels[claim.id];
      if (expected === undefined) continue;
      labelled += 1;
      if (check(`claim.${claim.id}.supportLabel`, claim.supportLabel, expected))
        correct += 1;
    }
    const supported = report.claims.filter(
      (c) => c.supportLabel !== "inference-only",
    ).length;
    claimMetrics = {
      total: report.claims.length,
      labelled,
      correctLabels: correct,
      labelPrecision:
        labelled === 0 ? null : Number((correct / labelled).toFixed(4)),
      unsupportedClaimRate:
        report.claims.length === 0
          ? null
          : Number(
              (
                (report.claims.length - supported) /
                report.claims.length
              ).toFixed(4),
            ),
    };
  }
  const durationMs = Number((performance.now() - started).toFixed(2));
  return {
    id: evalCase.id,
    target: basename(evalCase.targetPath),
    sha256: fingerprint.sha256,
    passed: checks.every((c) => c.pass),
    checks,
    checkCounts: {
      total: checks.length,
      passed: checks.filter((c) => c.pass).length,
    },
    claimMetrics,
    durationMs,
    observations,
  };
}

/** Run every case directory under `suiteDir` (each containing case.json). */
export async function runEvaluationSuite(suiteDir, options = {}) {
  const root = resolve(suiteDir);
  const entries = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(root, entry.name))
    .sort();
  const cases = [];
  for (const dir of entries) {
    try {
      await stat(join(dir, "case.json"));
    } catch {
      continue;
    }
    cases.push(await loadCase(dir));
  }
  if (cases.length === 0)
    throw new Error(`no evaluation cases found under ${root}`);
  const filter = options.only ? new Set(options.only) : null;
  const results = [];
  for (const evalCase of cases) {
    if (filter && !filter.has(evalCase.id)) continue;
    results.push(await runCase(evalCase));
  }
  const totals = results.reduce(
    (acc, result) => {
      acc.checks += result.checkCounts.total;
      acc.checksPassed += result.checkCounts.passed;
      if (result.claimMetrics) {
        acc.claims += result.claimMetrics.total;
        acc.labelled += result.claimMetrics.labelled;
        acc.correctLabels += result.claimMetrics.correctLabels;
        acc.unsupported += Math.round(
          (result.claimMetrics.unsupportedClaimRate ?? 0) *
            result.claimMetrics.total,
        );
      }
      acc.durationMs += result.durationMs;
      return acc;
    },
    {
      checks: 0,
      checksPassed: 0,
      claims: 0,
      labelled: 0,
      correctLabels: 0,
      unsupported: 0,
      durationMs: 0,
    },
  );
  const durations = results.map((r) => r.durationMs).sort((a, b) => a - b);
  const percentile = (p) =>
    durations.length === 0
      ? null
      : durations[
          Math.min(durations.length - 1, Math.floor(p * durations.length))
        ];
  return {
    reportVersion: EVAL_REPORT_VERSION,
    suite: root,
    cases: results.length,
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
    metrics: {
      checkPassRate:
        totals.checks === 0
          ? null
          : Number((totals.checksPassed / totals.checks).toFixed(4)),
      claimLabelPrecision:
        totals.labelled === 0
          ? null
          : Number((totals.correctLabels / totals.labelled).toFixed(4)),
      unsupportedClaimRate:
        totals.claims === 0
          ? null
          : Number((totals.unsupported / totals.claims).toFixed(4)),
      medianDurationMs: percentile(0.5),
      p95DurationMs: percentile(0.95),
      totalDurationMs: Number(totals.durationMs.toFixed(2)),
    },
    results,
    environment: { node: process.versions.node, platform: process.platform },
    note: "Durations are wall-clock on this machine and are not comparable across hosts; accuracy metrics are.",
  };
}

/** Compare a new report against a baseline; regressions are accuracy drops or newly failing cases. */
export function compareEvaluationReports(baseline, current) {
  const baselineById = new Map((baseline.results ?? []).map((r) => [r.id, r]));
  const regressions = [];
  const improvements = [];
  for (const result of current.results ?? []) {
    const before = baselineById.get(result.id);
    if (!before) continue;
    if (before.passed && !result.passed)
      regressions.push({ id: result.id, change: "now failing" });
    if (!before.passed && result.passed)
      improvements.push({ id: result.id, change: "now passing" });
  }
  const delta = (key) => {
    const a = baseline.metrics?.[key];
    const b = current.metrics?.[key];
    return a === null || a === undefined || b === null || b === undefined
      ? null
      : Number((b - a).toFixed(4));
  };
  const precisionDelta = delta("claimLabelPrecision");
  const unsupportedDelta = delta("unsupportedClaimRate");
  if (precisionDelta !== null && precisionDelta < 0)
    regressions.push({
      id: "*",
      change: `claim label precision dropped by ${-precisionDelta}`,
    });
  if (unsupportedDelta !== null && unsupportedDelta > 0)
    regressions.push({
      id: "*",
      change: `unsupported claim rate rose by ${unsupportedDelta}`,
    });
  return {
    baselineCases: baseline.cases ?? 0,
    currentCases: current.cases ?? 0,
    newCases: (current.results ?? [])
      .filter((r) => !baselineById.has(r.id))
      .map((r) => r.id),
    removedCases: [...baselineById.keys()].filter(
      (id) => !(current.results ?? []).some((r) => r.id === id),
    ),
    deltas: {
      checkPassRate: delta("checkPassRate"),
      claimLabelPrecision: precisionDelta,
      unsupportedClaimRate: unsupportedDelta,
      medianDurationMs: delta("medianDurationMs"),
    },
    regressions,
    improvements,
    verdict: regressions.length === 0 ? "no-regression" : "regression",
  };
}

export const evaluationSuiteDefaultDir = (root) =>
  join(root, "examples", "ptah-eval");
