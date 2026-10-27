/**
 * Benchmark harness: runs chosen tasks over a set of targets through the
 * engine and measures wall-clock time, the provider chosen, evidence count,
 * and status. All numbers are measured from the PTAH Engine on the given
 * machine; it does not fabricate figures for other tools.
 */
import { createEvidence } from "./evidence.mjs";

const ATTESTATION = {
  ownership: "owner",
  purpose: "security-research",
  statement: "benchmark fixtures built by PTAH",
};

/**
 * @param {object} options
 * @param {import("./engine.mjs")} options.engine  engine created by createEngine
 * @param {{path:string, tasks?:string[]}[]} options.targets
 * @param {string[]} [options.tasks]  default tasks to try per target
 */
export async function benchmark({
  engine,
  targets,
  tasks = ["manifest", "sections", "symbols", "importsExports", "strings"],
  attestation = ATTESTATION,
}) {
  const results = [];
  for (const entry of targets) {
    let session;
    const opened = process.hrtime.bigint();
    try {
      session = await engine.open(entry.path, attestation);
    } catch (error) {
      results.push({ path: entry.path, error: error.message });
      continue;
    }
    const openMs = Number((process.hrtime.bigint() - opened) / 1_000_000n);
    for (const task of entry.tasks ?? tasks) {
      const started = process.hrtime.bigint();
      const result = await session.run(task, entry.context ?? {});
      const ms = Number((process.hrtime.bigint() - started) / 1_000_000n);
      const ev = result.evidence[0];
      results.push({
        target: session.target.name,
        format: session.target.format,
        task,
        provider: result.provider,
        status: ev.status,
        evidenceCount: result.evidence.length,
        cached: result.cached,
        fallbacks: result.attempts.length,
        ms,
      });
    }
    results.push({
      target: session.target.name,
      task: "open",
      ms: openMs,
      meta: true,
    });
  }
  return { results, totals: summarize(results) };
}

function summarize(results) {
  const ran = results.filter((r) => !r.meta && !r.error && r.provider);
  const ok = ran.filter((r) => r.status === "ok" || r.status === "partial");
  return {
    tasksRun: ran.length,
    succeeded: ok.length,
    unavailable: results.filter((r) => r.status === "unavailable").length,
    totalMs: results.reduce((sum, r) => sum + (r.ms ?? 0), 0),
    providersUsed: [...new Set(ran.map((r) => r.provider))].sort(),
    formatsCovered: [...new Set(ran.map((r) => r.format))].sort(),
  };
}

/** Record a benchmark result set as a single evidence object for a case bundle. */
export function benchmarkEvidence(report, targetSha256) {
  return createEvidence({
    task: "resources",
    targetSha256,
    provider: {
      id: "ptah-benchmark",
      tool: "ptah",
      version: "0.1.0",
      argv: ["<benchmark>"],
    },
    confidence: "observed",
    status: "ok",
    summary: `${report.totals.succeeded}/${report.totals.tasksRun} tasks succeeded across ${report.totals.formatsCovered.length} formats in ${report.totals.totalMs} ms`,
    data: { kind: "benchmark", ...report.totals },
  });
}

/** Render a benchmark report as a Markdown table. */
export function renderBenchmarkMarkdown(report) {
  const rows = report.results.filter((r) => !r.meta && !r.error);
  const lines = [
    "# PTAH Engine benchmark",
    "",
    `Measured on this machine: ${report.totals.succeeded}/${report.totals.tasksRun} tasks produced evidence across ${report.totals.formatsCovered.length} formats in ${report.totals.totalMs} ms. Providers used: ${report.totals.providersUsed.join(", ")}.`,
    "",
    "| Target | Format | Task | Provider | Status | Evidence | Fallbacks | ms |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map(
      (r) =>
        `| ${r.target} | ${r.format} | ${r.task} | ${r.provider ?? "-"} | ${r.status ?? "-"} | ${r.evidenceCount ?? 0} | ${r.fallbacks ?? 0} | ${r.ms} |`,
    ),
  ];
  return `${lines.join("\n")}\n`;
}
