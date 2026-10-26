import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, symlink, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  buildEvidenceGraph,
  buildEvidenceReport,
  planNextAction,
  validateInvestigation,
  verifyInvestigation,
  probeExecutable,
  probeProviders,
  analyzeTarget,
  attachAnalysisEvidence,
  createInvestigationForTarget,
} from "../ptah-engine.mjs";

const targetDigest = "a".repeat(64);
function fixture(overrides = {}) {
  return {
    schemaVersion: 1,
    target: { id: "sample-app", sha256: targetDigest },
    evidence: [
      {
        id: "ev-static",
        kind: "static-analysis",
        summary: "Found a handler reference",
        source: "fixture.js:10",
        confidence: "observed",
        targetSha256: targetDigest,
      },
    ],
    claims: [
      {
        id: "claim-1",
        text: "The app registers a handler",
        evidenceIds: ["ev-static"],
        status: "supported",
      },
    ],
    questions: [
      {
        id: "q-runtime",
        text: "Does the handler run?",
        priority: 90,
        requiredEvidenceKinds: ["runtime-observation"],
      },
    ],
    actions: [
      {
        id: "a-runtime",
        name: "Run controlled runtime trace",
        produces: ["runtime-observation"],
        cost: 3,
      },
      {
        id: "a-docs",
        name: "Inspect docs",
        produces: ["documentation"],
        cost: 1,
      },
    ],
    ...overrides,
  };
}

void test("investigation validator requires provenance and valid target digest", () => {
  assert.equal(validateInvestigation(fixture()).schemaVersion, 1);
  assert.throws(
    () =>
      validateInvestigation(fixture({ target: { id: "x", sha256: "bad" } })),
    /SHA-256/,
  );
  assert.throws(
    () =>
      validateInvestigation(
        fixture({
          claims: [{ id: "c", text: "claim", evidenceIds: ["missing"] }],
        }),
      ),
    /missing evidence/,
  );
  assert.throws(
    () =>
      validateInvestigation(
        fixture({ claims: [{ id: "c", text: "claim", evidenceIds: [] }] }),
      ),
    /at least one evidence/,
  );
});

void test("evidence report preserves source references and avoids calling inferred evidence verified", () => {
  const report = buildEvidenceReport(
    fixture({
      evidence: [
        {
          id: "ev-guess",
          kind: "static-analysis",
          summary: "Possible handler",
          source: "module.js",
          confidence: "inferred",
          targetSha256: targetDigest,
        },
      ],
      claims: [
        {
          id: "claim-guess",
          text: "Handler may run",
          evidenceIds: ["ev-guess"],
        },
      ],
    }),
  );
  assert.equal(report.claims[0].supportLabel, "inference-only");
  assert.equal(report.claims[0].evidence[0].source, "module.js");
  assert.equal(report.claims[0].status, "hypothesis");
});

void test("evidence graph links source observations to claims and open questions", () => {
  const graph = buildEvidenceGraph(fixture());
  assert.equal(graph.nodes.filter((node) => node.type === "target").length, 1);
  assert.ok(
    graph.edges.some(
      (edge) =>
        edge.type === "supports" &&
        edge.from === "evidence:ev-static" &&
        edge.to === "claim:claim-1",
    ),
  );
  const question = graph.nodes.find((node) => node.type === "question");
  assert.deepEqual(question.missingEvidenceKinds, ["runtime-observation"]);
});

void test("stale evidence from a different target digest is rejected", () => {
  const stale = fixture({
    evidence: [
      {
        id: "old",
        kind: "static-analysis",
        summary: "Old result",
        source: "x.js",
        confidence: "observed",
        targetSha256: "b".repeat(64),
      },
    ],
  });
  assert.throws(
    () => validateInvestigation(stale),
    /stale or cross-target evidence/,
  );
});

void test("verification checks schema and detects target-byte drift", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-verify-"));
  try {
    const targetPath = join(dir, "target.bin");
    await writeFile(targetPath, Buffer.from("initial target bytes"));
    const { fingerprintTarget } = await import("../ptah-engine.mjs");
    const fp = await fingerprintTarget(targetPath);
    const investigation = fixture({
      target: { id: "target.bin", sha256: fp.sha256 },
      evidence: [],
      claims: [],
    });
    const valid = await verifyInvestigation(investigation, targetPath);
    assert.equal(valid.valid, true);
    assert.equal(valid.targetMatches, true);
    await writeFile(targetPath, Buffer.from("changed target bytes"));
    const stale = await verifyInvestigation(investigation, targetPath);
    assert.equal(stale.valid, false);
    assert.equal(stale.targetMatches, false);
    assert.match(stale.error, /digest mismatch/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("planner chooses an action that covers highest-priority missing evidence", () => {
  const plan = planNextAction(fixture(), { maxCalls: 1, maxCost: 5 });
  assert.equal(plan.status, "planned");
  assert.equal(plan.questionId, "q-runtime");
  assert.equal(plan.selectedAction.id, "a-runtime");
  assert.deepEqual(plan.selectedAction.produces, ["runtime-observation"]);
});

void test("planner stops honestly when budget or provider capability blocks progress", () => {
  assert.equal(
    planNextAction(fixture(), { maxCalls: 0 }).status,
    "budget-exhausted",
  );
  assert.equal(planNextAction(fixture(), { maxCost: 1 }).status, "blocked");
  const resolved = fixture({
    questions: [
      {
        id: "q",
        text: "Already answered",
        resolved: true,
        requiredEvidenceKinds: ["runtime-observation"],
      },
    ],
  });
  assert.equal(planNextAction(resolved).status, "no-action-needed");
});

void test("CLI report, graph, and planner commands accept a JSON investigation file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-engine-"));
  try {
    const inputPath = join(dir, "investigation.json");
    await writeFile(inputPath, JSON.stringify(fixture()));
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const report = spawnSync(
      process.execPath,
      [entry, "report", "--input", inputPath],
      { encoding: "utf8" },
    );
    assert.equal(report.status, 0, report.stderr);
    assert.equal(JSON.parse(report.stdout).summary.evidenceCount, 1);
    const graph = spawnSync(
      process.execPath,
      [entry, "graph", "--input", inputPath],
      { encoding: "utf8" },
    );
    assert.equal(graph.status, 0, graph.stderr);
    assert.ok(JSON.parse(graph.stdout).edges.length >= 1);
    const verify = spawnSync(
      process.execPath,
      [entry, "verify", "--input", inputPath],
      { encoding: "utf8" },
    );
    assert.equal(verify.status, 0, verify.stderr);
    assert.equal(JSON.parse(verify.stdout).valid, true);
    const targetPath = join(dir, "target.bin");
    await writeFile(targetPath, "different target");
    const verifyTarget = spawnSync(
      process.execPath,
      [entry, "verify", "--input", inputPath, "--target", targetPath],
      { encoding: "utf8" },
    );
    assert.equal(verifyTarget.status, 2);
    assert.equal(JSON.parse(verifyTarget.stdout).targetMatches, false);
    const plan = spawnSync(
      process.execPath,
      [entry, "plan", "--input", inputPath, "--max-cost", "5"],
      { encoding: "utf8" },
    );
    assert.equal(plan.status, 0, plan.stderr);
    assert.equal(JSON.parse(plan.stdout).selectedAction.id, "a-runtime");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("fingerprint computes the real SHA-256 and identifies common binary signatures without executing the target", async () => {
  const { fingerprintTarget } = await import("../ptah-engine.mjs");
  const { createHash } = await import("node:crypto");
  const dir = await mkdtemp(join(tmpdir(), "ptah-fingerprint-"));
  try {
    const targetPath = join(dir, "sample.wasm");
    const bytes = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    await writeFile(targetPath, bytes);
    const result = await fingerprintTarget(targetPath);
    assert.equal(
      result.sha256,
      createHash("sha256").update(bytes).digest("hex"),
    );
    assert.equal(result.sizeBytes, bytes.length);
    assert.equal(result.detectedFormat, "WebAssembly");
    assert.equal(result.executed, false);
    assert.equal(result.modified, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("init creates a versioned investigation tied to actual target bytes and persists it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-init-"));
  try {
    const targetPath = join(dir, "sample.js");
    const outputPath = join(dir, "nested", "investigation.json");
    await writeFile(targetPath, "export const answer = 42;");
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const result = spawnSync(
      process.execPath,
      [
        entry,
        "init",
        "--target",
        targetPath,
        "--output",
        outputPath,
        "--id",
        "fixture-target",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout);
    assert.equal(response.status, "created");
    const saved = JSON.parse(
      await (await import("node:fs/promises")).readFile(outputPath, "utf8"),
    );
    assert.equal(saved.schemaVersion, 1);
    assert.equal(saved.target.id, "fixture-target");
    assert.match(saved.target.sha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(saved.evidence, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("fingerprint CLI fails clearly for a missing target", () => {
  const entry = new URL("../ptah.mjs", import.meta.url).pathname;
  const result = spawnSync(process.execPath, [entry, "fingerprint"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Missing required --target FILE/);
});

void test("provider discovery reports PATH availability without executing external tools", async () => {
  const { discoverProviders } = await import("../ptah-engine.mjs");
  const result = await discoverProviders({ PATH: process.env.PATH });
  assert.equal(result.detection, "PATH presence only; tools were not executed");
  assert.ok(
    result.providers.some(
      (provider) => provider.id === "node" && provider.available,
    ),
  );
  assert.equal(
    result.summary.detected,
    result.providers.filter((provider) => provider.available).length,
  );
});

void test("providers CLI returns structured provider capability data", () => {
  const entry = new URL("../ptah.mjs", import.meta.url).pathname;
  const result = spawnSync(process.execPath, [entry, "providers", "--json"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schemaVersion, 1);
  assert.ok(report.providers.length >= 10);
  assert.match(report.detection, /not executed/);
});

void test("init -> add-evidence -> report forms a real file-backed investigation workflow", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-workflow-"));
  try {
    const targetPath = join(dir, "sample.js");
    const investigationPath = join(dir, "investigation.json");
    const updatedPath = join(dir, "investigation-updated.json");
    await writeFile(targetPath, "export function answer() { return 42; }");
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const init = spawnSync(
      process.execPath,
      [entry, "init", "--target", targetPath, "--output", investigationPath],
      { encoding: "utf8" },
    );
    assert.equal(init.status, 0, init.stderr);
    const add = spawnSync(
      process.execPath,
      [
        entry,
        "add-evidence",
        "--input",
        investigationPath,
        "--output",
        updatedPath,
        "--id",
        "ev-1",
        "--kind",
        "static-analysis",
        "--summary",
        "Found answer function",
        "--source",
        "sample.js:1",
        "--confidence",
        "observed",
      ],
      { encoding: "utf8" },
    );
    assert.equal(add.status, 0, add.stderr);
    assert.equal(JSON.parse(add.stdout).status, "evidence-added");
    const report = spawnSync(
      process.execPath,
      [entry, "report", "--input", updatedPath],
      { encoding: "utf8" },
    );
    assert.equal(report.status, 0, report.stderr);
    assert.equal(JSON.parse(report.stdout).summary.evidenceCount, 1);
    const saved = JSON.parse(
      await (await import("node:fs/promises")).readFile(updatedPath, "utf8"),
    );
    assert.equal(saved.evidence[0].targetSha256, saved.target.sha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("add-evidence rejects invalid evidence kinds without corrupting the source file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-invalid-evidence-"));
  try {
    const targetPath = join(dir, "sample.bin");
    const investigationPath = join(dir, "investigation.json");
    const outputPath = join(dir, "output.json");
    await writeFile(targetPath, "sample");
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const init = spawnSync(
      process.execPath,
      [entry, "init", "--target", targetPath, "--output", investigationPath],
      { encoding: "utf8" },
    );
    assert.equal(init.status, 0, init.stderr);
    const add = spawnSync(
      process.execPath,
      [
        entry,
        "add-evidence",
        "--input",
        investigationPath,
        "--output",
        outputPath,
        "--id",
        "ev-1",
        "--kind",
        "made-up",
        "--summary",
        "bad kind",
        "--source",
        "fixture",
      ],
      { encoding: "utf8" },
    );
    assert.equal(add.status, 1);
    assert.match(add.stderr, /unsupported/);
    assert.equal(
      JSON.parse(
        await (
          await import("node:fs/promises")
        ).readFile(investigationPath, "utf8"),
      ).evidence.length,
      0,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("file-backed investigation supports adding claims, questions, and planner actions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-full-case-"));
  try {
    const targetPath = join(dir, "sample.js");
    const paths = Array.from({ length: 5 }, (_, index) =>
      join(dir, `case-${index}.json`),
    );
    await writeFile(targetPath, "export const x = 1;");
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const call = (args) =>
      spawnSync(process.execPath, [entry, ...args], { encoding: "utf8" });
    let result = call(["init", "--target", targetPath, "--output", paths[0]]);
    assert.equal(result.status, 0, result.stderr);
    result = call([
      "add-evidence",
      "--input",
      paths[0],
      "--output",
      paths[1],
      "--id",
      "ev-1",
      "--kind",
      "static-analysis",
      "--summary",
      "Export x exists",
      "--source",
      "sample.js:1",
    ]);
    assert.equal(result.status, 0, result.stderr);
    result = call([
      "add-claim",
      "--input",
      paths[1],
      "--output",
      paths[2],
      "--id",
      "claim-1",
      "--text",
      "The module exports x",
      "--evidence-ids",
      "ev-1",
      "--status",
      "supported",
    ]);
    assert.equal(result.status, 0, result.stderr);
    result = call([
      "add-question",
      "--input",
      paths[2],
      "--output",
      paths[3],
      "--id",
      "q-runtime",
      "--text",
      "Is x changed at runtime?",
      "--priority",
      "90",
      "--required-evidence-kinds",
      "runtime-observation",
    ]);
    assert.equal(result.status, 0, result.stderr);
    result = call([
      "add-action",
      "--input",
      paths[3],
      "--output",
      paths[4],
      "--id",
      "trace",
      "--name",
      "Trace authorized runtime",
      "--produces",
      "runtime-observation",
      "--cost",
      "2",
    ]);
    assert.equal(result.status, 0, result.stderr);
    result = call([
      "plan",
      "--input",
      paths[4],
      "--max-calls",
      "1",
      "--max-cost",
      "3",
    ]);
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.status, "planned");
    assert.equal(plan.selectedAction.id, "trace");
    const report = JSON.parse(call(["report", "--input", paths[4]]).stdout);
    assert.equal(report.summary.evidenceCount, 1);
    assert.equal(report.summary.claimCount, 1);
    assert.equal(report.summary.unresolvedQuestionCount, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("bounded executable probe captures version output without a shell", async () => {
  const result = await probeExecutable(process.execPath, ["--version"], {
    timeoutMs: 1000,
    maxOutputBytes: 1024,
  });
  assert.equal(result.status, "ok");
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^v\d+\./);
  assert.equal(result.outputTruncated, false);
  assert.ok(result.durationMs < 1000);
});

void test("bounded executable probe kills a hung process at its deadline", async () => {
  const result = await probeExecutable(
    process.execPath,
    ["-e", "setTimeout(() => {}, 5000)"],
    { timeoutMs: 200, maxOutputBytes: 1024 },
  );
  assert.equal(result.status, "timeout");
  assert.match(result.error, /timeout/);
});

void test("provider probe is opt-in, uses PATH discovery, and reports bounded probe results", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-provider-probe-"));
  try {
    await symlink(process.execPath, join(dir, "node"));
    const result = await probeProviders(
      { PATH: dir },
      { timeoutMs: 1000, maxOutputBytes: 1024 },
    );
    assert.match(result.detection, /Explicit bounded/);
    assert.equal(result.safety.shell, false);
    assert.equal(result.summary.detected, 1);
    assert.equal(
      result.providers.find((item) => item.id === "node").probe.status,
      "ok",
    );
    assert.equal(
      result.providers.find((item) => item.id === "java").probe.status,
      "not-found",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("PTAH MCP stdio server implements initialize, tools/list, and safe fingerprint calls", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-mcp-"));
  try {
    const target = join(dir, "target.bin");
    await writeFile(target, Buffer.from("mcp fingerprint fixture"));
    const server = new URL("../ptah-mcp.mjs", import.meta.url).pathname;
    const requests = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1" },
        },
      },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "ptah_fingerprint", arguments: { target } },
      },
    ];
    const run = spawnSync(process.execPath, [server], {
      input: requests.map((item) => JSON.stringify(item)).join("\n") + "\n",
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(run.status, 0, run.stderr);
    const messages = run.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(messages[0].result.serverInfo.name, "ptah-mcp");
    assert.ok(
      messages[1].result.tools.some((tool) => tool.name === "ptah_fingerprint"),
    );
    assert.equal(messages[2].result.isError, false);
    assert.match(
      messages[2].result.structuredContent?.sha256 ??
        messages[2].result.content[0].text,
      /sha256|[a-f0-9]{64}/,
    );
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(payload.executed, false);
    assert.match(payload.sha256, /^[a-f0-9]{64}$/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("PTAH MCP returns tool errors as MCP tool results rather than crashing the server", () => {
  const server = new URL("../ptah-mcp.mjs", import.meta.url).pathname;
  const request = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "ptah_report",
      arguments: { input: "/missing/ptah-investigation.json" },
    },
  };
  const run = spawnSync(process.execPath, [server], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(run.status, 0, run.stderr);
  const message = JSON.parse(run.stdout.trim());
  assert.equal(message.result.isError, true);
  assert.match(message.result.content[0].text, /ENOENT/);
});

void test("static analyzer adapter passes target paths as argv, bounds execution, and never launches the target", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-static-analyzer-"));
  try {
    const target = join(dir, "target with spaces.bin");
    const tool = join(dir, "objdump");
    await writeFile(target, "fixture object bytes");
    await writeFile(
      tool,
      '#!/bin/sh\nprintf "static metadata fixture\\n"\nprintf "ARG:%s\\n" "$@"\nexit 0\n',
    );
    await chmod(tool, 0o755);
    const result = await analyzeTarget(target, "objdump", {
      env: { PATH: dir },
      timeoutMs: 1000,
      maxOutputBytes: 2048,
    });
    assert.equal(result.status, "ok");
    assert.equal(result.targetExecuted, false);
    assert.equal(result.targetChanged, false);
    assert.equal(result.analysisKind, "static-file-metadata");
    assert.match(result.execution.stdout, /ARG:--/);
    assert.match(result.execution.stdout, /ARG:.*target with spaces\.bin/);
    assert.match(result.target.sha256Before, /^[a-f0-9]{64}$/);
    assert.equal(result.target.sha256Before, result.target.sha256After);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("static analyzer adapter refuses non-allow-listed providers and missing tools", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-static-analyzer-deny-"));
  try {
    const target = join(dir, "target.bin");
    await writeFile(target, "fixture");
    await assert.rejects(
      () => analyzeTarget(target, "docker", { env: { PATH: dir } }),
      /unsupported static analyzer/,
    );
    await assert.rejects(
      () => analyzeTarget(target, "objdump", { env: { PATH: dir } }),
      /provider not found on PATH/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("successful static analysis can be recorded as provenance-bound investigation evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-analysis-evidence-"));
  try {
    const target = join(dir, "target.bin");
    const tool = join(dir, "objdump");
    await writeFile(target, "analysis evidence target");
    await writeFile(
      tool,
      '#!/bin/sh\nprintf "file format fixture\\n"\nexit 0\n',
    );
    await chmod(tool, 0o755);
    const investigation = await createInvestigationForTarget(target);
    const analysis = await analyzeTarget(target, "objdump", {
      env: { PATH: dir },
      timeoutMs: 1000,
      maxOutputBytes: 1024,
    });
    const updated = attachAnalysisEvidence(
      investigation,
      analysis,
      "ev-objdump",
    );
    assert.equal(updated.evidence.length, 1);
    assert.equal(updated.evidence[0].kind, "static-analysis");
    assert.equal(updated.evidence[0].confidence, "observed");
    assert.equal(updated.evidence[0].targetSha256, investigation.target.sha256);
    assert.match(updated.evidence[0].source, /output-sha256/);
    assert.throws(
      () =>
        attachAnalysisEvidence(
          { ...investigation, target: { id: "wrong", sha256: "f".repeat(64) } },
          analysis,
          "ev-cross",
        ),
      /cross-target/,
    );
    assert.throws(
      () =>
        attachAnalysisEvidence(
          investigation,
          { ...analysis, status: "timeout" },
          "ev-failed",
        ),
      /only successful analysis/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("CLI static analysis records evidence only after a successful bounded provider run", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-analysis-cli-"));
  try {
    const target = join(dir, "target.bin");
    const tool = join(dir, "objdump");
    const investigationPath = join(dir, "investigation.json");
    const outputPath = join(dir, "updated.json");
    await writeFile(target, "cli integration target");
    await writeFile(
      tool,
      '#!/bin/sh\nprintf "fake static metadata\\n"\nexit 0\n',
    );
    await chmod(tool, 0o755);
    const initial = await createInvestigationForTarget(target);
    await writeFile(investigationPath, JSON.stringify(initial));
    const entry = new URL("../ptah.mjs", import.meta.url).pathname;
    const run = spawnSync(
      process.execPath,
      [
        entry,
        "analyze",
        "--target",
        target,
        "--provider",
        "objdump",
        "--investigation",
        investigationPath,
        "--save-investigation",
        outputPath,
        "--evidence-id",
        "ev-cli",
        "--timeout-ms",
        "1000",
      ],
      { encoding: "utf8", env: { ...process.env, PATH: dir }, timeout: 5000 },
    );
    assert.equal(run.status, 0, run.stderr);
    const response = JSON.parse(run.stdout);
    assert.equal(response.evidence.recorded, true);
    const saved = JSON.parse(
      await (await import("node:fs/promises")).readFile(outputPath, "utf8"),
    );
    assert.equal(saved.evidence[0].id, "ev-cli");
    assert.equal(saved.evidence[0].targetSha256, saved.target.sha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("local UI serves the workbench and supports upload, evidence, report, and export APIs", async () => {
  const { createPtahUiServer } = await import("../ptah-ui-server.mjs");
  const app = await createPtahUiServer({ maxUploadBytes: 1024 });
  try {
    await new Promise((resolve, reject) =>
      app.server.listen(0, "127.0.0.1", (error) =>
        error ? reject(error) : resolve(),
      ),
    );
    const address = app.server.address();
    const base = `http://127.0.0.1:${address.port}`;
    const page = await fetch(base);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /PTAH.*Local Investigation Workbench/s);
    const upload = await fetch(`${base}/api/init`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "x-target-name": "fixture.wasm",
      },
      body: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]),
    });
    assert.equal(upload.status, 201);
    const created = await upload.json();
    assert.equal(created.target.name, "fixture.wasm");
    assert.match(created.target.sha256, /^[a-f0-9]{64}$/);
    const evidence = await fetch(`${base}/api/evidence`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "ev-ui",
        kind: "static-analysis",
        summary: "Fixture inspected",
        source: "ui test",
        confidence: "observed",
      }),
    });
    assert.equal(evidence.status, 201);
    const report = await fetch(`${base}/api/report`);
    assert.equal((await report.json()).summary.evidenceCount, 1);
    const download = await fetch(`${base}/api/download`);
    const saved = JSON.parse(await download.text());
    assert.equal(saved.evidence[0].id, "ev-ui");
  } finally {
    await app.close();
  }
});

void test("local UI rejects non-loopback binding and oversized target uploads", async () => {
  const { createPtahUiServer } = await import("../ptah-ui-server.mjs");
  await assert.rejects(
    () => createPtahUiServer({ host: "0.0.0.0" }),
    /loopback binding/,
  );
  const app = await createPtahUiServer({ maxUploadBytes: 4 });
  try {
    await new Promise((resolve, reject) =>
      app.server.listen(0, "127.0.0.1", (error) =>
        error ? reject(error) : resolve(),
      ),
    );
    const base = `http://127.0.0.1:${app.server.address().port}`;
    const response = await fetch(`${base}/api/init`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array([1, 2, 3, 4, 5]),
    });
    assert.equal(response.status, 413);
  } finally {
    await app.close();
  }
});

void test("WebAssembly validation adapter requires a confirmed wasm signature and invokes only wasm-tools validate", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-wasm-analyzer-"));
  try {
    const target = join(dir, "target.wasm");
    const tool = join(dir, "wasm-tools");
    await writeFile(
      target,
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    await writeFile(
      tool,
      '#!/bin/sh\nprintf "WebAssembly module valid\\n"\nprintf "ARG:%s\\n" "$@"\nexit 0\n',
    );
    await chmod(tool, 0o755);
    const result = await analyzeTarget(target, "wasm-tools", {
      env: { PATH: dir },
      timeoutMs: 1000,
      maxOutputBytes: 2048,
    });
    assert.equal(result.status, "ok");
    assert.equal(result.analysisKind, "wasm-validation");
    assert.equal(result.targetExecuted, false);
    assert.match(result.execution.stdout, /ARG:validate/);
    assert.match(result.execution.stdout, /target\.wasm/);
    const notWasm = join(dir, "not-wasm.bin");
    await writeFile(notWasm, "plain text");
    await assert.rejects(
      () => analyzeTarget(notWasm, "wasm-tools", { env: { PATH: dir } }),
      /requires a confirmed WebAssembly magic signature/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
