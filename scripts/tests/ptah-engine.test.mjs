import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, symlink, chmod } from "node:fs/promises";
import { readFileSync } from "node:fs";
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
  createInvestigationCase,
  verifyInvestigationCase,
  importInvestigationCase,
  saveInvestigationCase,
  renderEvidenceReportMarkdown,
  diffInvestigations,
  inspectTarget,
  recordHistory,
  setClaimStatus,
  resolveQuestion,
  lintInvestigation,
  investigationStats,
  planSteps,
  renderEvidenceGraph,
  investigationJsonSchema,
} from "../ptah-engine.mjs";
import {
  describeFormat,
  extractStrings,
  shannonEntropy,
} from "../ptah-analysis.mjs";

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

void test("case bundles are deterministic, integrity-checked, and target-bound on import", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-case-"));
  try {
    const targetPath = join(dir, "target.bin");
    const casePath = join(dir, "case.json");
    const targetBytes = Buffer.from("authorized fixture target bytes");
    await writeFile(targetPath, targetBytes);
    const { fingerprintTarget } = await import("../ptah-engine.mjs");
    const fingerprint = await fingerprintTarget(targetPath);
    const investigation = fixture({
      target: { id: "fixture-target", sha256: fingerprint.sha256 },
      evidence: [
        {
          ...fixture().evidence[0],
          targetSha256: fingerprint.sha256,
        },
      ],
    });
    const bundle = createInvestigationCase(investigation);
    assert.throws(
      () =>
        createInvestigationCase({ ...investigation, unsupported: undefined }),
      /JSON values/,
    );
    const reordered = Object.fromEntries(
      Object.entries(investigation).reverse(),
    );
    assert.equal(
      createInvestigationCase(reordered).integrity.payloadSha256,
      bundle.integrity.payloadSha256,
    );
    assert.equal(verifyInvestigationCase(bundle).valid, true);
    assert.equal(
      JSON.stringify(bundle).includes(targetBytes.toString()),
      false,
      "case bundles must not embed target bytes",
    );
    await saveInvestigationCase(casePath, investigation);
    const { readFile } = await import("node:fs/promises");
    assert.deepEqual(
      await importInvestigationCase(
        JSON.parse(await readFile(casePath, "utf8")),
        targetPath,
      ),
      validateInvestigation(investigation),
    );

    const tampered = structuredClone(bundle);
    tampered.investigation.evidence[0].summary = "altered after export";
    assert.equal(verifyInvestigationCase(tampered).valid, false);
    await assert.rejects(
      () => importInvestigationCase(tampered),
      /checksum mismatch/,
    );
    await writeFile(targetPath, "different target bytes");
    await assert.rejects(
      () => importInvestigationCase(bundle, targetPath),
      /target digest mismatch/,
    );
    assert.throws(
      () => verifyInvestigationCase({ ...bundle, formatVersion: 99 }),
      /formatVersion/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("markdown report preserves provenance, escapes table cells, and never infers verification", () => {
  const investigation = fixture({
    evidence: [
      { ...fixture().evidence[0], summary: "Found | pipe\nand newline" },
      {
        id: "ev-guess",
        kind: "other",
        summary: "Probably a login flow",
        source: "analyst note",
        confidence: "inferred",
        targetSha256: targetDigest,
      },
    ],
    claims: [
      ...fixture().claims,
      {
        id: "claim-guess",
        text: "The app authenticates users",
        evidenceIds: ["ev-guess"],
      },
    ],
  });
  const markdown = renderEvidenceReportMarkdown(investigation);
  assert.equal(markdown, renderEvidenceReportMarkdown(investigation));
  assert.match(markdown, /^# PTAH evidence report — sample-app/m);
  assert.match(markdown, new RegExp(`\`${targetDigest}\``));
  assert.match(markdown, /### claim-1 — evidence-backed \(supported\)/);
  assert.match(markdown, /### claim-guess — inference-only \(hypothesis\)/);
  assert.match(markdown, /Found \\\| pipe and newline/);
  assert.doesNotMatch(markdown, /— verified/);
  assert.match(
    markdown,
    /\*\*q-runtime\*\* \(priority 90\).*needs runtime-observation/,
  );
  assert.match(markdown, /PTAH does not infer verification/);
});

void test("investigation diff is deterministic and reports target drift, changes, and status transitions", () => {
  const base = fixture();
  const head = fixture({
    evidence: [
      { ...base.evidence[0], summary: "Found a handler reference (updated)" },
      {
        id: "ev-runtime",
        kind: "runtime-observation",
        summary: "Handler executed under trace",
        source: "trace.log:42",
        confidence: "observed",
        targetSha256: targetDigest,
      },
    ],
    claims: [{ ...base.claims[0], status: "verified" }],
    questions: [{ ...base.questions[0], resolved: true }],
    actions: [base.actions[1]],
  });
  const diff = diffInvestigations(base, head);
  assert.equal(diff.identical, false);
  assert.equal(diff.target.sameTarget, true);
  assert.deepEqual(diff.evidence, {
    added: ["ev-runtime"],
    removed: [],
    changed: [{ id: "ev-static", fields: ["summary"] }],
  });
  assert.deepEqual(diff.claimStatusChanges, [
    { id: "claim-1", from: "supported", to: "verified" },
  ]);
  assert.deepEqual(diff.questionsResolved, ["q-runtime"]);
  assert.deepEqual(diff.actions.removed, ["a-runtime"]);
  assert.equal(diff.changeCount, 5);
  assert.equal(
    JSON.stringify(diffInvestigations(base, head)),
    JSON.stringify(diff),
  );
  assert.equal(diffInvestigations(base, base).identical, true);

  const otherTarget = fixture({
    target: { id: "other", sha256: "b".repeat(64) },
    evidence: [],
    claims: [],
  });
  const drift = diffInvestigations(base, otherTarget);
  assert.equal(drift.target.sameTarget, false);
  assert.match(drift.target.note, /not transferable/);
  assert.equal(drift.identical, false);

  const bundle = createInvestigationCase(head);
  assert.equal(diffInvestigations(base, bundle).changeCount, 5);
  const tampered = structuredClone(bundle);
  tampered.investigation.claims[0].text = "edited";
  assert.throws(() => diffInvestigations(base, tampered), /checksum mismatch/);
});

void test("format inspection decodes ELF, PE, and Mach-O headers and reports entropy without executing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-inspect-"));
  try {
    const elf = Buffer.alloc(64);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
    elf.writeUInt16LE(3, 16);
    elf.writeUInt16LE(0xb7, 18);
    const elfPath = join(dir, "lib.so");
    await writeFile(elfPath, elf);
    assert.deepEqual(await describeFormat(elfPath), {
      format: "ELF",
      class: "ELF64",
      endianness: "little",
      osAbi: 0,
      type: "shared-object",
      machine: "AArch64",
    });

    const pe = Buffer.alloc(0x100);
    pe.write("MZ", 0, "ascii");
    pe.writeUInt32LE(0x80, 0x3c);
    pe.write("PE\0\0", 0x80, "ascii");
    pe.writeUInt16LE(0x8664, 0x84);
    pe.writeUInt16LE(5, 0x86);
    pe.writeUInt16LE(0x2002, 0x80 + 22);
    pe.writeUInt16LE(0x20b, 0x80 + 24);
    const pePath = join(dir, "app.exe");
    await writeFile(pePath, pe);
    const peDetails = await describeFormat(pePath);
    assert.equal(peDetails.format, "PE");
    assert.equal(peDetails.machine, "x86-64");
    assert.equal(peDetails.sectionCount, 5);
    assert.equal(peDetails.isDll, true);
    assert.equal(peDetails.optionalHeader, "PE32+");
    const inspected = await inspectTarget(pePath);
    assert.equal(
      inspected.detectedFormat,
      "DOS MZ header (PE format not confirmed)",
    );
    assert.equal(inspected.formatDetails.format, "PE");
    assert.equal(inspected.executed, false);
    assert.ok(
      inspected.entropy.bitsPerByte < 1,
      "mostly-zero file has low entropy",
    );

    const mzOnly = Buffer.from(
      "MZ not a real PE file at all, just text that mentions MZ",
    );
    const mzPath = join(dir, "fake.exe");
    await writeFile(mzPath, mzOnly);
    assert.equal(
      (await describeFormat(mzPath)).format,
      "DOS MZ header (PE format not confirmed)",
    );

    const macho = Buffer.alloc(32);
    macho.writeUInt32BE(0xcffaedfe, 0);
    macho.writeUInt32LE(0x0100000c, 4);
    const machoPath = join(dir, "bin");
    await writeFile(machoPath, macho);
    assert.deepEqual(await describeFormat(machoPath), {
      format: "Mach-O 64-bit",
      endianness: "little",
      cpu: "ARM64",
    });

    const textPath = join(dir, "notes.txt");
    await writeFile(textPath, "plain text");
    assert.equal((await inspectTarget(textPath)).formatDetails, null);
    assert.equal(shannonEntropy(Buffer.alloc(0)), 0);
    assert.equal(shannonEntropy(Buffer.from([0, 0, 0, 0])), 0);
    assert.equal(shannonEntropy(Buffer.from([0, 1, 2, 3])), 2);

    const { fingerprintTarget } = await import("../ptah-engine.mjs");
    const gz = join(dir, "a.gz");
    await writeFile(gz, Buffer.from([0x1f, 0x8b, 0x08, 0x00]));
    assert.equal((await fingerprintTarget(gz)).detectedFormat, "gzip archive");
    const tar = Buffer.alloc(512);
    tar.write("ustar", 257, "ascii");
    const tarPath = join(dir, "a.tar");
    await writeFile(tarPath, tar);
    assert.equal(
      (await fingerprintTarget(tarPath)).detectedFormat,
      "tar archive (ustar)",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("string extraction is bounded, offset-accurate, and handles UTF-16LE", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-strings-"));
  try {
    const path = join(dir, "blob.bin");
    const wide = Buffer.from("WideString!", "utf16le");
    const data = Buffer.concat([
      Buffer.from([0, 1, 2]),
      Buffer.from("hello world"),
      Buffer.from([0xff, 0xfe]),
      wide,
      Buffer.from([0, 0]),
      Buffer.from("short"),
      Buffer.from([0]),
      Buffer.from("x".repeat(40)),
    ]);
    await writeFile(path, data);
    const result = await extractStrings(path, { minLength: 6 });
    assert.equal(result.executed, false);
    assert.equal(result.truncated, false);
    const ascii = result.strings.find((s) => s.text === "hello world");
    assert.deepEqual(ascii, {
      offset: 3,
      encoding: "ascii",
      length: 11,
      text: "hello world",
    });
    const utf16 = result.strings.find((s) => s.encoding === "utf-16le");
    assert.equal(utf16.text, "WideString!");
    assert.equal(utf16.offset, 16);
    assert.ok(!result.strings.some((s) => s.text === "short"));

    const limited = await extractStrings(path, { minLength: 6, maxResults: 1 });
    assert.equal(limited.count, 1);
    assert.equal(limited.truncated, true);
    const partial = await extractStrings(path, { minLength: 6, maxBytes: 10 });
    assert.equal(partial.truncated, true);
    assert.equal(partial.scannedBytes, 10);
    await assert.rejects(
      () => extractStrings(path, { minLength: 1 }),
      /minLength/,
    );
    await assert.rejects(() => extractStrings(dir), /regular file/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("history is an append-only hash chain and tampering is rejected", () => {
  const first = recordHistory(
    fixture(),
    "init",
    { targetId: "sample-app" },
    "2026-01-01T00:00:00.000Z",
  );
  const second = recordHistory(
    first,
    "evidence-added",
    { evidenceId: "ev-static" },
    "2026-01-01T00:01:00.000Z",
  );
  assert.equal(second.history.length, 2);
  assert.equal(second.history[0].previousEntrySha256, null);
  assert.equal(
    second.history[1].previousEntrySha256,
    second.history[0].entrySha256,
  );
  assert.match(second.history[1].entrySha256, /^[a-f0-9]{64}$/);
  assert.equal(validateInvestigation(second).history.length, 2);
  assert.deepEqual(
    recordHistory(
      fixture(),
      "init",
      { targetId: "sample-app" },
      "2026-01-01T00:00:00.000Z",
    ),
    first,
    "same input and timestamp produce the same chain",
  );

  const edited = structuredClone(second);
  edited.history[0].action = "forged";
  assert.throws(
    () => validateInvestigation(edited),
    /entrySha256 does not match/,
  );
  const reordered = structuredClone(second);
  reordered.history.reverse();
  assert.throws(() => validateInvestigation(reordered), /seq must be/);
  const dropped = structuredClone(second);
  dropped.history.splice(0, 1);
  assert.throws(() => validateInvestigation(dropped), /seq must be 1/);
  assert.throws(
    () => recordHistory(fixture(), "x", {}, "not a date"),
    /ISO timestamp/,
  );
});

void test("claim status and question resolution are guarded and recorded in history", () => {
  const base = fixture({
    evidence: [
      ...fixture().evidence,
      {
        id: "ev-guess",
        kind: "other",
        summary: "Looks like it",
        source: "note",
        confidence: "inferred",
        targetSha256: targetDigest,
      },
    ],
    claims: [
      ...fixture().claims,
      { id: "claim-guess", text: "Guess", evidenceIds: ["ev-guess"] },
    ],
  });
  const verified = setClaimStatus(base, "claim-1", "verified", {
    reason: "trace matched",
    at: "2026-01-01T00:00:00.000Z",
  });
  assert.equal(verified.claims[0].status, "verified");
  assert.deepEqual(
    (({ seq, action, claimId, from, to, reason }) => ({
      seq,
      action,
      claimId,
      from,
      to,
      reason,
    }))(verified.history.at(-1)),
    {
      seq: 1,
      action: "claim-status",
      claimId: "claim-1",
      from: "supported",
      to: "verified",
      reason: "trace matched",
    },
  );
  assert.throws(
    () => setClaimStatus(base, "claim-guess", "verified"),
    /no cited evidence is observed/,
  );
  assert.throws(
    () => setClaimStatus(base, "missing", "rejected"),
    /claim not found/,
  );
  assert.throws(
    () => setClaimStatus(base, "claim-1", "maybe"),
    /status must be one of/,
  );

  const resolved = resolveQuestion(
    base,
    "q-runtime",
    { reason: "answered by trace", evidenceIds: ["ev-static"] },
    { at: "2026-01-01T00:00:00.000Z" },
  );
  assert.equal(resolved.questions[0].resolved, true);
  assert.deepEqual(resolved.questions[0].resolution, {
    reason: "answered by trace",
    evidenceIds: ["ev-static"],
  });
  assert.equal(resolved.history.at(-1).action, "question-resolved");
  assert.throws(
    () =>
      resolveQuestion(base, "q-runtime", {
        reason: "x",
        evidenceIds: ["nope"],
      }),
    /missing evidence/,
  );
  assert.throws(
    () => resolveQuestion(base, "q-runtime", { evidenceIds: [] }),
    /resolution.reason/,
  );
  const reopened = resolveQuestion(resolved, "q-runtime", null);
  assert.equal(reopened.questions[0].resolved, false);
  assert.equal(reopened.questions[0].resolution, undefined);
  assert.equal(reopened.history.length, 2);
  const broken = structuredClone(resolved);
  broken.questions[0].resolution.evidenceIds = ["ghost"];
  assert.throws(
    () => validateInvestigation(broken),
    /references missing evidence/,
  );
});

void test("lint and stats are deterministic and never mutate the investigation", () => {
  const investigation = fixture({
    evidence: [
      ...fixture().evidence,
      {
        id: "ev-dup",
        kind: "static-analysis",
        summary: "found a handler reference",
        source: "other.js:1",
        confidence: "observed",
        targetSha256: targetDigest,
      },
      {
        id: "ev-guess",
        kind: "other",
        summary: "Looks like it",
        source: "note",
        confidence: "inferred",
        targetSha256: targetDigest,
      },
    ],
    claims: [
      ...fixture().claims,
      {
        id: "claim-overstated",
        text: "Overstated",
        evidenceIds: ["ev-guess"],
        status: "supported",
      },
    ],
    questions: [
      ...fixture().questions,
      { id: "q-vague", text: "What else?", priority: 10 },
      { id: "q-done", text: "Done?", resolved: true },
    ],
    actions: [fixture().actions[1]],
  });
  const snapshot = JSON.stringify(investigation);
  const lint = lintInvestigation(investigation);
  assert.equal(JSON.stringify(investigation), snapshot);
  assert.equal(lint.ok, false);
  assert.deepEqual(lint.counts, { error: 1, warning: 4, info: 4 });
  const codes = lint.findings.map(
    (f) => `${f.severity}:${f.code}:${f.subject}`,
  );
  assert.deepEqual(codes, [
    "error:status-exceeds-evidence:claim-overstated",
    "warning:duplicate-evidence-summary:ev-dup",
    "warning:inference-only-claim:claim-overstated",
    "warning:resolved-without-reason:q-done",
    "warning:unreachable-question:q-runtime",
    "info:observed-without-artifact:ev-dup",
    "info:observed-without-artifact:ev-static",
    "info:orphan-evidence:ev-dup",
    "info:question-without-requirements:q-vague",
  ]);
  assert.equal(
    JSON.stringify(lintInvestigation(investigation)),
    JSON.stringify(lint),
  );

  const stats = investigationStats(investigation);
  assert.equal(stats.evidence.total, 3);
  assert.deepEqual(stats.evidence.byConfidence, {
    observed: 2,
    derived: 0,
    inferred: 1,
  });
  assert.equal(stats.evidence.citedRatio, Number((2 / 3).toFixed(4)));
  assert.deepEqual(stats.claims.bySupportLabel, {
    "evidence-backed": 1,
    "derived-support": 0,
    "inference-only": 1,
    verified: 0,
  });
  assert.equal(stats.claims.evidenceBackedRatio, 0.5);
  assert.deepEqual(stats.questions, {
    total: 3,
    resolved: 1,
    open: 2,
    openWithMissingEvidence: 1,
    resolvedRatio: Number((1 / 3).toFixed(4)),
  });
  assert.equal(
    investigationStats(fixture({ evidence: [], claims: [] })).claims
      .evidenceBackedRatio,
    null,
  );
  assert.equal(lintInvestigation(fixture()).ok, true);
});

void test("multi-step planning respects budgets and stops honestly", () => {
  const investigation = fixture({
    questions: [
      ...fixture().questions,
      {
        id: "q-docs",
        text: "Documented?",
        priority: 40,
        requiredEvidenceKinds: ["documentation"],
      },
    ],
  });
  const plan = planSteps(investigation, { steps: 3 });
  assert.equal(plan.status, "planned");
  assert.deepEqual(
    plan.steps.map((s) => [s.step, s.actionId, s.questionId]),
    [
      [1, "a-runtime", "q-runtime"],
      [2, "a-docs", "q-docs"],
    ],
  );
  assert.equal(plan.totalEstimatedCost, 4);
  assert.equal(plan.stoppedBecause.status, "no-action-needed");
  const budgeted = planSteps(investigation, { steps: 3, maxCost: 3 });
  assert.equal(budgeted.steps.length, 1);
  assert.equal(budgeted.stoppedBecause.status, "budget-exhausted");
  const tight = planSteps(investigation, { steps: 3, maxCost: 2 });
  assert.equal(tight.steps.length, 0);
  assert.equal(tight.status, "blocked");
  assert.equal(tight.stoppedBecause.status, "blocked");
  const limited = planSteps(investigation, { steps: 1 });
  assert.equal(limited.stoppedBecause.status, "step-limit");
  assert.equal(
    planSteps(fixture({ questions: [] }), { steps: 2 }).status,
    "no-action-needed",
  );
  assert.throws(() => planSteps(investigation, { steps: 0 }), /steps/);
  assert.equal(
    JSON.stringify(planSteps(investigation, { steps: 3 })),
    JSON.stringify(plan),
  );
});

void test("graph renders to DOT and Mermaid with escaped labels", () => {
  const investigation = fixture({
    evidence: [{ ...fixture().evidence[0], summary: 'Says "hi" | twice' }],
  });
  const dot = renderEvidenceGraph(investigation, "dot");
  assert.match(dot, /^digraph ptah \{/);
  assert.match(
    dot,
    /"target:sample-app" \[label="target: sample-app", shape=ellipse\]/,
  );
  assert.match(dot, /Says \\"hi\\" \| twice/);
  assert.match(
    dot,
    /"evidence:ev-static" -> "claim:claim-1" \[label="supports"\]/,
  );
  assert.match(dot, /"question:q-runtime".*style=dashed/);
  const mermaid = renderEvidenceGraph(investigation, "mermaid");
  assert.match(mermaid, /^graph LR/);
  assert.match(mermaid, /n0\["target: sample-app"\]/);
  assert.match(mermaid, /&quot;hi&quot;/);
  assert.match(mermaid, /n1 -->\|supports\| n2/);
  assert.throws(
    () => renderEvidenceGraph(investigation, "svg"),
    /json, dot, or mermaid/,
  );
});

void test("JSON schema describes the accepted document and the fixture conforms structurally", () => {
  const schema = investigationJsonSchema();
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.required, ["schemaVersion", "target"]);
  assert.equal(schema.properties.schemaVersion.const, 1);
  assert.ok(
    schema.properties.evidence.items.properties.kind.enum.includes(
      "static-analysis",
    ),
  );
  assert.deepEqual(schema.properties.claims.items.properties.status.enum, [
    "hypothesis",
    "supported",
    "verified",
    "rejected",
  ]);
  assert.ok(schema.properties.history.items.required.includes("entrySha256"));
  for (const key of Object.keys(fixture()))
    assert.ok(key in schema.properties, key);
  const committed = JSON.parse(
    readFileSync(
      new URL(
        "../../docs/schema/ptah-investigation.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.deepEqual(
    committed,
    schema,
    "docs/schema file drifted from the engine; run `ptah schema`",
  );
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

void test("PTAH MCP exports, verifies, and imports portable case bundles", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-mcp-case-"));
  try {
    const targetPath = join(dir, "target.bin");
    const inputPath = join(dir, "investigation.json");
    const bundlePath = join(dir, "case.json");
    const restoredPath = join(dir, "restored.json");
    await writeFile(targetPath, "mcp portable target");
    const { fingerprintTarget } = await import("../ptah-engine.mjs");
    const fingerprint = await fingerprintTarget(targetPath);
    await writeFile(
      inputPath,
      JSON.stringify(
        fixture({
          target: { id: "mcp-target", sha256: fingerprint.sha256 },
          evidence: [],
          claims: [],
        }),
      ),
    );
    const server = new URL("../ptah-mcp.mjs", import.meta.url).pathname;
    const requests = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "ptah_case_export",
          arguments: { input: inputPath, output: bundlePath },
        },
      },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "ptah_case_verify",
          arguments: { input: bundlePath, target: targetPath },
        },
      },
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "ptah_case_import",
          arguments: {
            input: bundlePath,
            output: restoredPath,
            target: targetPath,
          },
        },
      },
      {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "ptah_report",
          arguments: { input: inputPath, format: "markdown" },
        },
      },
      {
        jsonrpc: "2.0",
        id: 6,
        method: "tools/call",
        params: {
          name: "ptah_diff",
          arguments: { base: inputPath, head: bundlePath },
        },
      },
      {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "ptah_inspect", arguments: { target: targetPath } },
      },
      {
        jsonrpc: "2.0",
        id: 8,
        method: "tools/call",
        params: {
          name: "ptah_strings",
          arguments: { target: targetPath, minLength: 3, maxResults: 10 },
        },
      },
      {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "ptah_lint", arguments: { input: inputPath } },
      },
      {
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "ptah_stats", arguments: { input: inputPath } },
      },
      {
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: { name: "ptah_schema", arguments: {} },
      },
      {
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: {
          name: "ptah_graph",
          arguments: { input: inputPath, format: "dot" },
        },
      },
      {
        jsonrpc: "2.0",
        id: 13,
        method: "tools/call",
        params: {
          name: "ptah_plan",
          arguments: { input: inputPath, steps: 2 },
        },
      },
    ];
    const run = spawnSync(process.execPath, [server], {
      input: `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`,
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(run.status, 0, run.stderr);
    const messages = run.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const listed = messages.find((message) => message.id === 1);
    assert.deepEqual(
      listed.result.tools
        .filter((tool) => tool.name.startsWith("ptah_case_"))
        .map((tool) => tool.name)
        .sort(),
      ["ptah_case_export", "ptah_case_import", "ptah_case_verify"],
    );
    const exported = messages.find((message) => message.id === 2);
    assert.equal(exported.result.isError, false);
    const verified = messages.find((message) => message.id === 3);
    assert.equal(JSON.parse(verified.result.content[0].text).valid, true);
    const imported = messages.find((message) => message.id === 4);
    assert.equal(imported.result.isError, false);
    const markdown = messages.find((message) => message.id === 5);
    assert.equal(markdown.result.isError, false);
    assert.match(
      markdown.result.content[0].text,
      /^# PTAH evidence report — mcp-target/,
    );
    const diffed = messages.find((message) => message.id === 6);
    assert.equal(diffed.result.isError, false);
    assert.equal(JSON.parse(diffed.result.content[0].text).identical, true);
    assert.ok(
      listed.result.tools.some((tool) => tool.name === "ptah_diff"),
      "ptah_diff must be listed",
    );
    const text = (id) =>
      messages.find((m) => m.id === id).result.content[0].text;
    const ok = (id) =>
      assert.equal(
        messages.find((m) => m.id === id).result.isError,
        false,
        `tool ${id}`,
      );
    for (const id of [7, 8, 9, 10, 11, 12, 13]) ok(id);
    assert.equal(JSON.parse(text(7)).executed, false);
    assert.ok("entropy" in JSON.parse(text(7)));
    assert.ok(
      JSON.parse(text(8)).strings.some((s) => s.text.includes("portable")),
    );
    assert.equal(JSON.parse(text(9)).ok, true);
    assert.equal(JSON.parse(text(10)).evidence.total, 0);
    assert.equal(JSON.parse(text(11)).title, "PTAH investigation");
    assert.match(text(12), /^digraph ptah/);
    assert.equal(JSON.parse(text(13)).status, "planned");
    assert.equal(JSON.parse(text(13)).steps[0].actionId, "a-runtime");
    const names = listed.result.tools.map((tool) => tool.name);
    for (const name of [
      "ptah_inspect",
      "ptah_strings",
      "ptah_lint",
      "ptah_stats",
      "ptah_schema",
    ])
      assert.ok(names.includes(name), name);
    assert.deepEqual(
      JSON.parse(
        await (await import("node:fs/promises")).readFile(restoredPath, "utf8"),
      ),
      JSON.parse(
        await (await import("node:fs/promises")).readFile(inputPath, "utf8"),
      ),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
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
    const pageHtml = await page.text();
    assert.match(pageHtml, /PTAH.*Local Investigation Workbench/s);
    assert.match(pageHtml, /Export verified case/);
    assert.match(pageHtml, /Verify & import case/);
    const importWithoutTarget = await fetch(`${base}/api/import-case`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(importWithoutTarget.status, 409);
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
    const markdownReport = await fetch(`${base}/api/report.md`);
    assert.equal(markdownReport.status, 200);
    assert.match(markdownReport.headers.get("content-type"), /text\/markdown/);
    assert.match(await markdownReport.text(), /\| ev-ui \| static-analysis \|/);
    assert.match(pageHtml, /Markdown report/);
    assert.match(pageHtml, /data-output="lint"/);
    assert.match(pageHtml, /data-output="strings"/);
    const lint = await (await fetch(`${base}/api/lint`)).json();
    assert.equal(lint.ok, true);
    const stats = await (await fetch(`${base}/api/stats`)).json();
    assert.equal(stats.evidence.total, 1);
    assert.equal(stats.historyEntries, 2);
    const inspect = await (await fetch(`${base}/api/inspect`)).json();
    assert.equal(inspect.detectedFormat, "WebAssembly");
    assert.equal(inspect.executed, false);
    const strings = await fetch(`${base}/api/strings?minLength=2&maxResults=5`);
    assert.equal(strings.status, 200);
    assert.equal((await strings.json()).executed, false);
    const badStrings = await fetch(`${base}/api/strings?maxResults=999999`);
    assert.equal(badStrings.status, 400);
    const state = await (await fetch(`${base}/api/state`)).json();
    assert.deepEqual(
      state.investigation.history.map((entry) => entry.action),
      ["init", "evidence-added"],
    );
    const download = await fetch(`${base}/api/download`);
    assert.equal(download.status, 200);
    assert.match(
      download.headers.get("content-disposition"),
      /ptah-case\.json/,
    );
    const saved = JSON.parse(await download.text());
    assert.equal(verifyInvestigationCase(saved).valid, true);
    assert.equal(saved.investigation.evidence[0].id, "ev-ui");
    const imported = await fetch(`${base}/api/import-case`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(saved),
    });
    assert.equal(imported.status, 200);
    assert.equal((await imported.json()).investigation.evidence[0].id, "ev-ui");

    const tampered = structuredClone(saved);
    tampered.investigation.evidence[0].summary = "tampered case";
    const rejected = await fetch(`${base}/api/import-case`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(tampered),
    });
    assert.equal(rejected.status, 400);
    assert.match((await rejected.json()).error, /checksum mismatch/);
    const unchanged = await fetch(`${base}/api/state`);
    assert.equal(
      (await unchanged.json()).investigation.evidence[0].summary,
      "Fixture inspected",
    );

    const differentTarget = await fetch(`${base}/api/init`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "x-target-name": "other.wasm",
      },
      body: new Uint8Array([0, 97, 115, 109, 9, 0, 0, 0]),
    });
    assert.equal(differentTarget.status, 201);
    const wrongTarget = await fetch(`${base}/api/import-case`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(saved),
    });
    assert.equal(wrongTarget.status, 400);
    assert.match((await wrongTarget.json()).error, /target digest mismatch/);
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
