import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  STATIC_ANALYZERS,
  STATIC_ANALYZER_IDS,
  analyzeTarget,
  attachAnalysisEvidence,
  createInvestigationForTarget,
  detectIsolationSupport,
  probeExecutable,
} from "../ptah-engine.mjs";
import {
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "../ptah-analysis.mjs";

const ELF = Buffer.concat([
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]),
  Buffer.alloc(56),
]);
const WASM_EMPTY = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
const ZIP = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.alloc(28),
]);
const MZ = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(62)]);

function fixtureFor(adapterId) {
  const required = STATIC_ANALYZERS[adapterId].requiresFormat?.source ?? "";
  if (required.startsWith("^ELF")) return ELF;
  if (required.startsWith("^WebAssembly")) return WASM_EMPTY;
  if (required.startsWith("^ZIP")) return ZIP;
  if (required.startsWith("^DOS MZ")) return MZ;
  return Buffer.from("generic fixture bytes");
}

async function fakeTool(dir, name, script) {
  const path = join(dir, name);
  await writeFile(path, `#!/bin/sh\n${script}`);
  await chmod(path, 0o755);
  return path;
}

for (const adapterId of STATIC_ANALYZER_IDS) {
  const adapter = STATIC_ANALYZERS[adapterId];
  void test(`provider conformance: ${adapterId} handles success, nonzero exit, timeout, output cap, missing tool, and wrong format`, async () => {
    const dir = await mkdtemp(join(tmpdir(), `ptah-conformance-${adapterId}-`));
    try {
      const target = join(dir, "target with spaces.bin");
      await writeFile(target, fixtureFor(adapterId));
      const command = adapter.providerId;
      const missing = await assert.rejects(
        () =>
          analyzeTarget(target, adapterId, {
            env: { PATH: join(dir, "empty") },
          }),
        /provider not found on PATH/,
      );
      assert.equal(missing, undefined);

      await fakeTool(
        dir,
        command,
        'printf "ok fixture\\n"; printf "ARG:%s\\n" "$@"; exit 0\n',
      );
      const ok = await analyzeTarget(target, adapterId, {
        env: { PATH: dir },
        timeoutMs: 2000,
        isolation: "none",
      });
      assert.equal(ok.status, "ok", JSON.stringify(ok.execution));
      assert.equal(ok.targetExecuted, false);
      assert.equal(ok.targetChanged, false);
      assert.equal(ok.analysisKind, adapter.analysisKind);
      assert.equal(ok.isolation.applied, "none");
      assert.equal(ok.isolation.requested, "none");
      assert.match(ok.execution.stdout, /ARG:.*target with spaces\.bin/);
      const expectedArgs = adapter.args(target);
      for (const arg of expectedArgs)
        assert.match(
          ok.execution.stdout,
          new RegExp(`ARG:${arg.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`),
        );
      assert.equal(
        ok.execution.args.length,
        expectedArgs.length,
        "no extra argv when isolation is off",
      );

      await fakeTool(dir, command, 'printf "boom\\n" >&2; exit 3\n');
      const nonzero = await analyzeTarget(target, adapterId, {
        env: { PATH: dir },
        timeoutMs: 2000,
        isolation: "none",
      });
      assert.equal(nonzero.status, "nonzero");
      assert.equal(nonzero.execution.exitCode, 3);
      assert.throws(
        () =>
          attachAnalysisEvidence(
            {
              schemaVersion: 1,
              target: { id: "t", sha256: nonzero.target.sha256After },
            },
            nonzero,
            "ev",
          ),
        /only successful analysis/,
      );

      await fakeTool(dir, command, "sleep 5\n");
      const timeout = await analyzeTarget(target, adapterId, {
        env: { PATH: dir },
        timeoutMs: 150,
        isolation: "none",
      });
      assert.equal(timeout.status, "timeout");
      assert.ok(timeout.execution.durationMs < 3000);

      await fakeTool(
        dir,
        command,
        'head -c 5000 /dev/zero | tr "\\0" "x"; exit 0\n',
      );
      const capped = await analyzeTarget(target, adapterId, {
        env: { PATH: dir },
        timeoutMs: 2000,
        maxOutputBytes: 512,
        isolation: "none",
      });
      assert.equal(capped.status, "ok");
      assert.equal(capped.execution.outputTruncated, true);
      assert.ok(Buffer.byteLength(capped.execution.stdout) <= 512);

      if (adapter.requiresFormat) {
        const wrong = join(dir, "wrong.bin");
        await writeFile(wrong, "plain text that matches nothing");
        await assert.rejects(
          () => analyzeTarget(wrong, adapterId, { env: { PATH: dir } }),
          /requires a confirmed/,
        );
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

void test("isolation wraps the analyzer in bubblewrap and prlimit when available, and reports honestly when not", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-isolation-"));
  try {
    const target = join(dir, "t.bin");
    await writeFile(target, "isolation fixture");
    await fakeTool(dir, "objdump", 'printf "inner:%s\\n" "$@"; exit 0\n');
    const none = await analyzeTarget(target, "objdump", {
      env: { PATH: dir },
      timeoutMs: 2000,
    });
    assert.equal(none.isolation.requested, "auto");
    assert.equal(none.isolation.applied, "none");
    assert.match(
      none.isolation.reasons.join(" "),
      process.platform === "linux" ? /bwrap\) not found/ : /Linux-only/,
    );
    assert.match(none.limitations[0], /was not applied/);
    await assert.rejects(
      () =>
        analyzeTarget(target, "objdump", {
          env: { PATH: dir },
          isolation: "required",
        }),
      /isolation required but unavailable/,
    );
    await assert.rejects(
      () =>
        analyzeTarget(target, "objdump", {
          env: { PATH: dir },
          isolation: "maximum",
        }),
      /isolation must be/,
    );
    await assert.rejects(
      () =>
        analyzeTarget(target, "objdump", {
          env: { PATH: dir },
          limits: { cpuSeconds: 0 },
        }),
      /limits.cpuSeconds/,
    );

    // Fake bwrap/prlimit: record their argv then exec the wrapped command after "--".
    const passthrough =
      'while [ "$1" != "--" ]; do printf "WRAP:%s\\n" "$1"; shift; done; shift; exec "$@"\n';
    await fakeTool(dir, "bwrap", passthrough);
    await fakeTool(dir, "prlimit", passthrough);
    const support = await detectIsolationSupport({ PATH: dir });
    assert.equal(support.bubblewrap.available, true);
    assert.equal(support.prlimit.available, true);
    const wrapped = await analyzeTarget(target, "objdump", {
      env: { PATH: dir },
      timeoutMs: 2000,
      limits: { cpuSeconds: 10, memoryBytes: 512 * 1024 * 1024 },
    });
    if (process.platform === "linux") {
      assert.equal(wrapped.status, "ok", JSON.stringify(wrapped.execution));
      assert.equal(wrapped.isolation.applied, "bubblewrap");
      assert.equal(wrapped.isolation.limitsApplied, true);
      assert.equal(wrapped.execution.executable, join(dir, "bwrap"));
      assert.match(wrapped.execution.stdout, /WRAP:--unshare-all/);
      assert.match(wrapped.execution.stdout, /WRAP:--ro-bind/);
      assert.match(wrapped.execution.stdout, /WRAP:--cpu=10/);
      assert.match(wrapped.execution.stdout, /WRAP:--as=536870912/);
      assert.match(wrapped.execution.stdout, /inner:-f/);
      assert.match(
        wrapped.execution.stdout,
        new RegExp(
          `inner:${target.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`,
        ),
      );
      assert.match(wrapped.limitations[0], /not a substitute/);
      const investigation = await createInvestigationForTarget(target);
      const recorded = attachAnalysisEvidence(investigation, wrapped, "ev-iso");
      assert.match(recorded.evidence[0].source, /isolation:bubblewrap/);
      assert.equal(recorded.evidence[0].artifact.sha256, wrapped.outputSha256);
    } else {
      assert.equal(wrapped.isolation.applied, "none");
    }
    const limitsOnly = await analyzeTarget(target, "objdump", {
      env: { PATH: dir },
      isolation: "none",
      limits: { fileSizeBytes: 1024 },
    });
    assert.equal(limitsOnly.isolation.applied, "none");
    assert.equal(limitsOnly.isolation.limitsApplied, true);
    assert.match(limitsOnly.execution.stdout, /WRAP:--fsize=1024/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("bounded execution can be cancelled through an AbortSignal", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cancel-"));
  try {
    const tool = await fakeTool(dir, "slow", "sleep 5\n");
    const controller = new AbortController();
    const pending = probeExecutable(tool, [], {
      timeoutMs: 4000,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 100);
    const result = await pending;
    assert.equal(result.status, "cancelled");
    assert.ok(result.durationMs < 3000);
    controller.abort();
    const preAborted = await probeExecutable(tool, [], {
      signal: controller.signal,
    });
    assert.equal(preAborted.status, "cancelled");
    assert.equal(preAborted.error, "cancelled before start");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("embedded signature carving reports offsets without executing or extracting", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-carve-"));
  try {
    const path = join(dir, "container.bin");
    const data = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]),
      Buffer.alloc(100, 0x11),
      Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0]),
      Buffer.alloc(50, 0x22),
      Buffer.from([0x1f, 0x8b, 0x08, 0]),
      Buffer.alloc(30, 0x33),
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    ]);
    await writeFile(path, data);
    const result = await findEmbeddedSignatures(path);
    assert.equal(result.executed, false);
    assert.deepEqual(
      result.embedded.map((hit) => [hit.offset, hit.format]),
      [
        [108, "ZIP"],
        [198, "PNG"],
      ],
      "3-byte signatures are excluded by default to limit false positives",
    );
    assert.equal(result.truncated, false);
    const shortSignatures = await findEmbeddedSignatures(path, {
      minimumSignatureLength: 3,
    });
    assert.deepEqual(
      shortSignatures.embedded.map((hit) => [hit.offset, hit.format]),
      [
        [108, "ZIP"],
        [164, "gzip"],
        [198, "PNG"],
      ],
    );
    const limited = await findEmbeddedSignatures(path, { maxResults: 1 });
    assert.equal(limited.count, 1);
    assert.equal(limited.truncated, true);
    const partial = await findEmbeddedSignatures(path, { maxBytes: 120 });
    assert.deepEqual(
      partial.embedded.map((hit) => hit.format),
      ["ZIP"],
    );
    assert.equal(partial.truncated, true);

    // Signatures spanning a chunk boundary must still be found.
    const big = Buffer.alloc(70000, 0x44);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]).copy(big, 65533);
    const spanPath = join(dir, "span.bin");
    await writeFile(spanPath, big);
    const span = await findEmbeddedSignatures(spanPath);
    assert.deepEqual(
      span.embedded.map((hit) => [hit.offset, hit.format]),
      [[65533, "7-Zip"]],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function buildAsar(files) {
  const header = { files: {} };
  let offset = 0;
  const chunks = [];
  for (const [path, content] of Object.entries(files)) {
    const parts = path.split("/");
    let node = header;
    for (const part of parts.slice(0, -1)) {
      node.files[part] ??= { files: {} };
      node = node.files[part];
    }
    const bytes = Buffer.from(content);
    node.files[parts.at(-1)] = { size: bytes.length, offset: String(offset) };
    chunks.push(bytes);
    offset += bytes.length;
  }
  // Layout per @electron/asar: [4: 4][4: header pickle length][4: payload = 4 + padded][4: json length][json padded to 4]
  const json = Buffer.from(JSON.stringify(header));
  const padded = Math.ceil(json.length / 4) * 4;
  const prefix = Buffer.alloc(16);
  prefix.writeUInt32LE(4, 0);
  prefix.writeUInt32LE(8 + padded, 4);
  prefix.writeUInt32LE(4 + padded, 8);
  prefix.writeUInt32LE(json.length, 12);
  const body = Buffer.alloc(padded);
  json.copy(body, 0);
  return Buffer.concat([prefix, body, ...chunks]);
}

void test("ASAR header parsing lists entries natively and rejects malformed archives", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-asar-"));
  try {
    const path = join(dir, "app.asar");
    await writeFile(
      path,
      buildAsar({
        "package.json": '{"name":"x"}',
        "src/main.js": "console.log(1)",
        "src/util/a.js": "x",
      }),
    );
    const parsed = await parseAsarHeader(path);
    assert.equal(parsed.format, "Electron ASAR");
    assert.equal(parsed.fileCount, 3);
    assert.equal(parsed.directoryCount, 2);
    assert.equal(parsed.executed, false);
    const main = parsed.entries.find((entry) => entry.path === "src/main.js");
    assert.equal(main.sizeBytes, 14);
    assert.equal(main.dataOffset, parsed.dataOffset + 12);
    assert.equal(parsed.totalFileBytes, 27);
    const limited = await parseAsarHeader(path, { maxEntries: 2 });
    assert.equal(limited.truncated, true);
    assert.equal(limited.entryCount, 2);
    await writeFile(join(dir, "bad.asar"), Buffer.alloc(16, 0xff));
    await assert.rejects(
      () => parseAsarHeader(join(dir, "bad.asar")),
      /pickle sizes are inconsistent/,
    );
    const tooBig = Buffer.alloc(16);
    tooBig.writeUInt32LE(4, 0);
    tooBig.writeUInt32LE(1000, 4);
    tooBig.writeUInt32LE(996, 8);
    tooBig.writeUInt32LE(990, 12);
    await writeFile(join(dir, "trunc.asar"), tooBig);
    await assert.rejects(
      () => parseAsarHeader(join(dir, "trunc.asar")),
      /past end of file/,
    );
    await writeFile(join(dir, "tiny.asar"), Buffer.alloc(4));
    await assert.rejects(
      () => parseAsarHeader(join(dir, "tiny.asar")),
      /too small/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

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
function wasmName(text) {
  const bytes = Buffer.from(text);
  return Buffer.concat([leb(bytes.length), bytes]);
}
function section(id, body) {
  return Buffer.concat([Buffer.from([id]), leb(body.length), body]);
}

void test("WASM section parsing extracts sections, imports, exports, and custom names natively", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-wasm-"));
  try {
    const typeSection = section(
      1,
      Buffer.concat([leb(1), Buffer.from([0x60, 0, 0])]),
    );
    const importSection = section(
      2,
      Buffer.concat([
        leb(2),
        wasmName("env"),
        wasmName("log"),
        Buffer.from([0]),
        leb(0),
        wasmName("env"),
        wasmName("mem"),
        Buffer.from([2, 0]),
        leb(1),
      ]),
    );
    const functionSection = section(3, Buffer.concat([leb(1), leb(0)]));
    const exportSection = section(
      7,
      Buffer.concat([leb(1), wasmName("run"), Buffer.from([0]), leb(1)]),
    );
    const startSection = section(8, leb(1));
    const codeSection = section(
      10,
      Buffer.concat([leb(1), leb(2), Buffer.from([0, 0x0b])]),
    );
    const custom = section(
      0,
      Buffer.concat([wasmName("name"), Buffer.from([1, 2, 3])]),
    );
    const module = Buffer.concat([
      WASM_EMPTY,
      typeSection,
      importSection,
      functionSection,
      exportSection,
      startSection,
      codeSection,
      custom,
    ]);
    const path = join(dir, "m.wasm");
    await writeFile(path, module);
    const parsed = await parseWasmSections(path);
    assert.equal(parsed.version, 1);
    assert.deepEqual(
      parsed.sections.map((s) => s.name),
      ["type", "import", "function", "export", "start", "code", "custom"],
    );
    assert.deepEqual(parsed.imports, [
      { module: "env", name: "log", kind: "function" },
      { module: "env", name: "mem", kind: "memory" },
    ]);
    assert.deepEqual(parsed.exports, [
      { name: "run", kind: "function", index: 1 },
    ]);
    assert.deepEqual(parsed.customSections, ["name"]);
    assert.equal(parsed.hasStart, true);
    assert.equal(parsed.executed, false);
    assert.equal(parsed.sections[0].count, 1);
    await writeFile(join(dir, "bad.wasm"), Buffer.from("not wasm at all"));
    await assert.rejects(
      () => parseWasmSections(join(dir, "bad.wasm")),
      /magic mismatch/,
    );
    await writeFile(
      join(dir, "trunc.wasm"),
      Buffer.concat([WASM_EMPTY, Buffer.from([1, 50, 0])]),
    );
    await assert.rejects(
      () => parseWasmSections(join(dir, "trunc.wasm")),
      /extends past end/,
    );
    await assert.rejects(
      () => parseWasmSections(path, { maxBytes: 4 }),
      /exceeds/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("workbench runs analyzer jobs with progress and cancellation, diffs uploaded cases, and exposes inspection endpoints", async () => {
  const { createPtahUiServer } = await import("../ptah-ui-server.mjs");
  const dir = await mkdtemp(join(tmpdir(), "ptah-ui-jobs-"));
  await fakeTool(dir, "objdump", 'printf "quick\\n"; exit 0\n');
  await fakeTool(dir, "file", "sleep 5\n");
  const app = await createPtahUiServer({ env: { PATH: dir } });
  try {
    await new Promise((resolveListen, reject) =>
      app.server.listen(0, "127.0.0.1", (error) =>
        error ? reject(error) : resolveListen(),
      ),
    );
    const base = `http://127.0.0.1:${app.server.address().port}`;
    const html = await (await fetch(base)).text();
    for (const marker of [
      'data-output="carve"',
      'data-output="asar"',
      'data-output="wasm"',
      'id="graphView"',
      'id="diffForm"',
      'id="analyzeJob"',
      'value="readelf"',
    ])
      assert.ok(html.includes(marker), marker);
    const json = (body) => ({
      method: "POST",
      headers: {
        "x-ptah-token": app.sessionToken,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const noTarget = await fetch(
      `${base}/api/jobs`,
      json({ provider: "objdump" }),
    );
    assert.equal(noTarget.status, 409);
    const upload = await fetch(`${base}/api/init`, {
      method: "POST",
      headers: {
        "x-ptah-token": app.sessionToken,
        "content-type": "application/octet-stream",
        "x-target-name": "a.wasm",
      },
      body: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]),
    });
    assert.equal(upload.status, 201);

    const badProvider = await fetch(
      `${base}/api/jobs`,
      json({ provider: "docker" }),
    );
    assert.equal(badProvider.status, 400);
    const started = await fetch(
      `${base}/api/jobs`,
      json({ provider: "objdump", isolation: "none" }),
    );
    assert.equal(started.status, 202);
    const job = await started.json();
    assert.equal(job.status, "running");
    let finished;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      finished = await (await fetch(`${base}/api/jobs/${job.id}`)).json();
      if (finished.status !== "running") break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(finished.status, "succeeded", JSON.stringify(finished));
    assert.equal(finished.result.evidence.recorded, true);
    assert.equal(finished.progress.phase, "done");
    const state = await (await fetch(`${base}/api/state`)).json();
    assert.equal(state.investigation.evidence.length, 1);

    const slow = await (
      await fetch(
        `${base}/api/jobs`,
        json({ provider: "file", isolation: "none", timeoutMs: 4000 }),
      )
    ).json();
    assert.equal(slow.status, "running");
    const cancelled = await (
      await fetch(`${base}/api/jobs/${slow.id}/cancel`, json({}))
    ).json();
    assert.equal(cancelled.id, slow.id);
    let after;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      after = await (await fetch(`${base}/api/jobs/${slow.id}`)).json();
      if (after.status !== "running") break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(after.status, "cancelled", JSON.stringify(after));
    assert.equal(
      (await (await fetch(`${base}/api/state`)).json()).investigation.evidence
        .length,
      1,
      "cancelled job records nothing",
    );
    const list = await (await fetch(`${base}/api/jobs`)).json();
    assert.equal(list.jobs.length, 2);
    assert.equal((await fetch(`${base}/api/jobs/not-a-job`)).status, 404);

    const currentCase = await (await fetch(`${base}/api/download`)).json();
    const identical = await (
      await fetch(`${base}/api/diff`, json(currentCase))
    ).json();
    assert.equal(identical.identical, true);
    const edited = structuredClone(currentCase.investigation);
    edited.evidence = [];
    delete edited.history;
    const changed = await (
      await fetch(`${base}/api/diff`, json(edited))
    ).json();
    assert.equal(changed.identical, false);
    assert.equal(changed.evidence.removed.length, 1);
    const badDiff = await fetch(`${base}/api/diff`, json({ nope: true }));
    assert.equal(badDiff.status, 400);

    const wasm = await (await fetch(`${base}/api/wasm`)).json();
    assert.equal(wasm.sectionCount, 0);
    const carve = await (await fetch(`${base}/api/carve`)).json();
    assert.equal(carve.executed, false);
    const asar = await fetch(`${base}/api/asar`);
    assert.equal(asar.status, 400);
    const isolation = await (await fetch(`${base}/api/isolation`)).json();
    assert.equal(isolation.bubblewrap.available, false);
  } finally {
    await app.close();
    await rm(dir, { recursive: true, force: true });
  }
});
