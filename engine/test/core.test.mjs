import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AnalysisProvider,
  CapabilityRegistry,
  PolicyRefusal,
  TargetDrift,
  canonicalJson,
  contractProblems,
  createEngine,
  createEvidence,
  identifyTarget,
  recordAttestation,
  runTool,
  validateEvidence,
} from "../src/index.mjs";

const engineRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "a".repeat(64);
const attestation = {
  ownership: "owner",
  purpose: "personal-study",
  statement: "my own build",
};

/** Minimal ZIP (stored entries) for container-format detection. */
function zip(names) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const name of names) {
    const nameBytes = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(nameBytes.length, 26);
    locals.push(local, nameBytes);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += local.length + nameBytes.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

function pe({ managed }) {
  const bytes = Buffer.alloc(512);
  bytes.write("MZ", 0, "latin1");
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write("PE\0\0", 0x80, "latin1");
  bytes.writeUInt16LE(0x20b, 0x98);
  if (managed) bytes.writeUInt32LE(0x2008, 0x98 + 112 + 14 * 8);
  return bytes;
}

class FakeProvider extends AnalysisProvider {
  constructor(id, { priority = 1, fails = false, available = true, sha } = {}) {
    super();
    Object.assign(this, { id, name: id, kind: "builtin", license: "MIT" });
    this.settings = { priority, fails, available, sha };
    this.calls = 0;
  }
  capabilities() {
    return {
      formats: ["elf"],
      tasks: { symbols: { priority: this.settings.priority } },
    };
  }
  async isAvailable() {
    return { available: this.settings.available, version: "1.0" };
  }
  async symbols(target) {
    this.calls += 1;
    if (this.settings.fails) throw new Error(`${this.id} crashed`);
    return [
      createEvidence({
        task: "symbols",
        targetSha256: this.settings.sha ?? target.sha256,
        provider: { id: this.id },
        confidence: "observed",
        summary: `${this.id} found 1 symbol`,
        data: { symbols: ["main"] },
      }),
    ];
  }
}

const tempTarget = async (bytes) => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-engine-"));
  const path = join(dir, "target.bin");
  await writeFile(path, bytes);
  return {
    dir,
    path,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
};

void test("evidence ids are content-derived and tampering is detected", () => {
  const input = {
    task: "symbols",
    targetSha256: SHA,
    provider: { id: "p" },
    confidence: "observed",
    summary: "s",
    data: { b: 1, a: [2] },
  };
  const first = createEvidence(input);
  const second = createEvidence({ ...input, data: { a: [2], b: 1 } });
  assert.equal(first.id, second.id);
  assert.match(first.id, /^ev_[a-f0-9]{32}$/);
  assert.ok(Object.isFrozen(first));
  assert.deepEqual(validateEvidence(JSON.parse(JSON.stringify(first))), first);
  assert.throws(
    () => validateEvidence({ ...first, summary: "edited" }),
    /does not match its content/,
  );
  assert.throws(
    () => createEvidence({ ...input, confidence: "certain" }),
    /confidence/,
  );
  assert.throws(
    () => createEvidence({ ...input, targetSha256: "abc" }),
    /SHA-256/,
  );
  assert.equal(
    canonicalJson({ b: 1, a: { d: 2, c: 3 } }),
    '{"a":{"c":3,"d":2},"b":1}',
  );
});

void test("targets are identified by digest and by format, including ZIP flavors and managed PE", async () => {
  const cases = [
    [Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), "elf"],
    [Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), "wasm"],
    [pe({ managed: false }), "pe"],
    [pe({ managed: true }), "dotnet"],
    [zip(["AndroidManifest.xml", "classes.dex", "res/a.xml"]), "apk"],
    [zip(["META-INF/MANIFEST.MF", "a/B.class"]), "jar"],
    [zip(["Payload/App.app/Info.plist"]), "ipa"],
    [zip(["readme.txt"]), "zip"],
    [Buffer.from("SQLite format 3\0rest"), "sqlite"],
    [Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), "java-class"],
    [Buffer.from("plain text"), "unknown"],
  ];
  for (const [bytes, format] of cases) {
    const t = await tempTarget(bytes);
    try {
      const target = await identifyTarget(t.path);
      assert.equal(target.format, format, format);
      assert.match(target.sha256, /^[a-f0-9]{64}$/);
      assert.equal(target.sizeBytes, bytes.length);
    } finally {
      await t.cleanup();
    }
  }
});

void test("policy requires an allow-listed ownership and purpose, and target checks can refuse", async () => {
  assert.throws(
    () => recordAttestation(undefined),
    (error) =>
      error instanceof PolicyRefusal && error.code === "attestation-missing",
  );
  assert.throws(
    () => recordAttestation({ ...attestation, ownership: "found-it" }),
    (error) => error.code === "ownership-not-established",
  );
  assert.throws(
    () => recordAttestation({ ...attestation, purpose: "something-else" }),
    (error) => error.code === "purpose-not-permitted",
  );
  const record = recordAttestation(
    attestation,
    new Date("2026-01-01T00:00:00Z"),
  );
  assert.equal(
    record.digest,
    recordAttestation(attestation, new Date("2026-01-01T00:00:00Z")).digest,
  );
  const t = await tempTarget(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  try {
    const engine = createEngine({
      registry: new CapabilityRegistry(),
      targetChecks: [
        (target) =>
          target.format === "elf"
            ? { code: "org-blocklist", reason: "listed by organization rules" }
            : undefined,
      ],
    });
    await assert.rejects(
      engine.open(t.path, attestation),
      (error) => error.code === "org-blocklist",
    );
    await assert.rejects(
      createEngine({ registry: new CapabilityRegistry() }).open(t.path, {}),
      PolicyRefusal,
    );
  } finally {
    await t.cleanup();
  }
});

void test("the provider contract is enforced at registration", () => {
  assert.deepEqual(contractProblems(new FakeProvider("ok")), []);
  assert.ok(contractProblems({ id: "x" }).length > 0);
  const registry = new CapabilityRegistry().register(new FakeProvider("a"));
  assert.throws(
    () => registry.register(new FakeProvider("a")),
    /already registered/,
  );
  assert.throws(() => registry.register({ id: "bad" }), /breaks the contract/);
});

void test("the registry routes by priority, falls back on failure, caches, and degrades safely", async () => {
  const t = await tempTarget(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]));
  try {
    const target = await identifyTarget(t.path);
    const best = new FakeProvider("best", { priority: 9, fails: true });
    const wrongDigest = new FakeProvider("wrong", { priority: 5, sha: SHA });
    const steady = new FakeProvider("steady", { priority: 1 });
    const offline = new FakeProvider("offline", {
      priority: 10,
      available: false,
    });
    const registry = new CapabilityRegistry()
      .register(steady)
      .register(best)
      .register(wrongDigest)
      .register(offline);
    const table = await registry.probe();
    assert.deepEqual(table.routes.elf.symbols, [
      "offline",
      "best",
      "wrong",
      "steady",
    ]);
    const result = await registry.run("symbols", target);
    assert.equal(result.provider, "steady");
    assert.deepEqual(
      result.attempts.map((item) => item.provider),
      ["best", "wrong"],
    );
    assert.match(result.attempts[1].error, /different target digest/);
    const again = await registry.run("symbols", target);
    assert.equal(again.cached, true);
    assert.equal(steady.calls, 1);
    const missing = await registry.run("decompile", target);
    assert.equal(missing.evidence[0].status, "unavailable");
    assert.equal(missing.evidence[0].confidence, "inferred");
    const all = await new CapabilityRegistry()
      .register(new FakeProvider("x", { fails: true }))
      .runAll(["symbols", "strings"], target);
    assert.equal(all.symbols.evidence[0].status, "unavailable");
    assert.equal(all.strings.evidence[0].status, "unavailable");
  } finally {
    await t.cleanup();
  }
});

void test("sessions record the attestation and refuse evidence after the target drifts", async () => {
  const t = await tempTarget(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]));
  try {
    const engine = createEngine({
      registry: new CapabilityRegistry().register(new FakeProvider("p")),
    });
    const session = await engine.open(t.path, attestation);
    assert.equal(session.attestation.purpose, "personal-study");
    const result = await session.run("symbols");
    assert.equal(result.evidence[0].targetSha256, session.target.sha256);
    assert.equal(session.evidence.length, 1);
    await writeFile(t.path, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 2]));
    await assert.rejects(
      session.run("symbols", { options: { again: true } }),
      TargetDrift,
    );
  } finally {
    await t.cleanup();
  }
});

void test("tools run without a shell, within a timeout, and with capped output", async () => {
  const injected = await runTool(process.execPath, [
    "-e",
    "process.stdout.write(process.argv[1])",
    "; echo pwned",
  ]);
  assert.equal(injected.stdout, "; echo pwned");
  const slow = await runTool(
    process.execPath,
    ["-e", "setTimeout(() => {}, 60000)"],
    { timeoutMs: 200 },
  );
  assert.equal(slow.timedOut, true);
  assert.ok(slow.durationMs < 5000);
  const loud = await runTool(
    process.execPath,
    ["-e", "process.stdout.write('x'.repeat(100000))"],
    { maxOutputBytes: 1000 },
  );
  assert.equal(loud.stdout.length, 1000);
  assert.equal(loud.truncated, true);
  const missing = await runTool("/nonexistent/tool", []);
  assert.equal(missing.code, null);
});

void test("the engine has no dependency on the baseline analyzer or anything outside its own directory", async () => {
  const files = [];
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.name.endsWith(".mjs")) files.push(path);
    }
  };
  await walk(join(engineRoot, "src"));
  assert.ok(files.length >= 8);
  for (const file of files) {
    const text = await readFile(file, "utf8");
    // Real module specifiers only: `from "x"`, `import("x")`, or a bare
    // `import "x"` at a statement boundary — not the word "import" inside a
    // string such as a CLI flag "-import".
    for (const [, from, dynamic, bare] of text.matchAll(
      /\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']|(?:^|[\n;])\s*import\s+["']([^"']+)["']/g,
    )) {
      const specifier = from ?? dynamic ?? bare;
      if (specifier.startsWith("node:")) continue;
      assert.ok(
        specifier.startsWith("."),
        `${relative(engineRoot, file)} imports ${specifier}`,
      );
      const resolved = resolve(dirname(file), specifier);
      assert.ok(
        resolved.startsWith(join(engineRoot, "src")),
        `${relative(engineRoot, file)} reaches outside the engine: ${specifier}`,
      );
    }
    assert.doesNotMatch(text, /rea-agents|scripts\/rea|dist\/|\.\.\/\.\.\/src/);
    // Locale-aware ordering would make reports differ between machines.
    assert.doesNotMatch(
      text,
      /localeCompare/,
      `${relative(engineRoot, file)} sorts by locale`,
    );
  }
  const pkg = JSON.parse(
    await readFile(join(engineRoot, "package.json"), "utf8"),
  );
  assert.equal(pkg.dependencies, undefined);
  assert.doesNotMatch(JSON.stringify(pkg), /\brea\b|rea-agents/i);
});
