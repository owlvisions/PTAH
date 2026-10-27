import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AnalysisProvider,
  CapabilityRegistry,
  NmProvider,
  Radare2Provider,
  ReadelfProvider,
  createDefaultRegistry,
  createEngine,
  createEvidence,
  findExecutable,
} from "../src/index.mjs";

const SHA = "a".repeat(64);
const LIVE = "/bin/true";
const have = async (...t) =>
  (await Promise.all(t.map((x) => findExecutable(x)))).every(Boolean) &&
  (await access(LIVE).then(
    () => true,
    () => false,
  ));

class SlowProvider extends AnalysisProvider {
  constructor() {
    super();
    Object.assign(this, {
      id: "slow",
      name: "slow",
      kind: "builtin",
      license: "MIT",
    });
  }
  capabilities() {
    return { formats: ["elf"], tasks: { symbols: { priority: 9 } } };
  }
  async isAvailable() {
    return { available: true };
  }
  async symbols() {
    return new Promise(() => {}); // never resolves
  }
}

class FlakyProvider extends AnalysisProvider {
  constructor(message) {
    super();
    Object.assign(this, {
      id: "flaky",
      name: "flaky",
      kind: "tool",
      license: "MIT",
      calls: 0,
      message,
    });
  }
  capabilities() {
    return { formats: ["elf"], tasks: { symbols: { priority: 9 } } };
  }
  async isAvailable() {
    return { available: true };
  }
  async symbols() {
    this.calls += 1;
    throw new Error(this.message);
  }
}

class SteadyProvider extends AnalysisProvider {
  constructor() {
    super();
    Object.assign(this, {
      id: "steady",
      name: "steady",
      kind: "builtin",
      license: "MIT",
      calls: 0,
    });
  }
  capabilities() {
    return { formats: ["elf"], tasks: { symbols: { priority: 1 } } };
  }
  async isAvailable() {
    return { available: true };
  }
  async symbols(target) {
    this.calls += 1;
    return [
      createEvidence({
        task: "symbols",
        targetSha256: target.sha256,
        provider: { id: this.id },
        confidence: "observed",
        summary: "ok",
        data: { tables: { s: [{ name: "main" }] } },
      }),
    ];
  }
}

const target = {
  path: LIVE,
  name: "true",
  sizeBytes: 1,
  sha256: SHA,
  format: "elf",
};

void test("a hung provider is bounded and the registry falls back", async () => {
  const registry = new CapabilityRegistry()
    .register(new SlowProvider())
    .register(new SteadyProvider());
  await registry.probe();
  const started = Date.now();
  const result = await registry.run("symbols", target, {
    providerTimeoutMs: 300,
  });
  assert.equal(result.provider, "steady");
  assert.ok(Date.now() - started < 5000, "did not wait on the hung provider");
  assert.ok(
    result.attempts.some(
      (a) => a.provider === "slow" && /timed out/u.test(a.error),
    ),
  );
});

void test("a provider that reports itself not installed is demoted and skipped next time", async () => {
  const flaky = new FlakyProvider("tool not installed on this machine");
  const steady = new SteadyProvider();
  const registry = new CapabilityRegistry().register(flaky).register(steady);
  await registry.probe();
  await registry.run("symbols", target);
  const second = await registry.run("symbols", target);
  assert.equal(flaky.calls, 1, "the demoted provider is not retried");
  assert.equal(second.provider, "steady");
  assert.equal(
    registry.table().providers.find((p) => p.id === "flaky").available,
    false,
  );
});

void test("a provider that fails for a run-specific reason is retried next time", async () => {
  const flaky = new FlakyProvider("parse error in this file");
  const steady = new SteadyProvider();
  const registry = new CapabilityRegistry().register(flaky).register(steady);
  await registry.probe();
  await registry.run("symbols", target);
  await registry.run("symbols", { ...target, sha256: "b".repeat(64) });
  assert.equal(
    flaky.calls,
    2,
    "a transient failure does not permanently demote",
  );
});

void test("live: cross-validation corroborates ELF imports across independent providers", async (t) => {
  if (!(await have("readelf", "nm", "r2")))
    return t.skip("readelf/nm/radare2 unavailable");
  const registry = new CapabilityRegistry()
    .register(new ReadelfProvider())
    .register(new NmProvider())
    .register(new Radare2Provider());
  await registry.probe();
  const session = await createEngine({ registry }).open(LIVE, {
    ownership: "open-source",
    purpose: "security-research",
  });
  const cross = await session.crossValidate("importsExports");
  assert.ok(cross.providers.length >= 2, "more than one provider ran");
  assert.ok(
    cross.corroborated > 0,
    "some imports are seen by more than one provider",
  );
  assert.ok(cross.agreement > 0 && cross.agreement <= 1);
  // getenv is imported by /bin/true and should be corroborated by all three.
  const getenv = cross.items.find((i) => i.value === "import:getenv");
  assert.ok(getenv && getenv.providers.length >= 2, "getenv corroborated");
});

void test("live: unblob runs without dropping a log in the working directory", async (t) => {
  if (!(await have("unblob"))) return t.skip("unblob unavailable");
  const here = dirname(fileURLToPath(import.meta.url));
  const fixture = join(here, "fixtures/firmware/sample.bin");
  const before = await readFile(
    join(here, "../..", "unblob.log"),
    "utf8",
  ).catch(() => null);
  const session = await createEngine({
    registry: createDefaultRegistry(),
  }).open(fixture, { ownership: "owner", purpose: "interoperability" });
  const result = await session.run("resources");
  assert.equal(result.provider, "unblob");
  const after = await readFile(join(here, "../..", "unblob.log"), "utf8").catch(
    () => null,
  );
  assert.equal(after, before, "unblob.log in the repo is unchanged by the run");
});
