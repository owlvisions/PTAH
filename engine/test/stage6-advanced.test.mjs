import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  capstoneDisassemble,
  deepDiff,
  emulate,
  findExecutable,
  identifyTarget,
  matchAdvisories,
  parseDependencies,
  probeOptionalEngine,
  scanDependencies,
  scanSecrets,
  yaraScan,
} from "../src/index.mjs";

const have = async (t) => Boolean(await findExecutable(t));
const pyModule = async (name) =>
  (await findExecutable("python3")) &&
  (await import("node:child_process")).spawnSync("python3", [
    "-I",
    "-c",
    `import ${name}`,
  ]).status === 0;

async function withFile(bytes, name, fn) {
  const dir = await mkdtemp(join(tmpdir(), "ptah-s6-"));
  const path = join(dir, name);
  await writeFile(path, bytes);
  try {
    return await fn(path, dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

void test("secret scanning finds patterns and never stores the value", async () => {
  const body = Buffer.from(
    "key=AKIAIOSFODNN7EXAMPLE\ntoken=ghp_" + "a".repeat(36) + "\nplain text\n",
  );
  await withFile(body, "cfg.txt", async (path) => {
    const target = await identifyTarget(path);
    const [evidence] = await scanSecrets(target);
    const types = evidence.data.findings.map((f) => f.type);
    assert.ok(types.includes("aws-access-key"));
    assert.ok(types.includes("github-token"));
    assert.equal(evidence.data.valuesRedacted, true);
    assert.doesNotMatch(JSON.stringify(evidence), /IOSFODNN7EXAMPLE/);
    assert.equal(evidence.data.findings[0].sha256.length, 64);
  });
});

void test("dependency parsing and offline advisory matching", async () => {
  const lock = JSON.stringify({
    packages: {
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/left-pad": { version: "1.3.0" },
    },
  });
  const components = parseDependencies("package-lock.json", lock);
  assert.ok(
    components.some((c) => c.name === "lodash" && c.version === "4.17.20"),
  );
  const advisories = [
    {
      ecosystem: "npm",
      name: "lodash",
      range: ["4.0.0", "4.17.21"],
      id: "GHSA-test",
      severity: "high",
    },
  ];
  const hits = matchAdvisories(components, advisories);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].advisory, "GHSA-test");
  assert.deepEqual(
    parseDependencies(
      "requirements.txt",
      "requests==2.19.1\nflask == 2.0.1\n# c\n",
    )
      .map((c) => c.name)
      .sort(),
    ["flask", "requests"],
  );

  await withFile(Buffer.from(lock), "package-lock.json", async (path) => {
    const target = await identifyTarget(path);
    const [withDb] = await scanDependencies(target, { advisories });
    assert.equal(withDb.data.vulnerabilities.length, 1);
    assert.equal(withDb.confidence, "observed");
    const [withoutDb] = await scanDependencies(target, {});
    assert.equal(withoutDb.confidence, "derived");
    assert.match(withoutDb.limitations.join(" "), /No advisory set/);
  });
});

void test("deep diff reports identity and changed byte regions deterministically", async () => {
  await withFile(Buffer.alloc(9000, 1), "a.bin", async (pa, dir) => {
    const b = Buffer.alloc(9000, 1);
    b.fill(2, 5000, 5100);
    const pb = join(dir, "b.bin");
    await writeFile(pb, b);
    const a = await identifyTarget(pa);
    const bt = await identifyTarget(pb);
    const [same] = await deepDiff(a, a);
    assert.equal(same.data.identical, true);
    const [diff] = await deepDiff(a, bt);
    assert.equal(diff.data.identical, false);
    assert.ok(
      diff.data.changedRegions.some(
        (r) => r.offset <= 5000 && r.offset + r.length > 5000,
      ),
    );
    const [diff2] = await deepDiff(a, bt);
    assert.equal(diff.id, diff2.id, "diff is deterministic");
  });
});

void test("optional engines not installed here report how to enable them", async () => {
  for (const id of ["angr", "frida", "diffoscope"]) {
    const state = await probeOptionalEngine(id, { env: { PATH: "/usr/bin" } });
    if (!state.available) assert.match(state.reason, /not installed/);
  }
});

void test("live: YARA scans with caller rules", async (t) => {
  if (!(await have("yara"))) return t.skip("yara unavailable");
  await withFile(
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2, 3]),
    "x.bin",
    async (path, dir) => {
      const rules = join(dir, "r.yar");
      await writeFile(
        rules,
        'rule is_elf { strings: $m = { 7f 45 4c 46 } condition: $m at 0 }\nrule has_zzz { strings: $s = "zzzzz" condition: $s }\n',
      );
      const target = await identifyTarget(path);
      const [evidence] = await yaraScan(target, rules);
      assert.equal(evidence.data.matches.length, 1);
      assert.equal(evidence.data.matches[0].rule, "is_elf");
    },
  );
});

void test("live: Capstone disassembles raw x86-64 bytes", async (t) => {
  if (!(await pyModule("capstone")))
    return t.skip("python capstone unavailable");
  await withFile(
    Buffer.from("554889e5c3", "hex"),
    "shell.bin",
    async (path) => {
      const target = await identifyTarget(path);
      const [evidence] = await capstoneDisassemble(target, {
        arch: "x86-64",
        length: 5,
      });
      assert.deepEqual(
        evidence.data.instructions.map((i) => i.mnemonic),
        ["push", "mov", "ret"],
      );
      assert.equal(evidence.confidence, "observed");
    },
  );
});

void test("live: Unicorn emulation runs only with consent and stays bounded", async (t) => {
  if (!(await pyModule("unicorn"))) return t.skip("python unicorn unavailable");
  await withFile(Buffer.from("4801d8", "hex"), "add.bin", async (path) => {
    const target = await identifyTarget(path);
    const refused = await emulate(target, { consent: false });
    assert.equal(refused[0].status, "unavailable");
    assert.match(refused[0].summary, /consent/);
    const [evidence] = await emulate(target, {
      consent: true,
      length: 3,
      maxInstructions: 10,
    });
    assert.equal(evidence.data.kind, "emulation");
    assert.ok(evidence.data.steps >= 1);
    assert.match(evidence.limitations.join(" "), /no OS or syscalls/);
  });
});
