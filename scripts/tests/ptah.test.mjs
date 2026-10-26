import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { isSupportedPtahNodeVersion } from "../ptah-runtime.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const entrypoint = join(root, "scripts/ptah.mjs");

function run(args) {
  return spawnSync(process.execPath, [entrypoint, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 5_000,
  });
}

void test("PTAH help is available without installing project dependencies", () => {
  const result = run(["help"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PTAH/);
  assert.match(result.stdout, /self-check/);
  assert.match(result.stdout, /original REA CLI remains available/);
});

void test("PTAH info reports compatibility honestly as a migration preview", () => {
  const result = run(["info", "--json"]);
  assert.equal(result.status, 0, result.stderr);
  const info = JSON.parse(result.stdout);
  assert.equal(info.product, "PTAH");
  assert.equal(info.status, "migration-preview");
  assert.equal(info.compatibilityEngine, "rea-agents");
  assert.equal(info.packageManagerNameUnchanged, true);
});

void test("PTAH self-check emits machine-readable readiness details", () => {
  const result = run(["self-check", "--json"]);
  assert.ok(result.status === 0 || result.status === 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.product, "PTAH");
  assert.equal(typeof report.nodeVersionSupported, "boolean");
  assert.equal(typeof report.dependenciesInstalled, "boolean");
  assert.equal(typeof report.readyForLegacyCommands, "boolean");
  assert.ok(Array.isArray(report.issues));
});

void test("PTAH runtime readiness matches the package Node engine boundaries", () => {
  for (const version of [
    "22.23.4",
    "22.99.0",
    "24.22.1",
    "24.99.0",
    "26.12.1",
    "27.0.0",
  ])
    assert.equal(isSupportedPtahNodeVersion(version), true, version);
  for (const version of [
    "22.23.3",
    "23.0.0",
    "24.22.0",
    "25.0.0",
    "26.12.0",
    "24.22.1-rc.1",
    "not-a-version",
  ])
    assert.equal(isSupportedPtahNodeVersion(version), false, version);
});

void test("case export, verification, and import preserve investigations and refuse tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-case-cli-"));
  try {
    const target = join(dir, "target.bin");
    const investigation = join(dir, "investigation.json");
    const bundle = join(dir, "case.json");
    const restored = join(dir, "restored.json");
    const rejected = join(dir, "rejected.json");
    await writeFile(target, "portable case target");
    assert.equal(
      run(["init", "--target", target, "--output", investigation]).status,
      0,
    );
    assert.equal(
      run([
        "add-evidence",
        "--input",
        investigation,
        "--output",
        investigation,
        "--id",
        "ev-case",
        "--kind",
        "static-analysis",
        "--summary",
        "Fixture metadata recorded",
        "--source",
        "case test",
      ]).status,
      0,
    );
    const exported = run([
      "export-case",
      "--input",
      investigation,
      "--output",
      bundle,
    ]);
    assert.equal(exported.status, 0, exported.stderr);
    assert.match(JSON.parse(exported.stdout).payloadSha256, /^[a-f0-9]{64}$/);
    const checked = run(["verify-case", "--input", bundle, "--target", target]);
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(JSON.parse(checked.stdout).valid, true);
    const imported = run([
      "import-case",
      "--input",
      bundle,
      "--output",
      restored,
      "--target",
      target,
    ]);
    assert.equal(imported.status, 0, imported.stderr);
    assert.deepEqual(
      JSON.parse(await readFile(restored, "utf8")),
      JSON.parse(await readFile(investigation, "utf8")),
    );
    const tampered = JSON.parse(await readFile(bundle, "utf8"));
    tampered.investigation.evidence[0].summary = "tampered";
    await writeFile(bundle, JSON.stringify(tampered));
    const invalid = run(["verify-case", "--input", bundle]);
    assert.equal(invalid.status, 2);
    assert.equal(JSON.parse(invalid.stdout).valid, false);
    const refused = run([
      "import-case",
      "--input",
      bundle,
      "--output",
      rejected,
    ]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /checksum mismatch/);
    await assert.rejects(readFile(rejected), { code: "ENOENT" });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("root branding identifies PTAH and documents the remaining compatibility migration", async () => {
  const { readFile } = await import("node:fs/promises");
  const readme = await readFile(join(root, "README.md"), "utf8");
  const audit = await readFile(join(root, "docs/PTAH-BRAND-AUDIT.md"), "utf8");
  const packageJson = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  assert.match(readme, /^# PTAH — Program Understanding & Analysis Toolkit/m);
  assert.match(readme, /migration preview/);
  assert.match(readme, /PTAH-BRAND-AUDIT\.md/);
  assert.match(audit, /not release-ready as a standalone PTAH package/);
  assert.match(audit, /Release gate checklist/);
  assert.match(packageJson.description, /PTAH/);
  assert.ok(packageJson.keywords.includes("ptah"));
  assert.equal(
    packageJson.name,
    "rea-agents",
    "keep package identity until coordinated migration is approved",
  );
});

void test("PTAH validation workflow runs native tests and upstream CI on supported Node", async () => {
  const workflow = await readFile(
    join(root, ".github/workflows/ptah-validation.yml"),
    "utf8",
  );
  assert.match(workflow, /node-version-file: \.nvmrc/);
  assert.match(workflow, /npm run test:ptah/);
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm run check:ci/);
  assert.match(workflow, /permissions:\n  contents: read/);
});

void test("upstream sync workflow proposes reviewed updates without auto-merging", async () => {
  const { readFile } = await import("node:fs/promises");
  const workflow = await readFile(
    join(root, ".github/workflows/ptah-upstream-sync.yml"),
    "utf8",
  );
  const guide = await readFile(
    join(root, "docs/PTAH-UPSTREAM-SYNC.md"),
    "utf8",
  );
  assert.match(workflow, /cron: ['"]?\*\/15 \* \* \* \*['"]?/);
  assert.match(workflow, /https:\/\/github\.com\/morluto\/rea\.git/);
  assert.match(workflow, /git merge --no-edit upstream\/main/);
  assert.match(workflow, /git merge --abort/);
  assert.match(workflow, /git push --force-with-lease origin/);
  assert.match(workflow, /git merge-base upstream\/main/);
  assert.match(workflow, /do not share Git history/);
  assert.match(
    workflow,
    /will not attempt a destructive or conflict-prone rebase/,
  );
  assert.match(workflow, /npm run test:ptah/);
  assert.match(workflow, /gh pr create/);
  assert.doesNotMatch(workflow, /gh pr merge/);
  assert.match(guide, /never auto-merges/i);
  assert.match(guide, /15 minutes/);
});
