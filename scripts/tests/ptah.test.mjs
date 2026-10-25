import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const entrypoint = join(root, "scripts/ptah.mjs");

function run(args) {
  return spawnSync(process.execPath, [entrypoint, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 5_000,
  });
}

test("PTAH help is available without installing project dependencies", () => {
  const result = run(["help"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PTAH/);
  assert.match(result.stdout, /self-check/);
  assert.match(result.stdout, /original REA CLI remains available/);
});

test("PTAH info reports compatibility honestly as a migration preview", () => {
  const result = run(["info", "--json"]);
  assert.equal(result.status, 0, result.stderr);
  const info = JSON.parse(result.stdout);
  assert.equal(info.product, "PTAH");
  assert.equal(info.status, "migration-preview");
  assert.equal(info.compatibilityEngine, "rea-agents");
  assert.equal(info.packageManagerNameUnchanged, true);
});

test("PTAH self-check emits machine-readable readiness details", () => {
  const result = run(["self-check", "--json"]);
  assert.ok(result.status === 0 || result.status === 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.product, "PTAH");
  assert.equal(typeof report.nodeVersionSupported, "boolean");
  assert.equal(typeof report.dependenciesInstalled, "boolean");
  assert.equal(typeof report.readyForLegacyCommands, "boolean");
  assert.ok(Array.isArray(report.issues));
});

test("root branding identifies PTAH and documents the remaining compatibility migration", async () => {
  const { readFile } = await import("node:fs/promises");
  const readme = await readFile(join(root, "README.md"), "utf8");
  const audit = await readFile(join(root, "docs/PTAH-BRAND-AUDIT.md"), "utf8");
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  assert.match(readme, /^# PTAH — Program Understanding & Analysis Toolkit/m);
  assert.match(readme, /migration preview/);
  assert.match(readme, /PTAH-BRAND-AUDIT\.md/);
  assert.match(audit, /not release-ready as a standalone PTAH package/);
  assert.match(audit, /Release gate checklist/);
  assert.match(packageJson.description, /PTAH/);
  assert.ok(packageJson.keywords.includes("ptah"));
  assert.equal(packageJson.name, "rea-agents", "keep package identity until coordinated migration is approved");
});


test("PTAH validation workflow runs native tests and upstream CI on supported Node", async () => {
  const workflow = await readFile(join(root, ".github/workflows/ptah-validation.yml"), "utf8");
  assert.match(workflow, /node-version: ['"]22\.19\.0['"]/);
  assert.match(workflow, /npm run test:ptah/);
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm run check:ci/);
  assert.match(workflow, /permissions:\n  contents: read/);
});

test("upstream sync workflow proposes reviewed updates without auto-merging", async () => {
  const { readFile } = await import("node:fs/promises");
  const workflow = await readFile(join(root, ".github/workflows/ptah-upstream-sync.yml"), "utf8");
  const guide = await readFile(join(root, "docs/PTAH-UPSTREAM-SYNC.md"), "utf8");
  assert.match(workflow, /cron: ['"]?\*\/15 \* \* \* \*['"]?/);
  assert.match(workflow, /https:\/\/github\.com\/morluto\/rea\.git/);
  assert.match(workflow, /git rebase upstream\/main/);
  assert.match(workflow, /git merge-base upstream\/main/);
  assert.match(workflow, /do not share Git history/);
  assert.match(workflow, /will not attempt a destructive or conflict-prone rebase/);
  assert.match(workflow, /npm run test:ptah/);
  assert.match(workflow, /gh pr create/);
  assert.doesNotMatch(workflow, /gh pr merge/);
  assert.match(guide, /never auto-merges/i);
  assert.match(guide, /15 minutes/);
});
