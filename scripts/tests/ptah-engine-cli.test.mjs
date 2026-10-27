import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { access } from "node:fs/promises";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cli = (...args) => {
  const r = spawnSync(
    process.execPath,
    [join(root, "scripts/ptah.mjs"), "engine", ...args],
    { cwd: root, encoding: "utf8", timeout: 60_000 },
  );
  let json;
  try {
    json = JSON.parse(r.stdout);
  } catch {
    json = undefined;
  }
  return { ...r, json };
};
const haveElf = () =>
  access("/bin/true").then(
    () => true,
    () => false,
  );

void test("ptah engine providers lists the full registry", () => {
  const r = cli("providers");
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.json.providers.length >= 33);
  assert.ok(
    r.json.providers.some((p) => p.id === "ghidra" && p.kind === "engine"),
  );
});

void test("ptah engine refuses analysis without an attestation", () => {
  const r = cli("--target", "/bin/true");
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /needs --ownership .* and --purpose|i-own-this/);
});

void test("ptah engine analyzes an ELF and selects a provider per task", async (t) => {
  if (!(await haveElf())) return t.skip("/bin/true unavailable");
  const r = cli("--target", "/bin/true", "--i-own-this");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.json.target.format, "elf");
  assert.equal(r.json.results.manifest.provider, "readelf");
  assert.equal(r.json.results.importsExports.status, "ok");
  assert.equal(
    r.json.target.path,
    undefined,
    "machine path is not leaked in output",
  );
});

void test("ptah engine runs a single task with an explicit provider", async (t) => {
  if (!(await haveElf())) return t.skip("/bin/true unavailable");
  const r = cli(
    "symbols",
    "--target",
    "/bin/true",
    "--provider",
    "gdb",
    "--ownership",
    "open-source",
    "--purpose",
    "security-research",
  );
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.json.provider, "gdb");
  assert.equal(r.json.evidence[0].confidence, "observed");
  assert.ok(r.json.evidence[0].data.tables.functions.length > 0);
});

void test("ptah engine reports help and lists the subcommand", () => {
  const help = spawnSync(
    process.execPath,
    [join(root, "scripts/ptah.mjs"), "help"],
    { cwd: root, encoding: "utf8", timeout: 30_000 },
  );
  assert.match(help.stdout, /ptah engine TASK\|matrix\|benchmark/);
});
