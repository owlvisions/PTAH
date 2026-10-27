import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createDefaultRegistry,
  createEngine,
  parseApkSigningBlock,
  parseAsar,
  parseIps,
  parsePyc,
  parseZipEntries,
  probeOptionalEngine,
} from "../src/index.mjs";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const attestation = { ownership: "owner", purpose: "interoperability" };
const open = (file) =>
  createEngine({ registry: createDefaultRegistry() }).open(
    join(fixtures, file),
    attestation,
  );

void test("archive inspector lists ZIP/APK central-directory entries", async () => {
  const bytes = await readFile(join(fixtures, "android/sample.apk"));
  const entries = parseZipEntries(bytes);
  assert.ok(entries.some((e) => e.name === "AndroidManifest.xml"));
  assert.ok(entries.some((e) => e.name === "classes.dex"));
  assert.ok(entries.every((e) => typeof e.size === "number"));
  const session = await open("android/sample.apk");
  const result = await session.run("resources", {
    provider: "archive-inspector",
  });
  assert.ok(result.evidence[0].data.files.length >= 3);
});

void test("APK signature inspector reports the same schemes apksigner verified (v1+v2+v3)", async () => {
  const bytes = await readFile(join(fixtures, "android/signed.apk"));
  const block = parseApkSigningBlock(bytes);
  const ids = block.schemes.map((s) => s.scheme);
  assert.ok(ids.includes("v2") && ids.includes("v3"), JSON.stringify(ids));
  const session = await open("android/signed.apk");
  const evidence = (
    await session.run("manifest", { provider: "apk-signature-inspector" })
  ).evidence[0];
  assert.equal(evidence.data.signed, true);
  const schemes = evidence.data.schemes.map((s) => s.scheme);
  assert.deepEqual(
    schemes.filter((s) => ["v1", "v2", "v3"].includes(s)).sort(),
    ["v1", "v2", "v3"],
  );
  assert.match(
    evidence.limitations.join(" "),
    /does not verify the certificate chain/,
  );
});

void test("unsigned APK is reported as unsigned, not as an error", async () => {
  const bytes = await readFile(join(fixtures, "android/sample.apk"));
  assert.equal(
    parseApkSigningBlock(bytes),
    null,
    "no signing block in the apktool-built APK",
  );
  const evidence = (
    await (
      await open("android/sample.apk")
    ).run("manifest", { provider: "apk-signature-inspector" })
  ).evidence[0];
  assert.equal(evidence.data.signed, false);
});

void test("Electron ASAR inspector lists the virtual filesystem", async () => {
  const bytes = await readFile(join(fixtures, "electron/app.asar"));
  const asar = parseAsar(bytes);
  assert.equal(asar.fileCount, 2);
  assert.ok(asar.files.some((f) => f.path === "pkg/util.js"));
  const session = await open("electron/app.asar");
  assert.equal(session.target.format, "asar");
  assert.equal((await session.run("manifest")).evidence[0].data.javascript, 2);
});

void test("Python .pyc and Apple IPS inspectors map their headers", async () => {
  assert.equal(
    parsePyc(await readFile(join(fixtures, "python/mod.pyc"))).pythonVersion,
    "3.11",
  );
  const ips = parseIps(await readFile(join(fixtures, "crash/report.ips")));
  assert.equal(ips.app, "PtahApp");
  assert.equal(ips.bugType, "309");
  assert.equal(ips.binaryImages, 2);
  const pyc = await open("python/mod.pyc");
  assert.equal(pyc.target.format, "pyc");
  assert.equal(
    (await pyc.run("manifest")).evidence[0].data.pythonVersion,
    "3.11",
  );
});

void test("the dynamic-tool roster (adb, gdb, cutter, sigrok, frida) probes and degrades", async () => {
  for (const id of ["adb", "gdb", "cutter", "sigrok-cli", "frida"]) {
    const state = await probeOptionalEngine(id, {
      env: { PATH: "/nonexistent" },
    });
    assert.equal(state.available, false);
    assert.match(state.reason, /not installed/);
  }
});

void test("the engine now covers every REA provider area it can statically", async () => {
  const registry = createDefaultRegistry();
  const { routes } = await registry.probe();
  // Formats added for REA parity in this stage.
  for (const [format, task] of [
    ["apk", "resources"],
    ["asar", "manifest"],
    ["pyc", "manifest"],
    ["ips", "manifest"],
    ["jar", "resources"],
  ])
    assert.ok(
      routes[format]?.[task]?.length,
      `${format}/${task} has a provider`,
    );
  // APK now has both decode (apktool) and signature (apk-signature-inspector).
  assert.ok(routes.apk.manifest.includes("apk-signature-inspector"));
  assert.ok(registry.providers.length >= 32);
});
