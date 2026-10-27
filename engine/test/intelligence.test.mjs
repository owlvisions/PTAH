/**
 * Tests for Batch B intelligence analyzers:
 * - #37 detectLicenses / scanLicenses
 * - #33 generateCycloneDx / exportSbom
 * - #35 fuzzyHash (degrades gracefully)
 * - #36 deepDiff (already existed, validate extended behavior)
 */
import assert from "node:assert/strict";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const DUMMY_SHA256 = "a".repeat(64); // valid 64-char hex
import {
  detectLicenses,
  scanLicenses,
  generateCycloneDx,
  exportSbom,
  fuzzyHash,
  deepDiff,
  parseDependencies,
} from "../src/index.mjs";

// ── #37 license detection ────────────────────────────────────────────────────

void test("detectLicenses finds MIT text", () => {
  const text =
    "Permission is hereby granted, free of charge, to any person obtaining a copy";
  const { licenses } = detectLicenses(text);
  assert.ok(licenses.includes("MIT"));
});

void test("detectLicenses finds Apache-2.0 identifier", () => {
  const text = "Apache License, Version 2.0";
  const { licenses } = detectLicenses(text);
  assert.ok(licenses.includes("Apache-2.0"));
});

void test("detectLicenses extracts SPDX-License-Identifier header", () => {
  const text = "// SPDX-License-Identifier: MIT\n// some code";
  const { licenses, spdx } = detectLicenses(text);
  assert.equal(spdx, "MIT");
  assert.ok(licenses.includes("MIT"));
});

void test("detectLicenses returns empty arrays for unrecognized text", () => {
  const { licenses, spdx } = detectLicenses("hello world, no license here");
  assert.deepEqual(licenses, []);
  assert.equal(spdx, null);
});

void test("scanLicenses returns evidence for a file with MIT text", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-lic-"));
  try {
    const path = join(dir, "LICENSE");
    await writeFile(
      path,
      "Permission is hereby granted, free of charge, to any person obtaining a copy of this software",
    );
    const target = {
      path,
      sha256: DUMMY_SHA256,
      name: "LICENSE",
      format: "unknown",
    };
    const evidence = await scanLicenses(target);
    assert.equal(evidence[0].status, "ok");
    assert.ok(evidence[0].data.licenses.includes("MIT"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── #33 SBOM export ──────────────────────────────────────────────────────────

void test("generateCycloneDx produces a valid CycloneDX 1.4 structure", () => {
  const components = [
    { ecosystem: "npm", name: "lodash", version: "4.17.21" },
    { ecosystem: "npm", name: "express", version: "4.18.2" },
  ];
  const sbom = generateCycloneDx(components, {
    target: "app.js",
    sha256: "deadbeef",
  });
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.4");
  assert.equal(sbom.components.length, 2);
  assert.ok(sbom.components[0].purl.startsWith("pkg:npm/lodash@"));
  assert.ok(typeof sbom.serialNumber === "string");
});

void test("generateCycloneDx handles empty component list", () => {
  const sbom = generateCycloneDx([]);
  assert.equal(sbom.components.length, 0);
  assert.equal(sbom.bomFormat, "CycloneDX");
});

void test("exportSbom generates CycloneDX evidence from package.json", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-sbom-"));
  try {
    const pkgJson = JSON.stringify({
      name: "test-app",
      dependencies: { lodash: "^4.17.21", express: "4.18.2" },
    });
    const path = join(dir, "package.json");
    await writeFile(path, pkgJson);
    const target = {
      path,
      sha256: DUMMY_SHA256,
      name: "package.json",
      format: "unknown",
    };
    const evidence = await exportSbom(target);
    assert.equal(evidence[0].status, "ok");
    assert.equal(evidence[0].data.format, "cyclonedx-1.4");
    assert.ok(evidence[0].data.sbom.components.length >= 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── #35 fuzzy hash ───────────────────────────────────────────────────────────

void test("fuzzyHash degrades gracefully when ssdeep/tlsh not installed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-fuzz-"));
  try {
    const path = join(dir, "sample.bin");
    await writeFile(path, Buffer.alloc(256, 0xaa));
    const target = {
      path,
      sha256: DUMMY_SHA256,
      name: "sample.bin",
      format: "unknown",
    };
    const evidence = await fuzzyHash(target, { env: { PATH: "/nonexistent" } });
    assert.equal(evidence[0].status, "unavailable");
    assert.match(evidence[0].summary, /ssdeep or tlsh is not installed/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── #36 deepDiff ─────────────────────────────────────────────────────────────

void test("deepDiff reports byte-identical targets", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-diff-"));
  try {
    const path = join(dir, "a.bin");
    await writeFile(path, Buffer.alloc(1024, 0x42));
    const target = {
      path,
      sha256: DUMMY_SHA256,
      name: "a.bin",
      format: "unknown",
    };
    const evidence = await deepDiff(target, target);
    assert.equal(evidence[0].data.identical, true);
    assert.equal(evidence[0].data.changedRegions.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("deepDiff detects changed byte regions between two files", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-diff2-"));
  try {
    const pathA = join(dir, "a.bin");
    const pathB = join(dir, "b.bin");
    const bufA = Buffer.alloc(8192, 0x00);
    const bufB = Buffer.alloc(8192, 0x00);
    bufB.fill(0xff, 100, 200); // different region
    await writeFile(pathA, bufA);
    await writeFile(pathB, bufB);
    const a = { path: pathA, sha256: DUMMY_SHA256, name: "a.bin" };
    const b = { path: pathB, sha256: "b".repeat(64), name: "b.bin" };
    const evidence = await deepDiff(a, b);
    assert.equal(evidence[0].data.identical, false);
    assert.ok(evidence[0].data.changedRegions.length >= 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
