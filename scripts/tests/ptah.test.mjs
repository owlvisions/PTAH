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
  assert.match(
    result.stdout,
    /^PTAH \(بتاح\) — Program Understanding & Analysis Toolkit/,
  );
  assert.match(result.stdout, /self-check/);
  assert.match(result.stdout, /ptah diff --base FILE --head FILE/);
  assert.match(result.stdout, /--format json\|markdown/);
  assert.match(
    result.stdout,
    /REA remains available as `rea` and `rea-agents`/,
  );
});

void test("PTAH info reports compatibility honestly as a migration preview", () => {
  const result = run(["info", "--json"]);
  assert.equal(result.status, 0, result.stderr);
  const info = JSON.parse(result.stdout);
  assert.equal(info.product, "PTAH");
  assert.equal(info.status, "migration-preview");
  assert.equal(info.compatibilityEngine, "@owlvisions/ptah");
  assert.match(info.packageIdentityStatus, /npm package is @owlvisions\/ptah/);
  assert.equal(info.packageManagerNameUnchanged, true);
  assert.ok(
    info.nativeCapabilities.some((item) =>
      item.includes("deterministic investigation diff"),
    ),
  );
  assert.match(info.inheritedCapabilities, /REA analyzers run beneath PTAH/);
  const text = run(["info"]);
  assert.match(text.stdout, /^PTAH \(بتاح\)/);
});

void test("history, lint, stats, claim status, question resolution, schema, strings, and inspect work from the CLI", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cli-workflow-"));
  try {
    const target = join(dir, "target.bin");
    const file = join(dir, "investigation.json");
    const artifact = join(dir, "objdump.txt");
    await writeFile(
      target,
      Buffer.concat([
        Buffer.from([0x1f, 0x8b, 8, 0]),
        Buffer.from("payload-string-here"),
      ]),
    );
    await writeFile(artifact, "section .text 0x1000");
    const ok = (result) => assert.equal(result.status, 0, result.stderr);
    ok(run(["init", "--target", target, "--output", file]));
    ok(
      run([
        "add-evidence",
        "--input",
        file,
        "--output",
        file,
        "--id",
        "ev-1",
        "--kind",
        "static-analysis",
        "--summary",
        "Sections listed",
        "--source",
        "objdump -h",
        "--artifact",
        artifact,
      ]),
    );
    ok(
      run([
        "add-claim",
        "--input",
        file,
        "--output",
        file,
        "--id",
        "c-1",
        "--text",
        "Has .text",
        "--evidence-ids",
        "ev-1",
      ]),
    );
    ok(
      run([
        "add-question",
        "--input",
        file,
        "--output",
        file,
        "--id",
        "q-1",
        "--text",
        "Runs?",
        "--required-evidence-kinds",
        "runtime-observation",
      ]),
    );
    const saved = JSON.parse(await readFile(file, "utf8"));
    assert.equal(saved.evidence[0].artifact.sizeBytes, 20);
    assert.match(saved.evidence[0].artifact.sha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(
      saved.history.map((h) => h.action),
      ["init", "evidence-added", "claims-added", "questions-added"],
    );

    const status = run([
      "set-claim-status",
      "--input",
      file,
      "--output",
      file,
      "--id",
      "c-1",
      "--status",
      "verified",
      "--reason",
      "header seen",
    ]);
    ok(status);
    assert.equal(JSON.parse(status.stdout).claimStatus, "verified");
    const resolved = run([
      "resolve-question",
      "--input",
      file,
      "--output",
      file,
      "--id",
      "q-1",
      "--reason",
      "not needed",
      "--evidence-ids",
      "ev-1",
    ]);
    ok(resolved);
    const history = run(["history", "--input", file]);
    ok(history);
    const chain = JSON.parse(history.stdout);
    assert.equal(chain.entries, 6);
    assert.equal(chain.chainValid, true);
    assert.equal(chain.history.at(-1).action, "question-resolved");

    const lint = run(["lint", "--input", file]);
    ok(lint);
    assert.equal(JSON.parse(lint.stdout).ok, true);
    const stats = run(["stats", "--input", file]);
    ok(stats);
    const metrics = JSON.parse(stats.stdout);
    assert.equal(metrics.claims.bySupportLabel.verified, 1);
    assert.equal(metrics.evidence.artifactRatio, 1);
    assert.equal(metrics.historyEntries, 6);

    const tampered = JSON.parse(await readFile(file, "utf8"));
    tampered.history[1].action = "forged";
    const tamperedPath = join(dir, "tampered.json");
    await writeFile(tamperedPath, JSON.stringify(tampered));
    const refused = run(["history", "--input", tamperedPath]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /entrySha256 does not match/);

    const inferredOnly = JSON.parse(await readFile(file, "utf8"));
    inferredOnly.evidence[0].confidence = "inferred";
    inferredOnly.claims[0].status = "supported";
    delete inferredOnly.history;
    const badPath = join(dir, "bad.json");
    await writeFile(badPath, JSON.stringify(inferredOnly));
    const badLint = run(["lint", "--input", badPath]);
    assert.equal(badLint.status, 2);
    assert.ok(
      JSON.parse(badLint.stdout).findings.some(
        (f) => f.code === "status-exceeds-evidence",
      ),
    );
    const cannotVerify = run([
      "set-claim-status",
      "--input",
      badPath,
      "--output",
      badPath,
      "--id",
      "c-1",
      "--status",
      "verified",
    ]);
    assert.equal(cannotVerify.status, 1);
    assert.match(cannotVerify.stderr, /no cited evidence is observed/);

    const schema = run(["schema"]);
    ok(schema);
    assert.equal(JSON.parse(schema.stdout).title, "PTAH investigation");
    const strings = run(["strings", "--target", target, "--min-length", "5"]);
    ok(strings);
    assert.ok(
      JSON.parse(strings.stdout).strings.some(
        (s) => s.text === "payload-string-here",
      ),
    );
    const inspect = run(["fingerprint", "--target", target, "--inspect"]);
    ok(inspect);
    const inspected = JSON.parse(inspect.stdout);
    assert.equal(inspected.detectedFormat, "gzip archive");
    assert.equal(typeof inspected.entropy.bitsPerByte, "number");
    const dot = run(["graph", "--input", file, "--format", "dot"]);
    ok(dot);
    assert.match(dot.stdout, /^digraph ptah/);
    const steps = run(["plan", "--input", file, "--steps", "2"]);
    ok(steps);
    assert.equal(JSON.parse(steps.stdout).status, "no-action-needed");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("freeze, merge, link, migrate, signing, encryption, gzip, and --quiet work from the CLI", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cli-case-tools-"));
  try {
    const target = join(dir, "t.bin");
    await writeFile(target, "case tools fixture");
    const a = join(dir, "a.json");
    const b = join(dir, "b.json");
    const merged = join(dir, "m.json");
    const ok = (result) => assert.equal(result.status, 0, result.stderr);
    const quiet = run(["init", "--target", target, "--output", a, "--quiet"]);
    ok(quiet);
    assert.equal(quiet.stdout, "");
    ok(
      run([
        "add-evidence",
        "--input",
        a,
        "--output",
        a,
        "--id",
        "e1",
        "--kind",
        "symbol",
        "--summary",
        "s",
        "--source",
        "nm",
        "--tags",
        "sym,exports",
      ]),
    );
    assert.deepEqual(JSON.parse(await readFile(a, "utf8")).evidence[0].tags, [
      "sym",
      "exports",
    ]);
    ok(run(["init", "--target", target, "--output", b, "--quiet"]));
    ok(
      run([
        "add-evidence",
        "--input",
        b,
        "--output",
        b,
        "--id",
        "e2",
        "--kind",
        "documentation",
        "--summary",
        "d",
        "--source",
        "man",
        "--quiet",
      ]),
    );
    ok(
      run([
        "add-evidence",
        "--input",
        b,
        "--output",
        b,
        "--id",
        "e1",
        "--kind",
        "symbol",
        "--summary",
        "different",
        "--source",
        "nm",
        "--quiet",
      ]),
    );
    const conflict = run([
      "merge",
      "--base",
      a,
      "--other",
      b,
      "--output",
      merged,
    ]);
    assert.equal(conflict.status, 1);
    assert.match(conflict.stderr, /merge conflicts on evidence\/e1/);
    const resolved = run([
      "merge",
      "--base",
      a,
      "--other",
      b,
      "--output",
      merged,
      "--prefer",
      "base",
    ]);
    ok(resolved);
    assert.deepEqual(JSON.parse(resolved.stdout).added, {
      evidence: 1,
      claims: 0,
      questions: 0,
      actions: 0,
    });

    ok(run(["freeze", "--input", merged, "--output", merged, "--quiet"]));
    const blocked = run([
      "add-claim",
      "--input",
      merged,
      "--output",
      merged,
      "--id",
      "c",
      "--text",
      "t",
      "--evidence-ids",
      "e1",
    ]);
    assert.equal(blocked.status, 1);
    assert.match(blocked.stderr, /frozen content digest mismatch/);
    ok(run(["unfreeze", "--input", merged, "--output", merged, "--quiet"]));
    ok(
      run([
        "add-claim",
        "--input",
        merged,
        "--output",
        merged,
        "--id",
        "c",
        "--text",
        "t",
        "--evidence-ids",
        "e1",
        "--tags",
        "format",
        "--quiet",
      ]),
    );

    const gz = join(dir, "case.json.gz");
    ok(
      run([
        "export-case",
        "--input",
        merged,
        "--output",
        gz,
        "--gzip",
        "--quiet",
      ]),
    );
    assert.deepEqual([...(await readFile(gz)).subarray(0, 2)], [0x1f, 0x8b]);
    const plainVerify = run(["verify-case", "--input", gz, "--target", target]);
    ok(plainVerify);
    const plain = JSON.parse(plainVerify.stdout);
    assert.equal(plain.compressed, true);
    assert.equal(plain.signature.present, false);
    const requireSig = run([
      "verify-case",
      "--input",
      gz,
      "--require-signature",
    ]);
    assert.equal(requireSig.status, 2);

    const keys = join(dir, "keys");
    const keygen = run(["keygen", "--output-dir", keys]);
    ok(keygen);
    const keyInfo = JSON.parse(keygen.stdout);
    const { stat } = await import("node:fs/promises");
    assert.equal(
      ((await stat(keyInfo.privateKeyPath)).mode & 0o777).toString(8),
      "600",
    );
    const signed = join(dir, "signed.json");
    ok(
      run([
        "sign-case",
        "--input",
        gz,
        "--key",
        keyInfo.privateKeyPath,
        "--output",
        signed,
        "--quiet",
      ]),
    );
    const verified = run([
      "verify-case",
      "--input",
      signed,
      "--public-key",
      keyInfo.publicKeyPath,
      "--require-signature",
    ]);
    ok(verified);
    assert.equal(JSON.parse(verified.stdout).signature.verified, true);
    const otherKeys = run(["keygen", "--output-dir", join(dir, "other-keys")]);
    ok(otherKeys);
    const wrongKey = run([
      "verify-case",
      "--input",
      signed,
      "--public-key",
      JSON.parse(otherKeys.stdout).publicKeyPath,
    ]);
    assert.equal(wrongKey.status, 2);
    assert.match(JSON.parse(wrongKey.stdout).error, /different key/);
    const importWrongKey = run([
      "import-case",
      "--input",
      signed,
      "--output",
      join(dir, "never.json"),
      "--public-key",
      JSON.parse(otherKeys.stdout).publicKeyPath,
    ]);
    assert.equal(importWrongKey.status, 1);
    await assert.rejects(readFile(join(dir, "never.json")), { code: "ENOENT" });

    const encrypted = join(dir, "enc.json");
    const env = {
      ...process.env,
      PTAH_CASE_PASSPHRASE: "a long enough passphrase",
    };
    const encrypt = spawnSync(
      process.execPath,
      [entrypoint, "encrypt-case", "--input", signed, "--output", encrypted],
      { cwd: root, encoding: "utf8", env },
    );
    assert.equal(encrypt.status, 0, encrypt.stderr);
    assert.ok(
      !(await readFile(encrypted, "utf8")).includes("different"),
      "ciphertext must not leak content",
    );
    const noPass = run(["verify-case", "--input", encrypted]);
    assert.equal(noPass.status, 1);
    assert.match(noPass.stderr, /PTAH_CASE_PASSPHRASE/);
    const noArgPass = run([
      "encrypt-case",
      "--input",
      signed,
      "--output",
      join(dir, "x.json"),
    ]);
    assert.equal(noArgPass.status, 1);
    assert.match(noArgPass.stderr, /never pass it as an argument/);
    const withPass = spawnSync(
      process.execPath,
      [
        entrypoint,
        "verify-case",
        "--input",
        encrypted,
        "--public-key",
        keyInfo.publicKeyPath,
      ],
      { cwd: root, encoding: "utf8", env },
    );
    assert.equal(withPass.status, 0, withPass.stderr);
    const decoded = JSON.parse(withPass.stdout);
    assert.equal(decoded.encrypted, true);
    assert.equal(decoded.signature.verified, true);
    const decrypted = spawnSync(
      process.execPath,
      [
        entrypoint,
        "decrypt-case",
        "--input",
        encrypted,
        "--output",
        join(dir, "dec.json"),
      ],
      { cwd: root, encoding: "utf8", env },
    );
    assert.equal(decrypted.status, 0, decrypted.stderr);
    assert.equal(
      JSON.parse(await readFile(join(dir, "dec.json"), "utf8")).signature
        .algorithm,
      "ed25519",
    );

    const linked = run([
      "link-case",
      "--input",
      a,
      "--output",
      a,
      "--case",
      signed,
      "--note",
      "merged pass",
    ]);
    ok(linked);
    assert.equal(JSON.parse(linked.stdout).related.sameTarget, true);
    assert.equal(
      run(["link-case", "--input", a, "--output", a, "--case", signed]).status,
      1,
    );

    const legacy = join(dir, "legacy.json");
    await writeFile(
      legacy,
      JSON.stringify({
        target: { id: "old", sha256: "A".repeat(64) },
        evidence: [
          {
            id: "e",
            kind: "other",
            summary: "s",
            source: "x",
            sha256: "A".repeat(64),
          },
        ],
      }),
    );
    const migrate = run([
      "migrate",
      "--input",
      legacy,
      "--output",
      join(dir, "new.json"),
    ]);
    ok(migrate);
    assert.equal(JSON.parse(migrate.stdout).fromVersion, 0);
    assert.equal(
      JSON.parse(await readFile(join(dir, "new.json"), "utf8")).evidence[0]
        .targetSha256,
      "a".repeat(64),
    );
    const list = run(["migrate", "--input", legacy, "--list"]);
    ok(list);
    assert.equal(JSON.parse(list.stdout).migrations.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("report --format markdown and diff work end to end from the CLI", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-report-diff-"));
  try {
    const target = join(dir, "target.bin");
    const base = join(dir, "base.json");
    const head = join(dir, "head.json");
    await writeFile(target, "report and diff fixture");
    assert.equal(run(["init", "--target", target, "--output", base]).status, 0);
    assert.equal(
      run([
        "add-evidence",
        "--input",
        base,
        "--output",
        head,
        "--id",
        "ev-1",
        "--kind",
        "static-analysis",
        "--summary",
        "Section headers listed",
        "--source",
        "objdump -h",
      ]).status,
      0,
    );
    const markdown = run(["report", "--input", head, "--format", "markdown"]);
    assert.equal(markdown.status, 0, markdown.stderr);
    assert.match(markdown.stdout, /^# PTAH evidence report — target\.bin/);
    assert.match(
      markdown.stdout,
      /\| ev-1 \| static-analysis \| observed \| objdump -h \| Section headers listed \|/,
    );
    const badFormat = run(["report", "--input", head, "--format", "pdf"]);
    assert.equal(badFormat.status, 1);
    assert.match(
      badFormat.stderr,
      /--format must be json, markdown, sarif, or html/,
    );

    const same = run(["diff", "--base", base, "--head", base]);
    assert.equal(same.status, 0, same.stderr);
    assert.equal(JSON.parse(same.stdout).identical, true);
    const changed = run(["diff", "--base", base, "--head", head]);
    assert.equal(changed.status, 3, changed.stderr);
    const diff = JSON.parse(changed.stdout);
    assert.deepEqual(diff.evidence.added, ["ev-1"]);
    assert.equal(diff.target.sameTarget, true);
    const missing = run(["diff", "--base", base]);
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /--head FILE/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
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
  assert.match(readme, /compatibility layer/);
  assert.match(readme, /PTAH-BRAND-AUDIT\.md/);
  assert.match(audit, /package identity migrated to `@owlvisions\/ptah`/);
  assert.match(audit, /Release gate checklist/);
  assert.match(packageJson.description, /PTAH/);
  assert.ok(packageJson.keywords.includes("ptah"));
  assert.equal(packageJson.name, "@owlvisions/ptah");
  assert.equal(packageJson.mcpName, "io.github.owlvisions/ptah");
  assert.match(packageJson.repository.url, /owlvisions\/PTAH/);
  assert.deepEqual(Object.keys(packageJson.bin).sort(), [
    "ptah",
    "ptah-mcp",
    "ptah-ui",
    "rea",
    "rea-agents",
  ]);
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

void test("upstream sync workflow validates without credentials and publishes only verified merges", async () => {
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
  assert.match(workflow, /node scripts\/ptah\.mjs upstream-sync --branch/);
  assert.match(workflow, /--bundle/);
  assert.match(workflow, /persist-credentials: false/);
  const validateJob = workflow.slice(
    workflow.indexOf("merge-and-validate:"),
    workflow.indexOf("\n  publish:"),
  );
  assert.doesNotMatch(validateJob, /contents: write|GITHUB_TOKEN/);
  assert.match(workflow, /rev-list --parents -n1/);
  assert.match(
    workflow,
    /git push origin "\$\{MERGED_SHA\}:refs\/heads\/\$\{BASE_BRANCH\}"/,
  );
  assert.doesNotMatch(workflow, /push --force(?!-with-lease)/);
  assert.match(workflow, /PTAH_UPSTREAM_AUTOMERGE/);
  assert.match(workflow, /gh issue create/);
  assert.match(guide, /without force/i);
  assert.match(guide, /15 minutes|every 15/i);
  assert.match(guide, /Actions has been disabled for this user/);
});

void test("carve, asar, wasm, isolation, and extended analyze providers work from the CLI", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-cli-analyzers-"));
  try {
    const ok = (result) => assert.equal(result.status, 0, result.stderr);
    const wasm = join(dir, "m.wasm");
    await writeFile(wasm, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
    const parsed = run(["wasm", "--target", wasm]);
    ok(parsed);
    assert.equal(JSON.parse(parsed.stdout).format, "WebAssembly");
    const carve = run(["carve", "--target", wasm, "--max-results", "5"]);
    ok(carve);
    assert.equal(JSON.parse(carve.stdout).executed, false);
    const asar = run(["asar", "--target", wasm]);
    assert.equal(asar.status, 1);
    assert.match(asar.stderr, /ASAR/);
    const isolation = run(["isolation"]);
    ok(isolation);
    assert.equal(
      typeof JSON.parse(isolation.stdout).bubblewrap.available,
      "boolean",
    );
    const help = run(["help"]);
    assert.match(
      help.stdout,
      /providers: objdump, llvm-objdump, readelf, nm, file, rabin2, rz-bin, monodis, aapt2, wasm-objdump, wasm-tools/,
    );
    const tool = join(dir, "file");
    await writeFile(tool, '#!/bin/sh\nprintf "data\\n"\nexit 0\n');
    await (await import("node:fs/promises")).chmod(tool, 0o755);
    const analyzed = spawnSync(
      process.execPath,
      [
        entrypoint,
        "analyze",
        "--target",
        wasm,
        "--provider",
        "file",
        "--isolation",
        "none",
      ],
      { cwd: root, encoding: "utf8", env: { ...process.env, PATH: dir } },
    );
    assert.equal(analyzed.status, 0, analyzed.stderr);
    const analysis = JSON.parse(analyzed.stdout);
    assert.equal(analysis.analysisKind, "file-type-identification");
    assert.equal(analysis.isolation.applied, "none");
    const required = spawnSync(
      process.execPath,
      [
        entrypoint,
        "analyze",
        "--target",
        wasm,
        "--provider",
        "file",
        "--isolation",
        "required",
      ],
      { cwd: root, encoding: "utf8", env: { ...process.env, PATH: dir } },
    );
    assert.equal(required.status, 1);
    assert.match(required.stderr, /isolation required but unavailable/);
    const unknown = run(["analyze", "--target", wasm, "--provider", "docker"]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /unsupported static analyzer/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
