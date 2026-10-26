import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createInvestigationCase,
  freezeInvestigation,
  unfreezeInvestigation,
  linkRelatedCase,
  mergeInvestigations,
  migrateInvestigation,
  listMigrations,
  validateInvestigation,
  investigationStats,
  renderEvidenceReportMarkdown,
  setClaimStatus,
  recordHistory,
  INVESTIGATION_SCHEMA_VERSION,
} from "../ptah-engine.mjs";
import {
  generateCaseKeyPair,
  signCase,
  verifyCaseSignature,
  encryptCase,
  decryptCase,
  compressCase,
  parseCaseBytes,
  isGzip,
} from "../ptah-case-tools.mjs";

const digest = "c".repeat(64);
const AT = "2026-01-01T00:00:00.000Z";
function fixture(overrides = {}) {
  return {
    schemaVersion: 1,
    target: { id: "fixture", sha256: digest },
    evidence: [
      {
        id: "ev-1",
        kind: "static-analysis",
        summary: "Header observed",
        source: "fingerprint",
        confidence: "observed",
        targetSha256: digest,
        tags: ["headers", "elf"],
      },
    ],
    claims: [
      {
        id: "c-1",
        text: "It is ELF",
        evidenceIds: ["ev-1"],
        status: "supported",
        tags: ["format"],
      },
    ],
    questions: [],
    actions: [],
    ...overrides,
  };
}

void test("tags are validated and surface in stats and markdown", () => {
  const stats = investigationStats(fixture());
  assert.deepEqual(stats.tags, { elf: 1, format: 1, headers: 1 });
  assert.match(
    renderEvidenceReportMarkdown(fixture()),
    /c-1 — evidence-backed \(supported\) · tags: format/,
  );
  assert.throws(
    () =>
      validateInvestigation(
        fixture({ claims: [{ ...fixture().claims[0], tags: ["a", "a"] }] }),
      ),
    /duplicate tag/,
  );
  assert.throws(
    () =>
      validateInvestigation(
        fixture({ claims: [{ ...fixture().claims[0], tags: ["bad tag!"] }] }),
      ),
    /invalid tag/,
  );
  assert.throws(
    () =>
      validateInvestigation(
        fixture({
          evidence: [
            {
              ...fixture().evidence[0],
              tags: Array.from({ length: 33 }, (_, i) => `t${i}`),
            },
          ],
        }),
      ),
    /at most 32/,
  );
});

void test("freeze makes content immutable until unfreeze, while history can still grow", () => {
  const frozen = freezeInvestigation(fixture(), { at: AT });
  assert.equal(frozen.frozen.at, AT);
  assert.match(frozen.frozen.contentSha256, /^[a-f0-9]{64}$/);
  assert.equal(frozen.history.at(-1).action, "frozen");
  assert.equal(
    validateInvestigation(frozen).frozen.contentSha256,
    frozen.frozen.contentSha256,
  );
  assert.throws(
    () => setClaimStatus(frozen, "c-1", "rejected"),
    /frozen content digest mismatch/,
  );
  const withHistory = recordHistory(
    frozen,
    "note",
    { text: "review done" },
    AT,
  );
  assert.equal(validateInvestigation(withHistory).history.length, 2);
  assert.throws(() => freezeInvestigation(frozen), /already frozen/);
  const thawed = unfreezeInvestigation(frozen, { at: AT });
  assert.equal(thawed.frozen, undefined);
  assert.equal(thawed.history.at(-1).action, "unfrozen");
  assert.equal(
    setClaimStatus(thawed, "c-1", "rejected").claims[0].status,
    "rejected",
  );
  assert.throws(() => unfreezeInvestigation(fixture()), /not frozen/);
  const tampered = structuredClone(frozen);
  tampered.evidence[0].summary = "changed";
  assert.throws(
    () => validateInvestigation(tampered),
    /unfreeze the investigation/,
  );
  assert.equal(investigationStats(frozen).frozen, true);
});

void test("related cases are verified before linking and deduplicated", () => {
  const otherSame = createInvestigationCase(
    fixture({ evidence: [], claims: [] }),
  );
  const otherTarget = createInvestigationCase(
    fixture({
      target: { id: "x", sha256: "d".repeat(64) },
      evidence: [],
      claims: [],
    }),
  );
  const linked = linkRelatedCase(fixture(), otherSame, {
    note: "earlier pass",
    at: AT,
  });
  assert.equal(linked.relatedCases.length, 1);
  assert.equal(linked.relatedCases[0].sameTarget, true);
  assert.equal(linked.relatedCases[0].note, "earlier pass");
  const linked2 = linkRelatedCase(linked, otherTarget, { at: AT });
  assert.equal(linked2.relatedCases[1].sameTarget, false);
  assert.throws(() => linkRelatedCase(linked2, otherSame), /already linked/);
  const corrupt = structuredClone(otherSame);
  corrupt.investigation.target.id = "edited";
  assert.throws(() => linkRelatedCase(fixture(), corrupt), /checksum mismatch/);
  assert.equal(investigationStats(linked2).relatedCases, 2);
  const broken = structuredClone(linked2);
  broken.relatedCases[0].sameTarget = "yes";
  assert.throws(
    () => validateInvestigation(broken),
    /sameTarget must be a boolean/,
  );
});

void test("merge unions by id, refuses different targets, and surfaces conflicts", () => {
  const base = fixture();
  const other = fixture({
    evidence: [
      fixture().evidence[0],
      {
        id: "ev-2",
        kind: "symbol",
        summary: "main exported",
        source: "nm",
        confidence: "observed",
        targetSha256: digest,
      },
    ],
    claims: [{ ...fixture().claims[0], text: "It is an ELF binary" }],
    questions: [{ id: "q-1", text: "Stripped?" }],
  });
  assert.throws(
    () => mergeInvestigations(base, other),
    (error) => {
      assert.match(error.message, /merge conflicts on claims\/c-1/);
      assert.deepEqual(error.conflicts, [{ collection: "claims", id: "c-1" }]);
      return true;
    },
  );
  const preferBase = mergeInvestigations(base, other, {
    prefer: "base",
    at: AT,
  });
  assert.equal(preferBase.investigation.claims[0].text, "It is ELF");
  assert.deepEqual(preferBase.added, {
    evidence: 1,
    claims: 0,
    questions: 1,
    actions: 0,
  });
  assert.equal(preferBase.investigation.history.at(-1).action, "merged");
  assert.equal(preferBase.investigation.history.at(-1).conflicts, 1);
  const preferOther = mergeInvestigations(base, other, {
    prefer: "other",
    at: AT,
  });
  assert.equal(preferOther.investigation.claims[0].text, "It is an ELF binary");
  assert.throws(
    () =>
      mergeInvestigations(
        base,
        fixture({
          target: { id: "y", sha256: "e".repeat(64) },
          evidence: [],
          claims: [],
        }),
      ),
    /different targets/,
  );
  assert.throws(
    () =>
      mergeInvestigations(freezeInvestigation(base), other, { prefer: "base" }),
    /frozen/,
  );
  assert.throws(
    () => mergeInvestigations(base, other, { prefer: "mine" }),
    /prefer must be/,
  );
  assert.equal(
    JSON.stringify(
      mergeInvestigations(base, other, { prefer: "base", at: AT }),
    ),
    JSON.stringify(preferBase),
  );
});

void test("migration upgrades legacy documents and rejects unknown versions", () => {
  assert.deepEqual(
    listMigrations().map((m) => [m.from, m.to]),
    [[0, 1]],
  );
  const legacy = {
    target: { id: "old", sha256: digest.toUpperCase() },
    evidence: [
      {
        id: "e",
        kind: "symbol",
        summary: "s",
        source: "nm",
        sha256: digest.toUpperCase(),
      },
    ],
    claims: [{ id: "c", text: "t", evidence: ["e"] }],
  };
  const migrated = migrateInvestigation(legacy);
  assert.equal(migrated.fromVersion, 0);
  assert.equal(migrated.toVersion, INVESTIGATION_SCHEMA_VERSION);
  assert.equal(migrated.applied.length, 1);
  assert.equal(migrated.investigation.target.sha256, digest);
  assert.equal(migrated.investigation.evidence[0].targetSha256, digest);
  assert.equal(migrated.investigation.evidence[0].confidence, "observed");
  assert.deepEqual(migrated.investigation.claims[0].evidenceIds, ["e"]);
  const current = migrateInvestigation(fixture());
  assert.deepEqual(current.applied, []);
  assert.throws(
    () =>
      migrateInvestigation({
        schemaVersion: 99,
        target: { id: "a", sha256: digest },
      }),
    /newer than this engine/,
  );
  assert.throws(
    () => migrateInvestigation({ foo: 1 }),
    /schemaVersion is missing/,
  );
});

void test("Ed25519 signatures bind to the exact bundle and key", () => {
  const keys = generateCaseKeyPair();
  assert.match(keys.publicKeyPem, /BEGIN PUBLIC KEY/);
  assert.match(keys.privateKeyPem, /BEGIN PRIVATE KEY/);
  const bundle = createInvestigationCase(fixture());
  const signed = signCase(bundle, keys.privateKeyPem);
  assert.equal(signed.signature.algorithm, "ed25519");
  assert.equal(signed.signature.publicKeySha256, keys.publicKeySha256);
  assert.deepEqual(verifyCaseSignature(signed, keys.publicKeyPem), {
    present: true,
    verified: true,
    publicKeySha256: keys.publicKeySha256,
    reason: "signature valid for supplied key",
  });
  assert.equal(verifyCaseSignature(bundle).present, false);
  assert.equal(verifyCaseSignature(signed).verified, null);
  const otherKeys = generateCaseKeyPair();
  assert.match(
    verifyCaseSignature(signed, otherKeys.publicKeyPem).reason,
    /different key/,
  );
  const tampered = structuredClone(signed);
  tampered.investigation.claims[0].text = "edited";
  assert.equal(
    verifyCaseSignature(tampered, keys.publicKeyPem).verified,
    false,
  );
  const resigned = structuredClone(signed);
  resigned.signature.value = Buffer.from("x".repeat(64)).toString("base64");
  assert.equal(
    verifyCaseSignature(resigned, keys.publicKeyPem).verified,
    false,
  );
  const corrupt = structuredClone(bundle);
  corrupt.investigation.target.id = "nope";
  assert.throws(
    () => signCase(corrupt, keys.privateKeyPem),
    /refusing to sign/,
  );
  assert.equal(
    verifyCaseSignature(
      { ...signed, signature: { ...signed.signature, algorithm: "rsa" } },
      keys.publicKeyPem,
    ).verified,
    false,
  );
});

void test("encryption round-trips, rejects wrong passphrases, and compression is transparent", () => {
  const bundle = createInvestigationCase(fixture());
  const envelope = encryptCase(bundle, "correct horse battery");
  assert.equal(envelope.format, "ptah-encrypted-case");
  assert.equal(envelope.payloadSha256, bundle.integrity.payloadSha256);
  assert.ok(
    !JSON.stringify(envelope).includes("Header observed"),
    "plaintext must not leak",
  );
  assert.deepEqual(decryptCase(envelope, "correct horse battery"), bundle);
  assert.throws(
    () => decryptCase(envelope, "wrong passphrase!"),
    /wrong passphrase or tampered/,
  );
  const flipped = structuredClone(envelope);
  flipped.ciphertext = Buffer.from(
    Buffer.from(flipped.ciphertext, "base64").map((b, i) =>
      i === 3 ? b ^ 1 : b,
    ),
  ).toString("base64");
  assert.throws(
    () => decryptCase(flipped, "correct horse battery"),
    /tampered/,
  );
  assert.throws(() => encryptCase(bundle, "short"), /at least 8/);
  assert.throws(
    () =>
      decryptCase(
        { ...envelope, kdf: { ...envelope.kdf, N: 2 ** 30 } },
        "correct horse battery",
      ),
    /out of accepted range/,
  );

  const gz = compressCase(bundle);
  assert.equal(isGzip(gz), true);
  assert.ok(gz.length < Buffer.byteLength(JSON.stringify(bundle, null, 2)));
  const parsed = parseCaseBytes(gz);
  assert.deepEqual(parsed, {
    document: bundle,
    compressed: true,
    encrypted: false,
  });
  const both = parseCaseBytes(compressCase(envelope), {
    passphrase: "correct horse battery",
  });
  assert.deepEqual(both, {
    document: bundle,
    compressed: true,
    encrypted: true,
  });
  assert.throws(
    () => parseCaseBytes(Buffer.from(JSON.stringify(envelope))),
    /PTAH_CASE_PASSPHRASE/,
  );
  assert.deepEqual(parseCaseBytes(Buffer.from(JSON.stringify(bundle))), {
    document: bundle,
    compressed: false,
    encrypted: false,
  });
});

void test("case tools never write outside the requested paths", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-case-tools-"));
  try {
    const bundle = createInvestigationCase(fixture());
    const path = join(dir, "case.json.gz");
    await writeFile(path, compressCase(bundle));
    const { readFile } = await import("node:fs/promises");
    assert.deepEqual(parseCaseBytes(await readFile(path)).document, bundle);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
