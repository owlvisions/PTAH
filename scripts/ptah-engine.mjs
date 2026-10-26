/**
 * Dependency-free PTAH investigation primitives (v1).
 * This is an additive migration slice, not a replacement for REA's existing
 * Evidence Ledger. Inputs are treated as untrusted JSON and validated here.
 */
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  basename,
  delimiter,
  dirname,
  extname,
  join,
  resolve,
} from "node:path";
import {
  constants,
  access,
  stat,
  open,
  mkdir,
  rename,
  unlink,
} from "node:fs/promises";
import { spawn } from "node:child_process";

export const INVESTIGATION_SCHEMA_VERSION = 1;
export const INVESTIGATION_CASE_FORMAT = "ptah-investigation-case";
export const INVESTIGATION_CASE_VERSION = 1;

const MAGIC_SIGNATURES = [
  { format: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { format: "DOS MZ header (PE format not confirmed)", bytes: [0x4d, 0x5a] },
  { format: "Mach-O 32-bit", bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { format: "Mach-O 64-bit", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { format: "Mach-O 64-bit (reversed)", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { format: "WebAssembly", bytes: [0x00, 0x61, 0x73, 0x6d] },
  { format: "Java class", bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { format: "DEX", bytes: [0x64, 0x65, 0x78, 0x0a] },
  {
    format: "ZIP container (format not uniquely identified)",
    bytes: [0x50, 0x4b, 0x03, 0x04],
  },
  {
    format: "ZIP empty archive (format not uniquely identified)",
    bytes: [0x50, 0x4b, 0x05, 0x06],
  },
  {
    format: "ZIP spanning archive (format not uniquely identified)",
    bytes: [0x50, 0x4b, 0x07, 0x08],
  },
  { format: "SQLite database", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65] },
  { format: "PDF document", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { format: "gzip archive", bytes: [0x1f, 0x8b] },
  { format: "xz archive", bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { format: "zstd archive", bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { format: "7-Zip archive", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { format: "RAR archive", bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { format: "bzip2 archive", bytes: [0x42, 0x5a, 0x68] },
  {
    format: "PNG image",
    bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  },
  { format: "LLVM bitcode", bytes: [0x42, 0x43, 0xc0, 0xde] },
  { format: "Lua bytecode", bytes: [0x1b, 0x4c, 0x75, 0x61] },
  {
    format: "Python compiled module (marshal, version-specific)",
    bytes: [0x00, 0x00, 0x0d, 0x0a],
    offset: 2,
  },
  {
    format: "Unix archive (ar / static library)",
    bytes: [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0x0a],
  },
  { format: "Script with shebang", bytes: [0x23, 0x21] },
];

const TAR_MAGIC_OFFSET = 257;
const TAR_MAGIC = Buffer.from("ustar");

function detectFormat(header, filePath, tarProbe = Buffer.alloc(0)) {
  const signature = MAGIC_SIGNATURES.find(({ bytes, offset = 0 }) =>
    bytes.every((byte, index) => header[offset + index] === byte),
  );
  if (signature) return signature.format;
  if (
    tarProbe.length >= TAR_MAGIC.length &&
    tarProbe.subarray(0, 5).equals(TAR_MAGIC)
  )
    return "tar archive (ustar)";
  const extension = extname(filePath).toLowerCase();
  const knownExtensions = new Map([
    [".apk", "Android APK (extension only; signature not confirmed)"],
    [".dex", "Dalvik DEX (extension only; signature not confirmed)"],
    [".wasm", "WebAssembly (extension only; signature not confirmed)"],
    [".dll", "Windows DLL (extension only; signature not confirmed)"],
    [".exe", "Windows executable (extension only; signature not confirmed)"],
    [".so", "Shared library (extension only; signature not confirmed)"],
    [
      ".dylib",
      "macOS dynamic library (extension only; signature not confirmed)",
    ],
    [
      ".asar",
      "Electron ASAR archive (extension only; signature not confirmed)",
    ],
    [".jar", "Java archive (extension only; signature not confirmed)"],
    [".pck", "Godot PCK (extension only; signature not confirmed)"],
  ]);
  return (
    knownExtensions.get(extension) ?? "Unknown (no recognized magic signature)"
  );
}

/** Fingerprint a target file without executing or modifying it. */
export async function fingerprintTarget(filePath) {
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError("target must be a regular file");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(absolutePath)) hash.update(chunk);
  const headerHandle = await open(absolutePath, "r");
  const header = Buffer.alloc(16);
  const tarProbe = Buffer.alloc(5);
  let headerLength = 0;
  let tarProbeLength = 0;
  try {
    headerLength = (await headerHandle.read(header, 0, 16, 0)).bytesRead;
    if (fileStat.size >= TAR_MAGIC_OFFSET + 5)
      tarProbeLength = (
        await headerHandle.read(tarProbe, 0, 5, TAR_MAGIC_OFFSET)
      ).bytesRead;
  } finally {
    await headerHandle.close();
  }
  const finalStat = await stat(absolutePath);
  if (
    fileStat.size !== finalStat.size ||
    fileStat.mtimeMs !== finalStat.mtimeMs ||
    fileStat.ino !== finalStat.ino
  ) {
    throw new Error(
      "target changed while it was being fingerprinted; retry against a stable file",
    );
  }
  return {
    id: basename(absolutePath),
    path: absolutePath,
    sizeBytes: fileStat.size,
    modifiedAt: fileStat.mtime.toISOString(),
    sha256: hash.digest("hex"),
    detectedFormat: detectFormat(
      header.subarray(0, headerLength),
      absolutePath,
      tarProbe.subarray(0, tarProbeLength),
    ),
    executed: false,
    modified: false,
  };
}

/** Fingerprint plus structural format details and entropy; still never executes the target. */
export async function inspectTarget(filePath, options = {}) {
  const fingerprint = await fingerprintTarget(filePath);
  const { describeFormat, fileEntropy } = await import("./ptah-analysis.mjs");
  const [details, entropy] = await Promise.all([
    describeFormat(filePath),
    fileEntropy(filePath, { maxBytes: options.maxEntropyBytes }),
  ]);
  return {
    ...fingerprint,
    formatDetails: details.format === null ? null : details,
    entropy,
  };
}

/** Create a new investigation tied to the actual target bytes. */
export async function createInvestigationForTarget(filePath, id = undefined) {
  if (id !== undefined && (typeof id !== "string" || id.trim().length === 0))
    throw new TypeError("target id must be a non-empty string when supplied");
  const fingerprint = await fingerprintTarget(filePath);
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: { id: id?.trim() || fingerprint.id, sha256: fingerprint.sha256 },
    evidence: [],
    claims: [],
    questions: [],
    actions: [],
  };
}

async function saveJsonAtomically(filePath, document) {
  const absolutePath = resolve(filePath);
  await mkdir(dirname(absolutePath), { recursive: true });
  const temporaryPath = `${absolutePath}.tmp-${process.pid}-${randomUUID()}`;
  let temporaryFileCreated = false;
  try {
    const temporaryFile = await open(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
    );
    temporaryFileCreated = true;
    let writeError;
    try {
      await temporaryFile.writeFile(`${JSON.stringify(document, null, 2)}\n`);
    } catch (error) {
      writeError = error;
    }
    try {
      await temporaryFile.close();
    } catch (error) {
      if (writeError)
        throw new AggregateError(
          [writeError, error],
          "Could not write and close the temporary JSON output",
        );
      throw error;
    }
    if (writeError) throw writeError;
    await rename(temporaryPath, absolutePath);
  } catch (error) {
    if (temporaryFileCreated) {
      try {
        await unlink(temporaryPath);
      } catch (cleanupError) {
        if (cleanupError.code !== "ENOENT")
          throw new AggregateError(
            [error, cleanupError],
            "Could not replace JSON output or clean up its temporary file",
          );
      }
    }
    throw error;
  }
  return absolutePath;
}

/** Validate and atomically persist an investigation JSON file. */
export async function saveInvestigation(filePath, document) {
  return saveJsonAtomically(filePath, validateInvestigation(document));
}

const CONFIDENCE = new Set(["observed", "derived", "inferred"]);
const EVIDENCE_KINDS = new Set([
  "static-analysis",
  "runtime-observation",
  "decompilation",
  "symbol",
  "network-observation",
  "filesystem-observation",
  "documentation",
  "test-result",
  "other",
]);
/** Evidence kinds accepted by validation, for tool schemas and help text. */
export const EVIDENCE_KIND_VALUES = Object.freeze([...EVIDENCE_KINDS]);

export function sha256Text(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value))
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    if (
      Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null
    )
      throw new TypeError("case payload must contain only JSON objects");
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined)
    throw new TypeError("case payload must contain only JSON values");
  return serialized;
}

/** Wrap a validated investigation in a portable bundle with a corruption checksum. */
export function createInvestigationCase(input) {
  const investigation = validateInvestigation(input);
  return {
    format: INVESTIGATION_CASE_FORMAT,
    formatVersion: INVESTIGATION_CASE_VERSION,
    integrity: {
      algorithm: "sha256",
      payloadSha256: sha256Text(canonicalJson(investigation)),
    },
    investigation,
  };
}

function validateInvestigationCase(input) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new TypeError("case bundle must be an object");
  if (input.format !== INVESTIGATION_CASE_FORMAT)
    throw new TypeError(`case format must be ${INVESTIGATION_CASE_FORMAT}`);
  if (input.formatVersion !== INVESTIGATION_CASE_VERSION)
    throw new TypeError(
      `case formatVersion must be ${INVESTIGATION_CASE_VERSION}`,
    );
  if (!input.integrity || typeof input.integrity !== "object")
    throw new TypeError("case integrity metadata is required");
  if (input.integrity.algorithm !== "sha256")
    throw new TypeError("case integrity algorithm must be sha256");
  if (
    typeof input.integrity.payloadSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(input.integrity.payloadSha256)
  )
    throw new TypeError(
      "case payloadSha256 must be a lowercase SHA-256 digest",
    );
  const investigation = validateInvestigation(input.investigation);
  const actualSha256 = sha256Text(canonicalJson(investigation));
  return {
    investigation,
    expectedSha256: input.integrity.payloadSha256,
    actualSha256,
    matches: actualSha256 === input.integrity.payloadSha256,
  };
}

/** Check bundle format, investigation validity, and its corruption checksum. */
export function verifyInvestigationCase(input) {
  const checked = validateInvestigationCase(input);
  return {
    format: INVESTIGATION_CASE_FORMAT,
    formatVersion: INVESTIGATION_CASE_VERSION,
    valid: checked.matches,
    integrity: {
      algorithm: "sha256",
      expectedSha256: checked.expectedSha256,
      actualSha256: checked.actualSha256,
      matches: checked.matches,
      note: "Checksum detects accidental corruption; it does not authenticate the author.",
    },
    target: checked.investigation.target,
    evidenceCount: checked.investigation.evidence.length,
    claimCount: checked.investigation.claims.length,
  };
}

/** Import a case only when its checksum, schema, and optional target digest match. */
export async function importInvestigationCase(input, targetPath = undefined) {
  const checked = validateInvestigationCase(input);
  if (!checked.matches)
    throw new Error("case payload checksum mismatch; import was refused");
  if (targetPath !== undefined) {
    const target = await fingerprintTarget(targetPath);
    if (
      target.sha256.toLowerCase() !==
      checked.investigation.target.sha256.toLowerCase()
    )
      throw new Error(
        "case target digest mismatch; investigation was not imported",
      );
  }
  return checked.investigation;
}

/** Atomically save a portable investigation case bundle. */
export async function saveInvestigationCase(filePath, input) {
  return saveJsonAtomically(filePath, createInvestigationCase(input));
}

function requireString(value, path) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

function requireArray(value, path) {
  if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
  return value;
}

function uniqueIds(items, path) {
  const seen = new Set();
  for (const item of items) {
    requireString(item.id, `${path}[].id`);
    if (seen.has(item.id))
      throw new TypeError(`${path} contains duplicate id: ${item.id}`);
    seen.add(item.id);
  }
  return seen;
}

function validateTags(tags, path) {
  requireArray(tags, path);
  if (tags.length > 32) throw new TypeError(`${path} may list at most 32 tags`);
  const seen = new Set();
  for (const tag of tags) {
    requireString(tag, `${path}[]`);
    if (tag.length > 64 || !/^[\p{L}\p{N}][\p{L}\p{N}._:/-]*$/u.test(tag))
      throw new TypeError(`${path} contains an invalid tag: ${tag}`);
    if (seen.has(tag))
      throw new TypeError(`${path} contains duplicate tag: ${tag}`);
    seen.add(tag);
  }
}

function contentDigest(document) {
  return sha256Text(
    canonicalJson({
      target: document.target,
      evidence: document.evidence ?? [],
      claims: document.claims ?? [],
      questions: document.questions ?? [],
      actions: document.actions ?? [],
    }),
  );
}

function validateFrozen(frozen, document) {
  if (!frozen || typeof frozen !== "object" || Array.isArray(frozen))
    throw new TypeError("frozen must be an object");
  requireString(frozen.at, "frozen.at");
  if (Number.isNaN(Date.parse(frozen.at)))
    throw new TypeError("frozen.at must be an ISO timestamp");
  requireString(frozen.contentSha256, "frozen.contentSha256");
  if (frozen.contentSha256 !== contentDigest(document))
    throw new TypeError(
      "frozen content digest mismatch; unfreeze the investigation before modifying evidence, claims, questions, or actions",
    );
}

function validateRelatedCases(related) {
  requireArray(related, "relatedCases");
  const seen = new Set();
  related.forEach((item, index) => {
    const path = `relatedCases[${index}]`;
    if (!item || typeof item !== "object")
      throw new TypeError(`${path} must be an object`);
    requireString(item.payloadSha256, `${path}.payloadSha256`);
    requireString(item.targetSha256, `${path}.targetSha256`);
    for (const key of ["payloadSha256", "targetSha256"])
      if (!/^[a-f0-9]{64}$/i.test(item[key]))
        throw new TypeError(`${path}.${key} must be a SHA-256 digest`);
    if (typeof item.sameTarget !== "boolean")
      throw new TypeError(`${path}.sameTarget must be a boolean`);
    if (item.note !== undefined) requireString(item.note, `${path}.note`);
    if (seen.has(item.payloadSha256))
      throw new TypeError(`${path} duplicates case ${item.payloadSha256}`);
    seen.add(item.payloadSha256);
  });
}

function validateArtifact(artifact, evidenceId) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact))
    throw new TypeError(`evidence.${evidenceId}.artifact must be an object`);
  requireString(artifact.sha256, `evidence.${evidenceId}.artifact.sha256`);
  if (!/^[a-f0-9]{64}$/i.test(artifact.sha256))
    throw new TypeError(
      `evidence.${evidenceId}.artifact.sha256 must be a 64-character hexadecimal SHA-256 digest`,
    );
  if (!Number.isInteger(artifact.sizeBytes) || artifact.sizeBytes < 0)
    throw new TypeError(
      `evidence.${evidenceId}.artifact.sizeBytes must be a non-negative integer`,
    );
  if (artifact.name !== undefined)
    requireString(artifact.name, `evidence.${evidenceId}.artifact.name`);
}

function historyEntryDigest(entry) {
  const { entrySha256: _ignored, ...rest } = entry;
  return sha256Text(canonicalJson(rest));
}

function validateHistory(history) {
  requireArray(history, "history");
  let previous = null;
  history.forEach((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new TypeError(`history[${index}] must be an object`);
    if (entry.seq !== index + 1)
      throw new TypeError(`history[${index}].seq must be ${index + 1}`);
    requireString(entry.action, `history[${index}].action`);
    requireString(entry.at, `history[${index}].at`);
    if (Number.isNaN(Date.parse(entry.at)))
      throw new TypeError(`history[${index}].at must be an ISO timestamp`);
    if ((entry.previousEntrySha256 ?? null) !== previous)
      throw new TypeError(
        `history[${index}].previousEntrySha256 breaks the hash chain`,
      );
    if (entry.entrySha256 !== historyEntryDigest(entry))
      throw new TypeError(`history[${index}].entrySha256 does not match`);
    previous = entry.entrySha256;
  });
}

/** Validate a portable, versioned investigation document. */
export function validateInvestigation(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new TypeError("investigation must be an object");
  }
  if (document.schemaVersion !== INVESTIGATION_SCHEMA_VERSION) {
    throw new TypeError(
      `schemaVersion must be ${INVESTIGATION_SCHEMA_VERSION}`,
    );
  }
  if (!document.target || typeof document.target !== "object") {
    throw new TypeError("target must be an object");
  }
  requireString(document.target.id, "target.id");
  requireString(document.target.sha256, "target.sha256");
  if (!/^[a-f0-9]{64}$/i.test(document.target.sha256)) {
    throw new TypeError(
      "target.sha256 must be a 64-character hexadecimal SHA-256 digest",
    );
  }

  const evidence = requireArray(document.evidence ?? [], "evidence");
  const claims = requireArray(document.claims ?? [], "claims");
  const questions = requireArray(document.questions ?? [], "questions");
  const actions = requireArray(document.actions ?? [], "actions");
  const evidenceIds = uniqueIds(evidence, "evidence");
  uniqueIds(claims, "claims");
  uniqueIds(questions, "questions");
  uniqueIds(actions, "actions");
  if (document.history !== undefined) validateHistory(document.history);
  if (document.frozen !== undefined) validateFrozen(document.frozen, document);
  if (document.relatedCases !== undefined)
    validateRelatedCases(document.relatedCases);

  for (const item of evidence) {
    requireString(item.summary, `evidence.${item.id}.summary`);
    requireString(item.source, `evidence.${item.id}.source`);
    requireString(item.kind, `evidence.${item.id}.kind`);
    if (!EVIDENCE_KINDS.has(item.kind))
      throw new TypeError(
        `evidence.${item.id}.kind is unsupported: ${item.kind}`,
      );
    if (!CONFIDENCE.has(item.confidence))
      throw new TypeError(
        `evidence.${item.id}.confidence must be observed, derived, or inferred`,
      );
    requireString(item.targetSha256, `evidence.${item.id}.targetSha256`);
    if (!/^[a-f0-9]{64}$/i.test(item.targetSha256)) {
      throw new TypeError(
        `evidence.${item.id}.targetSha256 must be a 64-character hexadecimal SHA-256 digest`,
      );
    }
    if (
      item.targetSha256.toLowerCase() !== document.target.sha256.toLowerCase()
    ) {
      throw new TypeError(
        `evidence.${item.id} belongs to a different target digest; stale or cross-target evidence is not accepted`,
      );
    }
    if (item.artifact !== undefined) validateArtifact(item.artifact, item.id);
    if (item.tags !== undefined)
      validateTags(item.tags, `evidence.${item.id}.tags`);
  }
  for (const claim of claims) {
    requireString(claim.text, `claims.${claim.id}.text`);
    const refs = requireArray(
      claim.evidenceIds,
      `claims.${claim.id}.evidenceIds`,
    );
    if (refs.length === 0)
      throw new TypeError(
        `claims.${claim.id} must cite at least one evidence item`,
      );
    for (const id of refs)
      if (!evidenceIds.has(id))
        throw new TypeError(
          `claims.${claim.id} references missing evidence: ${id}`,
        );
    if (
      claim.status &&
      !["hypothesis", "supported", "verified", "rejected"].includes(
        claim.status,
      )
    ) {
      throw new TypeError(`claims.${claim.id}.status is invalid`);
    }
    if (claim.tags !== undefined)
      validateTags(claim.tags, `claims.${claim.id}.tags`);
  }
  for (const question of questions) {
    requireString(question.text, `questions.${question.id}.text`);
    const kinds = requireArray(
      question.requiredEvidenceKinds ?? [],
      `questions.${question.id}.requiredEvidenceKinds`,
    );
    for (const kind of kinds)
      if (!EVIDENCE_KINDS.has(kind))
        throw new TypeError(
          `questions.${question.id} has unsupported evidence kind: ${kind}`,
        );
    if (
      question.priority !== undefined &&
      (!Number.isFinite(question.priority) ||
        question.priority < 0 ||
        question.priority > 100)
    ) {
      throw new TypeError(
        `questions.${question.id}.priority must be between 0 and 100`,
      );
    }
    if (question.resolution !== undefined) {
      const resolution = question.resolution;
      if (!resolution || typeof resolution !== "object")
        throw new TypeError(
          `questions.${question.id}.resolution must be an object`,
        );
      requireString(
        resolution.reason,
        `questions.${question.id}.resolution.reason`,
      );
      for (const id of requireArray(
        resolution.evidenceIds ?? [],
        `questions.${question.id}.resolution.evidenceIds`,
      ))
        if (!evidenceIds.has(id))
          throw new TypeError(
            `questions.${question.id}.resolution references missing evidence: ${id}`,
          );
    }
  }
  for (const action of actions) {
    requireString(action.name, `actions.${action.id}.name`);
    const produces = requireArray(
      action.produces ?? [],
      `actions.${action.id}.produces`,
    );
    for (const kind of produces)
      if (!EVIDENCE_KINDS.has(kind))
        throw new TypeError(
          `actions.${action.id} produces unsupported evidence kind: ${kind}`,
        );
    if (
      action.cost !== undefined &&
      (!Number.isFinite(action.cost) || action.cost <= 0)
    ) {
      throw new TypeError(
        `actions.${action.id}.cost must be a positive number`,
      );
    }
  }
  return { ...document, evidence, claims, questions, actions };
}

/** Verify a saved investigation and optionally re-hash the current target bytes. */
export async function verifyInvestigation(input, targetPath = undefined) {
  const investigation = validateInvestigation(input);
  const result = {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    valid: true,
    evidenceCount: investigation.evidence.length,
    claimCount: investigation.claims.length,
    target: {
      id: investigation.target.id,
      expectedSha256: investigation.target.sha256,
    },
    targetChecked: targetPath !== undefined,
    targetMatches: null,
  };
  if (targetPath !== undefined) {
    const actual = await fingerprintTarget(targetPath);
    result.target.actualSha256 = actual.sha256;
    result.target.path = actual.path;
    result.targetMatches =
      actual.sha256.toLowerCase() === investigation.target.sha256.toLowerCase();
    result.valid = result.targetMatches;
    if (!result.targetMatches)
      result.error =
        "target digest mismatch: investigation was created for different bytes";
  }
  return result;
}

/**
 * Append a hash-chained history entry. Entries are append-only: each digest
 * covers the entry and the previous digest, so reordering or editing is detectable.
 */
export function recordHistory(input, action, details = {}, at = undefined) {
  const investigation = validateInvestigation(input);
  requireString(action, "action");
  const history = investigation.history ?? [];
  const previous = history.at(-1)?.entrySha256 ?? null;
  const timestamp = at ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(timestamp)))
    throw new TypeError("history timestamp must be an ISO timestamp");
  const entry = {
    seq: history.length + 1,
    action,
    at: timestamp,
    ...details,
    previousEntrySha256: previous,
  };
  entry.entrySha256 = historyEntryDigest(entry);
  return { ...investigation, history: [...history, entry] };
}

/** Append one evidence item bound to the investigation's target digest. */
export function addEvidence(input, record, options = {}) {
  const investigation = validateInvestigation(input);
  if ((investigation.evidence ?? []).some((item) => item.id === record.id))
    throw new Error(`Evidence id already exists: ${record.id}`);
  const item = {
    id: record.id,
    kind: record.kind,
    summary: record.summary,
    source: record.source,
    confidence: record.confidence ?? "observed",
    targetSha256: investigation.target.sha256,
    ...(record.artifact ? { artifact: record.artifact } : {}),
    ...(record.tags?.length ? { tags: [...record.tags] } : {}),
  };
  return recordHistory(
    {
      ...investigation,
      evidence: [...(investigation.evidence ?? []), item],
    },
    "evidence-added",
    { evidenceId: record.id, kind: record.kind },
    options.at,
  );
}

const RECORD_COLLECTIONS = new Set(["claims", "questions", "actions"]);

/** Append a claim, question, or action; validation enforces cited evidence and kinds. */
export function addInvestigationRecord(
  input,
  collection,
  record,
  options = {},
) {
  if (!RECORD_COLLECTIONS.has(collection))
    throw new TypeError("collection must be claims, questions, or actions");
  const investigation = validateInvestigation(input);
  const existing = investigation[collection] ?? [];
  if (existing.some((item) => item.id === record.id))
    throw new Error(`${collection} id already exists: ${record.id}`);
  return recordHistory(
    { ...investigation, [collection]: [...existing, record] },
    `${collection}-added`,
    { id: record.id },
    options.at,
  );
}

const CLAIM_STATUSES = ["hypothesis", "supported", "verified", "rejected"];

/** Change a claim's status; `verified` requires at least one observed evidence item. */
export function setClaimStatus(input, claimId, status, options = {}) {
  const investigation = validateInvestigation(input);
  if (!CLAIM_STATUSES.includes(status))
    throw new TypeError(`status must be one of ${CLAIM_STATUSES.join(", ")}`);
  const claim = investigation.claims.find((item) => item.id === claimId);
  if (!claim) throw new Error(`claim not found: ${claimId}`);
  const evidenceById = indexById(investigation.evidence);
  if (
    status === "verified" &&
    !claim.evidenceIds.some(
      (id) => evidenceById.get(id)?.confidence === "observed",
    )
  )
    throw new Error(
      `claim ${claimId} cannot be verified: no cited evidence is observed`,
    );
  const previous = claim.status ?? "hypothesis";
  const updated = {
    ...investigation,
    claims: investigation.claims.map((item) =>
      item.id === claimId ? { ...item, status } : item,
    ),
  };
  return recordHistory(
    updated,
    "claim-status",
    {
      claimId,
      from: previous,
      to: status,
      ...(options.reason ? { reason: options.reason } : {}),
    },
    options.at,
  );
}

/** Resolve or reopen a question with a reason and optional supporting evidence. */
export function resolveQuestion(input, questionId, resolution, options = {}) {
  const investigation = validateInvestigation(input);
  const question = investigation.questions.find((q) => q.id === questionId);
  if (!question) throw new Error(`question not found: ${questionId}`);
  const reopen = resolution === null;
  if (!reopen) {
    requireString(resolution?.reason, "resolution.reason");
    const evidenceIds = indexById(investigation.evidence);
    for (const id of resolution.evidenceIds ?? [])
      if (!evidenceIds.has(id))
        throw new Error(`resolution references missing evidence: ${id}`);
  }
  const updated = {
    ...investigation,
    questions: investigation.questions.map((q) => {
      if (q.id !== questionId) return q;
      if (reopen) {
        const { resolution: _dropped, ...rest } = q;
        return { ...rest, resolved: false };
      }
      return {
        ...q,
        resolved: true,
        resolution: {
          reason: resolution.reason,
          evidenceIds: [...(resolution.evidenceIds ?? [])],
        },
      };
    }),
  };
  return recordHistory(
    updated,
    reopen ? "question-reopened" : "question-resolved",
    { questionId, ...(reopen ? {} : { reason: resolution.reason }) },
    options.at,
  );
}

/** Freeze content so any later change to evidence/claims/questions/actions fails validation. */
export function freezeInvestigation(input, options = {}) {
  const investigation = validateInvestigation(input);
  if (investigation.frozen) throw new Error("investigation is already frozen");
  const at = options.at ?? new Date().toISOString();
  const frozen = { at, contentSha256: contentDigest(investigation) };
  return recordHistory(
    { ...investigation, frozen },
    "frozen",
    { contentSha256: frozen.contentSha256 },
    at,
  );
}

/** Remove the freeze marker; the unfreeze itself is recorded in history. */
export function unfreezeInvestigation(input, options = {}) {
  const investigation = validateInvestigation(input);
  if (!investigation.frozen) throw new Error("investigation is not frozen");
  const { frozen, ...rest } = investigation;
  return recordHistory(
    rest,
    "unfrozen",
    { previousContentSha256: frozen.contentSha256 },
    options.at,
  );
}

/** Record a cross-reference to another verified case bundle. */
export function linkRelatedCase(input, bundle, options = {}) {
  const investigation = validateInvestigation(input);
  const verification = verifyInvestigationCase(bundle);
  if (!verification.valid)
    throw new Error("related case checksum mismatch; refusing to link");
  const related = investigation.relatedCases ?? [];
  const payloadSha256 = verification.integrity.expectedSha256;
  if (related.some((item) => item.payloadSha256 === payloadSha256))
    throw new Error("case is already linked");
  const entry = {
    payloadSha256,
    targetSha256: verification.target.sha256,
    sameTarget:
      verification.target.sha256.toLowerCase() ===
      investigation.target.sha256.toLowerCase(),
    ...(options.note ? { note: options.note } : {}),
  };
  return recordHistory(
    { ...investigation, relatedCases: [...related, entry] },
    "case-linked",
    { payloadSha256, sameTarget: entry.sameTarget },
    options.at,
  );
}

function mergeCollection(baseItems, otherItems, prefer, conflicts, name) {
  const merged = indexById(baseItems);
  for (const item of otherItems) {
    const existing = merged.get(item.id);
    if (!existing) {
      merged.set(item.id, item);
      continue;
    }
    if (canonicalJson(existing) === canonicalJson(item)) continue;
    conflicts.push({ collection: name, id: item.id });
    if (prefer === "other") merged.set(item.id, item);
  }
  return [...merged.values()];
}

/** Merge two investigations of the same target; conflicting IDs require an explicit preference. */
export function mergeInvestigations(baseInput, otherInput, options = {}) {
  const base = validateInvestigation(baseInput);
  const other = validateInvestigation(otherInput);
  if (base.target.sha256.toLowerCase() !== other.target.sha256.toLowerCase())
    throw new Error(
      "cannot merge investigations of different targets; evidence is not transferable",
    );
  if (base.frozen || other.frozen)
    throw new Error("cannot merge a frozen investigation; unfreeze first");
  const prefer = options.prefer;
  if (prefer !== undefined && !["base", "other"].includes(prefer))
    throw new TypeError("prefer must be base or other");
  const conflicts = [];
  const merged = {
    ...base,
    evidence: mergeCollection(
      base.evidence,
      other.evidence,
      prefer,
      conflicts,
      "evidence",
    ),
    claims: mergeCollection(
      base.claims,
      other.claims,
      prefer,
      conflicts,
      "claims",
    ),
    questions: mergeCollection(
      base.questions,
      other.questions,
      prefer,
      conflicts,
      "questions",
    ),
    actions: mergeCollection(
      base.actions,
      other.actions,
      prefer,
      conflicts,
      "actions",
    ),
  };
  if (conflicts.length > 0 && prefer === undefined) {
    const error = new Error(
      `merge conflicts on ${conflicts.map((c) => `${c.collection}/${c.id}`).join(", ")}; pass prefer=base|other`,
    );
    error.conflicts = conflicts;
    throw error;
  }
  const validated = validateInvestigation(merged);
  return {
    investigation: recordHistory(
      validated,
      "merged",
      {
        otherContentSha256: contentDigest(other),
        otherHistoryEntries: other.history?.length ?? 0,
        conflicts: conflicts.length,
        prefer: prefer ?? null,
      },
      options.at,
    ),
    conflicts,
    added: {
      evidence: validated.evidence.length - base.evidence.length,
      claims: validated.claims.length - base.claims.length,
      questions: validated.questions.length - base.questions.length,
      actions: validated.actions.length - base.actions.length,
    },
    note: "The other investigation's history is not chained into the result; its content digest is recorded instead.",
  };
}

/**
 * Migration registry. Each entry upgrades a document from `from` to `to`.
 * Unversioned legacy documents (no schemaVersion, target.sha256 present) are
 * treated as version 0.
 */
const MIGRATIONS = [
  {
    from: 0,
    to: 1,
    description:
      "Normalize legacy documents: add schemaVersion, default collections, lowercase digests, map evidence.sha256 to targetSha256.",
    apply(document) {
      const lower = (value) =>
        typeof value === "string" ? value.toLowerCase() : value;
      return {
        schemaVersion: 1,
        target: { ...document.target, sha256: lower(document.target?.sha256) },
        evidence: (document.evidence ?? []).map((item) => {
          const { sha256, ...rest } = item;
          return {
            ...rest,
            confidence: rest.confidence ?? "observed",
            targetSha256: lower(
              rest.targetSha256 ?? sha256 ?? document.target?.sha256,
            ),
          };
        }),
        claims: (document.claims ?? []).map((claim) => ({
          ...claim,
          evidenceIds: claim.evidenceIds ?? claim.evidence ?? [],
        })),
        questions: document.questions ?? [],
        actions: document.actions ?? [],
        ...(document.history ? { history: document.history } : {}),
      };
    },
  },
];

export function listMigrations() {
  return MIGRATIONS.map(({ from, to, description }) => ({
    from,
    to,
    description,
  }));
}

/** Upgrade a document to the current schema, reporting each applied step. */
export function migrateInvestigation(document) {
  if (!document || typeof document !== "object" || Array.isArray(document))
    throw new TypeError("investigation must be an object");
  let current = document;
  let version =
    document.schemaVersion === undefined && document.target?.sha256
      ? 0
      : document.schemaVersion;
  if (!Number.isInteger(version))
    throw new TypeError("schemaVersion is missing or not an integer");
  if (version > INVESTIGATION_SCHEMA_VERSION)
    throw new TypeError(
      `schemaVersion ${version} is newer than this engine supports (${INVESTIGATION_SCHEMA_VERSION})`,
    );
  const applied = [];
  while (version < INVESTIGATION_SCHEMA_VERSION) {
    const step = MIGRATIONS.find((m) => m.from === version);
    if (!step) throw new Error(`no migration from schemaVersion ${version}`);
    current = step.apply(current);
    applied.push({
      from: step.from,
      to: step.to,
      description: step.description,
    });
    version = step.to;
  }
  return {
    investigation: validateInvestigation(current),
    fromVersion: applied.length ? applied[0].from : version,
    toVersion: INVESTIGATION_SCHEMA_VERSION,
    applied,
  };
}

/** Quality checks that do not change the document; findings are advisory and deterministic. */
export function lintInvestigation(input) {
  const investigation = validateInvestigation(input);
  const findings = [];
  const add = (severity, code, subject, message) =>
    findings.push({ severity, code, subject, message });
  const evidenceById = indexById(investigation.evidence);
  const citedEvidence = new Set(
    investigation.claims.flatMap((claim) => claim.evidenceIds),
  );
  for (const q of investigation.questions)
    for (const id of q.resolution?.evidenceIds ?? []) citedEvidence.add(id);
  for (const item of investigation.evidence) {
    if (!citedEvidence.has(item.id))
      add(
        "info",
        "orphan-evidence",
        item.id,
        "Evidence is not cited by any claim or question resolution.",
      );
    if (item.confidence === "observed" && item.artifact === undefined)
      add(
        "info",
        "observed-without-artifact",
        item.id,
        "Observed evidence has no artifact digest; attach raw output for reproducibility.",
      );
  }
  const summaries = new Map();
  for (const item of investigation.evidence) {
    const key = `${item.kind}\u0000${item.summary.trim().toLowerCase()}`;
    if (summaries.has(key))
      add(
        "warning",
        "duplicate-evidence-summary",
        item.id,
        `Same kind and summary as ${summaries.get(key)}.`,
      );
    else summaries.set(key, item.id);
  }
  for (const claim of investigation.claims) {
    const cited = claim.evidenceIds.map((id) => evidenceById.get(id));
    const status = claim.status ?? "hypothesis";
    if (cited.every((e) => e.confidence === "inferred"))
      add(
        status === "hypothesis" ? "info" : "warning",
        "inference-only-claim",
        claim.id,
        "Claim relies only on inferred evidence.",
      );
    if (
      (status === "verified" || status === "supported") &&
      !cited.some((e) => e.confidence === "observed")
    )
      add(
        "error",
        "status-exceeds-evidence",
        claim.id,
        `Claim is ${status} but cites no observed evidence.`,
      );
  }
  const producible = new Set(
    investigation.actions.flatMap((action) => action.produces ?? []),
  );
  const present = new Set(investigation.evidence.map((item) => item.kind));
  for (const q of investigation.questions) {
    if (q.resolved) {
      if (!q.resolution)
        add(
          "warning",
          "resolved-without-reason",
          q.id,
          "Question is resolved but records no resolution reason.",
        );
      continue;
    }
    const missing = (q.requiredEvidenceKinds ?? []).filter(
      (kind) => !present.has(kind),
    );
    const unproducible = missing.filter((kind) => !producible.has(kind));
    if (unproducible.length > 0)
      add(
        "warning",
        "unreachable-question",
        q.id,
        `No candidate action produces: ${unproducible.join(", ")}.`,
      );
    if ((q.requiredEvidenceKinds ?? []).length === 0)
      add(
        "info",
        "question-without-requirements",
        q.id,
        "Question lists no required evidence kinds; the planner cannot act on it.",
      );
  }
  findings.sort(
    (a, b) =>
      ["error", "warning", "info"].indexOf(a.severity) -
        ["error", "warning", "info"].indexOf(b.severity) ||
      a.code.localeCompare(b.code) ||
      a.subject.localeCompare(b.subject),
  );
  const counts = { error: 0, warning: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: investigation.target,
    ok: counts.error === 0,
    counts,
    findings,
  };
}

/** Deterministic quality metrics; ratios are null when the denominator is zero. */
export function investigationStats(input) {
  const investigation = validateInvestigation(input);
  const report = buildEvidenceReport(investigation);
  const ratio = (numerator, denominator) =>
    denominator === 0 ? null : Number((numerator / denominator).toFixed(4));
  const byLabel = {
    "evidence-backed": 0,
    "derived-support": 0,
    "inference-only": 0,
    verified: 0,
  };
  for (const claim of report.claims) byLabel[claim.supportLabel] += 1;
  const byConfidence = { observed: 0, derived: 0, inferred: 0 };
  const byKind = {};
  const byTag = {};
  let withArtifact = 0;
  for (const item of investigation.evidence) {
    byConfidence[item.confidence] += 1;
    byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
    for (const tag of item.tags ?? []) byTag[tag] = (byTag[tag] ?? 0) + 1;
    if (item.artifact) withArtifact += 1;
  }
  for (const claim of investigation.claims)
    for (const tag of claim.tags ?? []) byTag[tag] = (byTag[tag] ?? 0) + 1;
  const sortedEntries = (object) =>
    Object.fromEntries(
      Object.entries(object).sort(([a], [b]) => a.localeCompare(b)),
    );
  const cited = new Set(investigation.claims.flatMap((c) => c.evidenceIds));
  const resolved = investigation.questions.filter((q) => q.resolved).length;
  const present = new Set(investigation.evidence.map((item) => item.kind));
  const openWithMissing = investigation.questions.filter(
    (q) =>
      !q.resolved &&
      (q.requiredEvidenceKinds ?? []).some((kind) => !present.has(kind)),
  ).length;
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: investigation.target,
    evidence: {
      total: investigation.evidence.length,
      byConfidence,
      byKind: sortedEntries(byKind),
      citedRatio: ratio(cited.size, investigation.evidence.length),
      artifactRatio: ratio(withArtifact, investigation.evidence.length),
    },
    claims: {
      total: report.claims.length,
      bySupportLabel: byLabel,
      evidenceBackedRatio: ratio(
        byLabel["evidence-backed"] + byLabel.verified,
        report.claims.length,
      ),
      inferenceOnlyRatio: ratio(
        byLabel["inference-only"],
        report.claims.length,
      ),
    },
    questions: {
      total: investigation.questions.length,
      resolved,
      open: investigation.questions.length - resolved,
      openWithMissingEvidence: openWithMissing,
      resolvedRatio: ratio(resolved, investigation.questions.length),
    },
    actions: { total: investigation.actions.length },
    tags: sortedEntries(byTag),
    frozen: Boolean(investigation.frozen),
    relatedCases: investigation.relatedCases?.length ?? 0,
    historyEntries: investigation.history?.length ?? 0,
  };
}

/** Plan up to `steps` actions greedily under a shared budget, simulating produced evidence. */
export function planSteps(input, budget = {}) {
  const investigation = validateInvestigation(input);
  const steps = budget.steps ?? 3;
  if (!Number.isInteger(steps) || steps < 1)
    throw new TypeError("budget.steps must be a positive integer");
  let remainingCost = budget.maxCost ?? Number.POSITIVE_INFINITY;
  let working = investigation;
  const plan = [];
  let terminal = null;
  for (let index = 0; index < steps; index += 1) {
    if (!(remainingCost > 0)) {
      terminal = {
        status: "budget-exhausted",
        reason: "The cost budget was consumed by earlier planned steps.",
      };
      break;
    }
    const next = planNextAction(working, {
      maxCalls: 1,
      maxCost: remainingCost,
    });
    if (next.status !== "planned") {
      terminal = next;
      break;
    }
    plan.push({
      step: index + 1,
      questionId: next.questionId,
      actionId: next.selectedAction.id,
      actionName: next.selectedAction.name,
      produces: next.selectedAction.produces,
      estimatedCost: next.selectedAction.estimatedCost,
    });
    remainingCost -= next.selectedAction.estimatedCost;
    working = {
      ...working,
      evidence: [
        ...working.evidence,
        ...next.selectedAction.produces.map((kind, i) => ({
          id: `simulated-${index + 1}-${i}`,
          kind,
          summary: "simulated by planner",
          source: "planner simulation",
          confidence: "inferred",
          targetSha256: working.target.sha256,
        })),
      ],
    };
  }
  return {
    status:
      plan.length === 0 ? (terminal?.status ?? "no-action-needed") : "planned",
    steps: plan,
    totalEstimatedCost: plan.reduce((sum, step) => sum + step.estimatedCost, 0),
    stoppedBecause: terminal
      ? { status: terminal.status, reason: terminal.reason }
      : plan.length === steps
        ? { status: "step-limit", reason: `Reached ${steps} planned steps.` }
        : null,
    note: "Planned steps assume each action yields its listed evidence kinds; nothing has been executed.",
  };
}

function graphLabel(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function mermaidLabel(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

/** Render the evidence graph as Graphviz DOT or Mermaid text. */
export function renderEvidenceGraph(input, format = "dot") {
  const graph = buildEvidenceGraph(input);
  if (format === "dot") {
    const lines = ["digraph ptah {", "  rankdir=LR;", "  node [shape=box];"];
    for (const node of graph.nodes)
      lines.push(
        `  "${graphLabel(node.id)}" [label="${graphLabel(`${node.type}: ${node.label}`)}"${
          node.type === "target"
            ? ", shape=ellipse"
            : node.type === "question" && !node.resolved
              ? ", style=dashed"
              : ""
        }];`,
      );
    for (const edge of graph.edges)
      lines.push(
        `  "${graphLabel(edge.from)}" -> "${graphLabel(edge.to)}" [label="${graphLabel(edge.type)}"];`,
      );
    lines.push("}", "");
    return lines.join("\n");
  }
  if (format === "mermaid") {
    const ids = new Map(graph.nodes.map((node, i) => [node.id, `n${i}`]));
    const lines = ["graph LR"];
    for (const node of graph.nodes)
      lines.push(
        `  ${ids.get(node.id)}["${mermaidLabel(`${node.type}: ${node.label}`)}"]`,
      );
    for (const edge of graph.edges)
      lines.push(
        `  ${ids.get(edge.from)} -->|${edge.type}| ${ids.get(edge.to)}`,
      );
    lines.push("");
    return lines.join("\n");
  }
  throw new TypeError("graph format must be json, dot, or mermaid");
}

/** JSON Schema (draft 2020-12) describing investigation documents accepted by this engine. */
export function investigationJsonSchema() {
  const sha256 = { type: "string", pattern: "^[a-fA-F0-9]{64}$" };
  const nonEmpty = { type: "string", minLength: 1 };
  const idList = { type: "array", items: nonEmpty };
  const kinds = { type: "string", enum: [...EVIDENCE_KINDS] };
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://github.com/owlvisions/PTAH/docs/schema/ptah-investigation.schema.json",
    title: "PTAH investigation",
    type: "object",
    required: ["schemaVersion", "target"],
    properties: {
      schemaVersion: { const: INVESTIGATION_SCHEMA_VERSION },
      target: {
        type: "object",
        required: ["id", "sha256"],
        properties: { id: nonEmpty, sha256 },
      },
      evidence: {
        type: "array",
        items: {
          type: "object",
          required: [
            "id",
            "kind",
            "summary",
            "source",
            "confidence",
            "targetSha256",
          ],
          properties: {
            id: nonEmpty,
            kind: kinds,
            summary: nonEmpty,
            source: nonEmpty,
            confidence: { type: "string", enum: [...CONFIDENCE] },
            targetSha256: sha256,
            tags: {
              type: "array",
              maxItems: 32,
              uniqueItems: true,
              items: { type: "string", minLength: 1, maxLength: 64 },
            },
            artifact: {
              type: "object",
              required: ["sha256", "sizeBytes"],
              properties: {
                sha256,
                sizeBytes: { type: "integer", minimum: 0 },
                name: nonEmpty,
              },
            },
          },
        },
      },
      claims: {
        type: "array",
        items: {
          type: "object",
          required: ["id", "text", "evidenceIds"],
          properties: {
            id: nonEmpty,
            text: nonEmpty,
            evidenceIds: { ...idList, minItems: 1 },
            status: { type: "string", enum: CLAIM_STATUSES },
            tags: {
              type: "array",
              maxItems: 32,
              uniqueItems: true,
              items: { type: "string", minLength: 1, maxLength: 64 },
            },
          },
        },
      },
      questions: {
        type: "array",
        items: {
          type: "object",
          required: ["id", "text"],
          properties: {
            id: nonEmpty,
            text: nonEmpty,
            priority: { type: "number", minimum: 0, maximum: 100 },
            requiredEvidenceKinds: { type: "array", items: kinds },
            resolved: { type: "boolean" },
            resolution: {
              type: "object",
              required: ["reason"],
              properties: { reason: nonEmpty, evidenceIds: idList },
            },
          },
        },
      },
      actions: {
        type: "array",
        items: {
          type: "object",
          required: ["id", "name"],
          properties: {
            id: nonEmpty,
            name: nonEmpty,
            produces: { type: "array", items: kinds },
            cost: { type: "number", exclusiveMinimum: 0 },
          },
        },
      },
      frozen: {
        type: "object",
        required: ["at", "contentSha256"],
        properties: {
          at: { type: "string", format: "date-time" },
          contentSha256: sha256,
        },
      },
      relatedCases: {
        type: "array",
        items: {
          type: "object",
          required: ["payloadSha256", "targetSha256", "sameTarget"],
          properties: {
            payloadSha256: sha256,
            targetSha256: sha256,
            sameTarget: { type: "boolean" },
            note: nonEmpty,
          },
        },
      },
      history: {
        type: "array",
        description:
          "Append-only hash chain; each entrySha256 covers the entry and previousEntrySha256.",
        items: {
          type: "object",
          required: [
            "seq",
            "action",
            "at",
            "previousEntrySha256",
            "entrySha256",
          ],
          properties: {
            seq: { type: "integer", minimum: 1 },
            action: nonEmpty,
            at: { type: "string", format: "date-time" },
            previousEntrySha256: { anyOf: [sha256, { type: "null" }] },
            entrySha256: sha256,
          },
        },
      },
    },
  };
}

/** Return claims with explicit evidence references and conservative support labels. */
export function buildEvidenceReport(input) {
  const investigation = validateInvestigation(input);
  const evidenceById = new Map(
    investigation.evidence.map((item) => [item.id, item]),
  );
  const claims = investigation.claims.map((claim) => {
    const evidence = claim.evidenceIds.map((id) => evidenceById.get(id));
    const observed = evidence.some((item) => item.confidence === "observed");
    const inferredOnly = evidence.every(
      (item) => item.confidence === "inferred",
    );
    const label =
      claim.status === "verified"
        ? "verified"
        : observed
          ? "evidence-backed"
          : inferredOnly
            ? "inference-only"
            : "derived-support";
    return {
      id: claim.id,
      text: claim.text,
      status: claim.status ?? "hypothesis",
      supportLabel: label,
      ...(claim.tags ? { tags: claim.tags } : {}),
      evidence: evidence.map(({ id, kind, source, confidence, summary }) => ({
        id,
        kind,
        source,
        confidence,
        summary,
      })),
    };
  });
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: investigation.target,
    summary: {
      evidenceCount: investigation.evidence.length,
      claimCount: claims.length,
      questionCount: investigation.questions.length,
      unresolvedQuestionCount: investigation.questions.filter(
        (q) => !q.resolved,
      ).length,
    },
    claims,
  };
}

function markdownCell(value) {
  return String(value ?? "")
    .replaceAll("|", "\\|")
    .replaceAll(/\r?\n/g, " ")
    .trim();
}

function evidenceRow(item) {
  return `| ${markdownCell(item.id)} | ${markdownCell(item.kind)} | ${markdownCell(item.confidence)} | ${markdownCell(item.source)} | ${markdownCell(item.summary)} |`;
}

const EVIDENCE_TABLE_HEADER = [
  "| ID | Kind | Confidence | Source | Summary |",
  "| --- | --- | --- | --- | --- |",
];

/** Render a provenance-preserving Markdown report; no claim is upgraded beyond its evidence. */
export function renderEvidenceReportMarkdown(input) {
  const investigation = validateInvestigation(input);
  const report = buildEvidenceReport(investigation);
  const lines = [
    `# PTAH evidence report — ${markdownCell(report.target.id)}`,
    "",
    `- Target SHA-256: \`${report.target.sha256}\``,
    `- Schema version: ${report.schemaVersion}`,
    `- Evidence items: ${report.summary.evidenceCount}`,
    `- Claims: ${report.summary.claimCount}`,
    `- Open questions: ${report.summary.unresolvedQuestionCount} of ${report.summary.questionCount}`,
    ...(investigation.frozen
      ? [
          `- Frozen: ${investigation.frozen.at} (content \`${investigation.frozen.contentSha256}\`)`,
        ]
      : []),
    "",
    "## Claims",
    "",
  ];
  if (report.claims.length === 0) lines.push("_No claims recorded._", "");
  for (const claim of report.claims) {
    lines.push(
      `### ${markdownCell(claim.id)} — ${claim.supportLabel} (${claim.status})${
        claim.tags?.length
          ? ` · tags: ${claim.tags.map(markdownCell).join(", ")}`
          : ""
      }`,
      "",
      claim.text.trim(),
      "",
      ...EVIDENCE_TABLE_HEADER,
      ...claim.evidence.map(evidenceRow),
      "",
    );
  }
  lines.push("## Evidence", "");
  if (investigation.evidence.length === 0)
    lines.push("_No evidence recorded._", "");
  else
    lines.push(
      ...EVIDENCE_TABLE_HEADER,
      ...investigation.evidence.map(evidenceRow),
      "",
    );
  const openQuestions = investigation.questions
    .filter((q) => !q.resolved)
    .sort(
      (a, b) =>
        (b.priority ?? 50) - (a.priority ?? 50) || a.id.localeCompare(b.id),
    );
  lines.push("## Open questions", "");
  if (openQuestions.length === 0) lines.push("_None._", "");
  for (const question of openQuestions) {
    const needs = question.requiredEvidenceKinds?.length
      ? ` — needs ${question.requiredEvidenceKinds.join(", ")}`
      : "";
    lines.push(
      `- **${markdownCell(question.id)}** (priority ${question.priority ?? 50}): ${markdownCell(question.text)}${needs}`,
    );
  }
  if (openQuestions.length > 0) lines.push("");
  lines.push(
    "---",
    "",
    "Support labels are derived from cited evidence confidence. `verified` appears only when the investigation workflow recorded that status; PTAH does not infer verification. Inferred-only claims require independent confirmation before being relied upon.",
    "",
  );
  return lines.join("\n");
}

function indexById(items) {
  return new Map(items.map((item) => [item.id, item]));
}

function changedFields(before, after) {
  const serialize = (owner, key) =>
    Object.hasOwn(owner, key) ? canonicalJson(owner[key]) : undefined;
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => key !== "id")
    .sort()
    .filter((key) => serialize(before, key) !== serialize(after, key));
}

function diffCollection(baseItems, headItems) {
  const base = indexById(baseItems);
  const head = indexById(headItems);
  const added = [...head.keys()].filter((id) => !base.has(id)).sort();
  const removed = [...base.keys()].filter((id) => !head.has(id)).sort();
  const changed = [...head.keys()]
    .filter((id) => base.has(id))
    .sort()
    .map((id) => ({ id, fields: changedFields(base.get(id), head.get(id)) }))
    .filter((entry) => entry.fields.length > 0);
  return { added, removed, changed };
}

function unwrapInvestigation(input) {
  if (
    input &&
    typeof input === "object" &&
    input.format === INVESTIGATION_CASE_FORMAT
  ) {
    const checked = validateInvestigationCase(input);
    if (!checked.matches)
      throw new Error("case payload checksum mismatch; refusing to diff");
    return checked.investigation;
  }
  return validateInvestigation(input);
}

/** Deterministically compare two investigations or verified case bundles. */
export function diffInvestigations(baseInput, headInput) {
  const base = unwrapInvestigation(baseInput);
  const head = unwrapInvestigation(headInput);
  const sameTarget =
    base.target.sha256.toLowerCase() === head.target.sha256.toLowerCase();
  const headClaims = indexById(head.claims);
  const claimStatusChanges = base.claims
    .filter((claim) => headClaims.has(claim.id))
    .map((claim) => ({
      id: claim.id,
      from: claim.status ?? "hypothesis",
      to: headClaims.get(claim.id).status ?? "hypothesis",
    }))
    .filter((change) => change.from !== change.to)
    .sort((a, b) => a.id.localeCompare(b.id));
  const headQuestions = indexById(head.questions);
  const questionsResolved = base.questions
    .filter((q) => !q.resolved && headQuestions.get(q.id)?.resolved === true)
    .map((q) => q.id)
    .sort();
  const questionsReopened = base.questions
    .filter((q) => q.resolved && headQuestions.get(q.id)?.resolved === false)
    .map((q) => q.id)
    .sort();
  const sections = {
    evidence: diffCollection(base.evidence, head.evidence),
    claims: diffCollection(base.claims, head.claims),
    questions: diffCollection(base.questions, head.questions),
    actions: diffCollection(base.actions, head.actions),
  };
  const changeCount = Object.values(sections).reduce(
    (total, section) =>
      total +
      section.added.length +
      section.removed.length +
      section.changed.length,
    0,
  );
  const result = {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: { base: base.target, head: head.target, sameTarget },
    identical: sameTarget && changeCount === 0,
    changeCount,
    ...sections,
    claimStatusChanges,
    questionsResolved,
    questionsReopened,
  };
  if (!sameTarget)
    result.target.note =
      "Targets differ; evidence is not transferable between target digests.";
  return result;
}

/** Build a portable directed graph from target, evidence, claims, and questions. */
export function buildEvidenceGraph(input) {
  const investigation = validateInvestigation(input);
  const nodes = [
    {
      id: `target:${investigation.target.id}`,
      type: "target",
      label: investigation.target.id,
      sha256: investigation.target.sha256,
    },
  ];
  const edges = [];
  for (const item of investigation.evidence) {
    const id = `evidence:${item.id}`;
    nodes.push({
      id,
      type: "evidence",
      label: item.summary,
      kind: item.kind,
      confidence: item.confidence,
      source: item.source,
    });
    edges.push({
      from: `target:${investigation.target.id}`,
      to: id,
      type: "contains-evidence",
    });
  }
  for (const claim of investigation.claims) {
    const id = `claim:${claim.id}`;
    nodes.push({
      id,
      type: "claim",
      label: claim.text,
      status: claim.status ?? "hypothesis",
    });
    for (const evidenceId of claim.evidenceIds)
      edges.push({ from: `evidence:${evidenceId}`, to: id, type: "supports" });
  }
  for (const question of investigation.questions) {
    const id = `question:${question.id}`;
    const missing = (question.requiredEvidenceKinds ?? []).filter(
      (kind) => !investigation.evidence.some((item) => item.kind === kind),
    );
    nodes.push({
      id,
      type: "question",
      label: question.text,
      resolved: question.resolved === true,
      priority: question.priority ?? 50,
      missingEvidenceKinds: missing,
    });
    for (const evidence of investigation.evidence) {
      if ((question.requiredEvidenceKinds ?? []).includes(evidence.kind)) {
        edges.push({
          from: `evidence:${evidence.id}`,
          to: id,
          type: "informs",
        });
      }
    }
  }
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    targetSha256: investigation.target.sha256,
    nodes,
    edges,
  };
}

/**
 * Choose a deterministic next action to address the highest-priority missing
 * evidence. This is deliberately rule-based; model-based planning can be
 * layered on top later without making budgets or provenance implicit.
 */
export function planNextAction(input, budget = {}) {
  const investigation = validateInvestigation(input);
  const maxCalls = budget.maxCalls ?? 1;
  const maxCost = budget.maxCost ?? Number.POSITIVE_INFINITY;
  if (!Number.isInteger(maxCalls) || maxCalls < 0)
    throw new TypeError("budget.maxCalls must be a non-negative integer");
  if (!(maxCost > 0)) throw new TypeError("budget.maxCost must be positive");
  if (maxCalls === 0)
    return {
      status: "budget-exhausted",
      reason: "maxCalls is zero",
      selectedAction: null,
      candidates: [],
    };

  const existingKinds = new Set(
    investigation.evidence.map((item) => item.kind),
  );
  const unresolved = investigation.questions
    .filter((q) => !q.resolved)
    .map((q) => ({
      ...q,
      missingKinds: (q.requiredEvidenceKinds ?? []).filter(
        (kind) => !existingKinds.has(kind),
      ),
    }))
    .filter((q) => q.missingKinds.length > 0)
    .sort(
      (a, b) =>
        (b.priority ?? 50) - (a.priority ?? 50) || a.id.localeCompare(b.id),
    );

  if (unresolved.length === 0)
    return {
      status: "no-action-needed",
      reason: "No unresolved question has a missing required evidence kind.",
      selectedAction: null,
      candidates: [],
    };

  const topQuestion = unresolved[0];
  const candidates = investigation.actions
    .map((action) => {
      const produces = action.produces ?? [];
      const matches = produces.filter((kind) =>
        topQuestion.missingKinds.includes(kind),
      );
      const cost = action.cost ?? 1;
      return {
        action,
        matches,
        cost,
        score: (matches.length * (topQuestion.priority ?? 50)) / cost,
      };
    })
    .filter(
      (candidate) => candidate.matches.length > 0 && candidate.cost <= maxCost,
    )
    .sort(
      (a, b) =>
        b.score - a.score ||
        a.cost - b.cost ||
        a.action.id.localeCompare(b.action.id),
    );

  if (candidates.length === 0)
    return {
      status: "blocked",
      reason:
        "No available action can produce the missing evidence within the supplied cost budget.",
      questionId: topQuestion.id,
      missingEvidenceKinds: topQuestion.missingKinds,
      selectedAction: null,
      candidates: [],
    };
  const selected = candidates[0];
  return {
    status: "planned",
    questionId: topQuestion.id,
    question: topQuestion.text,
    missingEvidenceKinds: topQuestion.missingKinds,
    selectedAction: {
      id: selected.action.id,
      name: selected.action.name,
      produces: selected.matches,
      estimatedCost: selected.cost,
      score: selected.score,
    },
    candidates: candidates.map(({ action, matches, cost, score }) => ({
      id: action.id,
      name: action.name,
      matches,
      estimatedCost: cost,
      score,
    })),
  };
}

const PROVIDER_CATALOG = [
  {
    id: "node",
    label: "Node.js runtime",
    commands: ["node"],
    probeArgs: ["--version"],
    areas: ["javascript", "electron", "cli"],
  },
  {
    id: "java",
    label: "Java runtime",
    commands: ["java"],
    probeArgs: ["-version"],
    areas: ["android", "jadx", "ghidra"],
  },
  {
    id: "ghidra",
    label: "Ghidra headless analyzer",
    commands: ["analyzeHeadless"],
    probeArgs: ["-help"],
    areas: ["native-binary", "firmware"],
  },
  {
    id: "jadx",
    label: "JADX Android decompiler",
    commands: ["jadx"],
    probeArgs: ["--version"],
    areas: ["android", "dex"],
  },
  {
    id: "adb",
    label: "Android Debug Bridge",
    commands: ["adb"],
    probeArgs: ["version"],
    areas: ["android-runtime", "device-analysis"],
  },
  {
    id: "frida",
    label: "Frida instrumentation",
    commands: ["frida", "frida-ps"],
    probeArgs: ["--version"],
    areas: ["runtime-observation", "instrumentation"],
  },
  {
    id: "apktool",
    label: "Apktool",
    commands: ["apktool"],
    probeArgs: ["--version"],
    areas: ["android", "resources"],
  },
  {
    id: "dotnet",
    label: ".NET runtime",
    commands: ["dotnet"],
    probeArgs: ["--version"],
    areas: ["dotnet", "managed-binaries"],
  },
  {
    id: "python",
    label: "Python runtime",
    commands: ["python3", "python"],
    probeArgs: ["--version"],
    areas: ["python", "automation"],
  },
  {
    id: "objdump",
    label: "GNU objdump",
    commands: ["objdump"],
    probeArgs: ["--version"],
    areas: ["native-binary", "disassembly"],
  },
  {
    id: "llvm-objdump",
    label: "LLVM objdump",
    commands: ["llvm-objdump"],
    probeArgs: ["--version"],
    areas: ["native-binary", "disassembly"],
  },
  {
    id: "radare2",
    label: "radare2",
    commands: ["r2"],
    probeArgs: ["-v"],
    areas: ["native-binary", "disassembly"],
  },
  {
    id: "wasm-tools",
    label: "WebAssembly tools",
    commands: ["wasm-tools"],
    probeArgs: ["--version"],
    areas: ["wasm"],
  },
  {
    id: "readelf",
    label: "GNU readelf",
    commands: ["readelf"],
    probeArgs: ["--version"],
    areas: ["native-binary", "elf"],
  },
  {
    id: "nm",
    label: "GNU nm",
    commands: ["nm"],
    probeArgs: ["--version"],
    areas: ["native-binary", "symbols"],
  },
  {
    id: "file",
    label: "file (libmagic)",
    commands: ["file"],
    probeArgs: ["--version"],
    areas: ["identification"],
  },
  {
    id: "rabin2",
    label: "radare2 rabin2",
    commands: ["rabin2"],
    probeArgs: ["-v"],
    areas: ["native-binary", "metadata"],
  },
  {
    id: "rz-bin",
    label: "rizin rz-bin",
    commands: ["rz-bin"],
    probeArgs: ["-v"],
    areas: ["native-binary", "metadata"],
  },
  {
    id: "monodis",
    label: "Mono disassembler (monodis)",
    commands: ["monodis"],
    probeArgs: ["--version"],
    areas: ["dotnet", "managed-binaries"],
  },
  {
    id: "aapt2",
    label: "Android aapt2",
    commands: ["aapt2"],
    probeArgs: ["version"],
    areas: ["android", "resources"],
  },
  {
    id: "wasm-objdump",
    label: "WABT wasm-objdump",
    commands: ["wasm-objdump"],
    probeArgs: ["--version"],
    areas: ["wasm"],
  },
  {
    id: "bubblewrap",
    label: "bubblewrap sandbox",
    commands: ["bwrap"],
    probeArgs: ["--version"],
    areas: ["isolation"],
  },
  {
    id: "prlimit",
    label: "prlimit (util-linux)",
    commands: ["prlimit"],
    probeArgs: ["--version"],
    areas: ["resource-limits"],
  },
  {
    id: "docker",
    label: "Docker",
    commands: ["docker"],
    probeArgs: ["--version"],
    areas: ["isolated-analysis", "reproducible-environments"],
  },
];

/** Discover external tools from PATH without launching them. */
export async function discoverProviders(env = process.env) {
  const pathEntries = (env.PATH ?? "").split(delimiter).filter(Boolean);
  const windows = process.platform === "win32";
  const extensions = windows
    ? (env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  const providers = [];
  for (const provider of PROVIDER_CATALOG) {
    const foundCommands = [];
    for (const command of provider.commands) {
      let foundPath;
      for (const directory of pathEntries) {
        for (const extension of extensions) {
          const candidate = join(
            directory,
            windows && !extname(command) ? `${command}${extension}` : command,
          );
          try {
            await access(candidate, constants.X_OK);
            foundPath = candidate;
            break;
          } catch {
            /* try next PATH candidate */
          }
        }
        if (foundPath) break;
      }
      if (foundPath) foundCommands.push({ command, path: foundPath });
    }
    providers.push({
      ...provider,
      available: foundCommands.length > 0,
      foundCommands,
    });
  }
  return {
    schemaVersion: 1,
    detection: "PATH presence only; tools were not executed",
    providers,
    summary: {
      detected: providers.filter((provider) => provider.available).length,
      total: providers.length,
    },
  };
}

/**
 * Execute a fixed, non-targeting version/help probe with strict time/output bounds.
 * This does not execute the analyzed target. The caller must explicitly opt in.
 */
export async function probeExecutable(executable, args = [], options = {}) {
  requireString(executable, "executable");
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string"))
    throw new TypeError("args must be an array of strings");
  const timeoutMs = Math.min(
    10_000,
    Math.max(
      100,
      Number.isFinite(options.timeoutMs) ? options.timeoutMs : 3_000,
    ),
  );
  const maxOutputBytes = Math.min(
    65_536,
    Math.max(
      256,
      Number.isInteger(options.maxOutputBytes) ? options.maxOutputBytes : 8_192,
    ),
  );
  const startedAt = Date.now();
  const signal = options.signal;
  if (signal?.aborted)
    return {
      executable,
      args,
      durationMs: 0,
      status: "cancelled",
      exitCode: null,
      signal: null,
      error: "cancelled before start",
      stdout: "",
      stderr: "",
      outputTruncated: false,
    };
  return await new Promise((resolveProbe) => {
    let settled = false;
    let timedOut = false;
    let cancelled = false;
    let stdout = "";
    let stderr = "";
    let outputTruncated = false;
    const append = (current, chunk) => {
      const next = current + chunk.toString("utf8");
      if (Buffer.byteLength(next) > maxOutputBytes) {
        outputTruncated = true;
        return Buffer.from(next).subarray(0, maxOutputBytes).toString("utf8");
      }
      return next;
    };
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, CI: "1", NO_COLOR: "1", TERM: "dumb" },
    });
    const onAbort = () => {
      cancelled = true;
      child.kill("SIGKILL");
      setTimeout(
        () =>
          finish({
            status: "cancelled",
            exitCode: null,
            signal: "SIGKILL",
            error: "cancelled by caller",
          }),
        100,
      ).unref?.();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolveProbe({
        executable,
        args,
        durationMs: Date.now() - startedAt,
        ...result,
        stdout: stdout.slice(0, maxOutputBytes),
        stderr: stderr.slice(0, maxOutputBytes),
        outputTruncated,
      });
    };
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.once("error", (error) =>
      finish({
        status: "error",
        exitCode: null,
        signal: null,
        error: error.message,
      }),
    );
    child.once("close", (code, exitSignal) =>
      finish({
        status: cancelled
          ? "cancelled"
          : timedOut
            ? "timeout"
            : code === 0
              ? "ok"
              : "nonzero",
        exitCode: code,
        signal: exitSignal,
        ...(cancelled
          ? { error: "cancelled by caller" }
          : timedOut
            ? { error: `probe exceeded ${timeoutMs}ms timeout` }
            : {}),
      }),
    );
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
      setTimeout(
        () =>
          finish({
            status: "timeout",
            exitCode: null,
            signal: "SIGKILL",
            error: `probe exceeded ${timeoutMs}ms timeout`,
          }),
        100,
      ).unref?.();
    }, timeoutMs);
    timer.unref?.();
  });
}

/** Probe discovered tools using fixed, non-targeting version/help arguments. */
export async function probeProviders(env = process.env, options = {}) {
  const discovery = await discoverProviders(env);
  const catalog = new Map(
    PROVIDER_CATALOG.map((provider) => [provider.id, provider]),
  );
  const providers = [];
  for (const provider of discovery.providers) {
    const definition = catalog.get(provider.id);
    if (!provider.available) {
      providers.push({
        ...provider,
        probe: { status: "not-found", reason: "No executable found on PATH" },
      });
      continue;
    }
    const command = provider.foundCommands[0];
    const probeArgs = definition.probeArgs ?? ["--version"];
    const probe = await probeExecutable(command.path, probeArgs, options);
    providers.push({
      ...provider,
      probe: { ...probe, command: command.command, path: command.path },
    });
  }
  const statuses = providers.map((provider) => provider.probe.status);
  return {
    schemaVersion: 1,
    detection:
      "Explicit bounded version/help probes; analyzed target was not supplied or executed",
    safety: {
      shell: false,
      timeoutMs: Math.min(
        10_000,
        Math.max(
          100,
          Number.isFinite(options.timeoutMs) ? options.timeoutMs : 3_000,
        ),
      ),
      maxOutputBytes: Math.min(
        65_536,
        Math.max(
          256,
          Number.isInteger(options.maxOutputBytes)
            ? options.maxOutputBytes
            : 8_192,
        ),
      ),
    },
    providers,
    summary: {
      total: providers.length,
      detected: providers.filter((provider) => provider.available).length,
      probed: providers.filter(
        (provider) => !["not-found"].includes(provider.probe.status),
      ).length,
      successful: statuses.filter((status) => status === "ok").length,
      failed: statuses.filter((status) =>
        ["error", "nonzero", "timeout"].includes(status),
      ).length,
    },
  };
}

/**
 * Allow-listed static analyzers. Every entry runs with fixed argv, no shell,
 * a timeout, and an output cap; none of them executes the target.
 */
export const STATIC_ANALYZERS = Object.freeze({
  objdump: {
    providerId: "objdump",
    args: (path) => ["-f", "-h", "--", path],
    analysisKind: "static-file-metadata",
    description: "object file format and section headers",
  },
  "llvm-objdump": {
    providerId: "llvm-objdump",
    args: (path) => ["-f", "-h", "--", path],
    analysisKind: "static-file-metadata",
    description: "object file format and section headers",
  },
  readelf: {
    providerId: "readelf",
    args: (path) => ["-h", "-S", "-W", "--", path],
    analysisKind: "static-file-metadata",
    requiresFormat: /^ELF/u,
    description: "ELF header and section table",
  },
  nm: {
    providerId: "nm",
    args: (path) => ["-D", "--defined-only", "--", path],
    analysisKind: "symbol-table",
    requiresFormat: /^ELF/u,
    description: "dynamic symbol table",
  },
  file: {
    providerId: "file",
    args: (path) => ["--brief", "--", path],
    analysisKind: "file-type-identification",
    description: "libmagic type identification",
  },
  rabin2: {
    providerId: "rabin2",
    args: (path) => ["-I", "--", path],
    analysisKind: "static-file-metadata",
    description: "radare2 binary information",
  },
  "rz-bin": {
    providerId: "rz-bin",
    args: (path) => ["-I", "--", path],
    analysisKind: "static-file-metadata",
    description: "rizin binary information",
  },
  monodis: {
    providerId: "monodis",
    args: (path) => ["--assembly", path],
    analysisKind: "managed-assembly-metadata",
    requiresFormat: /^DOS MZ header/u,
    description: ".NET assembly manifest",
  },
  aapt2: {
    providerId: "aapt2",
    args: (path) => ["dump", "badging", path],
    analysisKind: "android-package-metadata",
    requiresFormat: /^ZIP container/u,
    description: "Android package badging (manifest summary)",
  },
  "wasm-objdump": {
    providerId: "wasm-objdump",
    args: (path) => ["-h", path],
    analysisKind: "wasm-section-headers",
    requiresFormat: /^WebAssembly$/u,
    description: "WebAssembly section headers",
  },
  "wasm-tools": {
    providerId: "wasm-tools",
    args: (path) => ["validate", path],
    analysisKind: "wasm-validation",
    requiresFormat: /^WebAssembly$/u,
    description: "WebAssembly validation",
  },
});

export const STATIC_ANALYZER_IDS = Object.freeze(Object.keys(STATIC_ANALYZERS));

/**
 * Detect optional OS-level isolation (bubblewrap) and resource-limit (prlimit)
 * helpers on PATH. Detection is PATH presence only; nothing is executed.
 */
export async function detectIsolationSupport(env = process.env) {
  const discovery = await discoverProviders(env);
  const find = (id) => discovery.providers.find((item) => item.id === id);
  const bwrap = find("bubblewrap");
  const prlimit = find("prlimit");
  return {
    bubblewrap: {
      available: Boolean(bwrap?.available),
      path: bwrap?.foundCommands[0]?.path ?? null,
    },
    prlimit: {
      available: Boolean(prlimit?.available),
      path: prlimit?.foundCommands[0]?.path ?? null,
    },
    platform: process.platform,
  };
}

function buildIsolatedCommand(command, args, targetPath, support, options) {
  const requested = options.isolation ?? "auto";
  if (!["auto", "required", "none"].includes(requested))
    throw new TypeError("isolation must be auto, required, or none");
  const limits = options.limits ?? {};
  for (const [key, max] of [
    ["cpuSeconds", 3600],
    ["memoryBytes", 64 * 1024 ** 3],
    ["fileSizeBytes", 64 * 1024 ** 3],
  ])
    if (
      limits[key] !== undefined &&
      (!Number.isInteger(limits[key]) || limits[key] < 1 || limits[key] > max)
    )
      throw new TypeError(
        `limits.${key} must be an integer between 1 and ${max}`,
      );
  const wantLimits = Object.keys(limits).length > 0;
  let executable = command.path;
  let argv = [...args];
  const report = {
    requested,
    applied: "none",
    sandbox: null,
    limitsRequested: limits,
    limitsApplied: false,
    reasons: [],
  };
  if (wantLimits) {
    if (support.prlimit.available) {
      const flags = [];
      if (limits.cpuSeconds !== undefined)
        flags.push(`--cpu=${limits.cpuSeconds}`);
      if (limits.memoryBytes !== undefined)
        flags.push(`--as=${limits.memoryBytes}`);
      if (limits.fileSizeBytes !== undefined)
        flags.push(`--fsize=${limits.fileSizeBytes}`);
      argv = [...flags, "--", executable, ...argv];
      executable = support.prlimit.path;
      report.limitsApplied = true;
    } else
      report.reasons.push(
        "prlimit not found on PATH; resource limits were not applied",
      );
  }
  if (requested !== "none") {
    if (support.bubblewrap.available && process.platform === "linux") {
      argv = [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        targetPath,
        targetPath,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--",
        executable,
        ...argv,
      ];
      executable = support.bubblewrap.path;
      report.applied = "bubblewrap";
      report.sandbox = {
        filesystem: "read-only root, private /tmp, no writable target",
        namespaces: "user, pid, net, uts, ipc, cgroup (unshare-all)",
        network: "none",
      };
    } else {
      report.reasons.push(
        process.platform === "linux"
          ? "bubblewrap (bwrap) not found on PATH; analyzer ran without OS-level isolation"
          : `OS-level isolation via bubblewrap is Linux-only (platform: ${process.platform})`,
      );
      if (requested === "required")
        throw new Error(
          `isolation required but unavailable: ${report.reasons.join("; ")}`,
        );
    }
  }
  return { executable, argv, report };
}

/**
 * Run a fixed-argument static analyzer on a target file. Only allow-listed
 * adapters are accepted; no shell is involved. Optional bubblewrap isolation
 * and prlimit resource limits are applied when available and reported honestly
 * when they are not. The target is re-hashed afterwards to flag byte changes.
 */
export async function analyzeTarget(targetPath, providerId, options = {}) {
  const adapter = STATIC_ANALYZERS[providerId];
  if (!adapter)
    throw new TypeError(
      `unsupported static analyzer: ${providerId}; allowed: ${STATIC_ANALYZER_IDS.join(", ")}`,
    );
  const before = await fingerprintTarget(targetPath);
  if (
    adapter.requiresFormat &&
    !adapter.requiresFormat.test(before.detectedFormat)
  )
    throw new TypeError(
      `${providerId} requires a confirmed ${adapter.requiresFormat.source.replaceAll(/[\\^$]/gu, "")} magic signature; detected: ${before.detectedFormat}`,
    );
  const env = options.env ?? process.env;
  const discovery = await discoverProviders(env);
  const provider = discovery.providers.find(
    (item) => item.id === adapter.providerId,
  );
  if (!provider?.available)
    throw new Error(`provider not found on PATH: ${providerId}`);
  const command = provider.foundCommands[0];
  const support = await detectIsolationSupport(env);
  const { executable, argv, report } = buildIsolatedCommand(
    command,
    adapter.args(before.path),
    before.path,
    support,
    options,
  );
  const execution = await probeExecutable(executable, argv, options);
  const after = await fingerprintTarget(before.path);
  const targetChanged = before.sha256 !== after.sha256;
  const limitations = [
    "A nonzero analyzer exit is reported as a failure and must not be treated as successful analysis.",
    `This adapter extracts ${adapter.description}; it is not full disassembly or semantic analysis.`,
  ];
  if (report.applied === "none")
    limitations.unshift(
      "The analyzer process is bounded by wall-clock timeout and captured-output limits, but OS-level CPU/memory/filesystem sandboxing was not applied in this run.",
    );
  else
    limitations.unshift(
      "bubblewrap isolation provides namespace and filesystem separation; it is not a substitute for analysing untrusted targets on a disposable machine.",
    );
  return {
    schemaVersion: 1,
    provider: { id: providerId, command: command.command, path: command.path },
    target: {
      path: before.path,
      id: before.id,
      sha256Before: before.sha256,
      sha256After: after.sha256,
      sizeBytes: before.sizeBytes,
      detectedFormat: before.detectedFormat,
    },
    execution: { ...execution, command: command.command, path: command.path },
    isolation: report,
    status: targetChanged ? "target-changed-during-analysis" : execution.status,
    outputSha256: sha256Text(`${execution.stdout}\n${execution.stderr}`),
    targetChanged,
    targetExecuted: false,
    analysisKind: adapter.analysisKind,
    limitations,
  };
}

/** Attach a successful static-analysis result to a matching investigation. */
export function attachAnalysisEvidence(input, analysis, evidenceId) {
  const investigation = validateInvestigation(input);
  requireString(evidenceId, "evidenceId");
  if (
    !analysis ||
    analysis.status !== "ok" ||
    analysis.targetChanged === true
  ) {
    throw new TypeError(
      "only successful analysis of an unchanged target can be recorded as evidence",
    );
  }
  if (
    analysis.target?.sha256After?.toLowerCase() !==
    investigation.target.sha256.toLowerCase()
  ) {
    throw new TypeError(
      "analysis target digest does not match this investigation; refusing cross-target evidence",
    );
  }
  if (investigation.evidence.some((item) => item.id === evidenceId))
    throw new TypeError(`evidence id already exists: ${evidenceId}`);
  investigation.evidence.push({
    id: evidenceId,
    kind:
      analysis.analysisKind === "symbol-table" ? "symbol" : "static-analysis",
    summary: `${analysis.provider.id} ${analysis.analysisKind ?? "static-analysis"} succeeded; output SHA-256 ${analysis.outputSha256}`,
    source: `provider:${analysis.provider.id}; target:${analysis.target.path}; output-sha256:${analysis.outputSha256}; isolation:${analysis.isolation?.applied ?? "unknown"}`,
    confidence: "observed",
    targetSha256: investigation.target.sha256,
    artifact: {
      sha256: analysis.outputSha256,
      sizeBytes: Buffer.byteLength(
        `${analysis.execution?.stdout ?? ""}\n${analysis.execution?.stderr ?? ""}`,
      ),
      name: `${analysis.provider.id}-output.txt`,
    },
  });
  return validateInvestigation(investigation);
}
