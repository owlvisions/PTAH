/**
 * The PTAH evidence model. Every analysis result is an Evidence object bound
 * to the target's SHA-256, labelled with how it was obtained (confidence) and
 * which provider produced it. Ids are content-derived, so identical analyses
 * produce identical evidence.
 */
import { canonicalJson, sha256 } from "./canonical.mjs";

export const CONFIDENCE = Object.freeze(["observed", "derived", "inferred"]);
export const STATUS = Object.freeze(["ok", "partial", "unavailable", "failed"]);
export const TASKS = Object.freeze([
  "disassemble",
  "decompile",
  "strings",
  "symbols",
  "importsExports",
  "resources",
  "manifest",
  "sections",
]);

const DIGEST = /^[a-f0-9]{64}$/u;

/** Thrown when a value does not satisfy the evidence model. */
export class EvidenceError extends TypeError {}

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "")
    throw new EvidenceError(`${name} must be a non-empty string`);
}

/**
 * Create a frozen Evidence object.
 * @param {object} input
 * @param {string} input.task one of TASKS
 * @param {string} input.targetSha256 digest of the analyzed bytes
 * @param {{id: string, tool?: string, version?: string|null, argv?: string[]}} input.provider
 * @param {"observed"|"derived"|"inferred"} input.confidence
 * @param {"ok"|"partial"|"unavailable"|"failed"} [input.status]
 * @param {string} input.summary one line a reviewer can check
 * @param {object} [input.data] structured, tool-independent result
 * @param {string} [input.rawSha256] digest of the raw tool output the data came from
 * @param {string[]} [input.limitations]
 */
export function createEvidence(input) {
  if (!TASKS.includes(input.task))
    throw new EvidenceError(`unknown task: ${input.task}`);
  if (!DIGEST.test(input.targetSha256 ?? ""))
    throw new EvidenceError("targetSha256 must be a SHA-256 hex digest");
  if (!CONFIDENCE.includes(input.confidence))
    throw new EvidenceError(
      `confidence must be one of ${CONFIDENCE.join(", ")}`,
    );
  const status = input.status ?? "ok";
  if (!STATUS.includes(status))
    throw new EvidenceError(`status must be one of ${STATUS.join(", ")}`);
  requireText(input.provider?.id, "provider.id");
  requireText(input.summary, "summary");
  if (input.rawSha256 != null && !DIGEST.test(input.rawSha256))
    throw new EvidenceError("rawSha256 must be a SHA-256 hex digest");
  const provider = {
    id: input.provider.id,
    tool: input.provider.tool ?? input.provider.id,
    version: input.provider.version ?? null,
    argv: input.provider.argv ? [...input.provider.argv] : [],
  };
  const body = {
    task: input.task,
    targetSha256: input.targetSha256.toLowerCase(),
    provider,
    confidence: input.confidence,
    status,
    summary: input.summary,
    data: input.data ?? {},
    rawSha256: input.rawSha256 ?? null,
    limitations: [...(input.limitations ?? [])],
  };
  // The id covers what was found and how, not when: reruns are byte-identical.
  return Object.freeze({
    id: `ev_${sha256(canonicalJson(body)).slice(0, 32)}`,
    ...body,
  });
}

/** Evidence that a task could not be performed; never mistaken for a finding. */
export function unavailableEvidence({
  task,
  targetSha256,
  reason,
  attempts = [],
}) {
  return createEvidence({
    task,
    targetSha256,
    provider: { id: "ptah-registry" },
    confidence: "inferred",
    status: "unavailable",
    summary: `No provider could perform ${task}: ${reason}`,
    data: { attempts },
    limitations: [
      "Absence of a result is not evidence of absence in the target.",
    ],
  });
}

/** Validate an evidence object (for evidence read back from storage). */
export function validateEvidence(evidence) {
  const { id, ...body } = evidence ?? {};
  const rebuilt = createEvidence(body);
  if (rebuilt.id !== id)
    throw new EvidenceError(`evidence ${id} does not match its content`);
  return rebuilt;
}
