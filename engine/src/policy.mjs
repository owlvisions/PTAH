/**
 * Analysis policy, enforced before any provider runs.
 *
 * Every session records the user's relationship to the target and a purpose
 * chosen from an allow-list. Anything outside the allow-list is refused, as is
 * any target matched by a configured target check (for example signature rules
 * an organization supplies). The free-text statement is recorded for audit only.
 */
import { canonicalJson, sha256 } from "./canonical.mjs";

export const OWNERSHIP = Object.freeze([
  "owner",
  "licensed",
  "authorized",
  "open-source",
]);
export const PURPOSES = Object.freeze([
  "interoperability",
  "security-research",
  "personal-study",
  "original-reimplementation",
  "own-software-maintenance",
]);

/** Raised when policy refuses a session; `code` names the rule. */
export class PolicyRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PolicyRefusal";
    this.code = code;
  }
}

/**
 * Validate an attestation and return the frozen record stored with the session.
 * @param {{ownership: string, purpose: string, statement?: string, actor?: string}} attestation
 */
export function recordAttestation(attestation, now = new Date()) {
  if (!attestation || typeof attestation !== "object")
    throw new PolicyRefusal(
      "attestation-missing",
      "Record ownership and purpose before analysis.",
    );
  if (!OWNERSHIP.includes(attestation.ownership))
    throw new PolicyRefusal(
      "ownership-not-established",
      `ownership must be one of ${OWNERSHIP.join(", ")}; PTAH analyzes only software you own, license, are authorized to examine, or that is open source.`,
    );
  if (!PURPOSES.includes(attestation.purpose))
    throw new PolicyRefusal(
      "purpose-not-permitted",
      `purpose must be one of ${PURPOSES.join(", ")}.`,
    );
  const record = {
    ownership: attestation.ownership,
    purpose: attestation.purpose,
    statement: String(attestation.statement ?? "").slice(0, 2000),
    actor: String(attestation.actor ?? "unspecified").slice(0, 200),
    recordedAt: now.toISOString(),
  };
  return Object.freeze({ ...record, digest: sha256(canonicalJson(record)) });
}

/**
 * Apply target checks. Each check receives the identified target and returns
 * undefined to allow or `{ code, reason }` to refuse.
 */
export async function evaluateTarget(target, checks = []) {
  for (const check of checks) {
    const verdict = await check(target);
    if (verdict)
      throw new PolicyRefusal(
        verdict.code ?? "target-refused",
        verdict.reason ?? "target refused by policy",
      );
  }
}
