import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { createEvidenceBundle, type EvidenceBundle } from "../../domain/evidenceBundle.js";

/** Minimal structural contract accepted from the dependency-free PTAH engine. */
export interface PtahInvestigationEvidence {
  readonly id: string;
  readonly kind: string;
  readonly summary: string;
  readonly source: string;
  readonly confidence: "observed" | "derived" | "inferred";
  readonly targetSha256: string;
}

export interface PtahInvestigationDocument {
  readonly schemaVersion: 1;
  readonly target: { readonly id: string; readonly sha256: string };
  readonly evidence: readonly PtahInvestigationEvidence[];
  readonly claims?: readonly {
    readonly id: string;
    readonly text: string;
    readonly evidenceIds: readonly string[];
  }[];
}

export interface PtahEvidenceBundleExport {
  /** Existing REA canonical bundle; safe to import into EvidenceLedger. */
  readonly bundle: EvidenceBundle;
  /** PTAH IDs are not REA semantic IDs; this explicit map joins the models. */
  readonly evidenceIdMap: Readonly<Record<string, string>>;
  /** Claims are kept as a separate PTAH layer, not misrepresented as Evidence. */
  readonly claims: readonly {
    readonly id: string;
    readonly text: string;
    readonly evidenceIds: readonly string[];
  }[];
  readonly limitations: readonly string[];
}

const isSha256 = (value: string): boolean => /^[a-f0-9]{64}$/i.test(value);

/**
 * Convert PTAH's portable evidence summaries to authenticated REA Evidence.
 * This intentionally records summaries as analyst assertions: PTAH's current
 * portable schema does not contain the original raw tool output or a verified
 * provider execution record, so this adapter must not imply that it does.
 */
export function exportPtahEvidenceBundle(
  investigation: PtahInvestigationDocument,
): PtahEvidenceBundleExport {
  if (investigation.schemaVersion !== 1)
    throw new TypeError("Unsupported PTAH investigation schema version");
  if (!isSha256(investigation.target.sha256))
    throw new TypeError("PTAH target digest must be a SHA-256 hex digest");

  const seen = new Set<string>();
  const records: Evidence[] = [];
  const evidenceIdMap: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const item of investigation.evidence) {
    if (seen.has(item.id)) throw new TypeError(`Duplicate PTAH evidence ID: ${item.id}`);
    seen.add(item.id);
    if (item.targetSha256.toLowerCase() !== investigation.target.sha256.toLowerCase())
      throw new TypeError(`Evidence ${item.id} belongs to a different target digest`);
    if (!item.summary.trim() || !item.source.trim() || !item.kind.trim())
      throw new TypeError(`Evidence ${item.id} must include kind, summary, and source`);

    const record = createEvidence(
      {
        path: investigation.target.id,
        sha256: investigation.target.sha256.toLowerCase(),
        format: "file",
      },
      { id: "ptah.import", name: "PTAH investigation import", version: "1" },
      {
        predicateType: "ptah.imported-evidence-summary",
        operation: "import-ptah-evidence-summary",
        parameters: { ptahEvidenceId: item.id, kind: item.kind, source: item.source },
        result: { summary: item.summary },
        confidence: item.confidence,
        authority: "analyst-inference",
        limitations: [
          "Imported from a PTAH evidence summary; original raw tool output was not included in the PTAH record.",
          "Provider execution and source reference were not independently verified by this adapter.",
        ],
      },
    );
    records.push(record);
    evidenceIdMap[item.id] = record.evidence_id;
  }

  const claims = (investigation.claims ?? []).map((claim) => {
    const mappedIds = claim.evidenceIds.map((id) => {
      const mapped = evidenceIdMap[id];
      if (mapped === undefined) throw new TypeError(`Claim ${claim.id} references unknown PTAH evidence ID: ${id}`);
      return mapped;
    });
    return { id: claim.id, text: claim.text, evidenceIds: mappedIds };
  });

  return {
    bundle: createEvidenceBundle(records),
    evidenceIdMap,
    claims,
    limitations: [
      "PTAH claims remain separate from the REA EvidenceBundle because they are not raw evidence records.",
      "Imported summaries are labeled analyst-inference and do not assert that an external tool was executed.",
    ],
  };
}
