import { describe, expect, it } from "vitest";
import { EvidenceLedger } from "./EvidenceLedger.js";
import { exportPtahEvidenceBundle } from "./PtahEvidenceAdapter.js";

const digest = "a".repeat(64);
const investigation = {
  schemaVersion: 1 as const,
  target: { id: "/tmp/fixture.bin", sha256: digest },
  evidence: [
    {
      id: "ptah-ev-1",
      kind: "static-analysis",
      summary: "A handler reference was found",
      source: "module.js:10",
      confidence: "observed" as const,
      targetSha256: digest,
    },
  ],
  claims: [{ id: "claim-1", text: "A handler is registered", evidenceIds: ["ptah-ev-1"] }],
};

describe("PTAH to REA evidence adapter", () => {
  it("exports authenticated REA evidence and preserves the ID crosswalk", () => {
    const exported = exportPtahEvidenceBundle(investigation);
    expect(exported.bundle.records).toHaveLength(1);
    expect(exported.bundle.records[0]?.authority).toBe("analyst-inference");
    expect(exported.bundle.records[0]?.subject?.digest.sha256).toBe(digest);
    expect(exported.bundle.records[0]?.limitations).toContain(
      "Imported from a PTAH evidence summary; original raw tool output was not included in the PTAH record.",
    );
    expect(exported.evidenceIdMap["ptah-ev-1"]).toBe(exported.bundle.records[0]?.evidence_id);
    expect(exported.claims[0]?.evidenceIds).toEqual([exported.bundle.records[0]?.evidence_id]);

    const ledger = new EvidenceLedger();
    expect(ledger.import(exported.bundle).ok).toBe(true);
    expect(ledger.export().records).toHaveLength(1);
  });

  it("rejects stale evidence and dangling claim references", () => {
    expect(() => exportPtahEvidenceBundle({
      ...investigation,
      evidence: [{ ...investigation.evidence[0], targetSha256: "b".repeat(64) }],
    })).toThrow(/different target digest/);
    expect(() => exportPtahEvidenceBundle({
      ...investigation,
      claims: [{ id: "bad-claim", text: "Dangling", evidenceIds: ["missing"] }],
    })).toThrow(/unknown PTAH evidence ID/);
  });

  it("rejects duplicate PTAH evidence IDs rather than silently merging them", () => {
    expect(() => exportPtahEvidenceBundle({
      ...investigation,
      evidence: [...investigation.evidence, investigation.evidence[0]],
    })).toThrow(/Duplicate PTAH evidence ID/);
  });
});
