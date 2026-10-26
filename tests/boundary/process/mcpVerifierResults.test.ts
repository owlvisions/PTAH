import { expect, it } from "vitest";

interface VerifierResults {
  readonly expandMcpSessionStatus: (status: unknown) => {
    readonly analysis_provider_candidates: unknown;
  };
  readonly expandProviderOutput: (providers: unknown) => {
    readonly analysis_provider_candidates: unknown;
  };
}

// The verifier helper imports the compiled contracts, so this runs after build.
const verifierResults = (): Promise<VerifierResults> =>
  import(
    new URL("../../../scripts/lib/mcp-verifier-results.mjs", import.meta.url)
      .href
  ) as Promise<VerifierResults>;

const provider = { id: "alpha", name: "alpha provider", version: null };
const summaryCandidate = {
  provider,
  availability: { status: "available", code: null, reason: null },
  target_support: { status: "unknown", code: null, reason: "No target." },
  selected: false,
};
const emptyTools = {
  client_requirements: {
    required: [],
    optional: [],
    missing_required: [],
    missing_optional: [],
  },
  groups: [],
};

it("keeps summary candidates only for MCP summary status", async () => {
  const { expandMcpSessionStatus } = await verifierResults();
  expect(
    expandMcpSessionStatus({
      detail: "summary",
      capabilities: [],
      analysis_provider_candidates: [summaryCandidate],
      tool_availability: emptyTools,
    }).analysis_provider_candidates,
  ).toEqual([summaryCandidate]);
  expect(() =>
    expandMcpSessionStatus({
      detail: "complete",
      capabilities: [],
      analysis_provider_candidates: [summaryCandidate],
      tool_availability: emptyTools,
    }),
  ).toThrow();
});

it("requires candidate capabilities in CLI provider output", async () => {
  const { expandProviderOutput } = await verifierResults();
  expect(() =>
    expandProviderOutput({
      capabilities: [],
      analysis_provider_candidates: [summaryCandidate],
    }),
  ).toThrow();
  expect(
    expandProviderOutput({
      capabilities: [],
      analysis_provider_candidates: [{ ...summaryCandidate, capabilities: [] }],
    }).analysis_provider_candidates,
  ).toEqual([{ ...summaryCandidate, capabilities: [] }]);
});
