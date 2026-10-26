/**
 * MCP tool definitions and handlers for structure, byte, intelligence,
 * triage, and investigation-view tools. Paths are checked by the server's
 * path policy before these handlers run.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { saveInvestigation } from "./ptah-engine.mjs";
import { analyzeStructure } from "./ptah-binary.mjs";
import {
  compareTargets,
  hashTarget,
  hexdumpTarget,
  searchTarget,
} from "./ptah-bytes.mjs";
import {
  extractIndicators,
  findSecrets,
  inferCapabilities,
  matchRules,
} from "./ptah-intel.mjs";
import {
  queryEvidence,
  renderTimeline,
  summarizeInvestigation,
  triageTarget,
} from "./ptah-triage.mjs";
import { renderHtmlReport, renderSarif } from "./ptah-reports.mjs";

const target = { type: "string", description: "Path to the target file" };
const input = {
  type: "string",
  description: "Path to a PTAH investigation JSON file",
};
const schema = (properties, required) => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});

export const INTEL_TOOLS = [
  {
    name: "ptah_triage",
    description:
      "Run every applicable native analysis on a target and write a new investigation with observed evidence, inferred capability hypotheses, prioritized questions, and next actions. Start here for an unknown file.",
    inputSchema: schema(
      {
        target,
        output: {
          type: "string",
          description: "Path for the new investigation JSON",
        },
        id: { type: "string" },
      },
      ["target", "output"],
    ),
  },
  {
    name: "ptah_structure",
    description:
      "Parse ELF/PE natively: sections with entropy, imports, exports, linked libraries, imphash, and packer hints.",
    inputSchema: schema({ target }, ["target"]),
  },
  {
    name: "ptah_hashes",
    description: "MD5, SHA-1, SHA-256, and SHA-512 of a target.",
    inputSchema: schema({ target }, ["target"]),
  },
  {
    name: "ptah_search",
    description:
      "Find a hex byte pattern (?? wildcards, e.g. '4D 5A ?? 00') or text (ASCII and UTF-16LE) with offsets.",
    inputSchema: schema(
      {
        target,
        hex: { type: "string" },
        text: { type: "string" },
        maxResults: { type: "integer", minimum: 1, maximum: 10000 },
      },
      ["target"],
    ),
  },
  {
    name: "ptah_hexdump",
    description: "Hexdump of up to 4096 bytes at an offset.",
    inputSchema: schema(
      {
        target,
        offset: { type: "integer", minimum: 0 },
        length: { type: "integer", minimum: 1, maximum: 4096 },
      },
      ["target"],
    ),
  },
  {
    name: "ptah_compare",
    description:
      "Compare two targets: identity, string and import similarity, and per-section size/entropy.",
    inputSchema: schema(
      { target, other: { type: "string", description: "Second target file" } },
      ["target", "other"],
    ),
  },
  {
    name: "ptah_iocs",
    description:
      "Extract URLs, domains, IPs, emails, file paths, and registry keys with offsets.",
    inputSchema: schema(
      { target, maxResults: { type: "integer", minimum: 1, maximum: 5000 } },
      ["target"],
    ),
  },
  {
    name: "ptah_secrets",
    description:
      "Detect embedded credentials and private keys. Values are redacted; each finding has a SHA-256 for correlation.",
    inputSchema: schema({ target }, ["target"]),
  },
  {
    name: "ptah_capabilities",
    description:
      "Infer behaviors (network, injection, persistence, anti-debugging, crypto, ...) from imports and strings, with ATT&CK ids. Results are inferences: record them as confidence inferred.",
    inputSchema: schema({ target }, ["target"]),
  },
  {
    name: "ptah_rules",
    description:
      "Match declarative rules: [{ id, strings: { name: { text | hex } }, condition: any|all|N }]. Regex rules are only accepted from the CLI.",
    inputSchema: schema(
      {
        target,
        rules: {
          type: "array",
          items: { type: "object" },
          minItems: 1,
          maxItems: 500,
        },
      },
      ["target", "rules"],
    ),
  },
  {
    name: "ptah_summary",
    description:
      "Compact, token-efficient view of an investigation: claims by status, open questions by priority, evidence lines.",
    inputSchema: schema(
      { input, maxItems: { type: "integer", minimum: 1, maximum: 200 } },
      ["input"],
    ),
  },
  {
    name: "ptah_query",
    description:
      "Filter evidence by text, kind, confidence, or tag, with the claims citing each item.",
    inputSchema: schema(
      {
        input,
        text: { type: "string" },
        kind: { type: "string" },
        confidence: {
          type: "string",
          enum: ["observed", "derived", "inferred"],
        },
        tag: { type: "string" },
      },
      ["input"],
    ),
  },
  {
    name: "ptah_timeline",
    description:
      "Markdown timeline of the investigation's hash-chained history.",
    inputSchema: schema({ input }, ["input"]),
  },
];

/** Tools that write files; every other PTAH tool only reads. */
export const WRITING_TOOLS = new Set([
  "ptah_init",
  "ptah_add_evidence",
  "ptah_add_claim",
  "ptah_add_question",
  "ptah_set_claim_status",
  "ptah_resolve_question",
  "ptah_case_export",
  "ptah_case_import",
  "ptah_triage",
]);

/** MCP tool annotations so clients can auto-approve read-only tools. */
export function annotate(tool) {
  const writes = WRITING_TOOLS.has(tool.name);
  return {
    ...tool,
    annotations: {
      title: tool.name.replace(/^ptah_/u, "PTAH ").replaceAll("_", " "),
      readOnlyHint: !writes,
      destructiveHint: false,
      idempotentHint: !writes,
      openWorldHint: false,
    },
  };
}

const loadJson = async (path) =>
  JSON.parse(await readFile(resolve(path), "utf8"));

/** Handle one of INTEL_TOOLS; returns undefined for other names. */
export async function callIntelTool(name, args) {
  switch (name) {
    case "ptah_triage": {
      const { investigation, digest } = await triageTarget(args.target, {
        id: args.id,
      });
      return {
        status: "triaged",
        path: await saveInvestigation(args.output, investigation),
        ...digest,
      };
    }
    case "ptah_structure":
      return analyzeStructure(args.target);
    case "ptah_hashes":
      return hashTarget(args.target);
    case "ptah_search":
      return searchTarget(
        args.target,
        { hex: args.hex, text: args.text },
        { maxResults: args.maxResults },
      );
    case "ptah_hexdump":
      return (
        await hexdumpTarget(args.target, {
          offset: args.offset,
          length: args.length,
        })
      ).dump;
    case "ptah_compare":
      return compareTargets(args.target, args.other);
    case "ptah_iocs":
      return extractIndicators(args.target, { maxResults: args.maxResults });
    case "ptah_secrets":
      return findSecrets(args.target);
    case "ptah_capabilities":
      return inferCapabilities(args.target);
    case "ptah_rules":
      return matchRules(args.target, args.rules, { allowRegex: false });
    case "ptah_summary":
      return summarizeInvestigation(await loadJson(args.input), {
        maxItems: args.maxItems,
      });
    case "ptah_query":
      return queryEvidence(await loadJson(args.input), args);
    case "ptah_timeline":
      return renderTimeline(await loadJson(args.input));
    default:
      return undefined;
  }
}

/** Extra report formats for ptah_report. */
export async function renderExtraReport(format, path, version) {
  const investigation = await loadJson(path);
  return format === "sarif"
    ? renderSarif(investigation, { version })
    : renderHtmlReport(investigation);
}
