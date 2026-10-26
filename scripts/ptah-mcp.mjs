#!/usr/bin/env node
/** Dependency-free Model Context Protocol stdio server for PTAH's safe native tools. */
import { createInterface } from "node:readline";
import { readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import {
  fingerprintTarget,
  createInvestigationForTarget,
  recordHistory,
  addEvidence,
  addInvestigationRecord,
  setClaimStatus,
  resolveQuestion,
  EVIDENCE_KIND_VALUES,
  verifyInvestigation,
  buildEvidenceReport,
  buildEvidenceGraph,
  planNextAction,
  discoverProviders,
  analyzeTarget,
  createInvestigationCase,
  importInvestigationCase,
  verifyInvestigationCase,
  saveInvestigationCase,
  saveInvestigation,
  renderEvidenceReportMarkdown,
  diffInvestigations,
  inspectTarget,
  lintInvestigation,
  investigationStats,
  planSteps,
  renderEvidenceGraph,
  investigationJsonSchema,
  STATIC_ANALYZER_IDS,
  detectIsolationSupport,
} from "./ptah-engine.mjs";
import { runEvaluationSuite, compareEvaluationReports } from "./ptah-eval.mjs";
import {
  extractStrings,
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "./ptah-analysis.mjs";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_VERSION = "0.9.0";
const cliArgs = process.argv.slice(2);
const rootIndex = cliArgs.indexOf("--root");
const RESOURCE_ROOT =
  rootIndex >= 0 && cliArgs[rootIndex + 1]
    ? resolve(cliArgs[rootIndex + 1])
    : null;
const MAX_RESOURCE_BYTES = 8 * 1024 * 1024;

const SERVER_INSTRUCTIONS = [
  "PTAH is an evidence-first program-analysis server. It never executes the target.",
  "Workflow: ptah_fingerprint or ptah_inspect the file, then ptah_init an investigation bound to its SHA-256.",
  "Record every finding with ptah_add_evidence before claiming anything; ptah_add_claim must cite evidence ids.",
  "Confidence: observed = direct tool output, derived = computed from observed data, inferred = interpretation. Only claims citing observed evidence can be verified.",
  "Use ptah_add_question for unknowns, ptah_plan to choose the next bounded step, ptah_lint and ptah_verify before reporting, and ptah_report for the final answer.",
  "Never state a conclusion that is not backed by recorded evidence; say what is unknown instead.",
].join(" ");

const prompts = [
  {
    name: "investigate-target",
    description:
      "Start an evidence-first investigation of a local file: fingerprint, inspect, record observations, and plan the next bounded step.",
    arguments: [
      {
        name: "target",
        description: "Absolute path to the file",
        required: true,
      },
      {
        name: "output",
        description: "Investigation JSON output path",
        required: true,
      },
    ],
  },
  {
    name: "review-claims",
    description:
      "Audit an investigation: run lint and stats, list inference-only claims, and propose evidence that would upgrade or reject each one.",
    arguments: [
      { name: "input", description: "Investigation JSON path", required: true },
    ],
  },
  {
    name: "compare-cases",
    description:
      "Explain what changed between two investigations or case bundles and whether the target drifted.",
    arguments: [
      {
        name: "base",
        description: "Older investigation/case path",
        required: true,
      },
      {
        name: "head",
        description: "Newer investigation/case path",
        required: true,
      },
    ],
  },
];

function renderPrompt(name, promptArgs = {}) {
  const need = (key) => {
    if (typeof promptArgs[key] !== "string" || !promptArgs[key].trim())
      throw new TypeError(`prompt argument ${key} is required`);
    return promptArgs[key];
  };
  const rules =
    "Rules: never execute the target; cite evidence IDs for every statement; use observed/derived/inferred confidence; do not call anything verified unless a verification step was performed; say 'unknown' when evidence is missing.";
  switch (name) {
    case "investigate-target": {
      const target = need("target");
      const output = need("output");
      return [
        {
          role: "user",
          content: {
            type: "text",
            text: `Investigate ${target} with PTAH tools only. Steps: 1) ptah_inspect and ptah_fingerprint on the target; 2) create the investigation at ${output} via the ptah CLI (init) or import; 3) record each observation with ptah add-evidence semantics (kind, source, confidence); 4) run ptah_strings and ptah_carve for leads; 5) run ptah_lint and ptah_plan and report the next bounded step. ${rules}`,
          },
        },
      ];
    }
    case "review-claims": {
      const input = need("input");
      return [
        {
          role: "user",
          content: {
            type: "text",
            text: `Review the investigation at ${input}. Run ptah_lint and ptah_stats, then ptah_report with format markdown. For every inference-only claim, list which evidence kind would upgrade it to evidence-backed and which observation would reject it. Do not change the file. ${rules}`,
          },
        },
      ];
    }
    case "compare-cases": {
      const base = need("base");
      const head = need("head");
      return [
        {
          role: "user",
          content: {
            type: "text",
            text: `Run ptah_diff with base=${base} and head=${head}. Summarise target drift, added/removed/changed evidence, claim status transitions, and resolved questions. Flag any claim whose status rose without new observed evidence. ${rules}`,
          },
        },
      ];
    }
    default:
      throw new Error(`unknown prompt: ${name}`);
  }
}

async function listResources() {
  if (!RESOURCE_ROOT) return [];
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(RESOURCE_ROOT, {
    withFileTypes: true,
    recursive: true,
  });
  return entries
    .filter((entry) => entry.isFile() && /\.json(\.gz)?$/u.test(entry.name))
    .map((entry) => {
      const absolute = join(entry.parentPath ?? entry.path, entry.name);
      const relative = absolute
        .slice(RESOURCE_ROOT.length + 1)
        .split(sep)
        .join("/");
      return {
        uri: `ptah://investigations/${relative}`,
        name: relative,
        mimeType: entry.name.endsWith(".gz")
          ? "application/gzip"
          : "application/json",
        description:
          "PTAH investigation or case bundle under the configured --root",
      };
    })
    .sort((a, b) => a.uri.localeCompare(b.uri));
}

async function readResource(uri) {
  if (!RESOURCE_ROOT)
    throw new Error("resources are disabled; start ptah-mcp with --root DIR");
  const prefix = "ptah://investigations/";
  if (typeof uri !== "string" || !uri.startsWith(prefix))
    throw new Error(`unknown resource: ${uri}`);
  const relative = decodeURIComponent(uri.slice(prefix.length));
  const absolute = resolve(RESOURCE_ROOT, relative);
  const within =
    relative.length > 0 &&
    !relative.startsWith("/") &&
    absolute.startsWith(`${RESOURCE_ROOT}${sep}`);
  if (!within || relative.split("/").includes(".."))
    throw new Error("resource path escapes the configured root");
  const { stat } = await import("node:fs/promises");
  const info = await stat(absolute);
  if (!info.isFile()) throw new Error("resource is not a file");
  if (info.size > MAX_RESOURCE_BYTES)
    throw new Error(`resource exceeds ${MAX_RESOURCE_BYTES} bytes`);
  const bytes = await readFile(absolute);
  return absolute.endsWith(".gz")
    ? { uri, mimeType: "application/gzip", blob: bytes.toString("base64") }
    : { uri, mimeType: "application/json", text: bytes.toString("utf8") };
}
const tools = [
  {
    name: "ptah_fingerprint",
    description:
      "Compute SHA-256 and identify a file signature without executing the target.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Path to a regular file to fingerprint",
        },
      },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_verify",
    description:
      "Validate an investigation and optionally compare the current target bytes with its recorded SHA-256.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "Path to a PTAH investigation JSON file",
        },
        target: {
          type: "string",
          description: "Optional target file path to re-hash",
        },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_case_export",
    description:
      "Write a portable investigation case bundle with a SHA-256 corruption checksum. The checksum does not authenticate the author.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Investigation JSON file path" },
        output: { type: "string", description: "Case bundle output path" },
      },
      required: ["input", "output"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_case_verify",
    description:
      "Verify case schema and checksum, optionally comparing the current target bytes.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Case bundle JSON file path" },
        target: {
          type: "string",
          description: "Optional target file to re-hash",
        },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_case_import",
    description:
      "Verify a portable case bundle and atomically restore its investigation JSON.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Case bundle JSON file path" },
        output: {
          type: "string",
          description: "Restored investigation output path",
        },
        target: {
          type: "string",
          description: "Optional target file to verify before import",
        },
      },
      required: ["input", "output"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_inspect",
    description:
      "Fingerprint a file and add executable-format details (ELF/PE/Mach-O class, machine, type) and entropy without executing it.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Path to a regular file" },
      },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_strings",
    description:
      "Extract printable ASCII and UTF-16LE strings with byte offsets under bounded length, result, and byte limits. Never executes the target.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Path to a regular file" },
        minLength: { type: "integer", minimum: 2 },
        maxResults: { type: "integer", minimum: 1 },
        maxBytes: { type: "integer", minimum: 1 },
      },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_lint",
    description:
      "Advisory, deterministic quality findings for an investigation: orphan evidence, status exceeding evidence, unreachable questions, duplicates.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Investigation JSON file path" },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_stats",
    description:
      "Deterministic evidence/claim/question metrics, including evidence-backed and inference-only claim ratios.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Investigation JSON file path" },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_schema",
    description: "Return the JSON Schema for PTAH investigation documents.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "ptah_isolation",
    description:
      "Report whether bubblewrap and prlimit are available for analyzer sandboxing.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "ptah_carve",
    description:
      "Find embedded file signatures (ZIP, ELF, PE, archives, images, WASM, DEX…) at any offset. Carving hints only; nothing is extracted or executed.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        maxResults: { type: "integer", minimum: 1 },
        minimumSignatureLength: { type: "integer", minimum: 2 },
        maxBytes: { type: "integer", minimum: 1 },
      },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_asar",
    description:
      "List Electron ASAR archive entries from the header without extracting.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" } },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_wasm",
    description:
      "Parse WebAssembly sections, imports, exports, and custom section names natively.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string" } },
      required: ["target"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_eval",
    description:
      "Run a pinned PTAH evaluation suite directory and report accuracy, unsupported-claim rate, and latency; optionally compare with a baseline report file.",
    inputSchema: {
      type: "object",
      properties: {
        suite: {
          type: "string",
          description: "Directory containing case subdirectories",
        },
        baseline: { type: "string", description: "Previous report JSON path" },
        only: { type: "array", items: { type: "string" } },
      },
      required: ["suite"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_report",
    description:
      "Create a provenance-aware report from a validated PTAH investigation as JSON or Markdown.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "Path to a PTAH investigation JSON file",
        },
        format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Output format; defaults to json",
        },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_diff",
    description:
      "Deterministically compare two investigations or verified case bundles: target drift, evidence/claim/question/action changes, claim status transitions.",
    inputSchema: {
      type: "object",
      properties: {
        base: {
          type: "string",
          description: "Base investigation or case path",
        },
        head: {
          type: "string",
          description: "Head investigation or case path",
        },
      },
      required: ["base", "head"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_graph",
    description:
      "Build the directed evidence graph for a validated PTAH investigation as JSON, Graphviz DOT, or Mermaid.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "Path to a PTAH investigation JSON file",
        },
        format: { type: "string", enum: ["json", "dot", "mermaid"] },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_plan",
    description:
      "Choose a deterministic next step within explicit call and cost budgets.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "Path to a PTAH investigation JSON file",
        },
        maxCalls: { type: "integer", minimum: 0 },
        maxCost: { type: "number", exclusiveMinimum: 0 },
        steps: {
          type: "integer",
          minimum: 1,
          description: "Plan this many greedy steps instead of one",
        },
      },
      required: ["input"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_providers",
    description: "Discover analysis tools on PATH without executing them.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "ptah_static_analyze",
    description:
      "Run an allow-listed static analyzer (objdump, readelf, nm, file, rabin2, rz-bin, monodis, aapt2, wasm-objdump, wasm-tools) with fixed argv, timeout, output cap, and optional bubblewrap isolation and prlimit limits; the target itself is not executed.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        provider: {
          type: "string",
          enum: [...STATIC_ANALYZER_IDS],
        },
        timeoutMs: { type: "integer", minimum: 100, maximum: 10000 },
        isolation: { type: "string", enum: ["auto", "required", "none"] },
        cpuSeconds: { type: "integer", minimum: 1 },
        memoryBytes: { type: "integer", minimum: 1 },
        maxOutputBytes: { type: "integer", minimum: 256, maximum: 65536 },
      },
      required: ["target", "provider"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_init",
    description:
      "Create an investigation bound to a target file's SHA-256. Start every analysis here; later evidence must match this digest.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Path to the target file" },
        output: {
          type: "string",
          description: "Path for the new investigation JSON file",
        },
        id: { type: "string", description: "Optional investigation id" },
      },
      required: ["target", "output"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_add_evidence",
    description:
      "Record one evidence item (what was observed, where, and how confident). Use confidence observed only for direct tool output; derived for computed results; inferred for interpretation.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Investigation JSON path" },
        output: {
          type: "string",
          description: "Where to save; defaults to updating input in place",
        },
        id: { type: "string" },
        kind: { type: "string", enum: [...EVIDENCE_KIND_VALUES] },
        summary: { type: "string" },
        source: {
          type: "string",
          description: "Reproducible reference: tool, command, offset, or file",
        },
        confidence: {
          type: "string",
          enum: ["observed", "derived", "inferred"],
        },
        artifact: {
          type: "string",
          description:
            "Optional file whose SHA-256 is recorded with the evidence",
        },
        tags: { type: "array", items: { type: "string" } },
      },
      required: ["input", "id", "kind", "summary", "source"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_add_claim",
    description:
      "Record a claim that cites existing evidence ids. Claims without cited evidence are rejected.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
        output: { type: "string" },
        id: { type: "string" },
        text: { type: "string" },
        evidenceIds: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
        },
        status: {
          type: "string",
          enum: ["hypothesis", "supported", "verified", "rejected"],
        },
        tags: { type: "array", items: { type: "string" } },
      },
      required: ["input", "id", "text", "evidenceIds"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_add_question",
    description:
      "Record an open question and the evidence kinds that would answer it; the planner uses these to choose the next step.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
        output: { type: "string" },
        id: { type: "string" },
        text: { type: "string" },
        priority: { type: "integer", minimum: 0, maximum: 100 },
        requiredEvidenceKinds: {
          type: "array",
          items: { type: "string", enum: [...EVIDENCE_KIND_VALUES] },
        },
      },
      required: ["input", "id", "text"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_set_claim_status",
    description:
      "Change a claim's status. verified requires at least one cited evidence item with confidence observed.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
        output: { type: "string" },
        claimId: { type: "string" },
        status: {
          type: "string",
          enum: ["hypothesis", "supported", "verified", "rejected"],
        },
        reason: { type: "string" },
      },
      required: ["input", "claimId", "status"],
      additionalProperties: false,
    },
  },
  {
    name: "ptah_resolve_question",
    description:
      "Resolve a question with a reason and supporting evidence ids, or reopen it with reopen: true.",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
        output: { type: "string" },
        questionId: { type: "string" },
        reason: { type: "string" },
        evidenceIds: { type: "array", items: { type: "string" } },
        reopen: { type: "boolean" },
      },
      required: ["input", "questionId"],
      additionalProperties: false,
    },
  },
];

async function loadInvestigation(path) {
  if (typeof path !== "string" || !path.trim())
    throw new TypeError("input must be a non-empty file path");
  return JSON.parse(await readFile(resolve(path), "utf8"));
}
function requirePathArgument(value, name) {
  if (typeof value !== "string" || !value.trim())
    throw new TypeError(`${name} must be a non-empty file path`);
}
async function artifactDigest(path) {
  requirePathArgument(path, "artifact");
  const fingerprint = await fingerprintTarget(path);
  return {
    sha256: fingerprint.sha256,
    sizeBytes: fingerprint.sizeBytes,
    name: fingerprint.id,
  };
}
async function callTool(name, args) {
  if (!args || typeof args !== "object" || Array.isArray(args))
    throw new TypeError("tool arguments must be an object");
  switch (name) {
    case "ptah_init": {
      requirePathArgument(args.target, "target");
      requirePathArgument(args.output, "output");
      const investigation = await createInvestigationForTarget(
        args.target,
        args.id,
      );
      const path = await saveInvestigation(
        args.output,
        recordHistory(investigation, "init", {
          targetId: investigation.target.id,
        }),
      );
      return { status: "created", path, target: investigation.target };
    }
    case "ptah_add_evidence": {
      const investigation = await loadInvestigation(args.input);
      const path = await saveInvestigation(
        args.output ?? args.input,
        addEvidence(investigation, {
          id: args.id,
          kind: args.kind,
          summary: args.summary,
          source: args.source,
          confidence: args.confidence,
          tags: args.tags,
          artifact:
            args.artifact === undefined
              ? undefined
              : await artifactDigest(args.artifact),
        }),
      );
      return {
        status: "evidence-added",
        evidenceId: args.id,
        targetSha256: investigation.target.sha256,
        path,
      };
    }
    case "ptah_add_claim":
    case "ptah_add_question": {
      const claim = name === "ptah_add_claim";
      const record = claim
        ? {
            id: args.id,
            text: args.text,
            evidenceIds: args.evidenceIds,
            ...(args.status ? { status: args.status } : {}),
            ...(args.tags?.length ? { tags: args.tags } : {}),
          }
        : {
            id: args.id,
            text: args.text,
            priority: args.priority ?? 50,
            requiredEvidenceKinds: args.requiredEvidenceKinds ?? [],
            resolved: false,
          };
      const collection = claim ? "claims" : "questions";
      const path = await saveInvestigation(
        args.output ?? args.input,
        addInvestigationRecord(
          await loadInvestigation(args.input),
          collection,
          record,
        ),
      );
      return { status: `${collection}-added`, id: args.id, path };
    }
    case "ptah_set_claim_status": {
      const path = await saveInvestigation(
        args.output ?? args.input,
        setClaimStatus(
          await loadInvestigation(args.input),
          args.claimId,
          args.status,
          { reason: args.reason },
        ),
      );
      return {
        status: "claim-status-set",
        claimId: args.claimId,
        to: args.status,
        path,
      };
    }
    case "ptah_resolve_question": {
      const path = await saveInvestigation(
        args.output ?? args.input,
        resolveQuestion(
          await loadInvestigation(args.input),
          args.questionId,
          args.reopen === true
            ? null
            : { reason: args.reason, evidenceIds: args.evidenceIds ?? [] },
        ),
      );
      return {
        status:
          args.reopen === true ? "question-reopened" : "question-resolved",
        questionId: args.questionId,
        path,
      };
    }
    case "ptah_fingerprint":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await fingerprintTarget(args.target);
    case "ptah_verify":
      return await verifyInvestigation(
        await loadInvestigation(args.input),
        args.target,
      );
    case "ptah_case_export": {
      const investigation = await loadInvestigation(args.input);
      const bundle = createInvestigationCase(investigation);
      const path = await saveInvestigationCase(args.output, investigation);
      return {
        status: "exported",
        path,
        ...bundle.integrity,
        target: investigation.target,
      };
    }
    case "ptah_case_verify": {
      const bundle = await loadInvestigation(args.input);
      const result = verifyInvestigationCase(bundle);
      if (result.valid && args.target !== undefined) {
        const target = await verifyInvestigation(
          bundle.investigation,
          args.target,
        );
        result.targetChecked = true;
        result.targetMatches = target.targetMatches;
        if (!target.valid) {
          result.valid = false;
          result.error = target.error;
        }
      }
      return result;
    }
    case "ptah_case_import": {
      const bundle = await loadInvestigation(args.input);
      const investigation = await importInvestigationCase(bundle, args.target);
      const path = await saveInvestigation(args.output, investigation);
      return {
        status: "imported",
        path,
        target: investigation.target,
        evidenceCount: investigation.evidence.length,
        claimCount: investigation.claims.length,
      };
    }
    case "ptah_inspect":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await inspectTarget(args.target);
    case "ptah_strings":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await extractStrings(args.target, {
        minLength: args.minLength,
        maxResults: args.maxResults,
        maxBytes: args.maxBytes,
      });
    case "ptah_lint":
      return lintInvestigation(await loadInvestigation(args.input));
    case "ptah_stats":
      return investigationStats(await loadInvestigation(args.input));
    case "ptah_schema":
      return investigationJsonSchema();
    case "ptah_report":
      if (args.format === "markdown")
        return renderEvidenceReportMarkdown(
          await loadInvestigation(args.input),
        );
      if (args.format !== undefined && args.format !== "json")
        throw new TypeError("format must be json or markdown");
      return buildEvidenceReport(await loadInvestigation(args.input));
    case "ptah_diff":
      return diffInvestigations(
        await loadInvestigation(args.base),
        await loadInvestigation(args.head),
      );
    case "ptah_graph":
      if (args.format !== undefined && args.format !== "json")
        return renderEvidenceGraph(
          await loadInvestigation(args.input),
          args.format,
        );
      return buildEvidenceGraph(await loadInvestigation(args.input));
    case "ptah_plan":
      if (args.steps !== undefined)
        return planSteps(await loadInvestigation(args.input), {
          steps: args.steps,
          maxCost: args.maxCost ?? Number.POSITIVE_INFINITY,
        });
      return planNextAction(await loadInvestigation(args.input), {
        maxCalls: args.maxCalls ?? 1,
        maxCost: args.maxCost ?? Number.POSITIVE_INFINITY,
      });
    case "ptah_providers":
      return await discoverProviders();
    case "ptah_static_analyze":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      if (!STATIC_ANALYZER_IDS.includes(args.provider))
        throw new TypeError(
          `provider must be one of ${STATIC_ANALYZER_IDS.join(", ")}`,
        );
      return await analyzeTarget(args.target, args.provider, {
        timeoutMs: args.timeoutMs ?? 5000,
        maxOutputBytes: args.maxOutputBytes ?? 16384,
        isolation: args.isolation ?? "auto",
        ...(args.cpuSeconds || args.memoryBytes
          ? {
              limits: {
                ...(args.cpuSeconds ? { cpuSeconds: args.cpuSeconds } : {}),
                ...(args.memoryBytes ? { memoryBytes: args.memoryBytes } : {}),
              },
            }
          : {}),
      });
    case "ptah_eval": {
      if (typeof args.suite !== "string" || !args.suite.trim())
        throw new TypeError("suite must be a non-empty directory path");
      const report = await runEvaluationSuite(args.suite, { only: args.only });
      if (args.baseline)
        report.comparison = compareEvaluationReports(
          await loadInvestigation(args.baseline),
          report,
        );
      return report;
    }
    case "ptah_isolation":
      return await detectIsolationSupport();
    case "ptah_carve":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await findEmbeddedSignatures(args.target, {
        maxResults: args.maxResults,
        minimumSignatureLength: args.minimumSignatureLength,
        maxBytes: args.maxBytes,
      });
    case "ptah_asar":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await parseAsarHeader(args.target);
    case "ptah_wasm":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      return await parseWasmSections(args.target);
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}
function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
function rpcError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

const rl = createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
  terminal: false,
});
for await (const line of rl) {
  if (!line.trim()) continue;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    rpcError(null, -32700, "Parse error");
    continue;
  }
  const id = request?.id;
  if (request?.jsonrpc !== "2.0" || typeof request.method !== "string") {
    if (id !== undefined) rpcError(id, -32600, "Invalid Request");
    continue;
  }
  try {
    switch (request.method) {
      case "initialize":
        send({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: {
              tools: {},
              prompts: {},
              ...(RESOURCE_ROOT ? { resources: {} } : {}),
            },
            serverInfo: { name: "ptah-mcp", version: SERVER_VERSION },
            instructions: SERVER_INSTRUCTIONS,
          },
        });
        break;
      case "notifications/initialized":
      case "notifications/cancelled":
        break;
      case "ping":
        send({ jsonrpc: "2.0", id, result: {} });
        break;
      case "tools/list":
        send({ jsonrpc: "2.0", id, result: { tools } });
        break;
      case "prompts/list":
        send({ jsonrpc: "2.0", id, result: { prompts } });
        break;
      case "prompts/get":
        send({
          jsonrpc: "2.0",
          id,
          result: {
            description: prompts.find((p) => p.name === request.params?.name)
              ?.description,
            messages: renderPrompt(
              request.params?.name,
              request.params?.arguments ?? {},
            ),
          },
        });
        break;
      case "resources/list":
        send({
          jsonrpc: "2.0",
          id,
          result: { resources: await listResources() },
        });
        break;
      case "resources/read":
        send({
          jsonrpc: "2.0",
          id,
          result: { contents: [await readResource(request.params?.uri)] },
        });
        break;
      case "tools/call": {
        const result = await callTool(
          request.params?.name,
          request.params?.arguments ?? {},
        );
        send({
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text:
                  typeof result === "string"
                    ? result
                    : JSON.stringify(result, null, 2),
              },
            ],
            isError: false,
          },
        });
        break;
      }
      default:
        if (id !== undefined)
          rpcError(id, -32601, `Method not found: ${request.method}`);
    }
  } catch (error) {
    if (request.method === "tools/call") {
      send({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: error instanceof Error ? error.message : String(error),
            },
          ],
          isError: true,
        },
      });
    } else if (id !== undefined) {
      rpcError(
        id,
        -32603,
        error instanceof Error ? error.message : String(error),
      );
    }
  }
}
