#!/usr/bin/env node
/** Dependency-free Model Context Protocol stdio server for PTAH's safe native tools. */
import { createInterface } from "node:readline";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  fingerprintTarget,
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
import {
  extractStrings,
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "./ptah-analysis.mjs";

const PROTOCOL_VERSION = "2024-11-05";
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
];

async function loadInvestigation(path) {
  if (typeof path !== "string" || !path.trim())
    throw new TypeError("input must be a non-empty file path");
  return JSON.parse(await readFile(resolve(path), "utf8"));
}
async function callTool(name, args) {
  if (!args || typeof args !== "object" || Array.isArray(args))
    throw new TypeError("tool arguments must be an object");
  switch (name) {
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
            capabilities: { tools: {} },
            serverInfo: { name: "ptah-mcp", version: "0.7.0" },
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
