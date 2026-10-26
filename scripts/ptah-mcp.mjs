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
} from "./ptah-engine.mjs";

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
      "Build the directed evidence graph for a validated PTAH investigation.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "Path to a PTAH investigation JSON file",
        },
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
      "Run allow-listed objdump metadata inspection with a wall-clock timeout and output cap; the target itself is not executed.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        provider: {
          type: "string",
          enum: ["objdump", "llvm-objdump", "wasm-tools"],
        },
        timeoutMs: { type: "integer", minimum: 100, maximum: 10000 },
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
      return buildEvidenceGraph(await loadInvestigation(args.input));
    case "ptah_plan":
      return planNextAction(await loadInvestigation(args.input), {
        maxCalls: args.maxCalls ?? 1,
        maxCost: args.maxCost ?? Number.POSITIVE_INFINITY,
      });
    case "ptah_providers":
      return await discoverProviders();
    case "ptah_static_analyze":
      if (typeof args.target !== "string" || !args.target.trim())
        throw new TypeError("target must be a non-empty file path");
      if (!["objdump", "llvm-objdump", "wasm-tools"].includes(args.provider))
        throw new TypeError(
          "provider must be objdump, llvm-objdump, or wasm-tools",
        );
      return await analyzeTarget(args.target, args.provider, {
        timeoutMs: args.timeoutMs ?? 5000,
        maxOutputBytes: args.maxOutputBytes ?? 16384,
      });
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
