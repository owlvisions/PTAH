/**
 * CLI commands for structure, byte, intelligence, triage, and agent-view
 * tools. Each analysis command can append its result to an investigation
 * with `--record INV`, so agents and users keep an evidence trail without a
 * separate add-evidence call.
 */
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { addEvidence, saveInvestigation } from "./ptah-engine.mjs";
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

const short = (items, limit = 8) =>
  items.length > limit
    ? `${items.slice(0, limit).join(", ")} (+${items.length - limit} more)`
    : items.join(", ");

/**
 * Analysis commands: `run` produces the result; `evidence` turns it into one
 * evidence record for `--record`.
 */
export const ANALYSIS_COMMANDS = {
  structure: {
    usage:
      "ptah structure --target FILE  Native ELF/PE sections with entropy, imports, exports, libraries, imphash, packer hints",
    run: (cli) => analyzeStructure(cli.required("--target")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `${r.format} ${r.bits}-bit, ${r.sections.length} sections, ${r.imports.length} imports, ${r.exports.length} exports${r.imphash ? `, imphash ${r.imphash}` : ""}${r.packerHints.length ? `; packer hints: ${short(r.packerHints.map((h) => h.packer))}` : ""}`,
    }),
  },
  hashes: {
    usage:
      "ptah hashes --target FILE  MD5, SHA-1, SHA-256, and SHA-512 in one pass",
    run: (cli) => hashTarget(cli.required("--target")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `md5 ${r.md5}; sha1 ${r.sha1}; sha256 ${r.sha256}`,
    }),
  },
  search: {
    usage:
      "ptah search --target FILE (--hex '4D 5A ?? 00' | --text TEXT) [--max-results N]  Find byte patterns (?? wildcards) or ASCII/UTF-16LE text",
    run: (cli) =>
      searchTarget(
        cli.required("--target"),
        { hex: cli.option("--hex"), text: cli.option("--text") },
        { maxResults: cli.integer("--max-results", 200) },
      ),
    evidence: (r, cli) => ({
      kind: "static-analysis",
      summary: `${r.count} matches for ${cli.option("--hex") ?? JSON.stringify(cli.option("--text"))} at offsets ${short(r.matches.map((m) => m.offset))}`,
    }),
  },
  hexdump: {
    usage:
      "ptah hexdump --target FILE [--offset N] [--length N]  Bounded hexdump (max 4096 bytes)",
    run: (cli) =>
      hexdumpTarget(cli.required("--target"), {
        offset: cli.integer("--offset", 0),
        length: cli.integer("--length", 256),
      }),
    text: (r) => `${r.dump}\n`,
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `Bytes at ${r.offset}..${r.offset + r.length}: ${r.dump.split("\n")[0]}`,
    }),
  },
  compare: {
    usage:
      "ptah compare --target FILE --other FILE  Similarity of strings, sections, and imports between two targets",
    run: (cli) =>
      compareTargets(cli.required("--target"), cli.required("--other")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `Compared with ${basename(r.right.path)} (sha256 ${r.right.sha256}): identical=${r.identical}, string similarity ${r.stringSimilarity}${r.importSimilarity === undefined ? "" : `, import similarity ${r.importSimilarity}`}`,
    }),
  },
  iocs: {
    usage:
      "ptah iocs --target FILE  URLs, domains, IPs, emails, paths, and registry keys with offsets",
    run: (cli) => extractIndicators(cli.required("--target")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `Indicators ${JSON.stringify(r.counts)}: ${short(
        r.indicators.map((i) => i.value),
        6,
      )}`,
    }),
  },
  secrets: {
    usage:
      "ptah secrets --target FILE  Embedded credentials and keys (values redacted, identified by SHA-256)",
    run: (cli) => findSecrets(cli.required("--target")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `${r.count} credential patterns (redacted): ${short(
        r.findings.map((f) => `${f.type}@${f.offset}`),
        6,
      )}`,
    }),
  },
  capabilities: {
    usage:
      "ptah capabilities --target FILE  Behaviors inferred from imports and strings, with ATT&CK ids",
    run: (cli) => inferCapabilities(cli.required("--target")),
    evidence: (r) => ({
      kind: "static-analysis",
      confidence: "inferred",
      summary: `Inferred capabilities: ${short(r.capabilities.map((c) => `${c.id} (${c.attack})`))}`,
    }),
  },
  rules: {
    usage:
      "ptah rules --target FILE --rules RULES.json  Match declarative text/hex/regex rules",
    run: (cli) => matchRules(cli.required("--target"), cli.required("--rules")),
    evidence: (r) => ({
      kind: "static-analysis",
      summary: `${r.matches.length}/${r.rules} rules matched: ${short(r.matches.map((m) => m.id))}`,
    }),
  },
};

/** Append a command result to the investigation named by --record. */
async function record(cli, name, spec, result) {
  const path = cli.option("--record");
  if (!path) return undefined;
  const investigation = JSON.parse(await readFile(resolve(path), "utf8"));
  const id =
    cli.option("--evidence-id") ??
    `${name}-${(investigation.evidence?.length ?? 0) + 1}`;
  const { kind, summary, confidence = "observed" } = spec.evidence(result, cli);
  const source = `ptah ${cli.args.filter((arg, index, all) => arg !== "--record" && all[index - 1] !== "--record" && arg !== "--evidence-id" && all[index - 1] !== "--evidence-id").join(" ")}`;
  await saveInvestigation(
    path,
    addEvidence(investigation, {
      id,
      kind,
      summary: summary.slice(0, 2000),
      source,
      confidence,
    }),
  );
  return { recorded: { investigation: resolve(path), evidenceId: id } };
}

/** Investigation views and the triage pipeline. */
const VIEW_COMMANDS = {
  triage: {
    usage:
      "ptah triage --target FILE --output INV [--id ID]  Run every applicable analysis and record evidence, hypotheses, questions, and next actions",
    async run(cli) {
      const { investigation, digest } = await triageTarget(
        cli.required("--target"),
        { id: cli.option("--id") },
      );
      const path = await saveInvestigation(
        cli.required("--output"),
        investigation,
      );
      return { status: "triaged", path, ...digest };
    },
  },
  summary: {
    usage:
      "ptah summary --input INV [--max-items 20]  Compact, token-efficient view of claims, open questions, and evidence",
    run: async (cli) =>
      summarizeInvestigation(await cli.readJson(cli.required("--input")), {
        maxItems: cli.integer("--max-items", 20),
      }),
  },
  query: {
    usage:
      "ptah query --input INV [--text T] [--kind K] [--confidence C] [--tag T]  Filter evidence and show which claims cite it",
    run: async (cli) =>
      queryEvidence(await cli.readJson(cli.required("--input")), {
        text: cli.option("--text"),
        kind: cli.option("--kind"),
        confidence: cli.option("--confidence"),
        tag: cli.option("--tag"),
      }),
  },
  timeline: {
    usage:
      "ptah timeline --input INV  Markdown timeline of the hash-chained history",
    run: async (cli) =>
      renderTimeline(await cli.readJson(cli.required("--input"))),
  },
};

export const INTEL_COMMAND_NAMES = [
  ...Object.keys(ANALYSIS_COMMANDS),
  ...Object.keys(VIEW_COMMANDS),
];
export const INTEL_USAGE = [
  ...Object.values(ANALYSIS_COMMANDS).map(
    (spec) => `${spec.usage} [--record INV [--evidence-id ID]]`,
  ),
  ...Object.values(VIEW_COMMANDS).map((spec) => spec.usage),
];

/** Run one of the commands above; `cli` supplies option parsing and output. */
export async function runIntelCommand(name, cli) {
  const analysis = ANALYSIS_COMMANDS[name];
  if (analysis) {
    const result = await analysis.run(cli);
    const recorded = await record(cli, name, analysis, result);
    if (analysis.text && !recorded) return cli.emit(analysis.text(result));
    return cli.emit(recorded ? { ...result, ...recorded } : result);
  }
  return cli.emit(await VIEW_COMMANDS[name].run(cli));
}
