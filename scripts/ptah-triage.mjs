/**
 * One-call triage and agent-oriented views of an investigation.
 *
 * `triageTarget` runs every applicable native analysis and records each
 * result as evidence with honest confidence: facts read from the bytes are
 * `observed`, capability matches are `inferred` and only back `hypothesis`
 * claims. Follow-up questions name the evidence that would settle them.
 */
import { basename } from "node:path";
import {
  addEvidence,
  addInvestigationRecord,
  createInvestigationForTarget,
  inspectTarget,
  recordHistory,
  validateInvestigation,
} from "./ptah-engine.mjs";
import {
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "./ptah-analysis.mjs";
import { analyzeStructure } from "./ptah-binary.mjs";
import { hashTarget } from "./ptah-bytes.mjs";
import {
  extractIndicators,
  findSecrets,
  inferCapabilities,
} from "./ptah-intel.mjs";

const optional = async (work) => {
  try {
    return await work();
  } catch {
    return undefined;
  }
};
const list = (items, limit = 8) =>
  items.length > limit
    ? `${items.slice(0, limit).join(", ")} (+${items.length - limit} more)`
    : items.join(", ");

/** Collect every applicable analysis for a target; failures leave a gap, not an error. */
async function collect(target) {
  const inspection = await inspectTarget(target);
  const format = inspection.detectedFormat ?? "unknown";
  const native = /^ELF|^DOS MZ/u.test(format);
  const [
    hashes,
    structure,
    indicators,
    secrets,
    capabilities,
    carved,
    wasm,
    asar,
  ] = await Promise.all([
    hashTarget(target),
    native ? optional(() => analyzeStructure(target)) : undefined,
    optional(() => extractIndicators(target)),
    optional(() => findSecrets(target)),
    optional(() => inferCapabilities(target)),
    optional(() => findEmbeddedSignatures(target, { maxResults: 50 })),
    format === "WebAssembly"
      ? optional(() => parseWasmSections(target))
      : undefined,
    /\.asar$/iu.test(target)
      ? optional(() => parseAsarHeader(target))
      : undefined,
  ]);
  return {
    inspection,
    format,
    hashes,
    structure,
    indicators,
    secrets,
    capabilities,
    carved,
    wasm,
    asar,
  };
}

const observed = (id, kind, summary, source) => ({
  id,
  kind,
  summary,
  source,
  confidence: "observed",
});

/** Evidence about the file's identity and native structure. */
function structureEvidence({ inspection, format, hashes, structure }, name) {
  const items = [
    observed(
      "triage-identity",
      "static-analysis",
      `${format}; ${inspection.sizeBytes} bytes; md5 ${hashes.md5}; sha1 ${hashes.sha1}; entropy ${inspection.entropy?.bitsPerByte ?? "n/a"} bits/byte`,
      `ptah fingerprint --inspect --target ${name}; ptah hashes --target ${name}`,
    ),
  ];
  if (!structure) return items;
  const source = `ptah structure --target ${name}`;
  const executable = structure.sections
    .filter((section) => section.executable)
    .map((section) => `${section.name}(${section.entropy})`);
  const imphash = structure.imphash ? `; imphash ${structure.imphash}` : "";
  const anomalies = structure.anomalies.length
    ? `; anomalies: ${list(structure.anomalies, 3)}`
    : "";
  items.push(
    observed(
      "triage-structure",
      "static-analysis",
      `${structure.format}${structure.bits ? ` ${structure.bits}-bit` : ""}: ${structure.sections.length} sections; executable ${list(executable)}${imphash}${anomalies}`,
      source,
    ),
  );
  if (structure.libraries.length)
    items.push(
      observed(
        "triage-libraries",
        "symbol",
        `Links ${structure.libraries.length} libraries: ${list(structure.libraries)}`,
        `${source} (imports)`,
      ),
    );
  if (structure.exports.length)
    items.push(
      observed(
        "triage-exports",
        "symbol",
        `Exports ${structure.exports.length} symbols: ${list(structure.exports)}`,
        `${source} (exports)`,
      ),
    );
  if (structure.packerHints.length)
    items.push(
      observed(
        "triage-packer",
        "static-analysis",
        `Packing indicators: ${list(
          structure.packerHints.map(
            (hint) => `${hint.packer} (${hint.reason})`,
          ),
          4,
        )}`,
        `${source} (packerHints)`,
      ),
    );
  return items;
}

/** Evidence from strings, embedded content, and containers. */
function contentEvidence({ indicators, secrets, carved, wasm, asar }, name) {
  const items = [];
  if (indicators?.indicators.length)
    items.push(
      observed(
        "triage-indicators",
        "static-analysis",
        `Embedded indicators ${JSON.stringify(indicators.counts)}: ${list(
          indicators.indicators.map((item) => item.value),
          6,
        )}`,
        `ptah iocs --target ${name}`,
      ),
    );
  if (secrets?.count)
    items.push(
      observed(
        "triage-secrets",
        "static-analysis",
        `Embedded credential patterns (values redacted): ${list(
          secrets.findings.map((item) => `${item.type}@${item.offset}`),
          6,
        )}`,
        `ptah secrets --target ${name}`,
      ),
    );
  const embedded = carved?.embedded?.filter((match) => match.offset > 0) ?? [];
  if (embedded.length)
    items.push(
      observed(
        "triage-embedded",
        "static-analysis",
        `Embedded file signatures after offset 0: ${list(
          embedded.map((match) => `${match.format}@${match.offset}`),
          6,
        )}`,
        `ptah carve --target ${name}`,
      ),
    );
  if (wasm)
    items.push(
      observed(
        "triage-wasm",
        "static-analysis",
        `WebAssembly: ${wasm.sectionCount ?? 0} sections, ${wasm.imports?.length ?? 0} imports, ${wasm.exports?.length ?? 0} exports`,
        `ptah wasm --target ${name}`,
      ),
    );
  if (asar)
    items.push(
      observed(
        "triage-asar",
        "filesystem-observation",
        `ASAR archive with ${asar.entryCount ?? 0} entries`,
        `ptah asar --target ${name}`,
      ),
    );
  return items;
}

/** Capability matches are interpretations of names, so they are recorded as inferred. */
const capabilityEvidence = ({ capabilities }, name) =>
  (capabilities?.capabilities ?? []).map((capability) => ({
    ...observed(
      `triage-capability-${capability.id}`,
      "static-analysis",
      `Names suggesting ${capability.id} (${capability.attack}): ${list(capability.evidence, 6)}`,
      `ptah capabilities --target ${name}`,
    ),
    confidence: "inferred",
  }));

/** Turn collected analyses into evidence items. */
const evidenceFrom = (facts, name) => [
  ...structureEvidence(facts, name),
  ...contentEvidence(facts, name),
  ...capabilityEvidence(facts, name),
];

/** Questions the triage leaves open, with the evidence kinds that would answer them. */
function questionsFrom(facts) {
  const questions = [];
  const ask = (id, text, priority, kinds) =>
    questions.push({
      id,
      text,
      priority,
      requiredEvidenceKinds: kinds,
      resolved: false,
    });
  const ids = new Set(
    (facts.capabilities?.capabilities ?? []).map((item) => item.id),
  );
  if (facts.structure?.packerHints.length)
    ask(
      "q-packed",
      "Is the target packed or obfuscated, and what does the unpacked code contain?",
      90,
      ["static-analysis", "decompilation"],
    );
  if (ids.has("network-communication") || facts.indicators?.counts?.ipv4)
    ask(
      "q-network",
      "Which endpoints does the target contact, and what data does it send?",
      85,
      ["network-observation", "decompilation"],
    );
  if (
    ids.has("process-injection") ||
    ids.has("registry-persistence") ||
    ids.has("service-persistence")
  )
    ask(
      "q-persistence",
      "Does the target persist or inject into other processes when run?",
      80,
      ["runtime-observation", "decompilation"],
    );
  if (facts.secrets?.count)
    ask(
      "q-secrets",
      "Are the embedded credentials live, and what do they grant?",
      75,
      ["documentation", "test-result"],
    );
  ask("q-purpose", "What is the target's primary purpose?", 50, [
    "decompilation",
    "documentation",
  ]);
  return questions;
}

/** Next steps the planner can choose to answer triage questions. */
const FOLLOW_UP_ACTIONS = [
  {
    id: "action-decompile",
    name: "Decompile with Ghidra or IDA through the REA layer (rea analyze)",
    produces: ["decompilation", "symbol"],
    cost: 3,
  },
  {
    id: "action-sandbox",
    name: "Run in an isolated, authorized sandbox with process and network capture",
    produces: [
      "runtime-observation",
      "network-observation",
      "filesystem-observation",
    ],
    cost: 5,
  },
  {
    id: "action-documentation",
    name: "Consult vendor documentation, package metadata, and public references",
    produces: ["documentation"],
    cost: 1,
  },
  {
    id: "action-credential-check",
    name: "Check credential validity only within an explicitly authorized scope",
    produces: ["test-result"],
    cost: 4,
  },
  {
    id: "action-static",
    name: "Deeper static analysis (ptah analyze, structure, rules)",
    produces: ["static-analysis"],
    cost: 1,
  },
];

/**
 * Create an investigation for `target`, populated by every applicable
 * analysis. Returns the investigation and a compact digest of the findings.
 */
export async function triageTarget(target, options = {}) {
  const facts = await collect(target);
  const name = basename(target);
  let investigation = recordHistory(
    await createInvestigationForTarget(target, options.id),
    "init",
    { targetId: name },
  );
  for (const item of evidenceFrom(facts, name))
    investigation = addEvidence(investigation, item);
  for (const capability of facts.capabilities?.capabilities ?? [])
    investigation = addInvestigationRecord(investigation, "claims", {
      id: `claim-${capability.id}`,
      text: `The target may have the capability ${capability.id} (ATT&CK ${capability.attack}); this is inferred from names only.`,
      evidenceIds: [`triage-capability-${capability.id}`],
      status: "hypothesis",
    });
  for (const question of questionsFrom(facts))
    investigation = addInvestigationRecord(
      investigation,
      "questions",
      question,
    );
  for (const action of FOLLOW_UP_ACTIONS)
    investigation = addInvestigationRecord(investigation, "actions", action);
  return { investigation, digest: summarizeInvestigation(investigation) };
}

/** A compact, token-efficient view of an investigation for agents. */
export function summarizeInvestigation(input, options = {}) {
  const investigation = validateInvestigation(input);
  const limit = options.maxItems ?? 20;
  const byStatus = {};
  for (const claim of investigation.claims) {
    const status = claim.status ?? "hypothesis";
    (byStatus[status] ??= []).push(`${claim.id}: ${claim.text}`.slice(0, 200));
  }
  return {
    target: investigation.target,
    counts: {
      evidence: investigation.evidence.length,
      claims: investigation.claims.length,
      openQuestions: investigation.questions.filter((item) => !item.resolved)
        .length,
    },
    claims: Object.fromEntries(
      Object.entries(byStatus).map(([status, items]) => [
        status,
        items.slice(0, limit),
      ]),
    ),
    openQuestions: investigation.questions
      .filter((item) => !item.resolved)
      .sort((left, right) => (right.priority ?? 50) - (left.priority ?? 50))
      .slice(0, limit)
      .map((item) => ({
        id: item.id,
        text: item.text,
        needs: item.requiredEvidenceKinds ?? [],
      })),
    evidence: investigation.evidence
      .slice(0, limit)
      .map((item) =>
        `${item.id} [${item.confidence}/${item.kind}] ${item.summary}`.slice(
          0,
          240,
        ),
      ),
  };
}

/** Filter evidence by text, kind, confidence, or tag. */
export function queryEvidence(input, query = {}) {
  const investigation = validateInvestigation(input);
  const text = query.text?.toLowerCase();
  const matches = investigation.evidence.filter(
    (item) =>
      (!text ||
        `${item.id} ${item.summary} ${item.source}`
          .toLowerCase()
          .includes(text)) &&
      (!query.kind || item.kind === query.kind) &&
      (!query.confidence || item.confidence === query.confidence) &&
      (!query.tag || (item.tags ?? []).includes(query.tag)),
  );
  const citing = (id) =>
    investigation.claims
      .filter((claim) => claim.evidenceIds.includes(id))
      .map((claim) => claim.id);
  return {
    count: matches.length,
    evidence: matches.map((item) => ({ ...item, citedBy: citing(item.id) })),
  };
}

/** Render the hash-chained history as a Markdown timeline. */
export function renderTimeline(input) {
  const investigation = validateInvestigation(input);
  const lines = [`# Timeline — ${investigation.target.id}`, ""];
  for (const entry of investigation.history ?? []) {
    const {
      seq,
      action,
      at,
      previousEntrySha256: _previous,
      entrySha256,
      ...details
    } = entry;
    const detail = Object.entries(details)
      .map(
        ([key, value]) =>
          `${key}=${typeof value === "string" ? value : JSON.stringify(value)}`,
      )
      .join(", ");
    lines.push(
      `- **${seq}** \`${at}\` ${action}${detail ? ` — ${detail}` : ""} (\`${entrySha256.slice(0, 12)}\`)`,
    );
  }
  if (!investigation.history?.length) lines.push("_No history recorded._");
  return `${lines.join("\n")}\n`;
}
