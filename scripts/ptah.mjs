#!/usr/bin/env node

/**
 * PTAH's first compatibility entry point.
 *
 * PTAH-owned commands are deliberately dependency-free so the project can
 * inspect its migration state before the legacy runtime has been built.
 * Existing REA commands continue through the established dispatcher until
 * equivalent PTAH-native implementations are proven by tests.
 */
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import {
  buildEvidenceGraph,
  buildEvidenceReport,
  planNextAction,
  fingerprintTarget,
  createInvestigationForTarget,
  saveInvestigation,
  discoverProviders,
  probeProviders,
  analyzeTarget,
  attachAnalysisEvidence,
  verifyInvestigation,
  createInvestigationCase,
  importInvestigationCase,
  verifyInvestigationCase,
  saveInvestigationCase,
  renderEvidenceReportMarkdown,
  diffInvestigations,
  inspectTarget,
  recordHistory,
  addEvidence,
  addInvestigationRecord,
  setClaimStatus,
  resolveQuestion,
  lintInvestigation,
  investigationStats,
  planSteps,
  renderEvidenceGraph,
  investigationJsonSchema,
  freezeInvestigation,
  unfreezeInvestigation,
  linkRelatedCase,
  mergeInvestigations,
  migrateInvestigation,
  listMigrations,
  STATIC_ANALYZER_IDS,
  detectIsolationSupport,
} from "./ptah-engine.mjs";
import {
  extractStrings,
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "./ptah-analysis.mjs";
import {
  runEvaluationSuite,
  compareEvaluationReports,
  evaluationSuiteDefaultDir,
} from "./ptah-eval.mjs";
import {
  generateCaseKeyPair,
  signCase,
  verifyCaseSignature,
  encryptCase,
  compressCase,
  parseCaseBytes,
} from "./ptah-case-tools.mjs";
import { mkdir, writeFile as writeFileAtomicUnsafe } from "node:fs/promises";
import { isSupportedPtahNodeVersion } from "./ptah-runtime.mjs";
import {
  INTEL_COMMAND_NAMES,
  INTEL_USAGE,
  runIntelCommand,
} from "./ptah-cli-intel.mjs";

process.stdout.on("error", (error) => {
  if (error.code === "EPIPE") process.exit(0);
  process.stderr.write(`PTAH output error: ${error.message}\n`);
  process.exitCode = 1;
});

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rawArgs = process.argv.slice(2);
const QUIET = rawArgs.includes("--quiet");
const args = rawArgs.filter((arg) => arg !== "--quiet");
/** Print a command result unless --quiet was supplied; errors always reach stderr. */
function emit(value) {
  if (QUIET) return;
  process.stdout.write(
    typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`,
  );
}
const packageJson = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);

function printHelp() {
  process.stdout.write(
    `PTAH (بتاح) — Program Understanding & Analysis Toolkit\n` +
      `Evidence-first reverse engineering: every claim cites provenance, targets are never executed.\n\n`,
  );
  process.stdout.write(`Usage:\n`);
  process.stdout.write(
    `  ptah info                 Show PTAH product and engine information\n`,
  );
  process.stdout.write(
    `  ptah self-check [--json]  Check local runtime/build readiness\n`,
  );
  process.stdout.write(
    `  ptah providers [--json] [--probe]  Detect tools; --probe runs bounded version/help checks\n`,
  );
  process.stdout.write(
    `  ptah analyze --target FILE --provider ID [--isolation auto|required|none] [--cpu-seconds N] [--memory-mb N]  Run a bounded allow-listed analyzer\n`,
  );
  process.stdout.write(`       providers: ${STATIC_ANALYZER_IDS.join(", ")}\n`);
  process.stdout.write(
    `  ptah isolation            Report bubblewrap/prlimit availability for analyzer sandboxing\n`,
  );
  process.stdout.write(
    `  ptah watch --input FILE --target FILE [--max-events N] [--debounce-ms 300] [--once]  Re-verify when the target changes\n`,
  );
  process.stdout.write(
    `  ptah completion bash|zsh|fish  Print shell completion script\n`,
  );
  process.stdout.write(
    `  ptah eval [--suite DIR] [--only ID,ID] [--baseline REPORT.json] [--json]  Run the pinned evaluation suite and compare with a baseline\n`,
  );
  process.stdout.write(
    `  ptah carve --target FILE [--max-results N] [--min-signature 4]  Find embedded file signatures at any offset\n`,
  );
  process.stdout.write(
    `  ptah asar --target FILE   List Electron ASAR entries from the header without extracting\n`,
  );
  process.stdout.write(
    `  ptah wasm --target FILE   Parse WebAssembly sections, imports, and exports natively\n`,
  );
  process.stdout.write(
    `       [--investigation FILE --save-investigation FILE --evidence-id ID]  Record successful analysis as evidence\n`,
  );
  process.stdout.write(
    `  ptah fingerprint --target FILE [--inspect]  Hash and identify a file without executing it; --inspect adds format details and entropy\n`,
  );
  process.stdout.write(
    `  ptah strings --target FILE [--min-length 6] [--max-results 500] [--max-bytes N]  Extract printable strings with offsets\n`,
  );
  process.stdout.write(
    `  ptah init --target FILE --output FILE [--id ID]  Create an investigation tied to target bytes\n`,
  );
  process.stdout.write(
    `  ptah add-evidence --input FILE --output FILE --id ID --kind KIND --summary TEXT --source REF [--confidence observed|derived|inferred] [--artifact FILE]\n`,
  );
  process.stdout.write(
    `  ptah add-claim --input FILE --output FILE --id ID --text TEXT --evidence-ids ID[,ID] [--status hypothesis|supported|verified|rejected]\n`,
  );
  process.stdout.write(
    `  ptah add-question --input FILE --output FILE --id ID --text TEXT [--priority 0..100] [--required-evidence-kinds KIND[,KIND]]\n`,
  );
  process.stdout.write(
    `  ptah add-action --input FILE --output FILE --id ID --name NAME --produces KIND[,KIND] [--cost NUMBER]\n`,
  );
  process.stdout.write(
    `  ptah set-claim-status --input FILE --output FILE --id ID --status hypothesis|supported|verified|rejected [--reason TEXT]\n`,
  );
  process.stdout.write(
    `  ptah resolve-question --input FILE --output FILE --id ID --reason TEXT [--evidence-ids ID[,ID]] | --reopen\n`,
  );
  process.stdout.write(
    `  ptah lint --input FILE    Advisory quality findings (exit 2 when errors exist)\n`,
  );
  process.stdout.write(
    `  ptah stats --input FILE   Deterministic evidence/claim/question metrics\n`,
  );
  process.stdout.write(
    `  ptah history --input FILE  Show and verify the append-only hash-chained history\n`,
  );
  process.stdout.write(
    `  ptah schema               Print the investigation JSON Schema\n`,
  );
  process.stdout.write(
    `  ptah freeze|unfreeze --input FILE --output FILE  Lock or unlock evidence/claims/questions/actions (history keeps growing)\n`,
  );
  process.stdout.write(
    `  ptah link-case --input FILE --output FILE --case FILE [--note TEXT]  Cross-reference a verified case bundle\n`,
  );
  process.stdout.write(
    `  ptah merge --base FILE --other FILE --output FILE [--prefer base|other]  Merge two investigations of the same target\n`,
  );
  process.stdout.write(
    `  ptah migrate --input FILE --output FILE | --list  Upgrade legacy documents to the current schema\n`,
  );
  process.stdout.write(
    `  ptah keygen --output-dir DIR  Generate an Ed25519 case-signing key pair\n`,
  );
  process.stdout.write(
    `  ptah sign-case --input FILE --key FILE [--output FILE] [--gzip]  Sign a case bundle\n`,
  );
  process.stdout.write(
    `  ptah encrypt-case --input FILE --output FILE  AES-256-GCM using PTAH_CASE_PASSPHRASE from the environment\n`,
  );
  process.stdout.write(
    `  ptah decrypt-case --input FILE --output FILE  Decrypt an encrypted case envelope\n`,
  );
  process.stdout.write(
    `  ptah verify --input FILE [--target FILE]  Validate evidence and optionally re-hash target bytes\n`,
  );
  process.stdout.write(
    `  ptah export-case --input FILE --output FILE [--gzip]  Create a portable checksummed case bundle\n`,
  );
  process.stdout.write(
    `  ptah verify-case --input FILE [--target FILE] [--public-key FILE] [--require-signature]  Verify a case bundle (gzip/encrypted accepted)\n`,
  );
  process.stdout.write(
    `  ptah import-case --input FILE --output FILE [--target FILE] [--public-key FILE]  Verify and restore a case bundle\n`,
  );
  process.stdout.write(
    `  ptah ui [--port 4177]  Start the loopback-only local GUI\n`,
  );
  for (const usage of INTEL_USAGE) process.stdout.write(`  ${usage}\n`);
  process.stdout.write(
    `  ptah doctor  Readiness of runtime, analyzers, isolation, agent registrations, and upstream sync\n`,
  );
  process.stdout.write(
    `  ptah upstream-sync [--push] [--update-local] [--bundle FILE] [--no-validate] [--branch main] [--upstream URL] | --install-timer [--interval hourly|15s|5min]  Merge the latest REA upstream in a temporary worktree, validate, and push without force\n`,
  );
  process.stdout.write(
    `  ptah agents list|install|uninstall|print [--client ID[,ID]|--all] [--workspace DIR [--no-instructions]] [--yes] [--force] [--no-skill] [--launcher local|npx]  Register the PTAH MCP server and skill with AI coding agents (preview unless --yes)\n`,
  );
  process.stdout.write(
    `  ptah report --input FILE [--format json|markdown|sarif|html]  Validate an investigation and print an evidence report\n`,
  );
  process.stdout.write(
    `  ptah diff --base FILE --head FILE  Compare two investigations or verified case bundles\n`,
  );
  process.stdout.write(
    `  ptah graph --input FILE [--format json|dot|mermaid]  Export the directed evidence graph\n`,
  );
  process.stdout.write(
    `  ptah plan --input FILE [--steps N] [--max-calls N] [--max-cost N]  Plan one bounded step, or N greedy steps\n`,
  );
  process.stdout.write(`  ptah help                 Show this help\n`);
  process.stdout.write(
    `  --quiet                   Suppress stdout for any command; errors still go to stderr\n`,
  );
  process.stdout.write(`  ptah <rea-command>\n`);
  process.stdout.write(
    `                            Run an inherited REA analyzer command through PTAH's compatibility layer\n\n`,
  );
  process.stdout.write(
    "REA remains available as `rea` and `rea-agents` for existing automation.\n",
  );
}

function printInfo(json = false) {
  const info = {
    product: "PTAH",
    productName: "PTAH (بتاح) — Program Understanding & Analysis Toolkit",
    status: "migration-preview",
    packageIdentityStatus:
      "npm package is @owlvisions/ptah; rea and rea-agents remain as compatibility executable names",
    compatibilityEngine: packageJson.name,
    compatibilityEngineVersion: packageJson.version,
    packageManagerNameUnchanged: true,
    entrypoints: {
      ptah: "scripts/ptah.mjs",
      ptahMcp: "scripts/ptah-mcp.mjs",
      ptahUi: "scripts/ptah-ui.mjs",
      legacy: "scripts/rea.mjs",
    },
    nativeCapabilities: [
      "target fingerprinting, format details, and entropy without execution",
      "bounded printable-string extraction",
      "provenance-validated investigations with hash-chained history",
      "evidence reports (JSON and Markdown), graphs (JSON, DOT, Mermaid)",
      "deterministic investigation diff, lint, and stats",
      "bounded single- and multi-step planner",
      "checksummed portable case bundles",
      "bounded static analyzer adapters",
      "loopback-only workbench",
    ],
    inheritedCapabilities:
      "REA analyzers run beneath PTAH through the compatibility layer",
    nextMilestone:
      "evaluation harness, provider conformance suite, and OS-level analyzer isolation",
  };
  process.stdout.write(
    json
      ? `${JSON.stringify(info, null, 2)}\n`
      : `${info.productName}\n` +
          `Status: ${info.status} (${info.packageIdentityStatus})\n` +
          `Compatibility engine: ${info.compatibilityEngine} ${info.compatibilityEngineVersion}\n` +
          `PTAH-native: ${info.nativeCapabilities.join("; ")}\n` +
          `Inherited: ${info.inheritedCapabilities}\n` +
          `Next milestone: ${info.nextMilestone}\n`,
  );
}

async function fileExists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function selfCheck(json = false) {
  const [major, minor, patch] = process.versions.node.split(".").map(Number);
  const nodeVersion = { major, minor, patch };
  const supported = isSupportedPtahNodeVersion(process.versions.node);
  const runtimeCandidates = [
    join(root, "dist/cli-runtime/cli.js"),
    join(root, "dist/mcp/main.js"),
  ];
  const runtimeFiles = {};
  for (const path of runtimeCandidates) {
    runtimeFiles[path.slice(root.length + 1)] = await fileExists(path);
  }
  const result = {
    product: "PTAH",
    nodeVersion: process.versions.node,
    nodeVersionSupported: supported,
    dependenciesInstalled: await fileExists(join(root, "node_modules")),
    compiledRuntime: runtimeFiles,
    legacyEntrypointPresent: await fileExists(join(root, "scripts/rea.mjs")),
    readyForLegacyCommands:
      supported &&
      runtimeFiles["dist/cli-runtime/cli.js"] === true &&
      (await fileExists(join(root, "node_modules"))),
  };
  const issues = [];
  if (!supported)
    issues.push("Node.js does not meet the package engine requirement.");
  if (!result.dependenciesInstalled)
    issues.push(
      "node_modules is missing; install dependencies with a supported Node.js/npm version.",
    );
  if (runtimeFiles["dist/cli-runtime/cli.js"] !== true)
    issues.push(
      "Compiled CLI runtime is missing; build the legacy engine before running analysis commands.",
    );
  if (!result.legacyEntrypointPresent)
    issues.push(
      "Legacy dispatcher is missing; compatibility commands cannot run.",
    );
  if (json) {
    emit({ ...result, issues });
  } else {
    process.stdout.write(`PTAH self-check\n`);
    process.stdout.write(
      `Node.js: ${result.nodeVersion} (${supported ? "supported" : "unsupported"})\n`,
    );
    process.stdout.write(
      `Dependencies: ${result.dependenciesInstalled ? "installed" : "missing"}\n`,
    );
    process.stdout.write(
      `Compiled runtime: ${Object.values(runtimeFiles).some(Boolean) ? "found" : "missing"}\n`,
    );
    process.stdout.write(
      `Legacy dispatcher: ${result.legacyEntrypointPresent ? "found" : "missing"}\n`,
    );
    for (const issue of issues) process.stdout.write(`- ${issue}\n`);
    if (issues.length === 0)
      process.stdout.write(
        "Environment is ready for legacy analysis commands.\n",
      );
  }
  return issues.length === 0 ? 0 : 1;
}

function optionValue(name) {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : undefined;
  return value && !value.startsWith("--") ? value : undefined;
}

async function runFingerprint() {
  const target = optionValue("--target");
  if (!target) throw new Error("Missing required --target FILE argument.");
  const result = args.includes("--inspect")
    ? await inspectTarget(target)
    : await fingerprintTarget(target);
  emit(result);
}

function integerOption(name, fallback) {
  const raw = optionValue(name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) throw new Error(`${name} must be an integer.`);
  return value;
}

async function runStrings() {
  const target = optionValue("--target");
  if (!target) throw new Error("Missing required --target FILE argument.");
  const result = await extractStrings(target, {
    minLength: integerOption("--min-length", 6),
    maxResults: integerOption("--max-results", 500),
    maxBytes: integerOption("--max-bytes", 16 * 1024 * 1024),
  });
  emit(result);
}

async function artifactDigest(filePath) {
  const fingerprint = await fingerprintTarget(filePath);
  return {
    sha256: fingerprint.sha256,
    sizeBytes: fingerprint.sizeBytes,
    name: fingerprint.id,
  };
}

async function runInit() {
  const target = optionValue("--target");
  const output = optionValue("--output");
  const id = optionValue("--id");
  if (!target) throw new Error("Missing required --target FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const investigation = await createInvestigationForTarget(target, id);
  const savedTo = await saveInvestigation(
    output,
    recordHistory(investigation, "init", {
      targetId: investigation.target.id,
    }),
  );
  emit({
    status: "created",
    path: savedTo,
    target: investigation.target,
    schemaVersion: investigation.schemaVersion,
  });
}

async function runAddEvidence() {
  const input = await readInvestigationInput();
  const id = optionValue("--id");
  const kind = optionValue("--kind");
  const summary = optionValue("--summary");
  const source = optionValue("--source");
  const confidence = optionValue("--confidence") ?? "observed";
  const output = optionValue("--output");
  for (const [name, value] of [
    ["--id", id],
    ["--kind", kind],
    ["--summary", summary],
    ["--source", source],
    ["--output", output],
  ]) {
    if (!value) throw new Error(`Missing required ${name} argument.`);
  }
  const artifactPath = optionValue("--artifact");
  const savedTo = await saveInvestigation(
    output,
    addEvidence(input, {
      id,
      kind,
      summary,
      source,
      confidence,
      artifact: artifactPath ? await artifactDigest(artifactPath) : undefined,
      tags: splitList("--tags"),
    }),
  );
  emit({
    status: "evidence-added",
    evidenceId: id,
    targetSha256: input.target.sha256,
    path: savedTo,
  });
}

async function appendInvestigationRecord(
  collection,
  record,
  requiredFields = [],
) {
  const input = await readInvestigationInput();
  const output = optionValue("--output");
  if (!output) throw new Error("Missing required --output FILE argument.");
  for (const field of requiredFields) {
    if (
      !record[field] ||
      (Array.isArray(record[field]) && record[field].length === 0)
    )
      throw new Error(
        `Missing required --${field.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} argument.`,
      );
  }
  const savedTo = await saveInvestigation(
    output,
    addInvestigationRecord(input, collection, record),
  );
  process.stdout.write(
    `${JSON.stringify({ status: `${collection}-added`, id: record.id, path: savedTo }, null, 2)}\n`,
  );
}

async function runAddClaim() {
  const evidenceIds =
    optionValue("--evidence-ids")
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean) ?? [];
  await appendInvestigationRecord(
    "claims",
    {
      id: optionValue("--id"),
      text: optionValue("--text"),
      evidenceIds,
      ...(optionValue("--status") ? { status: optionValue("--status") } : {}),
      ...(splitList("--tags").length ? { tags: splitList("--tags") } : {}),
    },
    ["id", "text", "evidenceIds"],
  );
}

async function runAddQuestion() {
  const priorityValue = optionValue("--priority");
  const kinds =
    optionValue("--required-evidence-kinds")
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean) ?? [];
  await appendInvestigationRecord(
    "questions",
    {
      id: optionValue("--id"),
      text: optionValue("--text"),
      priority: priorityValue === undefined ? 50 : Number(priorityValue),
      requiredEvidenceKinds: kinds,
      resolved: false,
    },
    ["id", "text"],
  );
}

async function runAddAction() {
  const produces =
    optionValue("--produces")
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean) ?? [];
  const costValue = optionValue("--cost");
  await appendInvestigationRecord(
    "actions",
    {
      id: optionValue("--id"),
      name: optionValue("--name"),
      produces,
      cost: costValue === undefined ? 1 : Number(costValue),
    },
    ["id", "name", "produces"],
  );
}

async function readInvestigationInput() {
  const inputIndex = args.indexOf("--input");
  if (inputIndex < 0 || !args[inputIndex + 1]) {
    throw new Error("Missing required --input FILE argument.");
  }
  const inputPath = resolve(process.cwd(), args[inputIndex + 1]);
  return JSON.parse(await readFile(inputPath, "utf8"));
}

async function runVerify() {
  const input = await readInvestigationInput();
  const targetPath = optionValue("--target");
  const result = await verifyInvestigation(input, targetPath);
  emit(result);
  if (!result.valid) process.exitCode = 2;
}

async function readJsonFile(filePath) {
  return JSON.parse(await readFile(resolve(process.cwd(), filePath), "utf8"));
}

async function readCaseFile(filePath) {
  const bytes = await readFile(resolve(process.cwd(), filePath));
  return parseCaseBytes(bytes, {
    passphrase: process.env.PTAH_CASE_PASSPHRASE,
  });
}

async function writeCaseBytes(filePath, bytes) {
  const absolutePath = resolve(process.cwd(), filePath);
  await mkdir(dirname(absolutePath), { recursive: true });
  const temporaryPath = `${absolutePath}.tmp-${process.pid}`;
  await writeFileAtomicUnsafe(temporaryPath, bytes, {
    flag: "wx",
    mode: 0o600,
  });
  const { rename } = await import("node:fs/promises");
  await rename(temporaryPath, absolutePath);
  return absolutePath;
}

async function runExportCase() {
  const output = optionValue("--output");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const bundle = createInvestigationCase(await readInvestigationInput());
  const gzip = args.includes("--gzip");
  const savedTo = gzip
    ? await writeCaseBytes(output, compressCase(bundle))
    : await saveInvestigationCase(output, bundle.investigation);
  emit({
    status: "exported",
    path: savedTo,
    compressed: gzip,
    ...bundle.integrity,
  });
}

async function runVerifyCase() {
  const inputPath = optionValue("--input");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  const {
    document: bundle,
    compressed,
    encrypted,
  } = await readCaseFile(inputPath);
  const result = verifyInvestigationCase(bundle);
  result.compressed = compressed;
  result.encrypted = encrypted;
  const publicKeyPath = optionValue("--public-key");
  result.signature = verifyCaseSignature(
    bundle,
    publicKeyPath
      ? await readFile(resolve(process.cwd(), publicKeyPath), "utf8")
      : undefined,
  );
  if (result.signature.verified === false) {
    result.valid = false;
    result.error = `signature check failed: ${result.signature.reason}`;
  }
  if (
    args.includes("--require-signature") &&
    result.signature.verified !== true
  ) {
    result.valid = false;
    result.error ??= "a verified signature is required";
  }
  const targetPath = optionValue("--target");
  if (result.valid && targetPath !== undefined) {
    const target = await verifyInvestigation(bundle.investigation, targetPath);
    result.targetChecked = true;
    result.targetMatches = target.targetMatches;
    if (!target.valid) {
      result.valid = false;
      result.error = target.error;
    }
  }
  emit(result);
  if (!result.valid) process.exitCode = 2;
}

async function runImportCase() {
  const inputPath = optionValue("--input");
  const output = optionValue("--output");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const { document: bundle } = await readCaseFile(inputPath);
  const publicKeyPath = optionValue("--public-key");
  if (publicKeyPath || args.includes("--require-signature")) {
    const signature = verifyCaseSignature(
      bundle,
      publicKeyPath
        ? await readFile(resolve(process.cwd(), publicKeyPath), "utf8")
        : undefined,
    );
    if (signature.verified !== true)
      throw new Error(`signature check failed: ${signature.reason}`);
  }
  const investigation = await importInvestigationCase(
    bundle,
    optionValue("--target"),
  );
  const savedTo = await saveInvestigation(output, investigation);
  emit({
    status: "imported",
    path: savedTo,
    target: investigation.target,
    evidenceCount: investigation.evidence.length,
    claimCount: investigation.claims.length,
  });
}

async function runKeygen() {
  const outputDir = optionValue("--output-dir");
  if (!outputDir)
    throw new Error("Missing required --output-dir DIR argument.");
  const keys = generateCaseKeyPair();
  const absolute = resolve(process.cwd(), outputDir);
  await mkdir(absolute, { recursive: true, mode: 0o700 });
  const privatePath = join(absolute, "ptah-case-signing.key");
  const publicPath = join(absolute, "ptah-case-signing.pub");
  await writeFileAtomicUnsafe(privatePath, keys.privateKeyPem, {
    flag: "wx",
    mode: 0o600,
  });
  await writeFileAtomicUnsafe(publicPath, keys.publicKeyPem, {
    flag: "wx",
    mode: 0o644,
  });
  emit({
    status: "keys-generated",
    algorithm: keys.algorithm,
    privateKeyPath: privatePath,
    publicKeyPath: publicPath,
    publicKeySha256: keys.publicKeySha256,
    note: "Keep the private key secret; share only the .pub file with reviewers.",
  });
}

async function runSignCase() {
  const inputPath = optionValue("--input");
  const output = optionValue("--output") ?? inputPath;
  const keyPath = optionValue("--key");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (!keyPath) throw new Error("Missing required --key FILE argument.");
  const { document: bundle } = await readCaseFile(inputPath);
  const signed = signCase(
    bundle,
    await readFile(resolve(process.cwd(), keyPath), "utf8"),
  );
  const savedTo = await writeCaseBytes(
    output,
    args.includes("--gzip")
      ? compressCase(signed)
      : Buffer.from(`${JSON.stringify(signed, null, 2)}\n`),
  );
  emit({ status: "signed", path: savedTo, ...signed.signature });
}

function requirePassphraseEnv() {
  const passphrase = process.env.PTAH_CASE_PASSPHRASE;
  if (!passphrase)
    throw new Error(
      "Set PTAH_CASE_PASSPHRASE in the environment (never pass it as an argument).",
    );
  return passphrase;
}

async function runEncryptCase() {
  const inputPath = optionValue("--input");
  const output = optionValue("--output");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const { document: bundle } = await readCaseFile(inputPath);
  const envelope = encryptCase(bundle, requirePassphraseEnv());
  const savedTo = await writeCaseBytes(
    output,
    args.includes("--gzip")
      ? compressCase(envelope)
      : Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`),
  );
  emit({
    status: "encrypted",
    path: savedTo,
    cipher: envelope.cipher,
    kdf: envelope.kdf.name,
  });
}

async function runDecryptCase() {
  const inputPath = optionValue("--input");
  const output = optionValue("--output");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const passphrase = requirePassphraseEnv();
  const bytes = await readFile(resolve(process.cwd(), inputPath));
  const { document: bundle, encrypted } = parseCaseBytes(bytes, { passphrase });
  if (!encrypted) throw new Error("input is not an encrypted case envelope");
  const savedTo = await writeCaseBytes(
    output,
    Buffer.from(`${JSON.stringify(bundle, null, 2)}\n`),
  );
  emit({ status: "decrypted", path: savedTo, ...bundle.integrity });
}

async function runFreeze(freeze) {
  const input = await readInvestigationInput();
  const output = optionValue("--output");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const updated = freeze
    ? freezeInvestigation(input)
    : unfreezeInvestigation(input);
  const savedTo = await saveInvestigation(output, updated);
  emit({
    status: freeze ? "frozen" : "unfrozen",
    path: savedTo,
    frozen: updated.frozen ?? null,
  });
}

async function runLinkCase() {
  const input = await readInvestigationInput();
  const output = optionValue("--output");
  const casePath = optionValue("--case");
  if (!output) throw new Error("Missing required --output FILE argument.");
  if (!casePath) throw new Error("Missing required --case FILE argument.");
  const { document: bundle } = await readCaseFile(casePath);
  const updated = linkRelatedCase(input, bundle, {
    note: optionValue("--note"),
  });
  const savedTo = await saveInvestigation(output, updated);
  emit({
    status: "case-linked",
    path: savedTo,
    related: updated.relatedCases.at(-1),
  });
}

async function runMerge() {
  const basePath = optionValue("--base");
  const otherPath = optionValue("--other");
  const output = optionValue("--output");
  if (!basePath) throw new Error("Missing required --base FILE argument.");
  if (!otherPath) throw new Error("Missing required --other FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const result = mergeInvestigations(
    await readJsonFile(basePath),
    await readJsonFile(otherPath),
    { prefer: optionValue("--prefer") },
  );
  const savedTo = await saveInvestigation(output, result.investigation);
  emit({
    status: "merged",
    path: savedTo,
    added: result.added,
    conflicts: result.conflicts,
    note: result.note,
  });
}

async function runMigrate() {
  const inputPath = optionValue("--input");
  const output = optionValue("--output");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (args.includes("--list")) {
    emit({ currentSchemaVersion: 1, migrations: listMigrations() });
    return;
  }
  if (!output) throw new Error("Missing required --output FILE argument.");
  const result = migrateInvestigation(await readJsonFile(inputPath));
  const savedTo = await saveInvestigation(output, result.investigation);
  emit({
    status: "migrated",
    path: savedTo,
    fromVersion: result.fromVersion,
    toVersion: result.toVersion,
    applied: result.applied,
  });
}

function splitList(name) {
  return (
    optionValue(name)
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean) ?? []
  );
}

async function runSetClaimStatus() {
  const input = await readInvestigationInput();
  const output = optionValue("--output");
  const id = optionValue("--id");
  const status = optionValue("--status");
  if (!output) throw new Error("Missing required --output FILE argument.");
  if (!id) throw new Error("Missing required --id argument.");
  if (!status) throw new Error("Missing required --status argument.");
  const updated = setClaimStatus(input, id, status, {
    reason: optionValue("--reason"),
  });
  const savedTo = await saveInvestigation(output, updated);
  emit({
    status: "claim-status-set",
    claimId: id,
    claimStatus: status,
    path: savedTo,
  });
}

async function runResolveQuestion() {
  const input = await readInvestigationInput();
  const output = optionValue("--output");
  const id = optionValue("--id");
  if (!output) throw new Error("Missing required --output FILE argument.");
  if (!id) throw new Error("Missing required --id argument.");
  const reopen = args.includes("--reopen");
  const reason = optionValue("--reason");
  if (!reopen && !reason)
    throw new Error("Missing required --reason argument (or pass --reopen).");
  const updated = resolveQuestion(
    input,
    id,
    reopen ? null : { reason, evidenceIds: splitList("--evidence-ids") },
  );
  const savedTo = await saveInvestigation(output, updated);
  emit({
    status: reopen ? "question-reopened" : "question-resolved",
    questionId: id,
    path: savedTo,
  });
}

async function runLint() {
  const result = lintInvestigation(await readInvestigationInput());
  emit(result);
  if (!result.ok) process.exitCode = 2;
}

async function runStats() {
  emit(investigationStats(await readInvestigationInput()));
}

async function runHistory() {
  const investigation = await readInvestigationInput();
  const { validateInvestigation } = await import("./ptah-engine.mjs");
  const validated = validateInvestigation(investigation);
  const history = validated.history ?? [];
  emit({
    target: validated.target,
    entries: history.length,
    chainValid: true,
    headSha256: history.at(-1)?.entrySha256 ?? null,
    history,
  });
}

function formatEvalText(report) {
  const lines = [
    `PTAH evaluation — ${report.cases} case(s), ${report.passed} passed, ${report.failed} failed`,
    `check pass rate: ${report.metrics.checkPassRate ?? "n/a"} · claim label precision: ${report.metrics.claimLabelPrecision ?? "n/a"} · unsupported claim rate: ${report.metrics.unsupportedClaimRate ?? "n/a"}`,
    `median ${report.metrics.medianDurationMs ?? "n/a"} ms · p95 ${report.metrics.p95DurationMs ?? "n/a"} ms · total ${report.metrics.totalDurationMs} ms`,
    "",
  ];
  for (const result of report.results) {
    lines.push(
      `${result.passed ? "[pass]" : "[FAIL]"} ${result.id} (${result.checkCounts.passed}/${result.checkCounts.total} checks, ${result.durationMs} ms)`,
    );
    for (const check of result.checks.filter((c) => !c.pass))
      lines.push(
        `       ✖ ${check.name}: expected ${JSON.stringify(check.expected)}, got ${JSON.stringify(check.actual)}`,
      );
  }
  return `${lines.join("\n")}\n`;
}

async function runEval() {
  const suite = optionValue("--suite") ?? evaluationSuiteDefaultDir(root);
  const only = optionValue("--only");
  const report = await runEvaluationSuite(suite, {
    only: only
      ? only
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : undefined,
  });
  const baselinePath = optionValue("--baseline");
  let comparison = null;
  if (baselinePath) {
    comparison = compareEvaluationReports(
      await readJsonFile(baselinePath),
      report,
    );
    report.comparison = comparison;
  }
  if (args.includes("--json")) emit(report);
  else {
    emit(formatEvalText(report));
    if (comparison)
      emit(
        `baseline: ${comparison.verdict}${comparison.regressions.length ? ` — ${comparison.regressions.map((r) => `${r.id}: ${r.change}`).join("; ")}` : ""}\n`,
      );
  }
  if (report.failed > 0 || comparison?.verdict === "regression")
    process.exitCode = 2;
}

async function runTargetTool(fn, extra = {}) {
  const target = optionValue("--target");
  if (!target) throw new Error("Missing required --target FILE argument.");
  emit(await fn(target, extra));
}

const SHELL_COMMANDS = [
  "info",
  "self-check",
  "providers",
  "fingerprint",
  "strings",
  "carve",
  "asar",
  "wasm",
  "isolation",
  "init",
  "add-evidence",
  "add-claim",
  "add-question",
  "add-action",
  "set-claim-status",
  "resolve-question",
  "freeze",
  "unfreeze",
  "verify",
  "lint",
  "stats",
  "history",
  "schema",
  "export-case",
  "verify-case",
  "import-case",
  "sign-case",
  "encrypt-case",
  "decrypt-case",
  "keygen",
  "link-case",
  "merge",
  "migrate",
  "report",
  "diff",
  "graph",
  "plan",
  "analyze",
  "eval",
  "watch",
  "completion",
  "agents",
  "upstream-sync",
  "doctor",
  ...INTEL_COMMAND_NAMES,
  "ui",
  "help",
  "legacy",
];

function renderCompletion(shell) {
  const words = SHELL_COMMANDS.join(" ");
  if (shell === "bash")
    return `# bash completion for ptah — eval "$(ptah completion bash)"\n_ptah() {\n  local cur="\${COMP_WORDS[COMP_CWORD]}"\n  if [ "$COMP_CWORD" -eq 1 ]; then\n    COMPREPLY=( $(compgen -W "${words}" -- "$cur") )\n  else\n    COMPREPLY=( $(compgen -W "--input --output --target --provider --format --base --head --other --prefer --steps --isolation --key --public-key --case --suite --baseline --json --quiet --gzip --inspect --tags --artifact" -- "$cur") $(compgen -f -- "$cur") )\n  fi\n}\ncomplete -F _ptah ptah\n`;
  if (shell === "zsh")
    return `#compdef ptah\n# zsh completion for ptah — eval "$(ptah completion zsh)"\n_ptah() {\n  local -a commands\n  commands=(${SHELL_COMMANDS.map((c) => `'${c}'`).join(" ")})\n  if (( CURRENT == 2 )); then\n    _describe 'command' commands\n  else\n    _arguments '*:file:_files'\n  fi\n}\ncompdef _ptah ptah\n`;
  if (shell === "fish")
    return `# fish completion for ptah — ptah completion fish | source\n${SHELL_COMMANDS.map((c) => `complete -c ptah -n '__fish_use_subcommand' -a ${c}`).join("\n")}\n`;
  throw new Error("completion shell must be bash, zsh, or fish");
}

async function runWatch() {
  const inputPath = optionValue("--input");
  const target = optionValue("--target");
  if (!inputPath) throw new Error("Missing required --input FILE argument.");
  if (!target) throw new Error("Missing required --target FILE argument.");
  const maxEvents = integerOption("--max-events", 0);
  const debounceMs = integerOption("--debounce-ms", 300);
  const { watch } = await import("node:fs");
  const investigation = await readJsonFile(inputPath);
  const absoluteTarget = resolve(process.cwd(), target);
  const check = async (reason) => {
    const result = await verifyInvestigation(investigation, absoluteTarget);
    emit({
      event: reason,
      at: new Date().toISOString(),
      valid: result.valid,
      targetMatches: result.targetMatches,
      actualSha256: result.target.actualSha256,
    });
    return result;
  };
  await check("initial");
  if (maxEvents === 0 && args.includes("--once")) return;
  let events = 0;
  let timer = null;
  await new Promise((finish, fail) => {
    let watcher;
    try {
      watcher = watch(
        dirname(absoluteTarget),
        { persistent: true },
        (_type, filename) => {
          if (filename && filename !== basename(absoluteTarget)) return;
          clearTimeout(timer);
          timer = setTimeout(async () => {
            try {
              const result = await check("target-changed");
              events += 1;
              if (!result.valid) process.exitCode = 2;
              if (maxEvents > 0 && events >= maxEvents) {
                watcher.close();
                finish();
              }
            } catch (error) {
              watcher.close();
              fail(error);
            }
          }, debounceMs);
        },
      );
      watcher.once("error", (error) => fail(error));
      process.once("SIGINT", () => {
        watcher.close();
        finish();
      });
    } catch (error) {
      fail(error);
    }
  });
}

/** Project-scoped registration: configs confined with --workspace, plus instruction files. */
async function runWorkspaceAgents(agents, action, directory, command) {
  const { workspaceClients } = await import("./ptah-agent-clients.mjs");
  const { workspaceInstructions } = await import("./ptah-agents.mjs");
  const selected = splitList("--client");
  const clients = workspaceClients(directory).filter(
    (client) => selected.length === 0 || selected.includes(client.id),
  );
  const confined = [...command, "--workspace", directory];
  const options = {
    command: confined,
    apply: args.includes("--yes"),
    force: args.includes("--force"),
    skill: !args.includes("--no-skill"),
  };
  if (action === "list") {
    const reports = [];
    for (const client of clients)
      reports.push(await agents.inspectClient(client, { command: confined }));
    emit({ workspace: directory, command: confined, clients: reports });
    return;
  }
  if (action !== "install" && action !== "uninstall")
    throw new Error(
      "with --workspace, agents action must be list, install, or uninstall",
    );
  const result =
    action === "install"
      ? await agents.installAgents(clients, options)
      : await agents.uninstallAgents(clients, options);
  const instructions = args.includes("--no-instructions")
    ? []
    : await workspaceInstructions(directory, {
        apply: options.apply,
        remove: action === "uninstall",
      });
  emit({
    workspace: directory,
    ...result,
    instructions,
    ...(options.apply
      ? {}
      : { next: "Preview only. Rerun with --yes to apply." }),
  });
  if (
    [...result.clients, ...result.skills].some(
      (item) => item.action === "conflict" || item.action === "blocked",
    )
  )
    process.exitCode = 2;
}

async function runAgents() {
  const agents = await import("./ptah-agents.mjs");
  const action = args[1] ?? "list";
  const launcher = optionValue("--launcher") ?? "local";
  const command = agents.serverCommand(launcher, packageJson.version);
  if (action === "print") {
    emit(agents.renderSnippet(optionValue("--client") ?? "json", command));
    return;
  }
  const workspace = optionValue("--workspace");
  if (workspace) {
    await runWorkspaceAgents(agents, action, resolve(workspace), command);
    return;
  }
  const clients = await agents.selectClients(
    args.includes("--all") ? "all" : splitList("--client"),
  );
  if (action === "list" || action === "doctor") {
    const reports = [];
    for (const client of args.includes("--all") || splitList("--client").length
      ? clients
      : agents.AGENT_CLIENTS)
      reports.push(await agents.inspectClient(client, { command }));
    emit({ command, clients: reports });
    if (reports.some((report) => report.registered && report.issues.length))
      process.exitCode = 2;
    return;
  }
  const options = {
    command,
    apply: args.includes("--yes"),
    force: args.includes("--force"),
    skill: !args.includes("--no-skill"),
  };
  if (action !== "install" && action !== "uninstall")
    throw new Error("agents action must be list, install, uninstall, or print");
  if (clients.length === 0)
    throw new Error(
      "No supported agent was detected. Pass --client ID[,ID] or --all; see ptah agents list.",
    );
  const result =
    action === "install"
      ? await agents.installAgents(clients, options)
      : await agents.uninstallAgents(clients, options);
  emit({
    ...result,
    ...(options.apply
      ? {}
      : {
          next: `Preview only. Rerun with --yes to apply: ptah agents ${action} ${args.slice(2).join(" ")} --yes`.trim(),
        }),
  });
  if (
    [...result.clients, ...result.skills].some(
      (item) => item.action === "conflict" || item.action === "blocked",
    )
  )
    process.exitCode = 2;
}

async function runUpstreamSync() {
  const sync = await import("./ptah-upstream-sync.mjs");
  if (args.includes("--install-timer")) {
    emit(
      await sync.installSyncTimer({
        repo: root,
        interval: optionValue("--interval") ?? "hourly",
      }),
    );
    return;
  }
  const nodeModules = join(root, "node_modules");
  const result = await sync.syncUpstream({
    repo: root,
    branch: optionValue("--branch") ?? "main",
    upstream: optionValue("--upstream") ?? sync.DEFAULT_UPSTREAM,
    push: args.includes("--push"),
    updateLocal: args.includes("--update-local"),
    bundle: optionValue("--bundle"),
    validation: args.includes("--no-validate") ? [] : sync.DEFAULT_VALIDATION,
    nodeModules: await access(nodeModules).then(
      () => nodeModules,
      () => undefined,
    ),
    log: (message) => {
      if (!QUIET) process.stderr.write(`ptah upstream-sync: ${message}\n`);
    },
  });
  emit(result);
  if (!["up-to-date", "merged", "pushed", "busy"].includes(result.status))
    process.exitCode = 2;
}

/** Option access shared with commands defined in other modules. */
const cliContext = {
  args,
  option: optionValue,
  integer: integerOption,
  emit,
  readJson: readJsonFile,
  required(name) {
    const value = optionValue(name);
    if (!value) throw new Error(`Missing required ${name} argument.`);
    return value;
  },
};

async function runDoctorCommand() {
  const { runDoctor } = await import("./ptah-doctor.mjs");
  const report = await runDoctor({ root, packageJson });
  emit(report);
  if (!report.ok) process.exitCode = 2;
}

const COMMAND_HANDLERS = {
  ...Object.fromEntries(
    INTEL_COMMAND_NAMES.map((name) => [
      name,
      () => runIntelCommand(name, cliContext),
    ]),
  ),
  doctor: runDoctorCommand,
  agents: runAgents,
  "upstream-sync": runUpstreamSync,
  eval: runEval,
  watch: runWatch,
  completion: async () => emit(renderCompletion(args[1] ?? "")),
  isolation: async () => emit(await detectIsolationSupport()),
  carve: () =>
    runTargetTool(findEmbeddedSignatures, {
      maxResults: integerOption("--max-results", 200),
      minimumSignatureLength: integerOption("--min-signature", 4),
      maxBytes: integerOption("--max-bytes", 64 * 1024 * 1024),
    }),
  asar: () => runTargetTool(parseAsarHeader),
  wasm: () => runTargetTool(parseWasmSections),
  strings: runStrings,
  "set-claim-status": runSetClaimStatus,
  "resolve-question": runResolveQuestion,
  lint: runLint,
  stats: runStats,
  history: runHistory,
  freeze: () => runFreeze(true),
  unfreeze: () => runFreeze(false),
  "link-case": runLinkCase,
  merge: runMerge,
  migrate: runMigrate,
  keygen: runKeygen,
  "sign-case": runSignCase,
  "encrypt-case": runEncryptCase,
  "decrypt-case": runDecryptCase,
};

async function runDiff() {
  const basePath = optionValue("--base");
  const headPath = optionValue("--head");
  if (!basePath) throw new Error("Missing required --base FILE argument.");
  if (!headPath) throw new Error("Missing required --head FILE argument.");
  const result = diffInvestigations(
    await readJsonFile(basePath),
    await readJsonFile(headPath),
  );
  emit(result);
  if (!result.identical) process.exitCode = 3;
}

async function runEngineCommand(command) {
  try {
    const input = await readInvestigationInput();
    let output;
    if (command === "report") {
      const format = optionValue("--format") ?? "json";
      if (format === "markdown" || format === "md") {
        process.stdout.write(renderEvidenceReportMarkdown(input));
        return;
      }
      if (format === "sarif" || format === "html") {
        const reports = await import("./ptah-reports.mjs");
        emit(
          format === "sarif"
            ? reports.renderSarif(input, { version: packageJson.version })
            : reports.renderHtmlReport(input),
        );
        return;
      }
      if (format !== "json")
        throw new Error("--format must be json, markdown, sarif, or html");
      output = buildEvidenceReport(input);
    } else if (command === "graph") {
      const format = optionValue("--format") ?? "json";
      if (format !== "json") {
        process.stdout.write(renderEvidenceGraph(input, format));
        return;
      }
      output = buildEvidenceGraph(input);
    } else {
      const callsIndex = args.indexOf("--max-calls");
      const costIndex = args.indexOf("--max-cost");
      const budget = {};
      if (callsIndex >= 0) budget.maxCalls = Number(args[callsIndex + 1]);
      if (costIndex >= 0) budget.maxCost = Number(args[costIndex + 1]);
      const steps = optionValue("--steps");
      output =
        steps === undefined
          ? planNextAction(input, budget)
          : planSteps(input, { ...budget, steps: Number(steps) });
    }
    emit(output);
    if (command === "plan" && output.status === "blocked") process.exitCode = 2;
  } catch (error) {
    process.stderr.write(
      `PTAH ${command} failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}

if (
  args.length === 0 ||
  args[0] === "help" ||
  args[0] === "--help" ||
  args[0] === "-h"
) {
  printHelp();
} else if (args[0] === "info") {
  printInfo(args.includes("--json"));
} else if (args[0] === "--version" || args[0] === "-V") {
  process.stdout.write(
    `PTAH migration preview (REA compatibility engine ${packageJson.version})\n`,
  );
} else if (args[0] === "self-check") {
  process.exitCode = await selfCheck(args.includes("--json"));
} else if (["add-claim", "add-question", "add-action"].includes(args[0])) {
  try {
    if (args[0] === "add-claim") await runAddClaim();
    else if (args[0] === "add-question") await runAddQuestion();
    else await runAddAction();
  } catch (error) {
    process.stderr.write(
      `PTAH ${args[0]} failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "add-evidence") {
  try {
    await runAddEvidence();
  } catch (error) {
    process.stderr.write(
      `PTAH add-evidence failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "providers") {
  try {
    const result = args.includes("--probe")
      ? await probeProviders(process.env, {
          timeoutMs:
            optionValue("--timeout-ms") === undefined
              ? 3000
              : Number(optionValue("--timeout-ms")),
          maxOutputBytes:
            optionValue("--max-output-bytes") === undefined
              ? 8192
              : Number(optionValue("--max-output-bytes")),
        })
      : await discoverProviders();
    if (args.includes("--json")) {
      emit(result);
    } else if (args.includes("--probe")) {
      process.stdout.write(
        result.providers
          .map(
            (provider) =>
              `${provider.probe.status === "ok" ? "[ok]" : provider.probe.status === "not-found" ? "[ ]" : "[!]"} ${provider.label}${provider.probe.stdout || provider.probe.stderr ? ` — ${(provider.probe.stdout || provider.probe.stderr).trim().split("\n")[0]}` : ""}`,
          )
          .join("\n") +
          `\n\nProbed ${result.summary.probed}; successful ${result.summary.successful}; failed ${result.summary.failed}. ${result.detection}.\n`,
      );
    } else {
      process.stdout.write(
        result.providers
          .map(
            (provider) =>
              `${provider.available ? "[x]" : "[ ]"} ${provider.label}${provider.foundCommands.length ? ` — ${provider.foundCommands.map((item) => item.path).join(", ")}` : ""}`,
          )
          .join("\n") +
          `\n\nDetected ${result.summary.detected}/${result.summary.total} providers. ${result.detection}.\n`,
      );
    }
  } catch (error) {
    process.stderr.write(
      `PTAH providers failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "fingerprint" || args[0] === "init") {
  try {
    if (args[0] === "fingerprint") await runFingerprint();
    else await runInit();
  } catch (error) {
    process.stderr.write(
      `PTAH ${args[0]} failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "ui") {
  const child = spawn(
    process.execPath,
    [join(root, "scripts/ptah-ui.mjs"), ...args.slice(1)],
    { cwd: root, env: process.env, stdio: "inherit" },
  );
  child.once("error", (error) => {
    process.stderr.write(`PTAH UI could not start: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.once("close", (code, signal) => {
    process.exitCode = signal ? 1 : (code ?? 1);
  });
} else if (args[0] === "analyze") {
  try {
    const target = optionValue("--target");
    const provider = optionValue("--provider");
    if (!target) throw new Error("Missing required --target FILE argument.");
    if (!provider)
      throw new Error(
        `Missing required --provider argument; allowed: ${STATIC_ANALYZER_IDS.join("|")}.`,
      );
    const timeoutValue = optionValue("--timeout-ms");
    const outputLimit = optionValue("--max-output-bytes");
    const limits = {};
    const cpuSeconds = optionValue("--cpu-seconds");
    const memoryMb = optionValue("--memory-mb");
    if (cpuSeconds !== undefined) limits.cpuSeconds = Number(cpuSeconds);
    if (memoryMb !== undefined)
      limits.memoryBytes = Number(memoryMb) * 1024 * 1024;
    const result = await analyzeTarget(target, provider, {
      timeoutMs: timeoutValue === undefined ? 5000 : Number(timeoutValue),
      maxOutputBytes: outputLimit === undefined ? 16384 : Number(outputLimit),
      isolation: optionValue("--isolation") ?? "auto",
      ...(Object.keys(limits).length ? { limits } : {}),
    });
    const investigationPath = optionValue("--investigation");
    const savePath = optionValue("--save-investigation");
    const evidenceId = optionValue("--evidence-id");
    const recordingRequested =
      investigationPath !== undefined ||
      savePath !== undefined ||
      evidenceId !== undefined;
    if (recordingRequested) {
      if (!investigationPath || !savePath || !evidenceId)
        throw new Error(
          "--investigation, --save-investigation, and --evidence-id must be supplied together.",
        );
      if (result.status !== "ok" || result.targetChanged)
        throw new Error(
          "Analysis failed or target changed; no evidence was recorded.",
        );
      const investigation = JSON.parse(
        await readFile(resolve(process.cwd(), investigationPath), "utf8"),
      );
      const updated = attachAnalysisEvidence(investigation, result, evidenceId);
      const savedTo = await saveInvestigation(savePath, updated);
      result.evidence = {
        id: evidenceId,
        investigationPath: savedTo,
        recorded: true,
      };
    }
    emit(result);
    if (result.status !== "ok" || result.targetChanged) process.exitCode = 2;
  } catch (error) {
    process.stderr.write(
      `PTAH analyze failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "verify") {
  try {
    await runVerify();
  } catch (error) {
    process.stderr.write(
      `PTAH verify failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (["export-case", "verify-case", "import-case"].includes(args[0])) {
  try {
    if (args[0] === "export-case") await runExportCase();
    else if (args[0] === "verify-case") await runVerifyCase();
    else await runImportCase();
  } catch (error) {
    process.stderr.write(
      `PTAH ${args[0]} failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "diff") {
  try {
    await runDiff();
  } catch (error) {
    process.stderr.write(
      `PTAH diff failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "schema") {
  emit(investigationJsonSchema());
} else if (Object.hasOwn(COMMAND_HANDLERS, args[0])) {
  try {
    const handlers = COMMAND_HANDLERS;
    await handlers[args[0]]();
  } catch (error) {
    process.stderr.write(
      `PTAH ${args[0]} failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
} else if (args[0] === "report" || args[0] === "plan" || args[0] === "graph") {
  await runEngineCommand(args[0]);
} else {
  const legacyArgs = args[0] === "legacy" ? args.slice(1) : args;
  const child = spawn(
    process.execPath,
    [join(root, "scripts/rea.mjs"), ...legacyArgs],
    {
      cwd: root,
      env: { ...process.env, PTAH_COMPAT_MODE: "1" },
      stdio: "inherit",
    },
  );
  child.once("error", (error) => {
    process.stderr.write(
      `PTAH could not start the REA compatibility runtime: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
  child.once("close", (code, signal) => {
    if (signal) {
      process.exitCode = 1;
    } else if (code !== null) {
      process.exitCode = code;
    }
  });
}
