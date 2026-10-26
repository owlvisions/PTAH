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
import { dirname, join, resolve } from "node:path";
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
} from "./ptah-engine.mjs";

process.stdout.on("error", (error) => {
  if (error.code === "EPIPE") process.exit(0);
  process.stderr.write(`PTAH output error: ${error.message}\n`);
  process.exitCode = 1;
});

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const packageJson = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);

function printHelp() {
  process.stdout.write(
    `PTAH — program analysis and reverse-engineering platform\n\n`,
  );
  process.stdout.write(`Usage:\n`);
  process.stdout.write(
    `  ptah info                 Show PTAH migration and engine information\n`,
  );
  process.stdout.write(
    `  ptah self-check [--json]  Check local runtime/build readiness\n`,
  );
  process.stdout.write(
    `  ptah providers [--json] [--probe]  Detect tools; --probe runs bounded version/help checks\n`,
  );
  process.stdout.write(
    `  ptah analyze --target FILE --provider objdump|llvm-objdump|wasm-tools  Run bounded static metadata analysis\n`,
  );
  process.stdout.write(
    `       [--investigation FILE --save-investigation FILE --evidence-id ID]  Record successful analysis as evidence\n`,
  );
  process.stdout.write(
    `  ptah fingerprint --target FILE  Hash and identify a file without executing it\n`,
  );
  process.stdout.write(
    `  ptah init --target FILE --output FILE [--id ID]  Create an investigation tied to target bytes\n`,
  );
  process.stdout.write(
    `  ptah add-evidence --input FILE --output FILE --id ID --kind KIND --summary TEXT --source REF [--confidence observed|derived|inferred]\n`,
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
    `  ptah verify --input FILE [--target FILE]  Validate evidence and optionally re-hash target bytes\n`,
  );
  process.stdout.write(
    `  ptah ui [--port 4177]  Start the loopback-only local GUI\n`,
  );
  process.stdout.write(
    `  ptah report --input FILE  Validate an investigation and print an evidence report\n`,
  );
  process.stdout.write(
    `  ptah graph --input FILE   Export a directed evidence graph as JSON\n`,
  );
  process.stdout.write(
    `  ptah plan --input FILE    Plan one bounded investigation step\n`,
  );
  process.stdout.write(`  ptah help                 Show this help\n`);
  process.stdout.write(`  ptah <existing-rea-command>\n`);
  process.stdout.write(
    `                            Run an existing REA command through the compatibility layer\n\n`,
  );
  process.stdout.write(
    "The original REA CLI remains available as `rea` and `rea-agents`.\n",
  );
}

function printInfo(json = false) {
  const info = {
    product: "PTAH",
    status: "migration-preview",
    compatibilityEngine: packageJson.name,
    compatibilityEngineVersion: packageJson.version,
    packageManagerNameUnchanged: true,
    entrypoints: {
      ptah: "scripts/ptah.mjs",
      legacy: "scripts/rea.mjs",
    },
    nativeCapabilities: "delegated to the existing REA runtime in this phase",
    nextMilestone:
      "baseline evaluation and unified investigation/evidence contracts",
  };
  process.stdout.write(
    json
      ? `${JSON.stringify(info, null, 2)}\n`
      : `PTAH migration preview\n` +
          `Compatibility engine: ${info.compatibilityEngine} ${info.compatibilityEngineVersion}\n` +
          `Status: ${info.status}\n` +
          `Existing REA commands remain available.\n` +
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
  const supported =
    (major === 22 && (minor > 19 || (minor === 19 && patch >= 0))) ||
    (major === 24 && (minor > 11 || (minor === 11 && patch >= 0))) ||
    major >= 26;
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
    process.stdout.write(`${JSON.stringify({ ...result, issues }, null, 2)}\n`);
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
  const result = await fingerprintTarget(target);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

async function runInit() {
  const target = optionValue("--target");
  const output = optionValue("--output");
  const id = optionValue("--id");
  if (!target) throw new Error("Missing required --target FILE argument.");
  if (!output) throw new Error("Missing required --output FILE argument.");
  const investigation = await createInvestigationForTarget(target, id);
  const savedTo = await saveInvestigation(output, investigation);
  process.stdout.write(
    `${JSON.stringify({ status: "created", path: savedTo, target: investigation.target, schemaVersion: investigation.schemaVersion }, null, 2)}\n`,
  );
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
  input.evidence ??= [];
  if (input.evidence.some((item) => item.id === id))
    throw new Error(`Evidence id already exists: ${id}`);
  input.evidence.push({
    id,
    kind,
    summary,
    source,
    confidence,
    targetSha256: input.target.sha256,
  });
  const savedTo = await saveInvestigation(output, input);
  process.stdout.write(
    `${JSON.stringify({ status: "evidence-added", evidenceId: id, targetSha256: input.target.sha256, path: savedTo }, null, 2)}\n`,
  );
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
  input[collection] ??= [];
  if (input[collection].some((item) => item.id === record.id))
    throw new Error(`${collection} id already exists: ${record.id}`);
  input[collection].push(record);
  const savedTo = await saveInvestigation(output, input);
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
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.valid) process.exitCode = 2;
}

async function runEngineCommand(command) {
  try {
    const input = await readInvestigationInput();
    let output;
    if (command === "report") {
      output = buildEvidenceReport(input);
    } else if (command === "graph") {
      output = buildEvidenceGraph(input);
    } else {
      const callsIndex = args.indexOf("--max-calls");
      const costIndex = args.indexOf("--max-cost");
      const budget = {};
      if (callsIndex >= 0) budget.maxCalls = Number(args[callsIndex + 1]);
      if (costIndex >= 0) budget.maxCost = Number(args[costIndex + 1]);
      output = planNextAction(input, budget);
    }
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
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
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
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
        "Missing required --provider objdump|llvm-objdump|wasm-tools argument.",
      );
    const timeoutValue = optionValue("--timeout-ms");
    const outputLimit = optionValue("--max-output-bytes");
    const result = await analyzeTarget(target, provider, {
      timeoutMs: timeoutValue === undefined ? 5000 : Number(timeoutValue),
      maxOutputBytes: outputLimit === undefined ? 16384 : Number(outputLimit),
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
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
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
