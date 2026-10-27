#!/usr/bin/env node
/**
 * Head-to-head harness: runs REA `inspect` and the PTAH Engine on the same
 * targets and writes engine/HEAD-TO-HEAD.md. All numbers are measured here.
 * Bridges the REA CLI (scripts/rea.mjs) and the standalone engine, so it lives
 * outside engine/ (which must stay REA-free).
 */
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compareInspections,
  createDefaultRegistry,
  createEngine,
  reaMetrics,
  renderHeadToHead,
} from "../engine/src/index.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const attestation = {
  ownership: "open-source",
  purpose: "security-research",
  statement: "head-to-head benchmark",
};

function reaInspect(target) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const child = spawn(
      process.execPath,
      [join(root, "scripts/rea.mjs"), "inspect", target, "--json"],
      { cwd: root, stdio: ["ignore", "pipe", "ignore"] },
    );
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.once("error", () => resolve(null));
    child.once("close", () => {
      const ms = Number((process.hrtime.bigint() - started) / 1_000_000n);
      try {
        resolve({ metrics: reaMetrics(JSON.parse(out)), ms });
      } catch {
        resolve(null);
      }
    });
  });
}

async function ptahInspect(engine, target) {
  const started = process.hrtime.bigint();
  const session = await engine.open(target, attestation);
  const [manifest, sections, strings, disasm] = await Promise.all([
    session.run("manifest"),
    session.run("sections"),
    session.run("strings"),
    session.run("disassemble"),
  ]);
  const ms = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const man = manifest.evidence[0].data;
  return {
    ms,
    metrics: {
      format: session.target.format,
      architecture:
        man.arch ??
        man.header?.arch ??
        (man.header?.Machine?.includes("X86-64") ? "x86_64" : null) ??
        null,
      sha256: session.target.sha256,
      sections: sections.evidence[0].data.sections?.length ?? null,
      functions: disasm.evidence[0].data.functions?.length ?? null,
      strings: strings.evidence[0].data.strings?.length ?? null,
    },
  };
}

async function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) targets.push("/bin/true");
  const engine = createEngine({ registry: createDefaultRegistry() });
  const entries = [];
  for (const target of targets) {
    const [rea, ptah] = [
      await reaInspect(target),
      await ptahInspect(engine, target),
    ];
    if (!rea) {
      process.stderr.write(`REA inspect unavailable for ${target}; skipping\n`);
      continue;
    }
    entries.push({
      target: target.split("/").pop(),
      reaMs: rea.ms,
      ptahMs: ptah.ms,
      comparison: compareInspections(rea.metrics, ptah.metrics),
    });
  }
  const markdown = renderHeadToHead(entries);
  await writeFile(join(root, "engine/HEAD-TO-HEAD.md"), markdown);
  process.stdout.write(markdown);
}

main();
