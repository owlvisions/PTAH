/**
 * Ghidra headless engine adapter. Imports the target into a throwaway project
 * and runs a bundled postscript (adapters/ghidra/PtahExport.java) that writes
 * decompiled functions and symbols as JSON. One run serves both the decompile
 * and symbols tasks (memoized per target digest). Ghidra is free/open and a
 * documented dependency; nothing is bundled from it.
 */
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "../canonical.mjs";
import { createEvidence } from "../evidence.mjs";
import { findExecutable, runTool, toolEnvironment } from "../exec.mjs";
import { AnalysisProvider } from "../provider.mjs";
import { ToolFailure } from "./tool-provider.mjs";

const SCRIPT_DIR = join(dirname(fileURLToPath(import.meta.url)), "ghidra");
const SCRIPT = "PtahExport.java";

/** Candidate analyzeHeadless locations, env first. */
function candidatePaths(env) {
  const names = ["analyzeHeadless", "analyzeHeadless.bat"];
  const roots = [
    env.GHIDRA_INSTALL_DIR,
    "/usr/share/ghidra",
    "/opt/ghidra",
    "/usr/local/share/ghidra",
  ].filter(Boolean);
  return roots.flatMap((root) =>
    names.map((name) => join(root, "support", name)),
  );
}

export class GhidraProvider extends AnalysisProvider {
  id = "ghidra";
  name = "Ghidra (headless)";
  kind = "engine";
  license = "Apache-2.0";
  #headless;
  #runs = new Map();

  capabilities() {
    return {
      formats: ["elf", "pe", "macho", "dex"],
      tasks: { decompile: { priority: 8 }, symbols: { priority: 2 } },
    };
  }

  async isAvailable(context = {}) {
    const env = context.env ?? process.env;
    for (const path of candidatePaths(env)) {
      const found = await findExecutable(path, env);
      if (found) {
        this.#headless = found;
        const properties = await readFile(
          join(found, "..", "..", "Ghidra", "application.properties"),
          "utf8",
        ).catch(() => "");
        return {
          available: true,
          version:
            /application\.version=(.+)/u.exec(properties)?.[1]?.trim() ?? null,
        };
      }
    }
    const onPath = await findExecutable("analyzeHeadless", env);
    if (onPath) {
      this.#headless = onPath;
      return { available: true, version: null };
    }
    return {
      available: false,
      reason: "analyzeHeadless not found; set GHIDRA_INSTALL_DIR",
    };
  }

  /** Import the target and run the export postscript once; memoized per digest. */
  async #analyze(target, context) {
    if (this.#runs.has(target.sha256)) return this.#runs.get(target.sha256);
    const promise = (async () => {
      if (!this.#headless) {
        const state = await this.isAvailable(context);
        if (!state.available) throw new ToolFailure(this.id, state.reason);
      }
      const base = await mkdtemp(join(tmpdir(), "ptah-ghidra-"));
      const project = join(base, "proj");
      await mkdir(project, { recursive: true });
      const output = join(base, "export.json");
      const maxFns = context.options?.maxFunctions ?? 1500;
      try {
        const result = await runTool(
          this.#headless,
          [
            project,
            "ptah",
            "-import",
            target.path,
            "-scriptPath",
            SCRIPT_DIR,
            "-postScript",
            SCRIPT,
            "-deleteProject",
            "-analysisTimeoutPerFile",
            "600",
          ],
          {
            timeoutMs: context.timeoutMs ?? 900_000,
            maxOutputBytes: 2 * 1024 * 1024,
            env: toolEnvironment(context.env ?? process.env, {
              PTAH_OUT: output,
              PTAH_MAX_FUNCS: String(maxFns),
            }),
          },
        );
        if (result.timedOut)
          throw new ToolFailure(
            this.id,
            `analyzeHeadless timed out after ${context.timeoutMs ?? 900_000} ms`,
          );
        const text = await readFile(output, "utf8").catch(() => null);
        if (!text)
          throw new ToolFailure(
            this.id,
            `no export produced (exit ${result.code}): ${result.stderr.trim().slice(0, 300)}`,
          );
        const parsed = JSON.parse(text);
        return {
          parsed,
          version: (await this.isAvailable(context)).version,
          rawSha256: sha256(text),
          maxFns,
        };
      } finally {
        await rm(base, { recursive: true, force: true });
      }
    })();
    this.#runs.set(target.sha256, promise);
    return promise;
  }

  #provider(argv) {
    return {
      id: this.id,
      tool: "analyzeHeadless",
      version: undefined,
      argv: [
        "analyzeHeadless",
        "<project>",
        "ptah",
        "-import",
        "<target>",
        "-postScript",
        SCRIPT,
        ...argv,
      ],
    };
  }

  async decompile(target, context = {}) {
    const { parsed, rawSha256, maxFns } = await this.#analyze(target, context);
    const classes = parsed.functions
      .filter((fn) => fn.code)
      .map((fn) => ({
        name: fn.name,
        entry: fn.entry,
        size: fn.size,
        code: fn.code,
      }));
    return [
      createEvidence({
        task: "decompile",
        targetSha256: target.sha256,
        provider: this.#provider([]),
        confidence: "derived",
        status: parsed.functionCount >= maxFns ? "partial" : "ok",
        summary: `Decompiled ${classes.length} of ${parsed.functionCount} functions (${parsed.language})`,
        data: { language: "c", from: parsed.language, functions: classes },
        rawSha256,
        limitations: [
          "Decompiled C is a reconstruction of behavior, not the original source.",
          ...(parsed.functionCount >= maxFns
            ? [`Stopped at the ${maxFns}-function cap.`]
            : []),
        ],
      }),
    ];
  }

  async symbols(target, context = {}) {
    const { parsed, rawSha256 } = await this.#analyze(target, context);
    return [
      createEvidence({
        task: "symbols",
        targetSha256: target.sha256,
        provider: this.#provider([]),
        confidence: "derived",
        status: "ok",
        summary: `${parsed.symbols.length} symbols recovered by analysis`,
        data: { tables: { analysis: parsed.symbols } },
        rawSha256,
        limitations: [
          "Symbols include names Ghidra inferred during analysis, not only those present in the file.",
        ],
      }),
    ];
  }
}

export const ghidraProviders = () => [new GhidraProvider()];
