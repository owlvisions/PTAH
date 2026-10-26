/**
 * Shared base for providers backed by an external executable: discovery on
 * PATH, version probing, bounded execution, and evidence construction. Raw
 * output never leaves the adapter; only the mapped data and its digest do.
 */
import { sha256 } from "../canonical.mjs";
import { createEvidence } from "../evidence.mjs";
import { findExecutable, runTool, toolEnvironment } from "../exec.mjs";
import { AnalysisProvider } from "../provider.mjs";

/** The tool ran but did not produce a usable result. */
export class ToolFailure extends Error {
  constructor(tool, detail) {
    super(`${tool} failed: ${detail}`);
    this.name = "ToolFailure";
  }
}

export class ToolProvider extends AnalysisProvider {
  kind = "tool";
  /** Executable names to try, first found wins. */
  executables = [];
  /** Arguments that print a version; the first output line is kept. */
  versionArgs = ["--version"];
  #resolved;

  async isAvailable(context = {}) {
    const env = context.env ?? process.env;
    for (const name of this.executables) {
      const path = await findExecutable(name, env);
      if (!path) continue;
      const probe = await runTool(path, this.versionArgs, {
        timeoutMs: 5000,
        maxOutputBytes: 8192,
        env: toolEnvironment(env),
      });
      const version =
        `${probe.stdout}\n${probe.stderr}`.trim().split("\n")[0]?.trim() ||
        null;
      this.#resolved = { path, version, env };
      return { available: true, version };
    }
    this.#resolved = undefined;
    return {
      available: false,
      reason: `${this.executables.join(" or ")} not found on PATH`,
    };
  }

  /**
   * Run the tool on a target. `args` contains the literal "{target}" where
   * the target path goes; evidence records "<target>" there so it stays
   * identical across machines.
   */
  async execute(target, args, context = {}) {
    if (!this.#resolved) {
      const state = await this.isAvailable(context);
      if (!state.available) throw new ToolFailure(this.id, state.reason);
    }
    const { path, version, env } = this.#resolved;
    const argv = args.map((arg) => (arg === "{target}" ? target.path : arg));
    const result = await runTool(path, argv, {
      timeoutMs: context.timeoutMs ?? 30_000,
      maxOutputBytes: context.maxOutputBytes ?? 8 * 1024 * 1024,
      env: toolEnvironment(env),
    });
    if (result.timedOut)
      throw new ToolFailure(
        this.id,
        `timed out after ${context.timeoutMs ?? 30_000} ms`,
      );
    if (result.code !== 0)
      throw new ToolFailure(
        this.id,
        `exit ${result.code ?? result.signal}: ${result.stderr.trim().slice(0, 300)}`,
      );
    return {
      stdout: result.stdout,
      truncated: result.truncated,
      provider: {
        id: this.id,
        tool: this.executables[0],
        version,
        argv: [
          this.executables[0],
          ...args.map((arg) => (arg === "{target}" ? "<target>" : arg)),
        ],
      },
      rawSha256: sha256(result.stdout),
    };
  }

  /** Build observed evidence from an execution and mapped data. */
  evidence(
    task,
    target,
    run,
    {
      summary,
      data,
      limitations = [],
      confidence = "observed",
      partial = false,
    },
  ) {
    return createEvidence({
      task,
      targetSha256: target.sha256,
      provider: run.provider,
      confidence,
      status: run.truncated || partial ? "partial" : "ok",
      summary,
      data,
      rawSha256: run.rawSha256,
      limitations: run.truncated
        ? [
            ...limitations,
            "Tool output exceeded the capture limit; results are partial.",
          ]
        : limitations,
    });
  }
}
