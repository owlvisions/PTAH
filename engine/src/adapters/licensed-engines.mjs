/**
 * Adapters for engines PTAH must NOT bundle: IDA, Hopper, JEB (commercial),
 * and Kuna. Each integrates with the user's own installation, located only
 * through an explicit environment variable. When the variable is unset the
 * provider reports unavailable with the exact variable to set, so the registry
 * degrades instead of failing. These never download or install anything.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "../canonical.mjs";
import { createEvidence } from "../evidence.mjs";
import { findExecutable, runTool, toolEnvironment } from "../exec.mjs";
import { AnalysisProvider } from "../provider.mjs";
import { ToolFailure } from "./tool-provider.mjs";

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), "scripts");

/**
 * Base for a user-licensed headless engine located by one env var. Subclasses
 * set the identity, the variable, and a `decompileScript`/argv builder.
 */
class LicensedEngine extends AnalysisProvider {
  kind = "engine";
  /** The environment variable naming the user's installed binary. */
  envVar = "";
  #binary;

  capabilities() {
    return { formats: [], tasks: {} };
  }

  async isAvailable(context = {}) {
    const env = context.env ?? process.env;
    const configured = env[this.envVar];
    if (!configured)
      return {
        available: false,
        reason: `${this.name} is user-licensed and not bundled; set ${this.envVar} to your installed binary to enable it`,
      };
    const path = await findExecutable(configured, env);
    if (!path)
      return {
        available: false,
        reason: `${this.envVar}=${configured} is not an executable on this machine`,
      };
    this.#binary = path;
    return { available: true, version: null };
  }

  /** Run the engine's headless CLI; subclasses provide argv and an output reader. */
  async runHeadless(target, args, readOutput, context) {
    if (!this.#binary) {
      const state = await this.isAvailable(context);
      if (!state.available) throw new ToolFailure(this.id, state.reason);
    }
    const result = await runTool(this.#binary, args, {
      timeoutMs: context.timeoutMs ?? 900_000,
      maxOutputBytes: 4 * 1024 * 1024,
      env: toolEnvironment(context.env ?? process.env, context.extraEnv ?? {}),
    });
    if (result.timedOut)
      throw new ToolFailure(this.id, "the licensed engine timed out");
    const text = await readOutput();
    if (text === null)
      throw new ToolFailure(
        this.id,
        `no output produced (exit ${result.code}): ${result.stderr.trim().slice(0, 200)}`,
      );
    return text;
  }

  evidence(
    task,
    target,
    text,
    { summary, data, confidence = "derived", limitations = [] },
  ) {
    return createEvidence({
      task,
      targetSha256: target.sha256,
      provider: {
        id: this.id,
        tool: this.id,
        version: null,
        argv: [`$${this.envVar}`, "<headless>", "<target>"],
      },
      confidence,
      status: "ok",
      summary,
      data,
      rawSha256: sha256(text),
      limitations: [
        `Produced by the user's licensed ${this.name} install, located via ${this.envVar}.`,
        ...limitations,
      ],
    });
  }
}

/**
 * IDA Pro / idat headless. The user points PTAH_IDA_BINARY at idat (or idat64)
 * and PTAH_IDA_SCRIPT at an IDAPython script that writes JSON to $PTAH_OUT.
 * Without the script PTAH does not ship IDA automation.
 */
export class IdaProvider extends LicensedEngine {
  id = "ida";
  name = "IDA";
  license = "commercial (user-licensed)";
  envVar = "PTAH_IDA_BINARY";
  capabilities() {
    return {
      formats: ["elf", "pe", "macho"],
      tasks: { decompile: { priority: 9 }, symbols: { priority: 3 } },
    };
  }
  async #run(target, context) {
    const env = context.env ?? process.env;
    // Default to the shipped headless script so the adapter is turnkey once
    // the licensed tool is present; override with PTAH_IDA_SCRIPT.
    const script = env.PTAH_IDA_SCRIPT ?? join(SCRIPTS, "ptah_ida_export.py");
    const out = `${target.path}.ptah-ida.json`;
    const text = await this.runHeadless(
      target,
      ["-A", `-S${script}`, `-OPTAH_OUT:${out}`, target.path],
      () => readFile(out, "utf8").catch(() => null),
      { ...context, extraEnv: { PTAH_OUT: out } },
    );
    return JSON.parse(text);
  }
  async decompile(target, context = {}) {
    const data = await this.#run(target, context);
    return [
      this.evidence("decompile", target, JSON.stringify(data), {
        summary: `IDA decompiled ${data.functions?.length ?? 0} functions`,
        data: { language: "c", functions: data.functions ?? [] },
      }),
    ];
  }
  async symbols(target, context = {}) {
    const data = await this.#run(target, context);
    return [
      this.evidence("symbols", target, JSON.stringify(data), {
        summary: `${data.symbols?.length ?? 0} symbols`,
        data: { tables: { ida: data.symbols ?? [] } },
      }),
    ];
  }
}

/** Hopper headless via its CLI script runner (PTAH_HOPPER_BINARY). */
export class HopperProvider extends LicensedEngine {
  id = "hopper";
  name = "Hopper";
  license = "commercial (user-licensed)";
  envVar = "PTAH_HOPPER_BINARY";
  capabilities() {
    return {
      formats: ["elf", "pe", "macho"],
      tasks: { decompile: { priority: 7 } },
    };
  }
  async decompile(target, context = {}) {
    const env = context.env ?? process.env;
    // Default to the shipped headless script so the adapter is turnkey once
    // the licensed tool is present; override with PTAH_HOPPER_SCRIPT.
    const script =
      env.PTAH_HOPPER_SCRIPT ?? join(SCRIPTS, "ptah_hopper_export.py");
    const out = `${target.path}.ptah-hopper.json`;
    const text = await this.runHeadless(
      target,
      ["-y", "-l", target.path, "-s", script],
      () => readFile(out, "utf8").catch(() => null),
      { ...context, extraEnv: { PTAH_OUT: out } },
    );
    const data = JSON.parse(text);
    return [
      this.evidence("decompile", target, text, {
        summary: `Hopper decompiled ${data.functions?.length ?? 0} functions`,
        data: { language: "c", functions: data.functions ?? [] },
      }),
    ];
  }
}

/** JEB headless for Android/DEX via its CLI (PTAH_JEB_BINARY + PTAH_JEB_SCRIPT). */
export class JebProvider extends LicensedEngine {
  id = "jeb";
  name = "JEB";
  license = "commercial (user-licensed)";
  envVar = "PTAH_JEB_BINARY";
  capabilities() {
    return {
      formats: ["apk", "aab", "dex"],
      tasks: { decompile: { priority: 9 } },
    };
  }
  async decompile(target, context = {}) {
    const env = context.env ?? process.env;
    // Default to the shipped headless script so the adapter is turnkey once
    // the licensed tool is present; override with PTAH_JEB_SCRIPT.
    const script = env.PTAH_JEB_SCRIPT ?? join(SCRIPTS, "ptah_jeb_export.py");
    const out = `${target.path}.ptah-jeb.json`;
    const text = await this.runHeadless(
      target,
      ["-c", `--srv2`, `--script=${script}`, target.path],
      () => readFile(out, "utf8").catch(() => null),
      { ...context, extraEnv: { PTAH_OUT: out } },
    );
    const data = JSON.parse(text);
    return [
      this.evidence("decompile", target, text, {
        summary: `JEB decompiled ${data.classes?.length ?? 0} classes`,
        data: {
          language: data.language ?? "java",
          classes: data.classes ?? [],
        },
      }),
    ];
  }
}

/** Kuna headless (free), located by PTAH_KUNA_BINARY. */
export class KunaProvider extends LicensedEngine {
  id = "kuna";
  name = "Kuna";
  license = "user-provided";
  envVar = "PTAH_KUNA_BINARY";
  capabilities() {
    return {
      formats: ["elf", "pe", "macho"],
      tasks: { symbols: { priority: 2 } },
    };
  }
  async symbols(target, context = {}) {
    const out = `${target.path}.ptah-kuna.json`;
    const text = await this.runHeadless(
      target,
      ["--json", "-o", out, target.path],
      () => readFile(out, "utf8").catch(() => null),
      context,
    );
    const data = JSON.parse(text);
    return [
      this.evidence("symbols", target, text, {
        summary: `${data.symbols?.length ?? 0} symbols`,
        data: { tables: { kuna: data.symbols ?? [] } },
      }),
    ];
  }
}

export const licensedEngineProviders = () => [
  new IdaProvider(),
  new HopperProvider(),
  new JebProvider(),
  new KunaProvider(),
];
