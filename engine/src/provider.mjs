/**
 * The AnalysisProvider contract. Every engine, external tool, and built-in
 * inspector implements it. Task methods receive an identified target and a
 * context, and return an array of Evidence objects; they never return raw
 * tool output (each provider maps its tool's format into evidence itself).
 */
import { TASKS } from "./evidence.mjs";

/** A provider was asked for a task it does not implement. */
export class UnsupportedTask extends Error {
  constructor(provider, task) {
    super(`${provider} does not implement ${task}`);
    this.name = "UnsupportedTask";
  }
}

export const PROVIDER_KINDS = Object.freeze(["builtin", "tool", "engine"]);

/**
 * Base class. Subclasses set `id`, `name`, `kind`, `license`, and override
 * `capabilities()`, `isAvailable()`, and the task methods they support.
 */
export class AnalysisProvider {
  id = "unnamed";
  name = "Unnamed provider";
  kind = "tool";
  /** SPDX id or "commercial (user-licensed)". PTAH never bundles commercial engines. */
  license = "unknown";

  /** @returns {{ formats: string[], tasks: Record<string, { priority: number }> }} */
  capabilities() {
    return { formats: [], tasks: {} };
  }

  /** @returns {Promise<{ available: boolean, version?: string|null, reason?: string }>} */
  async isAvailable() {
    return { available: false, reason: "not implemented" };
  }

  async disassemble() {
    throw new UnsupportedTask(this.id, "disassemble");
  }
  async decompile() {
    throw new UnsupportedTask(this.id, "decompile");
  }
  async strings() {
    throw new UnsupportedTask(this.id, "strings");
  }
  async symbols() {
    throw new UnsupportedTask(this.id, "symbols");
  }
  async importsExports() {
    throw new UnsupportedTask(this.id, "importsExports");
  }
  async resources() {
    throw new UnsupportedTask(this.id, "resources");
  }
  async manifest() {
    throw new UnsupportedTask(this.id, "manifest");
  }
  async sections() {
    throw new UnsupportedTask(this.id, "sections");
  }
}

/** Check that an object satisfies the contract; returns a list of problems. */
export function contractProblems(provider) {
  const problems = [];
  for (const field of ["id", "name", "kind", "license"])
    if (typeof provider?.[field] !== "string" || provider[field] === "")
      problems.push(`missing ${field}`);
  if (!PROVIDER_KINDS.includes(provider?.kind))
    problems.push(`kind must be one of ${PROVIDER_KINDS.join(", ")}`);
  for (const method of ["capabilities", "isAvailable", ...TASKS])
    if (typeof provider?.[method] !== "function")
      problems.push(`missing method ${method}()`);
  if (problems.length === 0) {
    const caps = provider.capabilities();
    if (!Array.isArray(caps?.formats))
      problems.push("capabilities().formats must be an array");
    for (const task of Object.keys(caps?.tasks ?? {}))
      if (!TASKS.includes(task))
        problems.push(`capabilities() declares unknown task ${task}`);
  }
  return problems;
}
