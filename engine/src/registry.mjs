/**
 * Capability Registry: probes providers, builds a format → task → providers
 * table, picks the best available provider for each request, falls back to
 * the next one on failure, and degrades to "unavailable" evidence instead of
 * failing. Results are cached by target digest, task, provider, and options.
 */
import { canonicalJson, compareCodePoints, sha256 } from "./canonical.mjs";
import { TASKS, unavailableEvidence, validateEvidence } from "./evidence.mjs";
import { contractProblems } from "./provider.mjs";

const PROBE_TIMEOUT_MS = 10_000;

const withTimeout = (promise, ms, label) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(`${label} timed out after ${ms} ms`)),
        ms,
      ).unref?.(),
    ),
  ]);

export class CapabilityRegistry {
  #providers = new Map();
  #probes = new Map();
  #cache = new Map();

  /** Register a provider after checking it against the contract. */
  register(provider) {
    const problems = contractProblems(provider);
    if (problems.length)
      throw new TypeError(
        `provider ${provider?.id ?? "?"} breaks the contract: ${problems.join("; ")}`,
      );
    if (this.#providers.has(provider.id))
      throw new TypeError(`provider ${provider.id} is already registered`);
    this.#providers.set(provider.id, provider);
    return this;
  }

  get providers() {
    return [...this.#providers.values()];
  }

  /** Probe every provider's availability once; a failing probe means unavailable. */
  async probe({ timeoutMs = PROBE_TIMEOUT_MS, refresh = false } = {}) {
    await Promise.all(
      this.providers.map(async (provider) => {
        if (this.#probes.has(provider.id) && !refresh) return;
        let state;
        try {
          state = await withTimeout(
            provider.isAvailable(),
            timeoutMs,
            `${provider.id} probe`,
          );
        } catch (error) {
          state = { available: false, reason: error.message };
        }
        this.#probes.set(provider.id, {
          available: Boolean(state?.available),
          version: state?.version ?? null,
          reason: state?.reason ?? null,
        });
      }),
    );
    return this.table();
  }

  /** Availability and capabilities of every provider, plus the format → task routing. */
  table() {
    const providers = this.providers.map((provider) => ({
      id: provider.id,
      name: provider.name,
      kind: provider.kind,
      license: provider.license,
      ...provider.capabilities(),
      ...(this.#probes.get(provider.id) ?? {
        available: null,
        version: null,
        reason: "not probed",
      }),
    }));
    const routes = {};
    for (const provider of providers)
      for (const format of provider.formats)
        for (const task of Object.keys(provider.tasks)) {
          routes[format] ??= {};
          (routes[format][task] ??= []).push(provider.id);
        }
    for (const tasks of Object.values(routes))
      for (const [task, ids] of Object.entries(tasks))
        ids.sort(
          (left, right) =>
            this.#priority(right, task) - this.#priority(left, task) ||
            compareCodePoints(left, right),
        );
    return { providers, routes };
  }

  #priority(id, task) {
    return this.#providers.get(id)?.capabilities().tasks[task]?.priority ?? 0;
  }

  /** Available providers for a task on a format, best first. */
  candidates(task, format) {
    return this.providers
      .filter((provider) => {
        const caps = provider.capabilities();
        return (
          (caps.formats.includes(format) || caps.formats.includes("*")) &&
          caps.tasks[task] &&
          this.#probes.get(provider.id)?.available
        );
      })
      .sort(
        (left, right) =>
          this.#priority(right.id, task) - this.#priority(left.id, task) ||
          compareCodePoints(left.id, right.id),
      );
  }

  /**
   * Run a task with fallback. Returns the first successful provider's
   * evidence, or a single "unavailable" evidence listing every attempt.
   */
  async run(task, target, context = {}) {
    if (!TASKS.includes(task)) throw new TypeError(`unknown task: ${task}`);
    if (this.#probes.size < this.#providers.size) await this.probe();
    const attempts = [];
    const only = context.provider;
    const candidates = this.candidates(task, target.format).filter(
      (provider) => !only || provider.id === only,
    );
    for (const provider of candidates) {
      const key = sha256(
        canonicalJson({
          sha: target.sha256,
          task,
          provider: provider.id,
          options: context.options ?? {},
        }),
      );
      if (this.#cache.has(key))
        return {
          evidence: this.#cache.get(key),
          provider: provider.id,
          cached: true,
          attempts,
        };
      try {
        const evidence = (await provider[task](target, context)).map(
          validateEvidence,
        );
        if (evidence.length === 0)
          throw new Error("provider returned no evidence");
        if (evidence.some((item) => item.targetSha256 !== target.sha256))
          throw new Error(
            "provider returned evidence for a different target digest",
          );
        this.#cache.set(key, evidence);
        return { evidence, provider: provider.id, cached: false, attempts };
      } catch (error) {
        attempts.push({ provider: provider.id, error: error.message });
      }
    }
    const reason =
      candidates.length === 0
        ? `no available provider supports ${task} for format ${target.format}`
        : "every candidate provider failed";
    return {
      evidence: [
        unavailableEvidence({
          task,
          targetSha256: target.sha256,
          reason,
          attempts,
        }),
      ],
      provider: null,
      cached: false,
      attempts,
    };
  }

  /** Run several tasks concurrently with a bounded number in flight. */
  async runAll(tasks, target, context = {}, concurrency = 4) {
    const results = {};
    const queue = [...tasks];
    await Promise.all(
      Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
        while (queue.length) {
          const task = queue.shift();
          results[task] = await this.run(task, target, context);
        }
      }),
    );
    return results;
  }
}
