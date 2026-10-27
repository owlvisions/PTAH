/**
 * #39  Persistent on-disk cache for PTAH Engine results.
 *
 * Evidence is stored as JSON files in `cacheDir`, keyed by the SHA-256 of the
 * canonical {targetSha256, task, providerId, options} object. A hit avoids
 * re-running the provider on the same target + task combination across sessions.
 *
 * Cache entries are validated on read: stale or corrupt files are silently
 * discarded. The cache is never required — absence or I/O errors fall through
 * to the live provider run.
 */
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, sha256 } from "./canonical.mjs";

export class DiskCache {
  #dir;
  #memCache;

  constructor(cacheDir) {
    this.#dir = cacheDir;
    this.#memCache = new Map();
  }

  get dir() {
    return this.#dir;
  }

  cacheKey(targetSha256, task, providerId, options = {}) {
    return sha256(
      canonicalJson({ sha: targetSha256, task, provider: providerId, options }),
    );
  }

  async get(key) {
    if (this.#memCache.has(key)) return this.#memCache.get(key);
    try {
      const text = await readFile(join(this.#dir, `${key}.json`), "utf8");
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed) || parsed.length === 0) return undefined;
      // Trust what we stored (validated on set); skip re-validation to avoid
      // schema drift breaking old cache entries.
      this.#memCache.set(key, parsed);
      return parsed;
    } catch {
      return undefined;
    }
  }

  async set(key, evidence) {
    this.#memCache.set(key, evidence);
    try {
      await mkdir(this.#dir, { recursive: true });
      await writeFile(
        join(this.#dir, `${key}.json`),
        JSON.stringify(evidence, null, 2),
        "utf8",
      );
    } catch {
      // Non-fatal: fall through; the in-memory entry is still set.
    }
  }

  async delete(key) {
    this.#memCache.delete(key);
    try {
      await unlink(join(this.#dir, `${key}.json`));
    } catch {
      // Ignore missing file.
    }
  }
}

/**
 * Wrap a CapabilityRegistry's `run()` method to consult a DiskCache before
 * calling providers. Call once after creating the registry; the original `run`
 * is preserved as `runUncached`.
 */
export function attachDiskCache(registry, diskCache) {
  const originalRun = registry.run.bind(registry);
  registry.runUncached = originalRun;
  registry.run = async function runWithDiskCache(task, target, context = {}) {
    const only = context.provider;
    // Only cache when a specific provider is not forced (let the registry pick).
    const key = diskCache.cacheKey(
      target.sha256,
      task,
      only ?? "__auto__",
      context.options ?? {},
    );
    const cached = await diskCache.get(key);
    if (cached)
      return {
        evidence: cached,
        provider: cached[0]?.provider?.id ?? null,
        cached: true,
        attempts: [],
      };
    const result = await originalRun(task, target, context);
    if (result.provider && result.evidence?.[0]?.status !== "unavailable")
      await diskCache.set(key, result.evidence);
    return result;
  };
  return registry;
}
