/**
 * #49  Plugin API — load third-party providers without forking PTAH.
 *
 * A PTAH plugin is any ES module that exports a `providers()` function
 * returning an array of AnalysisProvider instances. PTAH validates each
 * one against the contract before registering it, so a malformed plugin
 * cannot silently corrupt the registry.
 *
 * Usage:
 *   const registry = createDefaultRegistry();
 *   await loadPlugin(registry, "file:///path/to/my-plugin.mjs");
 *   // my-plugin.mjs exports: export function providers() { return [new MyProvider()]; }
 */
import { contractProblems } from "./provider.mjs";

/**
 * Load a plugin module from `moduleUrl` and register its providers into
 * `registry`. Returns the list of provider ids that were registered.
 * Throws if the module does not export `providers()` or if any provider
 * breaks the contract.
 */
export async function loadPlugin(registry, moduleUrl) {
  let mod;
  try {
    mod = await import(moduleUrl);
  } catch (error) {
    throw new Error(`failed to import plugin ${moduleUrl}: ${error.message}`);
  }
  if (typeof mod.providers !== "function")
    throw new TypeError(
      `plugin ${moduleUrl} must export a providers() function returning AnalysisProvider[]`,
    );
  const instances = mod.providers();
  if (!Array.isArray(instances))
    throw new TypeError(`plugin ${moduleUrl} providers() must return an array`);
  const registered = [];
  for (const provider of instances) {
    const problems = contractProblems(provider);
    if (problems.length)
      throw new TypeError(
        `plugin ${moduleUrl} provider ${provider?.id ?? "?"} breaks the contract: ${problems.join("; ")}`,
      );
    registry.register(provider);
    registered.push(provider.id);
  }
  return registered;
}

/**
 * Load multiple plugins in order, collecting all registered provider ids.
 * Failures in any plugin are re-thrown; partial registration may occur.
 */
export async function loadPlugins(registry, moduleUrls) {
  const all = [];
  for (const url of moduleUrls) {
    const ids = await loadPlugin(registry, url);
    all.push(...ids);
  }
  return all;
}
