/**
 * Capability matrix and coverage summary for the PTAH Engine.
 *
 * The PTAH side is read from the live registry (measured from code). The REA
 * comparison columns are REA's *documented* capabilities, not measured here,
 * and are labelled as such: each row is marked "parity" when REA has an
 * equivalent for that format, or "beyond" when it does not.
 */
import { compareCodePoints } from "./canonical.mjs";
import { ADVANCED_ANALYZERS } from "./analyzers.mjs";

/** Formats REA is documented to analyze (used only to annotate parity). */
export const REA_FORMATS = Object.freeze(
  new Set([
    "elf",
    "pe",
    "dotnet",
    "macho",
    "apk",
    "aab",
    "dex",
    "jar",
    "java-class",
    "wasm",
    "evm",
    "il2cpp-metadata",
    "gguf",
    "safetensors",
    "godot-pck",
    "beam",
    "sqlite",
    "pcap",
    "pcapng",
    "unknown",
    "bin",
  ]),
);

/** Analysis capabilities REA does not have; PTAH's additions over REA. */
export const BEYOND_REA = Object.freeze(
  new Set([
    "dependencies",
    "diff",
    "yara",
    "capstone",
    "unicorn",
    "angr",
    "frida",
    "diffoscope",
    "cross-validation",
  ]),
);

/**
 * One row per (format, task): which providers serve it, and whether it is at
 * parity with REA or beyond it. Built from the registry's capability table.
 */
export function capabilityMatrix(registry) {
  const { providers, routes } = registry.table();
  const byId = new Map(providers.map((p) => [p.id, p]));
  const rows = [];
  for (const format of Object.keys(routes).sort(compareCodePoints))
    for (const task of Object.keys(routes[format]).sort(compareCodePoints)) {
      const ids = routes[format][task];
      rows.push({
        format,
        task,
        providers: ids,
        kinds: [...new Set(ids.map((id) => byId.get(id)?.kind))].sort(
          compareCodePoints,
        ),
        availableProviders: ids.filter((id) => byId.get(id)?.available),
        comparison: REA_FORMATS.has(format) ? "parity" : "beyond",
      });
    }
  return rows;
}

/** Headline counts: providers, formats, tasks, and the beyond-REA additions. */
export function coverageSummary(registry) {
  const { providers } = registry.table();
  const formats = new Set();
  const tasks = new Set();
  for (const provider of providers) {
    for (const format of provider.formats) formats.add(format);
    for (const task of Object.keys(provider.tasks)) tasks.add(task);
  }
  const byKind = {};
  for (const provider of providers)
    byKind[provider.kind] = (byKind[provider.kind] ?? 0) + 1;
  return {
    providers: providers.length,
    byKind,
    formats: [...formats].sort(compareCodePoints),
    formatCount: formats.size,
    tasks: [...tasks].sort(compareCodePoints),
    advancedAnalyzers: ADVANCED_ANALYZERS.map((a) => a.id),
    beyondReaFormats: [...formats]
      .filter((f) => !REA_FORMATS.has(f))
      .sort(compareCodePoints),
    beyondReaCapabilities: ADVANCED_ANALYZERS.filter((a) =>
      BEYOND_REA.has(a.id),
    ).map((a) => a.id),
  };
}

/** Render the matrix and summary as a Markdown report. */
export function renderMatrixMarkdown(registry) {
  const summary = coverageSummary(registry);
  const rows = capabilityMatrix(registry);
  const lines = [
    "# PTAH Engine capability matrix",
    "",
    `Providers: ${summary.providers} (${Object.entries(summary.byKind)
      .map(([k, n]) => `${n} ${k}`)
      .join(", ")}). ` +
      `Formats: ${summary.formatCount}. Advanced analyzers: ${summary.advancedAnalyzers.length}.`,
    "",
    "The PTAH column is read from the engine's registry. The REA column marks whether REA is documented to cover that format (parity) or not (beyond REA); it is not a measurement of REA.",
    "",
    "| Format | Task | PTAH providers | Kinds | vs REA |",
    "| --- | --- | --- | --- | --- |",
    ...rows.map(
      (r) =>
        `| ${r.format} | ${r.task} | ${r.providers.join(", ")} | ${r.kinds.join(", ")} | ${r.comparison} |`,
    ),
    "",
    "## Beyond REA",
    "",
    `- Formats PTAH adds: ${summary.beyondReaFormats.join(", ") || "none"}`,
    `- Capabilities PTAH adds: ${summary.beyondReaCapabilities.join(", ")}`,
  ];
  return `${lines.join("\n")}\n`;
}
