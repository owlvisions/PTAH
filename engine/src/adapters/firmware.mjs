/**
 * Firmware adapters. binwalk maps the signature scan to located components;
 * unblob additionally extracts them and lists the recovered files. Both report
 * under the `resources` task, meaning "components contained in the target".
 */
import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { compareCodePoints } from "../canonical.mjs";
import { ToolProvider } from "./tool-provider.mjs";

const MAX_ENTRIES = 5000;

/**
 * binwalk's signature table, "DECIMAL HEXADECIMAL DESCRIPTION". Handles both
 * comma-separated (--csv) and the space-padded default layout, since the flag
 * is honored inconsistently across binwalk builds.
 */
export function parseBinwalkCsv(text) {
  const components = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || /^(DECIMAL|-{3,})/u.test(trimmed)) continue;
    const match = /^(\d+)[,\s]+(0x[0-9a-fA-F]+)[,\s]+(.*)$/u.exec(trimmed);
    if (!match) continue;
    const description = match[3].replace(/^"|"$/gu, "").trim();
    components.push({
      offset: Number(match[1]),
      description,
      type: description.split(",")[0].trim(),
    });
  }
  return components;
}

export class BinwalkProvider extends ToolProvider {
  id = "binwalk";
  name = "Binwalk";
  license = "MIT";
  executables = ["binwalk"];
  versionArgs = ["--help"];
  async isAvailable(context = {}) {
    const state = await super.isAvailable(context);
    return state.available
      ? {
          available: true,
          version: /Binwalk v([\d.]+)/u.exec(state.version)?.[1] ?? null,
        }
      : state;
  }
  capabilities() {
    return {
      formats: ["unknown", "bin"],
      tasks: { resources: { priority: 4 } },
    };
  }
  async resources(target, context) {
    const run = await this.execute(target, ["{target}"], context);
    const components = parseBinwalkCsv(run.stdout);
    return [
      this.evidence("resources", target, run, {
        summary: `${components.length} embedded components: ${[...new Set(components.map((c) => c.type))].slice(0, 6).join(", ") || "none"}`,
        data: { components, extracted: false },
        limitations: [
          "binwalk locates signatures without extracting; use unblob for recovered files.",
        ],
      }),
    ];
  }
}

async function listExtracted(dir) {
  const files = [];
  let truncated = false;
  const walk = async (current) => {
    for (const entry of (
      await readdir(current, { withFileTypes: true }).catch(() => [])
    ).sort((a, b) => compareCodePoints(a.name, b.name))) {
      if (files.length >= MAX_ENTRIES) {
        truncated = true;
        return;
      }
      const path = join(current, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) {
        const info = await stat(path).catch(() => null);
        if (info) files.push({ path: relative(dir, path), bytes: info.size });
      }
    }
  };
  await walk(dir);
  return { files, truncated };
}

export class UnblobProvider extends ToolProvider {
  id = "unblob";
  name = "unblob";
  license = "MIT";
  executables = ["unblob"];
  versionArgs = ["--version"];
  capabilities() {
    return {
      formats: ["unknown", "bin"],
      tasks: { resources: { priority: 6 } },
    };
  }
  async resources(target, context) {
    const run = await this.executeToDir(
      target,
      ["-f", "-e", "{outdir}", "{target}"],
      async (dir) => listExtracted(dir),
      { ...context, timeoutMs: context.timeoutMs ?? 180_000 },
    );
    const carriers = run.output.files.filter(
      (file) => !file.path.endsWith(".padding"),
    );
    return [
      this.evidence("resources", target, run, {
        summary: `Extracted ${carriers.length} files from the firmware image`,
        data: { files: carriers, extracted: true },
        partial: run.output.truncated,
        limitations: run.output.truncated
          ? ["Extraction listing hit the entry cap and is partial."]
          : [],
      }),
    ];
  }
}

export const firmwareProviders = () => [
  new BinwalkProvider(),
  new UnblobProvider(),
];
