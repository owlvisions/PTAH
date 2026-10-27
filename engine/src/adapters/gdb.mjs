/**
 * GDB engine adapter, static only. Runs gdb in batch mode (--batch --nx) with
 * fixed commands that read the file without executing it: `info functions`
 * for symbols and `maintenance info sections` for sections. A debugging run
 * against a live inferior is a separate, consent-gated capability, not this.
 */
import { ToolProvider } from "./tool-provider.mjs";

/** `info functions`: "0xADDR  name" lines, grouped under defined/non-debugging. */
export function parseGdbFunctions(text) {
  const functions = [];
  for (const line of text.split("\n")) {
    const match = /^(0x[0-9a-f]+)\s+(\S.*)$/u.exec(line.trim());
    if (match)
      functions.push({
        address: Number.parseInt(match[1], 16),
        name: match[2].replace(/@plt$/u, ""),
        plt: match[2].endsWith("@plt"),
      });
  }
  return functions;
}

/** `maintenance info sections`: "[n] START->END at OFF: name FLAGS". */
export function parseGdbSections(text) {
  const sections = [];
  for (const line of text.split("\n")) {
    const match =
      /\[\s*\d+\]\s+0x([0-9a-f]+)->0x([0-9a-f]+)\s+at\s+0x([0-9a-f]+):\s+(\S+)\s*(.*)$/u.exec(
        line.trim(),
      );
    if (!match) continue;
    const flags = match[5].trim().split(/\s+/u).filter(Boolean);
    sections.push({
      name: match[4],
      address: Number.parseInt(match[1], 16),
      size: Number.parseInt(match[2], 16) - Number.parseInt(match[1], 16),
      offset: Number.parseInt(match[3], 16),
      flags,
      executable: flags.includes("CODE"),
    });
  }
  return sections;
}

export class GdbProvider extends ToolProvider {
  id = "gdb";
  name = "GDB (static batch)";
  kind = "engine";
  license = "GPL-3.0-or-later";
  executables = ["gdb"];
  versionArgs = ["--version"];
  capabilities() {
    return {
      formats: ["elf", "pe"],
      tasks: { symbols: { priority: 2 }, sections: { priority: 2 } },
    };
  }
  async symbols(target, context) {
    const run = await this.execute(
      target,
      ["--batch", "--nx", "-ex", "info functions", "{target}"],
      context,
    );
    const functions = parseGdbFunctions(run.stdout);
    return [
      this.evidence("symbols", target, run, {
        summary: `${functions.length} functions (${functions.filter((f) => f.plt).length} PLT stubs)`,
        data: { tables: { functions } },
      }),
    ];
  }
  async sections(target, context) {
    const run = await this.execute(
      target,
      ["--batch", "--nx", "-ex", "maintenance info sections", "{target}"],
      context,
    );
    const sections = parseGdbSections(run.stdout);
    return [
      this.evidence("sections", target, run, {
        summary: `${sections.length} sections; code: ${
          sections
            .filter((s) => s.executable)
            .map((s) => s.name)
            .join(", ") || "none"
        }`,
        data: { sections },
      }),
    ];
  }
}

export const gdbProviders = () => [new GdbProvider()];
