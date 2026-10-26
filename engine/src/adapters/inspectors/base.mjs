/**
 * Base for built-in inspectors: format parsers written in PTAH's own code,
 * needing no external tool. Always available; results are `observed` facts
 * read directly from the target's bytes. A malformed structure becomes an
 * anomaly in the evidence, never a thrown crash.
 */
import { createEvidence } from "../../evidence.mjs";
import { readTargetBytes } from "../../bytes.mjs";
import { AnalysisProvider } from "../../provider.mjs";

export const ENGINE_VERSION = "0.1.0";

export class BuiltinInspector extends AnalysisProvider {
  kind = "builtin";
  license = "MIT";

  async isAvailable() {
    return { available: true, version: ENGINE_VERSION };
  }

  /** Read the target's bytes (bounded) for a parser. */
  async read(target, context = {}) {
    return readTargetBytes(target.path, context.maxBytes);
  }

  /**
   * Build observed evidence from a parse. `parse(bytes)` returns
   * `{ summary, data, anomalies?, confidence?, limitations? }`.
   */
  async inspect(task, target, context, parse) {
    const { bytes, truncated } = await this.read(target, context);
    let result;
    const anomalies = [];
    try {
      result = parse(bytes);
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      result = {
        summary: `malformed ${target.format}: ${error.message}`,
        data: {},
        confidence: "inferred",
      };
      anomalies.push(error.message);
    }
    const allAnomalies = [...anomalies, ...(result.anomalies ?? [])];
    return [
      createEvidence({
        task,
        targetSha256: target.sha256,
        provider: {
          id: this.id,
          tool: this.id,
          version: ENGINE_VERSION,
          argv: ["<builtin>", this.id],
        },
        confidence: result.confidence ?? "observed",
        status: truncated ? "partial" : allAnomalies.length ? "partial" : "ok",
        summary: result.summary,
        data: {
          ...result.data,
          ...(allAnomalies.length ? { anomalies: allAnomalies } : {}),
        },
        limitations: [
          ...(result.limitations ?? []),
          ...(truncated
            ? ["Target exceeded the read cap; parse is partial."]
            : []),
        ],
      }),
    ];
  }
}
