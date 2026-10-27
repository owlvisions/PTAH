/**
 * The PTAH Engine entry point. A session binds one identified target to a
 * recorded attestation; no provider runs before policy accepts both. Every
 * run re-checks the target digest so evidence can never describe bytes that
 * changed underneath it.
 */
import { checkDrift, identifyTarget } from "./target.mjs";
import { evaluateTarget, recordAttestation } from "./policy.mjs";

/** The target's bytes changed after the session started. */
export class TargetDrift extends Error {
  constructor(drift) {
    super(
      `target changed during analysis: expected ${drift.expected}, found ${drift.actual}`,
    );
    this.name = "TargetDrift";
    this.drift = drift;
  }
}

/**
 * @param {{ registry: import("./registry.mjs").CapabilityRegistry, targetChecks?: Function[] }} options
 */
export function createEngine({ registry, targetChecks = [] }) {
  return {
    registry,
    /** Open an analysis session; throws PolicyRefusal when policy declines. */
    async open(filePath, attestation) {
      const record = recordAttestation(attestation);
      const target = await identifyTarget(filePath);
      await evaluateTarget(target, targetChecks);
      const log = [];
      const guard = async () => {
        const drift = await checkDrift(target);
        if (drift.drifted) throw new TargetDrift(drift);
      };
      return {
        target,
        attestation: record,
        /** Evidence produced so far, in run order. */
        get evidence() {
          return log.flatMap((entry) => entry.evidence);
        },
        async run(task, context = {}) {
          const result = await registry.run(task, target, context);
          await guard();
          log.push(result);
          return result;
        },
        async runAll(tasks, context = {}) {
          const results = await registry.runAll(tasks, target, context);
          await guard();
          log.push(...Object.values(results));
          return results;
        },
        async crossValidate(task, context = {}) {
          const result = await registry.crossValidate(task, target, context);
          await guard();
          log.push(...result.evidence);
          return result;
        },
        verify: () => checkDrift(target),
      };
    },
  };
}
