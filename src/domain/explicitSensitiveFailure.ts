import type { AnalysisError } from "./analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
  resourceConstraintRecovery,
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "./analysisErrorCore.js";
import { redactExplicitText } from "./explicitSensitiveValues.js";
import type { JsonValue } from "./jsonValue.js";
import { ProviderAdapterError } from "./providerAdapterError.js";
import { ProviderCleanupError } from "./providerCleanupError.js";
import {
  fileSnapshotPartialObservationSchema,
  type FileSnapshotPartialObservation,
} from "./fileSnapshotObservation.js";

/** Exclude whole identity values; redacted text is no longer a path or digest. */
const excludeSnapshotIdentity = (
  value: unknown,
  values: readonly string[],
): FileSnapshotPartialObservation | undefined => {
  if (
    value === null ||
    typeof value !== "object" ||
    !("kind" in value) ||
    (value.kind !== "file-snapshot-hash" && value.kind !== "file-snapshot-read")
  )
    return undefined;
  const parsed = fileSnapshotPartialObservationSchema.safeParse(value);
  if (!parsed.success) return undefined;
  const snapshot = parsed.data;
  const exclude = (identity: string | null): string | null =>
    identity !== null &&
    values.some((literal) => literal !== "" && identity.includes(literal))
      ? null
      : identity;
  const path = exclude(snapshot.path);
  if (snapshot.kind === "file-snapshot-hash") {
    const sha256 = exclude(snapshot.sha256);
    return { ...snapshot, path, sha256 };
  }
  const admitted_sha256 = exclude(snapshot.admitted_sha256);
  return { ...snapshot, path, admitted_sha256 };
};

/** Keep a real JSON-pointer ancestor when a property identity is explicitly excluded. */
export const redactExplicitPointer = (
  pointer: string,
  values: readonly string[],
): string => {
  let parent = "";
  for (const segment of pointer.split("/").slice(1)) {
    const decoded = segment.replaceAll("~1", "/").replaceAll("~0", "~");
    const child = `${parent}/${segment}`;
    if (
      values.some(
        (literal) => decoded.includes(literal) || child.includes(literal),
      )
    )
      return parent;
    parent = child;
  }
  return parent;
};

/** Exclude explicit literals from common acquisition/decoder failures, preserving typed diagnostics. */
export const redactExplicitFailure = (
  error: AnalysisError,
  values: readonly string[],
): AnalysisError => {
  if (values.length === 0) return error;
  const snapshot = excludeSnapshotIdentity(error.partialObservation, values);
  if (snapshot !== undefined) error.partialObservation = snapshot;
  const redacted = redactFailure(error, values);
  // Other observation owners already apply their format-aware exclusions.
  // Keep those facts across diagnostic replacements, including input/capacity.
  if (redacted !== error && error.partialObservation !== undefined)
    redacted.retainPartialObservation(error.partialObservation);
  return redacted === error
    ? error
    : mirrorCleanup(error, redacted, (value) =>
        redactExplicitText(value, values),
      );
};

const redactFailure = (
  error: AnalysisError,
  values: readonly string[],
): AnalysisError => {
  const text = (value: string): string => redactExplicitText(value, values);
  const path = (
    parts: readonly (string | number)[],
    ordinaryNames: boolean,
  ): (string | number)[] => {
    const retained: (string | number)[] = [];
    for (const part of parts) {
      if (typeof part !== "string") {
        retained.push(part);
      } else if (!ordinaryNames && part.startsWith("/")) {
        const pointer = redactExplicitPointer(part, values);
        retained.push(pointer);
        if (pointer !== part) break;
      } else {
        if (values.some((literal) => part.includes(literal))) break;
        retained.push(part);
      }
    }
    return retained;
  };
  const diagnostics = (
    value: Readonly<Record<string, JsonValue>>,
  ): Record<string, JsonValue> =>
    Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !values.some((literal) => key.includes(literal)))
        .map(([key, item]) => [key, visit(item)]),
    );
  const visit = (value: JsonValue): JsonValue => {
    const snapshot = excludeSnapshotIdentity(value, values);
    if (snapshot !== undefined) return snapshot;
    if (typeof value === "string") return text(value);
    if (Array.isArray(value)) return value.map(visit);
    if (typeof value === "object" && value !== null) return diagnostics(value);
    return value;
  };
  const context = {
    cause: error,
    ...(error.limit === undefined ? {} : { limit: error.limit }),
    ...(error.cleanupPrimary === undefined
      ? {}
      : {
          cleanupPrimary: redactExplicitFailure(error.cleanupPrimary, values),
        }),
    ...(error.diagnostics === undefined
      ? {}
      : { diagnostics: diagnostics(error.diagnostics) }),
    ...(error.capturedOutput === undefined
      ? {}
      : {
          capturedOutput: {
            ...error.capturedOutput,
            stdout: text(error.capturedOutput.stdout),
            stderr: text(error.capturedOutput.stderr),
          },
        }),
    ...(error.cleanup === undefined
      ? {}
      : {
          cleanup: {
            reason: text(error.cleanup.reason),
            resources: error.cleanup.resources.map(text),
          },
        }),
  };
  if (error instanceof AnalysisCancelledError)
    return new AnalysisCancelledError(error.operation, {
      ...context,
      cause: error.cause,
    });
  if (error instanceof AnalysisTimeoutError)
    return new AnalysisTimeoutError(error.operation, error.timeoutMs, {
      ...context,
      ...(error.userMessage === undefined
        ? {}
        : { userMessage: text(error.userMessage) }),
      ...(error.remediationAction === undefined
        ? {}
        : { remediationAction: text(error.remediationAction) }),
    });
  if (error instanceof AnalysisAccessDeniedError)
    return new AnalysisAccessDeniedError(
      error.operation,
      text(error.path),
      error.systemCode,
      context,
    );
  if (error instanceof AnalysisArtifactChangedError)
    return new AnalysisArtifactChangedError(
      error.operation,
      text(error.path),
      text(error.reason),
      context,
    );
  if (error instanceof AnalysisInputError)
    return new AnalysisInputError(
      error.operation,
      context,
      error.issues.map((issue) => ({
        ...issue,
        // Unknown-argument paths contain literal field names, including names
        // beginning with '/'; they are not producer JSON-pointer coordinates.
        path: path(issue.path, issue.reason === "unknown_argument"),
        ...(issue.message === undefined
          ? {}
          : { message: text(issue.message) }),
        ...(issue.expected === undefined
          ? {}
          : { expected: visit(issue.expected) }),
        ...(issue.observed === undefined
          ? {}
          : { observed: visit(issue.observed) }),
      })),
    );
  if (error instanceof AnalysisOutputError)
    return new AnalysisOutputError(
      error.operation,
      text(error.reason),
      context,
    );
  if (error instanceof AnalysisCapabilityUnavailableError)
    return new AnalysisCapabilityUnavailableError(
      error.providerId,
      error.operation,
      text(error.reason),
      {
        ...context,
        ...(error.userMessage === undefined
          ? {}
          : { userMessage: text(error.userMessage) }),
        ...(error.retryable ? { retryable: true } : {}),
      },
    );
  if (error instanceof AnalysisResourceConstraintError)
    return new AnalysisResourceConstraintError(
      error.operation,
      error.resource,
      text(error.reason),
      error.reportedLimits === null ? null : diagnostics(error.reportedLimits),
      { ...context, ...resourceConstraintRecovery(error, text) },
    );
  if (error instanceof ProviderCleanupError)
    return new ProviderCleanupError(
      error.providerId,
      error.cleanupResources.map(text),
      diagnostics(error.diagnostics ?? {}),
      {
        ...context,
        operation: error.operation,
      },
    );
  if (error instanceof ProviderAdapterError)
    return new ProviderAdapterError(error.providerId, error.operation, {
      ...context,
      ...(error.userMessage === undefined
        ? {}
        : { userMessage: text(error.userMessage) }),
      ...(error.remediationAction === undefined
        ? {}
        : { remediationAction: text(error.remediationAction) }),
    });
  return error;
};

const mirrorCleanup = <Value extends AnalysisError>(
  source: AnalysisError,
  redacted: Value,
  redact: (value: string) => string,
): Value =>
  redacted.bindCleanupDependencies([source], {
    get cleanupResources(): readonly string[] {
      return source.cleanupResources.map(redact);
    },
  });
