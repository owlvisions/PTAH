/** Canonical JSON and hashing: the basis for byte-stable ids, reports, and diffs. */
import { createHash } from "node:crypto";

/** JSON with object keys sorted at every level; arrays keep their order. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  const text = JSON.stringify(value);
  if (text === undefined)
    throw new TypeError("value is not representable as JSON");
  return text;
}

/** Locale-independent ordering, so sorted output is identical on every machine. */
export const compareCodePoints = (left, right) =>
  left < right ? -1 : left > right ? 1 : 0;

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");
