/**
 * Byte-level tools: multi-algorithm hashes, wildcard pattern search, bounded
 * hexdump, and structural comparison of two targets. Nothing executes the
 * target; every result is bounded.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { analyzeStructure, readTargetBytes } from "./ptah-binary.mjs";
import { extractStrings } from "./ptah-analysis.mjs";

const HASHES = ["md5", "sha1", "sha256", "sha512"];

/** MD5, SHA-1, SHA-256, and SHA-512 in one streaming pass. */
export async function hashTarget(filePath) {
  const path = resolve(filePath);
  const info = await stat(path);
  if (!info.isFile()) throw new TypeError("target must be a regular file");
  const hashes = HASHES.map((name) => createHash(name));
  for await (const chunk of createReadStream(path))
    for (const hash of hashes) hash.update(chunk);
  return {
    path,
    sizeBytes: info.size,
    ...Object.fromEntries(
      HASHES.map((name, index) => [name, hashes[index].digest("hex")]),
    ),
  };
}

/** Parse `4D 5A ?? 00` style patterns; `??` matches any byte. */
export function parseHexPattern(pattern) {
  const compact = String(pattern).replace(/\s+/gu, "");
  if (compact.length % 2 !== 0)
    throw new TypeError("hex pattern must have whole bytes");
  const bytes = compact.match(/.{2}/gu) ?? [];
  if (bytes.length === 0 || bytes.length > 256)
    throw new TypeError("hex pattern must have 1 to 256 bytes");
  const parsed = bytes.map((token) => {
    if (token === "??") return null;
    if (!/^[0-9a-f]{2}$/iu.test(token))
      throw new TypeError(`invalid hex byte: ${token}`);
    return Number.parseInt(token, 16);
  });
  if (parsed.every((value) => value === null))
    throw new TypeError("hex pattern must constrain at least one byte");
  return parsed;
}

function findPattern(bytes, pattern, maxResults) {
  const anchor = pattern.findIndex((value) => value !== null);
  const matches = [];
  let from = 0;
  while (matches.length < maxResults) {
    const hit = bytes.indexOf(pattern[anchor], from + anchor);
    if (hit < 0) break;
    const start = hit - anchor;
    if (
      start >= 0 &&
      start + pattern.length <= bytes.length &&
      pattern.every(
        (value, index) => value === null || bytes[start + index] === value,
      )
    )
      matches.push(start);
    from = start + 1;
  }
  return matches;
}

/** Search a target for a hex pattern (with `??` wildcards) or text (ASCII and UTF-16LE). */
export async function searchTarget(filePath, query, options = {}) {
  const maxResults = Math.min(options.maxResults ?? 200, 10_000);
  const { path, bytes, size, truncated } = await readTargetBytes(
    filePath,
    options.maxBytes,
  );
  const patterns = [];
  if (query.hex !== undefined)
    patterns.push({ encoding: "hex", values: parseHexPattern(query.hex) });
  if (query.text !== undefined) {
    if (
      typeof query.text !== "string" ||
      query.text.length === 0 ||
      query.text.length > 256
    )
      throw new TypeError("text must be 1 to 256 characters");
    patterns.push({
      encoding: "ascii",
      values: [...Buffer.from(query.text, "latin1")],
    });
    patterns.push({
      encoding: "utf16le",
      values: [...Buffer.from(query.text, "utf16le")],
    });
  }
  if (patterns.length === 0)
    throw new TypeError("provide hex or text to search for");
  const matches = [];
  for (const { encoding, values } of patterns)
    for (const offset of findPattern(
      bytes,
      values,
      maxResults - matches.length,
    ))
      matches.push({
        offset,
        encoding,
        context: bytes
          .subarray(
            offset,
            Math.min(bytes.length, offset + Math.max(values.length, 16)),
          )
          .toString("hex"),
      });
  matches.sort((left, right) => left.offset - right.offset);
  return {
    path,
    sizeBytes: size,
    scannedBytes: bytes.length,
    truncated,
    count: matches.length,
    limited: matches.length >= maxResults,
    matches,
  };
}

/** Classic 16-byte-per-line hexdump of at most 4 KiB. */
export async function hexdumpTarget(filePath, options = {}) {
  const offset = options.offset ?? 0;
  const length = Math.min(options.length ?? 256, 4096);
  if (!Number.isSafeInteger(offset) || offset < 0)
    throw new TypeError("offset must be a non-negative integer");
  if (!Number.isSafeInteger(length) || length < 1)
    throw new TypeError("length must be a positive integer");
  const path = resolve(filePath);
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, offset);
    const lines = [];
    for (let line = 0; line < bytesRead; line += 16) {
      const chunk = buffer.subarray(line, Math.min(line + 16, bytesRead));
      const hex = [...chunk]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(" ");
      const text = [...chunk]
        .map((byte) =>
          byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".",
        )
        .join("");
      lines.push(
        `${(offset + line).toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${text}|`,
      );
    }
    return { path, offset, length: bytesRead, dump: lines.join("\n") };
  } finally {
    await handle.close();
  }
}

const jaccard = (left, right) => {
  if (left.size === 0 && right.size === 0) return 1;
  let shared = 0;
  for (const item of left) if (right.has(item)) shared += 1;
  return shared / (left.size + right.size - shared);
};

async function structureOrNull(path) {
  try {
    return await analyzeStructure(path);
  } catch {
    return null;
  }
}

/** Compare two targets: identity, strings similarity, and section/import differences. */
export async function compareTargets(leftPath, rightPath) {
  const [left, right] = await Promise.all([
    hashTarget(leftPath),
    hashTarget(rightPath),
  ]);
  const [leftStrings, rightStrings] = await Promise.all(
    [leftPath, rightPath].map(
      async (path) =>
        new Set(
          (await extractStrings(path, { maxResults: 20_000 })).strings.map(
            (item) => item.text,
          ),
        ),
    ),
  );
  const [leftStructure, rightStructure] = await Promise.all([
    structureOrNull(leftPath),
    structureOrNull(rightPath),
  ]);
  const result = {
    left: { path: left.path, sha256: left.sha256, sizeBytes: left.sizeBytes },
    right: {
      path: right.path,
      sha256: right.sha256,
      sizeBytes: right.sizeBytes,
    },
    identical: left.sha256 === right.sha256,
    stringSimilarity:
      Math.round(jaccard(leftStrings, rightStrings) * 1000) / 1000,
    stringsOnlyLeft: [...leftStrings]
      .filter((item) => !rightStrings.has(item))
      .slice(0, 50),
    stringsOnlyRight: [...rightStrings]
      .filter((item) => !leftStrings.has(item))
      .slice(0, 50),
  };
  if (leftStructure && rightStructure) {
    const sections = (structure) =>
      new Map(structure.sections.map((section) => [section.name, section]));
    const a = sections(leftStructure);
    const b = sections(rightStructure);
    result.sections = [...new Set([...a.keys(), ...b.keys()])].map((name) => ({
      name,
      leftSize: a.get(name)?.size ?? null,
      rightSize: b.get(name)?.size ?? null,
      leftEntropy: a.get(name)?.entropy ?? null,
      rightEntropy: b.get(name)?.entropy ?? null,
    }));
    const importsA = new Set(leftStructure.imports);
    const importsB = new Set(rightStructure.imports);
    result.importSimilarity =
      Math.round(jaccard(importsA, importsB) * 1000) / 1000;
    result.importsOnlyLeft = [...importsA]
      .filter((item) => !importsB.has(item))
      .slice(0, 100);
    result.importsOnlyRight = [...importsB]
      .filter((item) => !importsA.has(item))
      .slice(0, 100);
  }
  return result;
}
