/**
 * Conflict policy for merging REA upstream into PTAH.
 *
 * PTAH owns its product surface; REA stays the authority for the inherited
 * runtime. Each conflicted path gets exactly one rule, and every decision is
 * reported so a reviewer can see what the automatic merge chose.
 */

/** Paths PTAH owns outright: keep PTAH's side on conflict. */
const PTAH_OWNED = [
  /^scripts\/ptah[^/]*\.mjs$/u,
  /^scripts\/tests\/ptah[^/]*\.test\.mjs$/u,
  /^docs\/PTAH-[^/]+$/u,
  /^docs\/schema\/ptah-/u,
  /^integrations\//u,
  /^web\/ptah\//u,
  /^examples\/ptah-/u,
  /^\.github\/workflows\/ptah-/u,
  /^README\.md$/u,
  /^SECURITY\.md$/u,
  /^server\.json$/u,
  /^install\.sh$/u,
  /^release-please-config\.json$/u,
];

/** Generated from other files: take upstream, then rebuild with `regenerate`. */
const GENERATED = [/^package-lock\.json$/u, /^licenses\/npm-[^/]+\.txt$/u];

/** package.json fields that carry PTAH's identity rather than REA's runtime. */
const PTAH_IDENTITY_FIELDS = new Set([
  "name",
  "mcpName",
  "description",
  "repository",
  "homepage",
  "bugs",
  "keywords",
]);
const UNION_FIELDS = new Set(["bin", "files", "scripts"]);
const DEPENDENCY_FIELDS = new Set([
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
  "overrides",
]);

/** Commands that rebuild generated files once sources are resolved. */
export const REGENERATE_COMMANDS = Object.freeze([
  [
    "npm",
    "install",
    "--package-lock-only",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
  ],
  ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
  ["npm", "run", "licenses:generate"],
]);

/** Decide how one conflicted path is resolved. */
export function conflictRule(path) {
  if (path === "package.json") return "package-json";
  if (GENERATED.some((pattern) => pattern.test(path))) return "regenerate";
  if (PTAH_OWNED.some((pattern) => pattern.test(path))) return "ours";
  return "theirs";
}

const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

const parseVersion = (value) => {
  const match = /^[~^]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/u.exec(
    String(value),
  );
  return match
    ? [Number(match[1]), Number(match[2]), Number(match[3]), match[4]]
    : undefined;
};

/** The newer of two exact or range-prefixed versions; undefined when not comparable. */
export function newerVersion(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return undefined;
  for (let index = 0; index < 3; index += 1)
    if (a[index] !== b[index]) return a[index] > b[index] ? left : right;
  if (a[3] === b[3]) return left;
  if (a[3] === undefined) return left;
  if (b[3] === undefined) return right;
  return a[3] > b[3] ? left : right;
}

const unionArrays = (ours, theirs) => [
  ...theirs,
  ...ours.filter((item) => !theirs.some((other) => same(other, item))),
];

/** Resolve a field both sides changed, following the package.json policy. */
function resolveFieldConflict(path, ours, theirs, decisions) {
  const top = path[0];
  const where = path.join(".");
  const keep = (kept, value) => {
    decisions.push({
      path: where,
      kept,
      ...(kept.includes("newer") ? { value } : {}),
    });
    return value;
  };
  if (PTAH_IDENTITY_FIELDS.has(top)) return keep("ptah", ours);
  if (UNION_FIELDS.has(top) && Array.isArray(ours) && Array.isArray(theirs))
    return keep("union", unionArrays(ours, theirs));
  if (
    DEPENDENCY_FIELDS.has(top) &&
    ours !== undefined &&
    theirs !== undefined
  ) {
    const newer = newerVersion(ours, theirs);
    if (newer !== undefined)
      return keep(newer === ours ? "ptah (newer)" : "upstream (newer)", newer);
  }
  if (UNION_FIELDS.has(top) && ours !== undefined) return keep("ptah", ours);
  return keep("upstream", theirs);
}

/**
 * Three-way merge of JSON values. Non-conflicting changes from both sides are
 * kept; true conflicts follow the package.json field policy above.
 */
export function mergeJson(sides, path = [], decisions = []) {
  const { base, ours, theirs } = sides;
  if (same(ours, theirs)) return ours;
  if (same(base, ours)) return theirs;
  if (same(base, theirs)) return ours;
  if (!isObject(ours) || !isObject(theirs))
    return resolveFieldConflict(path, ours, theirs, decisions);
  const merged = {};
  for (const key of new Set([...Object.keys(theirs), ...Object.keys(ours)])) {
    const value = mergeJson(
      {
        base: isObject(base) ? base[key] : undefined,
        ours: ours[key],
        theirs: theirs[key],
      },
      [...path, key],
      decisions,
    );
    if (value !== undefined) merged[key] = value;
  }
  return merged;
}

/** Merge three package.json texts; returns the text and the decisions made. */
export function mergePackageJson(baseText, oursText, theirsText) {
  const decisions = [];
  const merged = mergeJson(
    {
      base: JSON.parse(baseText),
      ours: JSON.parse(oursText),
      theirs: JSON.parse(theirsText),
    },
    [],
    decisions,
  );
  return { text: `${JSON.stringify(merged, null, 2)}\n`, decisions };
}
