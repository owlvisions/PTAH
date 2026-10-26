const SUPPORTED_NODE_MINIMUMS = [
  [22, 23, 4],
  [24, 22, 1],
  [26, 12, 1],
];

/** Check the supported Node.js major lines without requiring project dependencies. */
export function isSupportedPtahNodeVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  if (!match) return false;
  const actual = match.slice(1).map(Number);
  if (!actual.every(Number.isSafeInteger)) return false;
  return (
    actual[0] > 26 ||
    SUPPORTED_NODE_MINIMUMS.some(([major, minor, patch]) => {
      if (actual[0] !== major) return false;
      if (actual[1] !== minor) return actual[1] > minor;
      return actual[2] >= patch;
    })
  );
}
