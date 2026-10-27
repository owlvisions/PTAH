import assert from "node:assert/strict";
import test from "node:test";
import {
  compareInspections,
  reaMetrics,
  renderHeadToHead,
} from "../src/index.mjs";

const SHA = "6974".padEnd(64, "a");

void test("reaMetrics normalizes a REA inspect record", () => {
  const m = reaMetrics({
    subject: { format: "elf", architecture: "x86_64", digest: { sha256: SHA } },
    normalized_result: {
      segment_count: 32,
      procedure_count: 244,
      string_count: 152,
    },
  });
  assert.deepEqual(m, {
    format: "elf",
    architecture: "x86_64",
    sha256: SHA,
    sections: 32,
    functions: 244,
    strings: 152,
  });
});

void test("compareInspections matches identity exactly and counts within tolerance", () => {
  const rea = {
    format: "elf",
    architecture: "x86_64",
    sha256: SHA,
    sections: 32,
    functions: 244,
    strings: 152,
  };
  const same = compareInspections(rea, { ...rea, sections: 29 });
  assert.equal(same.identityMatch, true);
  assert.equal(
    same.rows.find((r) => r.metric === "sections").agree,
    true,
    "29 vs 32 within 25%",
  );
  const diff = compareInspections(rea, { ...rea, functions: 49, strings: 72 });
  assert.equal(diff.rows.find((r) => r.metric === "functions").agree, false);
  assert.equal(diff.rows.find((r) => r.metric === "functions").delta, 49 - 244);
  const wrongTarget = compareInspections(rea, {
    ...rea,
    sha256: "b".repeat(64),
  });
  assert.equal(wrongTarget.identityMatch, false);
});

void test("renderHeadToHead produces a table with timings and interpretation", () => {
  const rea = {
    format: "elf",
    architecture: "x86_64",
    sha256: SHA,
    sections: 32,
    functions: 244,
    strings: 152,
  };
  const md = renderHeadToHead([
    {
      target: "true",
      reaMs: 16804,
      ptahMs: 2003,
      comparison: compareInspections(rea, {
        ...rea,
        sections: 29,
        functions: 49,
        strings: 72,
      }),
    },
  ]);
  assert.match(md, /# PTAH Engine vs REA/);
  assert.match(md, /\| true \| format \| elf \| elf \| yes \|/);
  assert.match(md, /\| true \| 16804 \| 2003 \|/);
  assert.match(md, /analysis \*depth\*, not capability/);
});
