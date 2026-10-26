import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { analyzeStructure } from "../ptah-binary.mjs";
import {
  compareTargets,
  hashTarget,
  hexdumpTarget,
  searchTarget,
} from "../ptah-bytes.mjs";
import {
  extractIndicators,
  findSecrets,
  inferCapabilities,
  matchRules,
} from "../ptah-intel.mjs";
import {
  queryEvidence,
  renderTimeline,
  summarizeInvestigation,
  triageTarget,
} from "../ptah-triage.mjs";
import { renderHtmlReport, renderSarif } from "../ptah-reports.mjs";
import {
  lintInvestigation,
  planNextAction,
  validateInvestigation,
} from "../ptah-engine.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cli = (args) =>
  spawnSync(process.execPath, [join(root, "scripts/ptah.mjs"), ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
  });

/** Minimal ELF64 shared object: needs libc.so.6, imports socket/connect, exports exported_fn. */
function buildElf() {
  const dynstr = Buffer.from(
    "\0libc.so.6\0socket\0connect\0exported_fn\0",
    "latin1",
  );
  const name = (text) => dynstr.indexOf(`${text}\0`, 1);
  const symbol = (nameOffset, shndx) => {
    const entry = Buffer.alloc(24);
    entry.writeUInt32LE(nameOffset, 0);
    entry[4] = 0x12;
    entry.writeUInt16LE(shndx, 6);
    return entry;
  };
  const dynsym = Buffer.concat([
    Buffer.alloc(24),
    symbol(name("socket"), 0),
    symbol(name("connect"), 0),
    symbol(name("exported_fn"), 4),
  ]);
  const dynamic = Buffer.alloc(32);
  dynamic.writeBigUInt64LE(1n, 0);
  dynamic.writeBigUInt64LE(BigInt(name("libc.so.6")), 8);
  const text = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3, 0x90, 0x90, 0x90]);
  const shstrtab = Buffer.from(
    "\0.dynsym\0.dynstr\0.dynamic\0.text\0.shstrtab\0",
    "latin1",
  );
  const parts = [dynsym, dynstr, dynamic, text, shstrtab];
  const offsets = [];
  let cursor = 64;
  for (const part of parts) {
    offsets.push(cursor);
    cursor += part.length;
  }
  const shoff = cursor;
  const header = Buffer.alloc(64);
  header.write("\x7fELF", 0, "latin1");
  header[4] = 2;
  header[5] = 1;
  header[6] = 1;
  header.writeUInt16LE(3, 16);
  header.writeUInt16LE(0x3e, 18);
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(BigInt(shoff), 0x28);
  header.writeUInt16LE(64, 0x34);
  header.writeUInt16LE(64, 0x3a);
  header.writeUInt16LE(6, 0x3c);
  header.writeUInt16LE(5, 0x3e);
  const sectionName = (text) => shstrtab.indexOf(`${text}\0`, 1);
  const section = ([nameText, type, flags, index, link, entsize]) => {
    const entry = Buffer.alloc(64);
    if (nameText === null) return entry;
    entry.writeUInt32LE(sectionName(nameText), 0);
    entry.writeUInt32LE(type, 4);
    entry.writeBigUInt64LE(BigInt(flags), 8);
    entry.writeBigUInt64LE(BigInt(offsets[index]), 24);
    entry.writeBigUInt64LE(BigInt(parts[index].length), 32);
    entry.writeUInt32LE(link, 40);
    entry.writeBigUInt64LE(BigInt(entsize), 56);
    return entry;
  };
  const sections = [
    [null],
    [".dynsym", 11, 2, 0, 2, 24],
    [".dynstr", 3, 2, 1, 0, 0],
    [".dynamic", 6, 3, 2, 2, 16],
    [".text", 1, 6, 3, 0, 0],
    [".shstrtab", 3, 0, 4, 0, 0],
  ].map(section);
  return Buffer.concat([header, ...parts, ...sections]);
}

/** Minimal PE32+ with a UPX0 section and KERNEL32 injection imports. */
function buildPe() {
  const file = Buffer.alloc(0x600);
  file.write("MZ", 0, "latin1");
  file.writeUInt32LE(0x80, 0x3c);
  file.write("PE\0\0", 0x80, "latin1");
  file.writeUInt16LE(0x8664, 0x84);
  file.writeUInt16LE(2, 0x86);
  file.writeUInt16LE(0xf0, 0x94);
  file.writeUInt16LE(0x2022, 0x96);
  const optional = 0x98;
  file.writeUInt16LE(0x20b, optional);
  file.writeUInt32LE(16, optional + 108);
  file.writeUInt32LE(0x2000, optional + 112 + 8);
  file.writeUInt32LE(40, optional + 112 + 12);
  const table = optional + 0xf0;
  const sectionHeader = ({ at, name, va, pointer, characteristics }) => {
    file.write(name, at, "latin1");
    file.writeUInt32LE(0x200, at + 8);
    file.writeUInt32LE(va, at + 12);
    file.writeUInt32LE(0x200, at + 16);
    file.writeUInt32LE(pointer, at + 20);
    file.writeUInt32LE(characteristics, at + 36);
  };
  sectionHeader({
    at: table,
    name: "UPX0",
    va: 0x1000,
    pointer: 0x200,
    characteristics: 0x60000020,
  });
  sectionHeader({
    at: table + 40,
    name: ".idata",
    va: 0x2000,
    pointer: 0x400,
    characteristics: 0xc0000040,
  });
  const at = (rva) => rva - 0x2000 + 0x400;
  file.writeUInt32LE(0x2040, at(0x2000));
  file.writeUInt32LE(0x2100, at(0x2000) + 12);
  file.writeUInt32LE(0x2040, at(0x2000) + 16);
  const functions = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
  ];
  functions.forEach((fn, index) => {
    const hint = 0x2120 + index * 0x20;
    file.writeBigUInt64LE(BigInt(hint), at(0x2040) + index * 8);
    file.write(`${fn}\0`, at(hint) + 2, "latin1");
  });
  file.write("KERNEL32.dll\0", at(0x2100), "latin1");
  file.write(
    "http://198.51.100.7/beacon AKIAIOSFODNN7EXAMPLE\0",
    0x580,
    "latin1",
  );
  return file;
}

const fixtures = async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-intel-"));
  const elf = join(dir, "lib.so");
  const pe = join(dir, "inject.exe");
  await writeFile(elf, buildElf());
  await writeFile(pe, buildPe());
  return {
    dir,
    elf,
    pe,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
};

void test("structure parses ELF symbols and libraries and PE imports, imphash, and packer hints", async () => {
  const { elf, pe, cleanup } = await fixtures();
  try {
    const e = await analyzeStructure(elf);
    assert.equal(e.format, "ELF");
    assert.deepEqual(e.libraries, ["libc.so.6"]);
    assert.deepEqual(e.imports, ["connect", "socket"]);
    assert.deepEqual(e.exports, ["exported_fn"]);
    assert.deepEqual(
      e.sections.map((s) => s.name),
      [".dynsym", ".dynstr", ".dynamic", ".text", ".shstrtab"],
    );
    assert.equal(e.sections.find((s) => s.name === ".text").executable, true);
    const p = await analyzeStructure(pe);
    assert.equal(p.format, "PE");
    assert.equal(p.bits, 64);
    assert.deepEqual(p.imports, [
      "KERNEL32.dll!VirtualAllocEx",
      "KERNEL32.dll!WriteProcessMemory",
      "KERNEL32.dll!CreateRemoteThread",
    ]);
    assert.equal(
      p.imphash,
      createHash("md5")
        .update(
          "kernel32.virtualallocex,kernel32.writeprocessmemory,kernel32.createremotethread",
        )
        .digest("hex"),
    );
    assert.ok(p.packerHints.some((hint) => hint.packer === "UPX"));
    const broken = Buffer.from(buildElf());
    broken.writeBigUInt64LE(10n ** 12n, 0x28);
    await writeFile(elf, broken);
    const damaged = await analyzeStructure(elf);
    assert.ok(
      damaged.anomalies.length > 0,
      "out-of-file section table is reported, not thrown",
    );
  } finally {
    await cleanup();
  }
});

void test("byte tools hash, search with wildcards, dump, and compare", async () => {
  const { elf, pe, cleanup } = await fixtures();
  try {
    const hashes = await hashTarget(pe);
    assert.equal(
      hashes.sha256,
      createHash("sha256").update(buildPe()).digest("hex"),
    );
    assert.equal(hashes.md5, createHash("md5").update(buildPe()).digest("hex"));
    const found = await searchTarget(pe, {
      hex: "50 45 ?? 00 64 86",
      text: "KERNEL32",
    });
    assert.deepEqual(
      found.matches.map((m) => [m.offset, m.encoding]),
      [
        [0x80, "hex"],
        [0x500, "ascii"],
      ],
    );
    await assert.rejects(
      searchTarget(pe, { hex: "?? ??" }),
      /constrain at least one byte/,
    );
    const dump = await hexdumpTarget(pe, { offset: 0, length: 16 });
    assert.match(dump.dump, /^00000000  4d 5a 00 00/);
    const comparison = await compareTargets(pe, pe);
    assert.equal(comparison.identical, true);
    assert.equal(comparison.stringSimilarity, 1);
    assert.equal((await compareTargets(elf, pe)).identical, false);
  } finally {
    await cleanup();
  }
});

void test("intelligence finds indicators, redacts secrets, infers capabilities, and matches rules", async () => {
  const { pe, cleanup } = await fixtures();
  try {
    const iocs = await extractIndicators(pe);
    assert.deepEqual(
      iocs.indicators.map((i) => [i.type, i.value]),
      [
        ["url", "http://198.51.100.7/beacon"],
        ["ipv4", "198.51.100.7"],
      ],
    );
    const secrets = await findSecrets(pe);
    assert.equal(secrets.findings[0].type, "aws-access-key-id");
    assert.doesNotMatch(JSON.stringify(secrets), /IOSFODNN7EXAMPL/);
    assert.equal(
      secrets.findings[0].sha256,
      createHash("sha256").update("AKIAIOSFODNN7EXAMPLE").digest("hex"),
    );
    const capabilities = await inferCapabilities(pe);
    const injection = capabilities.capabilities.find(
      (c) => c.id === "process-injection",
    );
    assert.equal(injection.attack, "T1055");
    assert.equal(injection.confidence, "inferred");
    const rules = await matchRules(pe, [
      {
        id: "injection-trio",
        strings: {
          a: { text: "VirtualAllocEx" },
          b: { text: "CreateRemoteThread" },
          c: { hex: "4D 5A" },
        },
        condition: "all",
      },
      { id: "absent", strings: { a: { text: "not-present" } } },
    ]);
    assert.deepEqual(
      rules.matches.map((m) => m.id),
      ["injection-trio"],
    );
    await assert.rejects(
      matchRules(pe, [{ id: "r", strings: { a: { regex: "(a+)+$" } } }], {
        allowRegex: false,
      }),
      /not accepted/,
    );
  } finally {
    await cleanup();
  }
});

void test("triage records honest evidence, plans, lints cleanly, and renders safe reports", async () => {
  const { pe, cleanup } = await fixtures();
  try {
    const { investigation } = await triageTarget(pe);
    validateInvestigation(investigation);
    const byId = Object.fromEntries(
      investigation.evidence.map((e) => [e.id, e]),
    );
    assert.equal(byId["triage-structure"].confidence, "observed");
    assert.equal(
      byId["triage-capability-process-execution"]?.confidence ??
        byId["triage-capability-process-injection"].confidence,
      "inferred",
    );
    assert.ok(
      investigation.claims.every((claim) => claim.status === "hypothesis"),
    );
    assert.ok(investigation.questions.some((q) => q.id === "q-packed"));
    assert.ok(investigation.questions.some((q) => q.id === "q-persistence"));
    assert.equal(
      lintInvestigation(investigation).findings.filter(
        (f) => f.severity === "error",
      ).length,
      0,
    );
    assert.equal(planNextAction(investigation).status, "planned");
    const summary = summarizeInvestigation(investigation, { maxItems: 2 });
    assert.ok(summary.openQuestions.length <= 2);
    assert.equal(summary.openQuestions[0].id, "q-packed");
    assert.ok(
      queryEvidence(investigation, { confidence: "inferred" }).evidence.every(
        (e) => e.citedBy.length === 1,
      ),
    );
    assert.match(renderTimeline(investigation), /^# Timeline/);

    const hostile = {
      ...investigation,
      claims: [
        ...investigation.claims,
        {
          id: "xss",
          text: "<script>alert(1)</script>",
          evidenceIds: ["triage-identity"],
        },
      ],
    };
    const html = renderHtmlReport(hostile);
    assert.doesNotMatch(html, /<script>alert/);
    assert.match(html, /default-src 'none'/);
    const sarif = renderSarif(hostile, { version: "1.2.3" });
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].tool.driver.version, "1.2.3");
    assert.ok(
      sarif.runs[0].results.some(
        (r) => r.partialFingerprints?.claimId === "xss" && r.level === "note",
      ),
    );
  } finally {
    await cleanup();
  }
});

void test("CLI triage, --record, and report formats work end to end", async () => {
  const { dir, pe, cleanup } = await fixtures();
  try {
    const inv = join(dir, "inv.json");
    assert.equal(cli(["triage", "--target", pe, "--output", inv]).status, 0);
    const recorded = cli([
      "iocs",
      "--target",
      pe,
      "--record",
      inv,
      "--evidence-id",
      "iocs-cli",
    ]);
    assert.equal(recorded.status, 0, recorded.stderr);
    const saved = JSON.parse(await readFile(inv, "utf8"));
    const evidence = saved.evidence.find((e) => e.id === "iocs-cli");
    assert.match(evidence.source, /^ptah iocs --target /);
    assert.doesNotMatch(evidence.source, /--record/);
    assert.equal(cli(["verify", "--input", inv, "--target", pe]).status, 0);
    assert.match(
      cli(["report", "--input", inv, "--format", "html"]).stdout,
      /^<!doctype html>/,
    );
    assert.equal(
      JSON.parse(cli(["report", "--input", inv, "--format", "sarif"]).stdout)
        .version,
      "2.1.0",
    );
    assert.match(
      cli(["hexdump", "--target", pe, "--length", "16"]).stdout,
      /^00000000  4d 5a/,
    );
  } finally {
    await cleanup();
  }
});

void test("MCP lists annotated tools, negotiates protocol, and runs triage under the path policy", async () => {
  const { dir, pe, cleanup } = await fixtures();
  try {
    const child = spawn(
      process.execPath,
      [join(root, "scripts/ptah-mcp.mjs"), "--workspace", dir],
      { stdio: ["pipe", "pipe", "inherit"] },
    );
    const messages = [];
    let buffer = "";
    const done = new Promise((finish) => {
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        buffer += chunk;
        let index;
        while ((index = buffer.indexOf("\n")) >= 0) {
          messages.push(JSON.parse(buffer.slice(0, index)));
          buffer = buffer.slice(index + 1);
          if (messages.length === 4) finish();
        }
      });
    });
    const send = (message) =>
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
    send({
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "t", version: "1" },
      },
    });
    send({ id: 2, method: "tools/list" });
    send({
      id: 3,
      method: "tools/call",
      params: {
        name: "ptah_triage",
        arguments: { target: pe, output: join(dir, "mcp.json") },
      },
    });
    send({
      id: 4,
      method: "tools/call",
      params: { name: "ptah_hashes", arguments: { target: "/etc/hostname" } },
    });
    await done;
    child.kill();
    const byId = Object.fromEntries(messages.map((m) => [m.id, m.result]));
    assert.equal(byId[1].protocolVersion, "2025-03-26");
    const tools = Object.fromEntries(byId[2].tools.map((t) => [t.name, t]));
    assert.ok(
      tools.ptah_triage &&
        tools.ptah_structure &&
        tools.ptah_iocs &&
        tools.ptah_summary,
    );
    assert.equal(tools.ptah_structure.annotations.readOnlyHint, true);
    assert.equal(tools.ptah_add_evidence.annotations.readOnlyHint, false);
    assert.equal(byId[3].isError, false, byId[3].content[0].text);
    assert.equal(byId[4].isError, true);
    assert.match(byId[4].content[0].text, /outside the allowed roots|refused/);
  } finally {
    await cleanup();
  }
});
