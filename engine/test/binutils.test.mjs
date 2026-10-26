import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CapabilityRegistry,
  NmProvider,
  ReadelfProvider,
  createDefaultRegistry,
  createEngine,
  findExecutable,
  importsExportsFromSymbols,
  parseNm,
  parseObjdumpDisassembly,
  parseObjdumpSections,
  parseReadelfDynamic,
  parseReadelfHeader,
  parseReadelfSections,
  parseReadelfSymbols,
} from "../src/index.mjs";

const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "binutils",
);
const fixture = (name) => readFile(join(fixtures, `${name}.txt`), "utf8");
const attestation = { ownership: "open-source", purpose: "personal-study" };
const LIVE_TARGET = "/bin/true";
const live = async (...tools) =>
  (await access(LIVE_TARGET).then(
    () => true,
    () => false,
  )) &&
  (await Promise.all(tools.map((tool) => findExecutable(tool)))).every(Boolean);

void test("readelf mappers parse header, sections, symbols, and dynamic entries from recorded output", async () => {
  const header = parseReadelfHeader(await fixture("readelf-header"));
  assert.equal(header.Class, "ELF64");
  assert.match(header.Machine, /X86-64/);
  const sections = parseReadelfSections(await fixture("readelf-sections"));
  assert.equal(sections.length, 29, "30 headers minus the NULL section");
  assert.equal(
    sections[0].name,
    ".note.gnu.build-id",
    "names wider than their column are kept whole",
  );
  assert.equal(sections.find((s) => s.name === ".text").executable, true);
  assert.equal(sections.find((s) => s.name === ".dynstr").executable, false);
  const tables = parseReadelfSymbols(await fixture("readelf-symbols"));
  assert.equal(
    tables[".dynsym"].length,
    58,
    "59 entries minus the unnamed null symbol",
  );
  const getenv = tables[".dynsym"].find((s) => s.name === "getenv");
  assert.deepEqual(
    [getenv.version, getenv.defined, getenv.type],
    ["GLIBC_2.2.5", false, "FUNC"],
  );
  const dynamic = parseReadelfDynamic(await fixture("readelf-dynamic"));
  assert.deepEqual(dynamic.libraries, ["libc.so.6"]);
  const { imports, exports } = importsExportsFromSymbols(
    parseReadelfSymbols(await fixture("readelf-dynamic"))[".dynsym"],
  );
  assert.ok(imports.some((item) => item.name === "getenv"));
  assert.ok(exports.some((item) => item.name === "error"));
});

void test("objdump and nm mappers parse disassembly, sections, and symbol tables", async () => {
  const listing = parseObjdumpDisassembly(await fixture("objdump-disassemble"));
  assert.equal(listing.format, "elf64-x86-64");
  const init = listing.functions.find((fn) => fn.name === ".init");
  assert.deepEqual(init.instructions[0], {
    address: 0x2000,
    mnemonic: "sub",
    operands: "$0x8,%rsp",
  });
  assert.equal(init.instructions.at(-1).mnemonic, "ret");
  const capped = parseObjdumpDisassembly(
    await fixture("objdump-disassemble"),
    3,
  );
  assert.equal(capped.instructionCount, 3);
  assert.equal(capped.truncated, true);
  const sections = parseObjdumpSections(await fixture("objdump-sections"));
  assert.equal(sections.find((s) => s.name === ".text").executable, true);
  assert.equal(sections.find((s) => s.name === ".rodata").writable, false);
  const defined = parseNm(await fixture("nm-defined"));
  assert.ok(
    defined.some((s) => s.name === "error" && s.type === "T" && s.defined),
  );
  const undefinedSymbols = parseNm(await fixture("nm-undefined"));
  assert.ok(undefinedSymbols.every((s) => s.address === null));
  assert.ok(
    undefinedSymbols.some(
      (s) => s.name === "__ctype_b_loc" && s.version === "GLIBC_2.3",
    ),
  );
});

void test("readelf and nm agree on the imported symbols of the same binary", async () => {
  const fromReadelf = importsExportsFromSymbols(
    parseReadelfSymbols(await fixture("readelf-dynamic"))[".dynsym"],
  ).imports.map((s) => s.name);
  const fromNm = parseNm(await fixture("nm-undefined")).map((s) => s.name);
  assert.deepEqual([...new Set(fromNm)].sort(), fromReadelf);
});

void test("live: the engine analyzes an ELF end to end through readelf, objdump, and nm", async (t) => {
  if (!(await live("readelf", "objdump", "nm")))
    return t.skip("binutils or /bin/true unavailable");
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(LIVE_TARGET, attestation);
  assert.equal(session.target.format, "elf");
  const results = await session.runAll([
    "manifest",
    "sections",
    "symbols",
    "importsExports",
  ]);
  for (const [task, result] of Object.entries(results)) {
    assert.equal(result.provider, "readelf", task);
    assert.equal(result.evidence[0].status, "ok", task);
    assert.equal(result.evidence[0].confidence, "observed");
    assert.equal(result.evidence[0].targetSha256, session.target.sha256);
    assert.ok(result.evidence[0].provider.argv.includes("<target>"));
    assert.ok(
      !result.evidence[0].provider.argv.includes(LIVE_TARGET),
      "machine paths stay out of evidence",
    );
  }
  assert.ok(
    results.importsExports.evidence[0].data.libraries.includes("libc.so.6"),
  );
  const disassembly = await session.run("disassemble", {
    options: { maxInstructions: 50 },
  });
  assert.equal(disassembly.provider, "objdump");
  assert.equal(disassembly.evidence[0].status, "partial");
  assert.equal(disassembly.evidence[0].data.instructionCount, 50);

  const again = await createEngine({ registry: createDefaultRegistry() }).open(
    LIVE_TARGET,
    attestation,
  );
  const rerun = await again.run("importsExports");
  assert.equal(
    rerun.evidence[0].id,
    results.importsExports.evidence[0].id,
    "identical analyses give identical evidence",
  );
});

void test("live: when readelf is unavailable the registry falls back to nm", async (t) => {
  if (!(await live("nm"))) return t.skip("nm or /bin/true unavailable");
  class MissingReadelf extends ReadelfProvider {
    executables = ["readelf-not-installed"];
  }
  const registry = new CapabilityRegistry()
    .register(new MissingReadelf())
    .register(new NmProvider());
  const table = await registry.probe();
  assert.equal(
    table.providers.find((p) => p.id === "readelf").available,
    false,
  );
  const session = await createEngine({ registry }).open(
    LIVE_TARGET,
    attestation,
  );
  const result = await session.run("importsExports");
  assert.equal(result.provider, "nm");
  assert.ok(result.evidence[0].data.imports.length > 0);
  const manifest = await session.run("manifest");
  assert.equal(manifest.evidence[0].status, "unavailable");
});
