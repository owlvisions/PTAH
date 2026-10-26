import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CapabilityRegistry,
  GhidraProvider,
  HopperProvider,
  IdaProvider,
  JebProvider,
  KunaProvider,
  Radare2Provider,
  RizinProvider,
  createDefaultRegistry,
  createEngine,
  findExecutable,
  mapInfo,
} from "../src/index.mjs";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const attestation = { ownership: "open-source", purpose: "security-research" };
const LIVE = "/bin/true";
const have = async (...t) =>
  (await Promise.all(t.map((x) => findExecutable(x)))).every(Boolean) &&
  (await readFile(LIVE).then(
    () => true,
    () => false,
  ));

void test("radare2 mapInfo maps the file-info JSON into a manifest", async () => {
  const info = mapInfo(
    JSON.parse(await readFile(join(fixtures, "radare2/ij.json"), "utf8")),
  );
  assert.equal(info.format, "elf");
  assert.equal(info.arch, "x86");
  assert.equal(info.bits, 64);
  assert.equal(info.endian, "little");
  assert.equal(info.canary, true);
});

void test("commercial engines are never bundled and report how to enable them", async () => {
  for (const Provider of [IdaProvider, HopperProvider, JebProvider]) {
    const provider = new Provider();
    assert.match(provider.license, /commercial \(user-licensed\)/);
    const state = await provider.isAvailable({ env: { PATH: "/usr/bin" } });
    assert.equal(state.available, false);
    assert.match(state.reason, /not bundled; set PTAH_\w+/);
  }
  const ida = new IdaProvider();
  const configured = await ida.isAvailable({
    env: { PATH: "/usr/bin", PTAH_IDA_BINARY: "/no/such/idat" },
  });
  assert.equal(configured.available, false);
  assert.match(configured.reason, /not an executable/);
  // Kuna is user-provided, not commercial, but still located only via its var.
  assert.equal(
    (await new KunaProvider().isAvailable({ env: { PATH: "/usr/bin" } }))
      .available,
    false,
  );
});

void test("the registry degrades safely when a licensed engine is the only decompiler", async () => {
  const registry = new CapabilityRegistry().register(new JebProvider());
  const { path } = { path: join(fixtures, "android/sample.apk") };
  const target = {
    path,
    name: "sample.apk",
    sizeBytes: 1,
    sha256: "b".repeat(64),
    format: "apk",
  };
  await registry.probe();
  const result = await registry.run("decompile", target, {
    env: { PATH: "/usr/bin" },
  });
  assert.equal(result.provider, null);
  assert.equal(result.evidence[0].status, "unavailable");
  assert.match(result.evidence[0].summary, /no provider/i);
});

void test("live: radare2 analyzes an ELF for manifest, symbols, imports, strings, and disassembly", async (t) => {
  if (!(await have("r2"))) return t.skip("radare2 unavailable");
  const registry = new CapabilityRegistry().register(new Radare2Provider());
  const session = await createEngine({ registry }).open(LIVE, attestation);
  const manifest = await session.run("manifest");
  assert.equal(manifest.provider, "radare2");
  assert.equal(manifest.evidence[0].data.format, "elf");
  const imports = await session.run("importsExports");
  assert.ok(imports.evidence[0].data.imports.some((i) => i.name === "getenv"));
  const strings = await session.run("strings");
  assert.ok(strings.evidence[0].data.strings.length > 0);
  const disasm = await session.run("disassemble", {
    options: { symbol: "main" },
  });
  assert.ok(disasm.evidence[0].data.functions.length > 0);
  assert.ok(
    disasm.evidence[0].data.focus.instructions.length > 0,
    "entry/main instructions decoded",
  );
});

void test("live: rizin is the automatic fallback when radare2 is absent", async (t) => {
  if (!(await have("rizin"))) return t.skip("rizin unavailable");
  class MissingR2 extends Radare2Provider {
    executables = ["r2-not-installed"];
  }
  const registry = new CapabilityRegistry()
    .register(new MissingR2())
    .register(new RizinProvider());
  await registry.probe();
  const session = await createEngine({ registry }).open(LIVE, attestation);
  const result = await session.run("symbols");
  assert.equal(result.provider, "rizin");
  assert.ok(result.evidence[0].data.tables.symbols.length > 0);
});

void test("live: Ghidra headless decompiles an ELF and recovers symbols in one run", async (t) => {
  if (!(await new GhidraProvider().isAvailable()).available)
    return t.skip("Ghidra (analyzeHeadless) unavailable");
  const registry = new CapabilityRegistry().register(new GhidraProvider());
  const session = await createEngine({ registry }).open(LIVE, attestation);
  const decompiled = await session.run("decompile", {
    options: { maxFunctions: 40 },
    timeoutMs: 600_000,
  });
  assert.equal(decompiled.provider, "ghidra");
  assert.equal(decompiled.evidence[0].confidence, "derived");
  assert.equal(decompiled.evidence[0].data.language, "c");
  assert.ok(
    decompiled.evidence[0].data.functions.some(
      (fn) => fn.code && fn.code.includes("{"),
    ),
    "has C pseudocode",
  );
  const symbols = await session.run("symbols");
  assert.equal(symbols.provider, "ghidra");
  assert.ok(symbols.evidence[0].data.tables.analysis.length > 0);
  assert.equal(
    symbols.cached,
    false,
    "symbols reuse the memoized decompile run, not a second headless pass",
  );
});

void test("the default registry routes decompile to the best available engine", async () => {
  const { routes } = await createDefaultRegistry().probe();
  // Static priority order (availability aside): user IDA/JEB first, then Ghidra.
  assert.equal(routes.elf.decompile[0], "ida");
  assert.ok(routes.elf.decompile.includes("ghidra"));
  assert.equal(routes.apk.decompile[0], "jeb");
  assert.ok(routes.apk.decompile.includes("jadx"));
  assert.ok(routes.macho.disassemble.includes("radare2"));
});
