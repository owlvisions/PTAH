import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createDefaultRegistry,
  createEngine,
  findExecutable,
  parseAssembly,
  parseAssemblyRef,
  parseBadging,
  parseBinwalkCsv,
  parseMethods,
  parseTsharkFields,
  parseTypedef,
  parseWasmDisassembly,
  parseWasmObjdumpDetails,
} from "../src/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");
const read = (name) => readFile(join(fixtures, name), "utf8");
const attestation = { ownership: "owner", purpose: "interoperability" };
const haveTools = async (...tools) =>
  (await Promise.all(tools.map((tool) => findExecutable(tool)))).every(Boolean);

void test("aapt2 badging maps package, version, permissions, and components", async () => {
  const badging = parseBadging(await read("android/aapt2-badging.txt"));
  assert.equal(badging.package, "dev.ptah.sample");
  assert.equal(badging.versionName, "1.2.3");
  assert.equal(badging.versionCode, "7");
  assert.deepEqual(badging.permissions, ["android.permission.INTERNET"]);
  assert.equal(badging.targetSdkVersion, "29");
  assert.deepEqual(badging.activities, ["dev.ptah.sample.MainActivity"]);
});

void test("wasm-objdump maps sections, imports, exports, and disassembly", async () => {
  const details = parseWasmObjdumpDetails(await read("wasm/objdump-x.txt"));
  assert.ok(details.sections.some((s) => s.name === "Type" && s.count === 3));
  assert.deepEqual(details.imports, [
    { kind: "func", module: "env", name: "log" },
  ]);
  assert.deepEqual(details.exports.map((e) => e.name).sort(), [
    "add",
    "memory",
    "ping",
  ]);
  const disasm = parseWasmDisassembly(await read("wasm/objdump-d.txt"));
  const add = disasm.functions.find((fn) => fn.name === "add");
  assert.deepEqual(add.instructions, [
    "local.get 0",
    "local.get 1",
    "i32.add",
    "end",
  ]);
  assert.equal(
    parseWasmDisassembly(await read("wasm/objdump-d.txt"), 2).truncated,
    true,
  );
});

void test("monodis maps assembly, types, methods, and references", async () => {
  assert.equal(parseAssembly(await read("dotnet/assembly.txt")).name, "lib");
  const types = parseTypedef(await read("dotnet/typedef.txt"));
  assert.ok(types.some((t) => t.name === "Ptah.Sample.Greeter" && t.public));
  assert.ok(types.some((t) => t.name === "Ptah.Sample.IGreeter"));
  const methods = parseMethods(await read("dotnet/method.txt"));
  assert.ok(
    methods.some(
      (m) => m.name === "Add" && m.static && m.returnType.includes("int32"),
    ),
  );
  assert.ok(methods.some((m) => m.name === "Greet" && !m.static));
  assert.ok(
    parseAssemblyRef(await read("dotnet/assemblyref.txt")).some(
      (r) => r.name === "mscorlib",
    ),
  );
});

void test("binwalk and tshark map components and network exchanges", async () => {
  const components = parseBinwalkCsv(await read("firmware/binwalk.csv"));
  assert.ok(components.some((c) => /gzip/iu.test(c.type)));
  assert.ok(components.some((c) => /[Ss]quashfs/u.test(c.type)));
  assert.ok(components.every((c) => Number.isInteger(c.offset)));
  const packets = parseTsharkFields(await read("network/tshark-fields.txt"));
  assert.ok(packets.some((p) => p.dns === "api.ptah.example"));
  const http = packets.find((p) => p.http);
  assert.equal(http.http.host, "api.ptah.example");
  assert.equal(http.http.method, "GET");
});

void test("live: APK analysis routes aapt2, apktool, and jadx through the engine", async (t) => {
  if (!(await haveTools("aapt2", "apktool", "jadx")))
    return t.skip("android tools unavailable");
  const engine = createEngine({ registry: createDefaultRegistry() });
  const session = await engine.open(
    join(fixtures, "android/sample.apk"),
    attestation,
  );
  assert.equal(session.target.format, "apk");
  const manifest = await session.run("manifest");
  assert.equal(manifest.provider, "aapt2");
  assert.equal(manifest.evidence[0].data.package, "dev.ptah.sample");
  const decompiled = await session.run("decompile");
  assert.equal(decompiled.provider, "jadx");
  assert.equal(decompiled.evidence[0].confidence, "derived");
  assert.ok(
    decompiled.evidence[0].data.classes.some((c) =>
      c.code.includes("api.ptah.example"),
    ),
  );
  const resources = await session.run("resources");
  assert.equal(resources.provider, "apktool");
  assert.ok(resources.evidence[0].data.files.length > 0);
});

void test("live: WASM, .NET, firmware, and pcap each route to their provider", async (t) => {
  const cases = [
    [
      "wasm/sample.wasm",
      "wasm",
      "importsExports",
      "wasm-objdump",
      (e) => e.data.imports.some((i) => i.module === "env"),
    ],
    [
      "dotnet/sample.dll",
      "dotnet",
      "symbols",
      "monodis",
      (e) => e.data.types.some((ty) => ty.name.includes("Greeter")),
    ],
    [
      "firmware/sample.bin",
      "unknown",
      "resources",
      "unblob",
      (e) => e.data.extracted === true && e.data.files.length > 0,
    ],
    [
      "network/sample.pcap",
      "pcap",
      "resources",
      "tshark",
      (e) => e.data.dnsQueries.includes("api.ptah.example"),
    ],
  ];
  const tools = {
    "wasm-objdump": "wasm-objdump",
    monodis: "monodis",
    unblob: "unblob",
    tshark: "tshark",
  };
  for (const [file, format, task, provider, check] of cases) {
    if (!(await haveTools(tools[provider]))) {
      t.diagnostic(`skip ${provider}: unavailable`);
      continue;
    }
    const session = await createEngine({
      registry: createDefaultRegistry(),
    }).open(join(fixtures, file), attestation);
    assert.equal(session.target.format, format, file);
    const result = await session.run(task);
    assert.equal(result.provider, provider, file);
    assert.equal(
      result.evidence[0].status,
      "ok",
      `${file}: ${result.evidence[0].summary}`,
    );
    assert.ok(check(result.evidence[0]), `${file} evidence check`);
    assert.equal(result.evidence[0].targetSha256, session.target.sha256);
  }
});

void test("the capability table advertises every stage-3 format and routes by priority", async () => {
  const registry = createDefaultRegistry();
  const { routes } = await registry.probe();
  assert.deepEqual(routes.apk.manifest.slice(0, 2), ["aapt2", "apktool"]);
  assert.ok(routes.wasm.disassemble.includes("wasm-objdump"));
  assert.ok(routes.dotnet.importsExports.includes("monodis"));
  assert.deepEqual(routes.unknown.resources, ["unblob", "binwalk"]);
  assert.ok(routes.pcap.resources.includes("tshark"));
});
