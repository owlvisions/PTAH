import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  HopperProvider,
  IdaProvider,
  JebProvider,
  createDefaultRegistry,
  createEngine,
  findExecutable,
  listAndroidDevices,
  parseAdbDevices,
  parseGdbFunctions,
  parseGdbSections,
  planApkPull,
} from "../src/index.mjs";

const engineRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const scripts = join(engineRoot, "src/adapters/scripts");
const have = async (t) =>
  Boolean(await findExecutable(t)) &&
  (await access("/bin/true").then(
    () => true,
    () => false,
  ));

void test("gdb static parsers map functions and sections", () => {
  const fns = parseGdbFunctions(
    "All defined functions:\n\nNon-debugging symbols:\n0x0000000000002030  getenv@plt\n0x0000000000001234  main\n",
  );
  assert.deepEqual(fns, [
    { address: 0x2030, name: "getenv", plt: true },
    { address: 0x1234, name: "main", plt: false },
  ]);
  const secs = parseGdbSections(
    " [0]      0x00000350->0x00000374 at 0x00000350: .text CODE ALLOC\n",
  );
  assert.equal(secs[0].name, ".text");
  assert.equal(secs[0].executable, true);
  assert.equal(secs[0].size, 0x374 - 0x350);
});

void test("live: gdb analyzes an ELF statically through the engine", async (t) => {
  if (!(await have("gdb"))) return t.skip("gdb unavailable");
  const registry = createDefaultRegistry();
  const session = await createEngine({ registry }).open("/bin/true", {
    ownership: "open-source",
    purpose: "security-research",
  });
  const symbols = await session.run("symbols", { provider: "gdb" });
  assert.equal(symbols.provider, "gdb");
  assert.ok(symbols.evidence[0].data.tables.functions.length > 0);
  const sections = await session.run("sections", { provider: "gdb" });
  assert.ok(sections.evidence[0].data.sections.some((s) => s.name === ".text"));
});

void test("the adb analyzer runs real commands and degrades without a device", async (t) => {
  assert.deepEqual(
    parseAdbDevices(
      "List of devices attached\nemulator-5554\tdevice product:x\n",
    ),
    [{ serial: "emulator-5554", state: "device", info: "product:x" }],
  );
  const planned = planApkPull("emulator-5554", "com.example.app");
  assert.deepEqual(planned.pathCommand, [
    "adb",
    "-s",
    "emulator-5554",
    "shell",
    "pm",
    "path",
    "com.example.app",
  ]);
  assert.throws(() => planApkPull("bad serial!", "com.x"), /serial/);
  assert.throws(() => planApkPull("emulator-5554", "../evil"), /package/);
  if (!(await findExecutable("adb"))) return t.skip("adb unavailable");
  const devices = await listAndroidDevices();
  assert.equal(devices.available, true);
  assert.ok(Array.isArray(devices.devices)); // empty here; real query ran
});

void test("commercial-engine adapters ship their headless scripts and still degrade without the tool", async () => {
  for (const name of [
    "ptah_ida_export.py",
    "ptah_hopper_export.py",
    "ptah_jeb_export.py",
  ])
    await access(join(scripts, name)); // shipped
  // Without the licensed binary, each still reports how to enable it.
  for (const Provider of [IdaProvider, HopperProvider, JebProvider]) {
    const state = await new Provider().isAvailable({
      env: { PATH: "/usr/bin" },
    });
    assert.equal(state.available, false);
    assert.match(state.reason, /not bundled; set PTAH_\w+/);
  }
  // The shipped Python scripts are syntactically valid where python3 exists.
  if (await findExecutable("python3"))
    for (const name of [
      "ptah_ida_export.py",
      "ptah_hopper_export.py",
      "ptah_jeb_export.py",
    ]) {
      const r = spawnSync("python3", ["-m", "py_compile", join(scripts, name)]);
      assert.equal(r.status, 0, `${name}: ${r.stderr}`);
    }
});

void test("gdb is registered as a working engine provider for ELF/PE", async () => {
  const registry = createDefaultRegistry();
  const { routes, providers } = await registry.probe();
  assert.ok(providers.find((p) => p.id === "gdb"));
  assert.ok(routes.elf.symbols.includes("gdb"));
  assert.ok(routes.elf.sections.includes("gdb"));
});
