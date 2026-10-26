import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { verifyInvestigationCase } from "../ptah-engine.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const entrypoint = join(root, "scripts/ptah.mjs");
const mcpEntrypoint = join(root, "scripts/ptah-mcp.mjs");
const run = (args, env = process.env) =>
  spawnSync(process.execPath, [entrypoint, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 10_000,
    env,
  });

void test("shell completion scripts list every command for bash, zsh, and fish", () => {
  const help = run(["help"]).stdout;
  for (const shell of ["bash", "zsh", "fish"]) {
    const result = run(["completion", shell]);
    assert.equal(result.status, 0, result.stderr);
    for (const command of [
      "fingerprint",
      "export-case",
      "sign-case",
      "eval",
      "watch",
      "diff",
      "lint",
    ]) {
      assert.ok(
        result.stdout.includes(command),
        `${shell} completion lacks ${command}`,
      );
      assert.ok(help.includes(`ptah ${command}`), `help lacks ${command}`);
    }
  }
  assert.match(run(["completion", "bash"]).stdout, /complete -F _ptah ptah/);
  assert.match(run(["completion", "zsh"]).stdout, /#compdef ptah/);
  assert.match(run(["completion", "fish"]).stdout, /complete -c ptah/);
  const bad = run(["completion", "powershell"]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /bash, zsh, or fish/);
});

void test("watch re-verifies the investigation when the target changes and exits after --max-events", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-watch-"));
  try {
    const target = join(dir, "target.bin");
    const investigation = join(dir, "i.json");
    await writeFile(target, "original bytes");
    assert.equal(
      run(["init", "--target", target, "--output", investigation, "--quiet"])
        .status,
      0,
    );
    const once = run([
      "watch",
      "--input",
      investigation,
      "--target",
      target,
      "--once",
    ]);
    assert.equal(once.status, 0, once.stderr);
    assert.equal(JSON.parse(once.stdout).event, "initial");

    const child = spawn(
      process.execPath,
      [
        entrypoint,
        "watch",
        "--input",
        investigation,
        "--target",
        target,
        "--max-events",
        "1",
        "--debounce-ms",
        "100",
      ],
      { cwd: root },
    );
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    await new Promise((r) => setTimeout(r, 600));
    await writeFile(target, "modified bytes");
    const exitCode = await new Promise((resolveExit) =>
      child.on("close", resolveExit),
    );
    const events = output
      .trim()
      .split("\n}\n")
      .map((piece, index, all) =>
        JSON.parse(index < all.length - 1 ? `${piece}\n}` : piece),
      );
    assert.equal(events[0].event, "initial");
    assert.equal(events[0].targetMatches, true);
    const changed = events.find((event) => event.event === "target-changed");
    assert.ok(changed, output);
    assert.equal(changed.targetMatches, false);
    assert.equal(exitCode, 2, "drift exits with code 2");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function mcp(requests, extraArgs = []) {
  const result = spawnSync(process.execPath, [mcpEntrypoint, ...extraArgs], {
    input: `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

void test("MCP exposes workflow prompts and root-bounded investigation resources", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ptah-mcp-resources-"));
  try {
    await writeFile(join(dir, "a.json"), JSON.stringify({ schemaVersion: 1 }));
    await (await import("node:fs/promises")).mkdir(join(dir, "nested"));
    await writeFile(
      join(dir, "nested", "b.json.gz"),
      Buffer.from([0x1f, 0x8b, 8, 0]),
    );
    await writeFile(join(dir, "ignored.txt"), "no");
    const outside = join(tmpdir(), `ptah-outside-${process.pid}.json`);
    await writeFile(outside, "{}");
    const messages = mcp(
      [
        { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
        { jsonrpc: "2.0", id: 2, method: "prompts/list" },
        {
          jsonrpc: "2.0",
          id: 3,
          method: "prompts/get",
          params: {
            name: "investigate-target",
            arguments: { target: "/tmp/x.bin", output: "/tmp/x.json" },
          },
        },
        {
          jsonrpc: "2.0",
          id: 4,
          method: "prompts/get",
          params: { name: "review-claims", arguments: {} },
        },
        { jsonrpc: "2.0", id: 5, method: "resources/list" },
        {
          jsonrpc: "2.0",
          id: 6,
          method: "resources/read",
          params: { uri: "ptah://investigations/a.json" },
        },
        {
          jsonrpc: "2.0",
          id: 7,
          method: "resources/read",
          params: { uri: "ptah://investigations/nested/b.json.gz" },
        },
        {
          jsonrpc: "2.0",
          id: 8,
          method: "resources/read",
          params: { uri: "ptah://investigations/../outside.json" },
        },
        {
          jsonrpc: "2.0",
          id: 9,
          method: "resources/read",
          params: { uri: `file://${outside}` },
        },
        {
          jsonrpc: "2.0",
          id: 10,
          method: "prompts/get",
          params: { name: "nope", arguments: {} },
        },
      ],
      ["--root", dir],
    );
    const byId = (id) => messages.find((m) => m.id === id);
    assert.deepEqual(Object.keys(byId(1).result.capabilities).sort(), [
      "prompts",
      "resources",
      "tools",
    ]);
    assert.deepEqual(
      byId(2).result.prompts.map((p) => p.name),
      ["triage-target", "investigate-target", "review-claims", "compare-cases"],
    );
    assert.match(
      byId(3).result.messages[0].content.text,
      /never execute the target/,
    );
    assert.match(byId(3).result.messages[0].content.text, /\/tmp\/x\.bin/);
    assert.match(byId(4).error.message, /input is required/);
    assert.deepEqual(
      byId(5).result.resources.map((r) => r.uri),
      [
        "ptah://investigations/a.json",
        "ptah://investigations/nested/b.json.gz",
      ],
    );
    assert.equal(JSON.parse(byId(6).result.contents[0].text).schemaVersion, 1);
    assert.equal(byId(7).result.contents[0].mimeType, "application/gzip");
    assert.match(byId(8).error.message, /escapes the configured root/);
    assert.match(byId(9).error.message, /unknown resource/);
    assert.match(byId(10).error.message, /unknown prompt/);

    const noRoot = mcp([
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 2, method: "resources/list" },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "resources/read",
        params: { uri: "ptah://investigations/a.json" },
      },
    ]);
    assert.equal("resources" in noRoot[0].result.capabilities, false);
    assert.deepEqual(noRoot[1].result.resources, []);
    assert.match(noRoot[2].error.message, /resources are disabled/);
    await rm(outside, { force: true });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void test("VS Code integration skeleton has a valid manifest, parses, and spawns PTAH without a shell", async () => {
  const manifest = JSON.parse(
    await readFile(join(root, "integrations/vscode-ptah/package.json"), "utf8"),
  );
  assert.equal(manifest.main, "./extension.js");
  assert.deepEqual(
    manifest.contributes.commands.map((c) => c.command),
    [
      "ptah.openWorkbench",
      "ptah.fingerprintActiveFile",
      "ptah.lintInvestigation",
    ],
  );
  const source = await readFile(
    join(root, "integrations/vscode-ptah/extension.js"),
    "utf8",
  );
  assert.match(source, /shell: false/);
  assert.doesNotMatch(source, /exec\(/);
  assert.doesNotMatch(source, /require\(/);
  const check = spawnSync(
    process.execPath,
    ["--check", join(root, "integrations/vscode-ptah/extension.js")],
    { encoding: "utf8" },
  );
  assert.equal(check.status, 0, check.stderr);
  const { createRequire } = await import("node:module");
  const requireFrom = createRequire(import.meta.url);
  const { ptahCommand } = requireFrom(
    join(root, "integrations/vscode-ptah/extension.js"),
  );
  assert.deepEqual(ptahCommand({ get: () => "" }), {
    command: "ptah",
    prefix: [],
  });
  assert.deepEqual(ptahCommand({ get: () => "/repo" }).prefix, [
    join("/repo", "scripts", "ptah.mjs"),
  ]);
});

void test("Arabic getting-started guide documents every PTAH CLI command", async () => {
  const arabic = await readFile(
    join(root, "docs/PTAH-GETTING-STARTED.ar.md"),
    "utf8",
  );
  const help = run(["help"]).stdout;
  const commands = [...help.matchAll(/^ {2}ptah ([a-z-]+)/gmu)]
    .map((m) => m[1])
    .filter((c) => !["help"].includes(c));
  assert.ok(commands.length > 30, `help lists ${commands.length} commands`);
  const missing = commands.filter(
    (command) =>
      !arabic.includes(`\`${command}`) &&
      !arabic.includes(` ${command}`) &&
      !arabic.includes(`|${command}`),
  );
  assert.deepEqual(missing, [], `Arabic guide missing: ${missing.join(", ")}`);
  assert.match(arabic, /بتاح/);
  assert.match(arabic, /PTAH_CASE_PASSPHRASE/);
});

void test("example case bundle verifies against its committed synthetic target and the security policy covers PTAH", async () => {
  const bundle = JSON.parse(
    await readFile(
      join(
        root,
        "examples/ptah-cases/synthetic-elf-walkthrough/case.ptah-case.json",
      ),
      "utf8",
    ),
  );
  assert.equal(verifyInvestigationCase(bundle).valid, true);
  const verify = run([
    "verify-case",
    "--input",
    "examples/ptah-cases/synthetic-elf-walkthrough/case.ptah-case.json",
    "--target",
    "examples/ptah-eval/elf-aarch64-shared/target.so",
  ]);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).targetMatches, true);
  const security = await readFile(join(root, "SECURITY.md"), "utf8");
  assert.match(security, /## PTAH responsible disclosure/);
  assert.match(security, /ptah-case-signing\.key/);
  assert.match(security, /path traversal in MCP `--root` resources/);
  const roadmap = await readFile(join(root, "docs/PTAH-ROADMAP.md"), "utf8");
  assert.match(roadmap, /## Public roadmap metrics/);
  assert.match(roadmap, /metrics\.claimLabelPrecision/);
});

void test("workbench serves DOT and Mermaid graph downloads", async () => {
  const { createPtahUiServer } = await import("../ptah-ui-server.mjs");
  const app = await createPtahUiServer();
  try {
    await new Promise((resolveListen, reject) =>
      app.server.listen(0, "127.0.0.1", (e) =>
        e ? reject(e) : resolveListen(),
      ),
    );
    const base = `http://127.0.0.1:${app.server.address().port}`;
    assert.equal((await fetch(`${base}/api/graph.dot`)).status, 409);
    await fetch(`${base}/api/init`, {
      method: "POST",
      headers: {
        "x-ptah-token": app.sessionToken,
        "content-type": "application/octet-stream",
        "x-target-name": "t.bin",
      },
      body: new Uint8Array([1, 2, 3]),
    });
    const dot = await fetch(`${base}/api/graph.dot`);
    assert.equal(dot.status, 200);
    assert.match(dot.headers.get("content-disposition"), /ptah-graph\.dot/);
    assert.match(await dot.text(), /^digraph ptah/);
    const mmd = await fetch(`${base}/api/graph.mmd`);
    assert.match(await mmd.text(), /^graph LR/);
    const html = await (await fetch(base)).text();
    assert.match(html, /id="downloadDot"/);
    assert.match(html, /id="downloadMermaid"/);
  } finally {
    await app.close();
  }
});

void test("workbench rejects cross-site state changes without the session token", async () => {
  const { createPtahUiServer } = await import("../ptah-ui-server.mjs");
  const app = await createPtahUiServer();
  await new Promise((ready) => app.server.listen(0, "127.0.0.1", ready));
  try {
    const base = `http://127.0.0.1:${app.server.address().port}`;
    const upload = (headers) =>
      fetch(`${base}/api/init`, {
        method: "POST",
        headers: { "content-type": "text/plain", ...headers },
        body: "attacker bytes",
      });
    assert.equal((await upload({})).status, 403);
    assert.equal(
      (await upload({ "x-ptah-token": "0".repeat(64) })).status,
      403,
    );
    assert.equal(
      (
        await upload({
          "x-ptah-token": app.sessionToken,
          origin: "https://evil.example",
        })
      ).status,
      403,
    );
    assert.equal(
      (await (await fetch(`${base}/api/state`)).json()).initialized,
      false,
    );
    const page = await (await fetch(base)).text();
    assert.ok(page.includes(`content="${app.sessionToken}"`));
    assert.equal(
      (await upload({ "x-ptah-token": app.sessionToken, origin: base })).status,
      201,
    );
  } finally {
    await app.close();
  }
});
