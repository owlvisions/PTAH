import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AGENT_CLIENTS,
  SKILL_SOURCE,
  serverCommand,
  splitTomlServer,
} from "../ptah-agents.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const entrypoint = join(root, "scripts/ptah.mjs");

/** Run the CLI against a sandboxed home so real client configs are never read or written. */
const agents = (home, args) => {
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  for (const key of [
    "XDG_CONFIG_HOME",
    "APPDATA",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "COPILOT_HOME",
    "OPENCODE_CONFIG_DIR",
    "QWEN_HOME",
  ])
    delete env[key];
  const result = spawnSync(process.execPath, [entrypoint, "agents", ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 20_000,
    env,
  });
  let json;
  try {
    json = JSON.parse(result.stdout);
  } catch {
    json = undefined;
  }
  return { ...result, json };
};

const sandbox = async () => {
  const home = await mkdtemp(join(tmpdir(), "ptah-agents-"));
  const context = { home, env: {}, platform: process.platform };
  return {
    home,
    context,
    cleanup: () => rm(home, { recursive: true, force: true }),
  };
};
const client = (id) => AGENT_CLIENTS.find((item) => item.id === id);
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

void test("agents covers fifteen coding agents with distinct ids and config paths", () => {
  assert.equal(AGENT_CLIENTS.length, 15);
  const context = { home: "/h", env: {}, platform: "linux" };
  assert.equal(new Set(AGENT_CLIENTS.map((item) => item.id)).size, 15);
  assert.equal(
    new Set(AGENT_CLIENTS.map((item) => item.config(context))).size,
    15,
  );
  for (const id of [
    "claude_code",
    "codex",
    "gemini_cli",
    "copilot_vscode",
    "copilot_cli",
    "cursor",
    "cline",
    "roo_code",
    "kiro",
    "amazon_q",
    "zed",
  ])
    assert.ok(client(id), `${id} is supported`);
});

void test("agents install previews by default and writes nothing", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const result = agents(home, ["install", "--all"]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.json.applied, false);
    assert.match(result.json.next, /--yes/);
    assert.ok(result.json.clients.every((item) => item.action === "register"));
    assert.deepEqual(await readdir(home), []);
    for (const item of AGENT_CLIENTS)
      assert.equal(item.config(context).startsWith(home), true);
  } finally {
    await cleanup();
  }
});

void test("agents install writes each client's own dialect and preserves other settings", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const cursor = client("cursor").config(context);
    await mkdir(dirname(cursor), { recursive: true });
    await writeFile(
      cursor,
      JSON.stringify({
        mcpServers: { other: { command: "x" } },
        theme: "dark",
      }),
    );
    const applied = agents(home, ["install", "--all", "--yes"]);
    assert.equal(applied.status, 0, applied.stderr);
    const [node, script] = applied.json.command;
    assert.equal(script, join(root, "scripts", "ptah-mcp.mjs"));
    const plain = { command: node, args: [script] };
    const typed = { type: "stdio", ...plain };
    const expected = {
      claude_code: ["mcpServers", typed],
      claude_desktop: ["mcpServers", plain],
      gemini_cli: ["mcpServers", plain],
      copilot_vscode: ["servers", typed],
      copilot_cli: ["mcpServers", { ...typed, tools: ["*"] }],
      cursor: ["mcpServers", plain],
      windsurf: ["mcpServers", plain],
      opencode: [
        "mcp",
        { type: "local", command: [node, script], enabled: true },
      ],
      qwen_code: ["mcpServers", plain],
    };
    for (const [id, [key, entry]] of Object.entries(expected))
      assert.deepEqual(
        (await readJson(client(id).config(context)))[key].ptah,
        entry,
        id,
      );
    const cursorConfig = await readJson(cursor);
    assert.deepEqual(cursorConfig.mcpServers.other, { command: "x" });
    assert.equal(cursorConfig.theme, "dark");
    const backup = applied.json.clients.find(
      (item) => item.id === "cursor",
    ).backup;
    assert.deepEqual(await readJson(backup), {
      mcpServers: { other: { command: "x" } },
      theme: "dark",
    });
  } finally {
    await cleanup();
  }
});

void test("agents install replaces only the Codex ptah table, installs skills, and is idempotent", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const codex = client("codex").config(context);
    await mkdir(dirname(codex), { recursive: true });
    await writeFile(
      codex,
      'model = "gpt"\n\n[mcp_servers.other]\ncommand = "y"\n\n[mcp_servers.ptah]\ncommand = "old"\nargs = ["/old/ptah-mcp.mjs"]\n\n[profiles.fast]\nmodel = "mini"\n',
    );
    const applied = agents(home, ["install", "--all", "--yes"]);
    assert.equal(applied.status, 0, applied.stderr);
    const toml = await readFile(codex, "utf8");
    assert.match(toml, /^model = "gpt"/);
    assert.match(toml, /\[mcp_servers\.other\]\ncommand = "y"/);
    assert.match(toml, /\[profiles\.fast\]\nmodel = "mini"/);
    assert.equal(toml.match(/\[mcp_servers\.ptah\]/g).length, 1);
    assert.doesNotMatch(toml, /\/old\/ptah-mcp/);
    assert.ok(
      splitTomlServer(toml).table.includes(
        `args = [${JSON.stringify(applied.json.command[1])}]`,
      ),
    );

    const skill = await readFile(SKILL_SOURCE, "utf8");
    for (const directory of [
      [".claude", "skills"],
      [".agents", "skills"],
    ])
      assert.equal(
        await readFile(join(home, ...directory, "ptah", "SKILL.md"), "utf8"),
        skill,
      );

    const again = agents(home, ["install", "--all", "--yes"]);
    assert.ok(again.json.clients.every((item) => item.action === "unchanged"));
    assert.ok(again.json.skills.every((item) => item.action === "unchanged"));
    const list = agents(home, ["list"]);
    assert.equal(list.status, 0, list.stderr);
    assert.ok(
      list.json.clients.every(
        (item) => item.registered && item.owned && item.current,
      ),
    );
  } finally {
    await cleanup();
  }
});

void test("agents never replaces a foreign ptah server or rewrites JSON with comments", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const cursor = client("cursor").config(context);
    await mkdir(dirname(cursor), { recursive: true });
    const foreign = JSON.stringify({
      mcpServers: { ptah: { command: "someone-else" } },
    });
    await writeFile(cursor, foreign);
    const windsurf = client("windsurf").config(context);
    await mkdir(dirname(windsurf), { recursive: true });
    const commented = '{\n  // mine\n  "mcpServers": {}\n}\n';
    await writeFile(windsurf, commented);

    const result = agents(home, [
      "install",
      "--client",
      "cursor,windsurf",
      "--yes",
    ]);
    assert.equal(result.status, 2);
    const actions = Object.fromEntries(
      result.json.clients.map((item) => [item.id, item.action]),
    );
    assert.deepEqual(actions, { cursor: "conflict", windsurf: "blocked" });
    assert.equal(await readFile(cursor, "utf8"), foreign);
    assert.equal(await readFile(windsurf, "utf8"), commented);

    const forced = agents(home, [
      "install",
      "--client",
      "cursor",
      "--yes",
      "--force",
    ]);
    assert.equal(forced.status, 0, forced.stderr);
    assert.match(JSON.stringify(await readJson(cursor)), /ptah-mcp/);
  } finally {
    await cleanup();
  }
});

void test("agents uninstall removes only PTAH and keeps a shared skill still in use", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const codex = client("codex").config(context);
    await mkdir(dirname(codex), { recursive: true });
    await writeFile(codex, '[mcp_servers.other]\ncommand = "y"\n');
    assert.equal(
      agents(home, ["install", "--client", "codex,cursor,claude_code", "--yes"])
        .status,
      0,
    );

    const partial = agents(home, ["uninstall", "--client", "codex", "--yes"]);
    assert.equal(partial.status, 0, partial.stderr);
    assert.equal(
      await readFile(codex, "utf8"),
      '[mcp_servers.other]\ncommand = "y"\n',
    );
    assert.deepEqual(
      partial.json.skills.map((item) => item.action),
      ["kept"],
    );
    await readFile(join(home, ".agents", "skills", "ptah", "SKILL.md"));

    const rest = agents(home, [
      "uninstall",
      "--client",
      "cursor,claude_code",
      "--yes",
    ]);
    assert.equal(rest.status, 0, rest.stderr);
    // The Cursor file held only PTAH's entry, so uninstall removes it.
    await assert.rejects(readFile(client("cursor").config(context)));
    await assert.rejects(
      readFile(join(home, ".agents", "skills", "ptah", "SKILL.md")),
    );
    await assert.rejects(
      readFile(join(home, ".claude", "skills", "ptah", "SKILL.md")),
    );
  } finally {
    await cleanup();
  }
});

void test("agents print renders manual snippets for clients and generic dialects", () => {
  const home = tmpdir();
  const codex = agents(home, ["print", "--client", "codex"]);
  assert.match(codex.stdout, /^\[mcp_servers\.ptah\]\ncommand = /);
  const vscode = JSON.parse(
    agents(home, ["print", "--client", "vscode"]).stdout,
  );
  assert.equal(vscode.servers.ptah.type, "stdio");
  const generic = JSON.parse(agents(home, ["print"]).stdout);
  assert.match(generic.mcpServers.ptah.args[0], /ptah-mcp\.mjs$/);
  const npx = JSON.parse(agents(home, ["print", "--launcher", "npx"]).stdout);
  assert.equal(npx.mcpServers.ptah.command, "npx");
  assert.ok(npx.mcpServers.ptah.args.includes("ptah-mcp"));
});

void test("the registered command starts PTAH MCP with instructions and evidence-recording tools", async () => {
  const [command, ...args] = serverCommand("local");
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
  const lines = [];
  child.stdout.setEncoding("utf8");
  let buffer = "";
  const done = new Promise((finish) => {
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(buffer.slice(0, index)));
        buffer = buffer.slice(index + 1);
        if (lines.length === 2) finish();
      }
    });
  });
  child.stdin.write(
    `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "1" } } })}\n${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`,
  );
  await done;
  child.kill();
  assert.match(lines[0].result.instructions, /evidence/i);
  const names = lines[1].result.tools.map((tool) => tool.name);
  for (const name of [
    "ptah_init",
    "ptah_add_evidence",
    "ptah_add_claim",
    "ptah_add_question",
    "ptah_set_claim_status",
    "ptah_resolve_question",
  ])
    assert.ok(names.includes(name), `${name} is listed`);
});

void test("agents writes Zed context_servers and the new clients' mcpServers entries", async () => {
  const { home, context, cleanup } = await sandbox();
  try {
    const applied = agents(home, [
      "install",
      "--client",
      "zed,cline,roo_code,kiro,amazon_q",
      "--yes",
    ]);
    assert.equal(applied.status, 0, applied.stderr);
    const [node, script] = applied.json.command;
    assert.deepEqual(
      (await readJson(client("zed").config(context))).context_servers.ptah,
      { source: "custom", command: node, args: [script], env: {} },
    );
    for (const id of ["cline", "roo_code", "kiro", "amazon_q"])
      assert.deepEqual(
        (await readJson(client(id).config(context))).mcpServers.ptah,
        { command: node, args: [script] },
        id,
      );
  } finally {
    await cleanup();
  }
});

void test("agents --workspace confines project registrations and round-trips instruction files", async () => {
  const { home, cleanup } = await sandbox();
  try {
    const workspace = join(home, "project");
    await mkdir(join(workspace, ".vscode"), { recursive: true });
    await writeFile(
      join(workspace, ".vscode", "mcp.json"),
      JSON.stringify({ servers: { mine: { command: "x" } } }),
    );
    await writeFile(join(workspace, "AGENTS.md"), "# Project rules\n");
    const installed = agents(home, [
      "install",
      "--workspace",
      workspace,
      "--yes",
    ]);
    assert.equal(installed.status, 0, installed.stderr);
    const project = await readJson(join(workspace, ".mcp.json"));
    assert.deepEqual(project.mcpServers.ptah.args.slice(-2), [
      "--workspace",
      workspace,
    ]);
    const vscode = await readJson(join(workspace, ".vscode", "mcp.json"));
    assert.deepEqual(vscode.servers.mine, { command: "x" });
    assert.equal(vscode.servers.ptah.type, "stdio");
    assert.match(
      await readFile(join(workspace, ".codex", "config.toml"), "utf8"),
      /\[mcp_servers\.ptah\]/,
    );
    const agentsMd = await readFile(join(workspace, "AGENTS.md"), "utf8");
    assert.match(agentsMd, /^# Project rules\n\n<!-- ptah:begin -->/);
    assert.match(
      await readFile(join(workspace, "CLAUDE.md"), "utf8"),
      /ptah_triage/,
    );
    const again = agents(home, ["install", "--workspace", workspace, "--yes"]);
    assert.ok(
      again.json.instructions.every((item) => item.action === "unchanged"),
    );
    assert.ok(again.json.clients.every((item) => item.action === "unchanged"));

    assert.equal(
      agents(home, ["uninstall", "--workspace", workspace, "--yes"]).status,
      0,
    );
    assert.equal(
      await readFile(join(workspace, "AGENTS.md"), "utf8"),
      "# Project rules\n",
    );
    assert.deepEqual(
      (await readJson(join(workspace, ".vscode", "mcp.json"))).servers,
      { mine: { command: "x" } },
    );
    await assert.rejects(readFile(join(workspace, ".mcp.json")));
    await assert.rejects(readFile(join(workspace, "CLAUDE.md")));
  } finally {
    await cleanup();
  }
});

void test("plugin and extension manifests launch this checkout's server and track the package version", async () => {
  const pkg = await readJson(join(root, "package.json"));
  const gemini = await readJson(join(root, "gemini-extension.json"));
  const plugin = await readJson(join(root, ".claude-plugin", "plugin.json"));
  const marketplace = await readJson(
    join(root, ".claude-plugin", "marketplace.json"),
  );
  assert.equal(gemini.version, pkg.version);
  assert.equal(plugin.version, pkg.version);
  assert.deepEqual(gemini.mcpServers.ptah.args, [
    "${extensionPath}/scripts/ptah-mcp.mjs",
  ]);
  assert.deepEqual(plugin.mcpServers.ptah.args, [
    "${CLAUDE_PLUGIN_ROOT}/scripts/ptah-mcp.mjs",
  ]);
  await readFile(join(root, gemini.contextFileName));
  assert.equal(marketplace.plugins[0].name, plugin.name);
  const release = await readJson(join(root, "release-please-config.json"));
  const bumped = release.packages["."]["extra-files"].map(
    (item) => item.path ?? item,
  );
  assert.ok(
    bumped.includes("gemini-extension.json") &&
      bumped.includes(".claude-plugin/plugin.json"),
  );
});

void test("doctor reports runtime, analyzers, agents, and upstream state without changing anything", async () => {
  const { home, cleanup } = await sandbox();
  try {
    const result = agents(home, ["list"]);
    assert.equal(result.status, 0);
    const doctor = spawnSync(process.execPath, [entrypoint, "doctor"], {
      cwd: root,
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, HOME: home },
    });
    const report = JSON.parse(doctor.stdout);
    assert.deepEqual(Object.keys(report.checks).sort(), [
      "agents",
      "analyzers",
      "isolation",
      "runtime",
      "upstream",
    ]);
    assert.equal(typeof report.checks.runtime.ok, "boolean");
    assert.deepEqual(await readdir(home), []);
  } finally {
    await cleanup();
  }
});
