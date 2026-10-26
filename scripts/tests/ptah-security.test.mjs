import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const mcpEntrypoint = join(root, "scripts/ptah-mcp.mjs");

/** Send tool calls to a fresh PTAH MCP server and return each result. */
async function callTools(calls, { home, args = [], env = {} }) {
  const child = spawn(process.execPath, [mcpEntrypoint, ...args], {
    env: { ...process.env, HOME: home, USERPROFILE: home, ...env },
    stdio: ["pipe", "pipe", "inherit"],
  });
  const results = new Map();
  let buffer = "";
  const done = new Promise((finish, fail) => {
    child.once("error", fail);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const message = JSON.parse(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
        results.set(message.id, message.result);
        if (results.size === calls.length) finish();
      }
    });
  });
  calls.forEach(([name, callArgs], id) =>
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: callArgs } })}\n`,
    ),
  );
  await done;
  child.kill();
  return calls.map((_, id) => ({
    isError: results.get(id).isError,
    text: results.get(id).content[0].text,
  }));
}

const fixture = async () => {
  const home = await mkdtemp(join(tmpdir(), "ptah-security-"));
  const work = join(home, "work");
  await mkdir(join(home, ".ssh"), { recursive: true });
  await mkdir(work, { recursive: true });
  await writeFile(
    join(home, ".ssh", "id_ed25519"),
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
  );
  await writeFile(join(work, ".env"), "API_TOKEN=secret\n");
  await writeFile(join(work, "target.bin"), "\u007fELF sample");
  await writeFile(join(home, ".bashrc"), "export PATH=$PATH\n");
  return {
    home,
    work,
    cleanup: () => rm(home, { recursive: true, force: true }),
  };
};

void test("MCP refuses to read credential locations, including through symlinks", async () => {
  const { home, work, cleanup } = await fixture();
  try {
    await symlink(join(home, ".ssh", "id_ed25519"), join(work, "innocent.bin"));
    const results = await callTools(
      [
        ["ptah_strings", { target: join(home, ".ssh", "id_ed25519") }],
        ["ptah_fingerprint", { target: join(work, ".env") }],
        ["ptah_inspect", { target: join(work, "innocent.bin") }],
        ["ptah_fingerprint", { target: join(work, "target.bin") }],
      ],
      { home },
    );
    for (const result of results.slice(0, 3)) {
      assert.equal(result.isError, true, result.text);
      assert.match(result.text, /refused/);
      assert.doesNotMatch(result.text, /PRIVATE KEY|API_TOKEN/);
    }
    assert.equal(results[3].isError, false, results[3].text);
  } finally {
    await cleanup();
  }
});

void test("MCP writes only new or PTAH-owned .json files and never through symlinks", async () => {
  const { home, work, cleanup } = await fixture();
  try {
    const investigation = join(work, "target.ptah.json");
    await symlink(join(home, ".bashrc"), join(work, "link.json"));
    const results = await callTools(
      [
        [
          "ptah_init",
          { target: join(work, "target.bin"), output: join(home, ".bashrc") },
        ],
        [
          "ptah_init",
          {
            target: join(work, "target.bin"),
            output: join(work, "notes.json.txt"),
          },
        ],
        [
          "ptah_init",
          { target: join(work, "target.bin"), output: join(work, "link.json") },
        ],
        [
          "ptah_init",
          { target: join(work, "target.bin"), output: investigation },
        ],
      ],
      { home },
    );
    for (const result of results.slice(0, 3))
      assert.equal(result.isError, true, result.text);
    assert.equal(
      await readFile(join(home, ".bashrc"), "utf8"),
      "export PATH=$PATH\n",
    );
    assert.equal(results[3].isError, false, results[3].text);

    await writeFile(join(work, "package.json"), '{"name":"mine"}\n');
    const [overwrite, update] = await callTools(
      [
        [
          "ptah_init",
          {
            target: join(work, "target.bin"),
            output: join(work, "package.json"),
          },
        ],
        [
          "ptah_add_evidence",
          {
            input: investigation,
            id: "e1",
            kind: "static-analysis",
            summary: "ELF magic",
            source: "ptah_fingerprint",
          },
        ],
      ],
      { home },
    );
    assert.equal(overwrite.isError, true);
    assert.match(overwrite.text, /not a PTAH investigation/);
    assert.equal(
      await readFile(join(work, "package.json"), "utf8"),
      '{"name":"mine"}\n',
    );
    assert.equal(update.isError, false, update.text);
  } finally {
    await cleanup();
  }
});

void test("MCP --workspace confines every path to the allowed roots", async () => {
  const { home, work, cleanup } = await fixture();
  try {
    const outside = join(home, "outside.bin");
    await writeFile(outside, "data");
    const [inside, escaped, traversal] = await callTools(
      [
        ["ptah_fingerprint", { target: join(work, "target.bin") }],
        ["ptah_fingerprint", { target: outside }],
        ["ptah_fingerprint", { target: join(work, "..", "outside.bin") }],
      ],
      { home, args: ["--workspace", work] },
    );
    assert.equal(inside.isError, false, inside.text);
    assert.match(escaped.text, /outside the allowed roots/);
    assert.match(traversal.text, /outside the allowed roots/);
  } finally {
    await cleanup();
  }
});
