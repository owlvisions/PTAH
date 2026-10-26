import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { installSyncTimer, syncUpstream } from "../ptah-upstream-sync.mjs";
import {
  conflictRule,
  mergePackageJson,
  newerVersion,
} from "../ptah-merge-policy.mjs";

const git = (cwd, ...args) =>
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
    },
  }).trim();

/** upstream (REA) and origin (PTAH fork, sharing history) plus a working clone. */
async function repositories() {
  const dir = await mkdtemp(join(tmpdir(), "ptah-sync-"));
  const upstreamWork = join(dir, "upstream-work");
  git(dir, "init", "-q", "-b", "main", upstreamWork);
  await writeFile(join(upstreamWork, "shared.txt"), "base\n");
  await writeFile(join(upstreamWork, "rea.txt"), "rea 1\n");
  git(upstreamWork, "add", ".");
  git(upstreamWork, "commit", "-q", "-m", "rea base");
  git(dir, "clone", "-q", "--bare", upstreamWork, join(dir, "origin.git"));
  const repo = join(dir, "ptah");
  git(dir, "clone", "-q", join(dir, "origin.git"), repo);
  await writeFile(join(repo, "ptah.txt"), "ptah\n");
  git(repo, "add", ".");
  git(repo, "commit", "-q", "-m", "ptah feature");
  git(repo, "push", "-q", "origin", "main");
  const upstreamCommit = async (file, text) => {
    await writeFile(join(upstreamWork, file), text);
    git(upstreamWork, "add", file);
    git(upstreamWork, "commit", "-qm", `rea change ${file}`);
  };
  return {
    dir,
    repo,
    upstream: `file://${upstreamWork}`,
    upstreamCommit,
    originMain: () =>
      git(dir, "--git-dir", join(dir, "origin.git"), "rev-parse", "main"),
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

void test("upstream sync merges a clean REA change, validates, and pushes without force", async () => {
  const r = await repositories();
  try {
    assert.equal(
      (
        await syncUpstream({
          repo: r.repo,
          upstream: r.upstream,
          validation: [],
          push: true,
        })
      ).status,
      "up-to-date",
    );
    await r.upstreamCommit("rea.txt", "rea 2\n");
    const before = r.originMain();
    const result = await syncUpstream({
      repo: r.repo,
      upstream: r.upstream,
      validation: [["node", "-e", "process.exit(0)"]],
      push: true,
    });
    assert.equal(result.status, "pushed", JSON.stringify(result));
    const after = r.originMain();
    const parents = git(
      r.dir,
      "--git-dir",
      join(r.dir, "origin.git"),
      "rev-list",
      "--parents",
      "-n1",
      after,
    ).split(" ");
    assert.deepEqual(parents.slice(1), [before, result.upstream]);
    assert.equal(
      git(
        r.dir,
        "--git-dir",
        join(r.dir, "origin.git"),
        "show",
        "main:rea.txt",
      ),
      "rea 2",
    );
    assert.equal(
      git(
        r.dir,
        "--git-dir",
        join(r.dir, "origin.git"),
        "show",
        "main:ptah.txt",
      ),
      "ptah",
    );
    assert.equal(
      git(r.repo, "worktree", "list").split("\n").length,
      1,
      "temporary worktree removed",
    );
  } finally {
    await r.cleanup();
  }
});

void test("upstream sync reports conflicts and failed validation without touching the branch", async () => {
  const r = await repositories();
  try {
    await writeFile(join(r.repo, "shared.txt"), "ptah edit\n");
    git(r.repo, "commit", "-qam", "ptah edits shared");
    git(r.repo, "push", "-q", "origin", "main");
    await r.upstreamCommit("shared.txt", "rea edit\n");
    const before = r.originMain();
    const conflict = await syncUpstream({
      repo: r.repo,
      upstream: r.upstream,
      validation: [],
      push: true,
      resolve: false,
    });
    assert.equal(conflict.status, "conflict");
    assert.deepEqual(conflict.conflicts, ["shared.txt"]);
    assert.equal(r.originMain(), before);
    assert.equal(
      await readFile(join(r.repo, "shared.txt"), "utf8"),
      "ptah edit\n",
    );
  } finally {
    await r.cleanup();
  }
  const v = await repositories();
  try {
    await v.upstreamCommit("rea.txt", "rea 3\n");
    const before = v.originMain();
    const failed = await syncUpstream({
      repo: v.repo,
      upstream: v.upstream,
      validation: [["node", "-e", "process.exit(4)"]],
      push: true,
    });
    assert.equal(failed.status, "validation-failed");
    assert.match(failed.failedStep, /process\.exit\(4\)/);
    assert.equal(v.originMain(), before);
    const dry = await syncUpstream({
      repo: v.repo,
      upstream: v.upstream,
      validation: [],
      push: false,
    });
    assert.equal(dry.status, "merged");
    assert.equal(v.originMain(), before);
  } finally {
    await v.cleanup();
  }
});

void test("upstream sync timer is written only on request and runs the push mode", async () => {
  const home = await mkdtemp(join(tmpdir(), "ptah-sync-timer-"));
  try {
    const result = await installSyncTimer({
      repo: "/repo",
      home,
      node: "/usr/bin/node",
    });
    assert.deepEqual(
      (await readdir(join(home, ".config", "systemd", "user"))).sort(),
      ["ptah-upstream-sync.service", "ptah-upstream-sync.timer"],
    );
    assert.match(
      await readFile(result.service, "utf8"),
      /ExecStart=\/usr\/bin\/node \/repo\/scripts\/ptah\.mjs upstream-sync --push/,
    );
    assert.match(await readFile(result.timer, "utf8"), /OnCalendar=hourly/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

void test("upstream sync resolves conflicts dynamically: PTAH files, REA runtime, package.json", async () => {
  const r = await repositories();
  const pkg = (fields) =>
    `${JSON.stringify({ name: "rea-agents", version: "1.0.0", dependencies: { zod: "4.4.3", a: "1.0.0" }, ...fields }, null, 2)}\n`;
  try {
    await r.upstreamCommit("package.json", pkg({}));
    await r.upstreamCommit("README.md", "REA readme\n");
    git(r.repo, "pull", "-q", r.upstream, "main", "--no-rebase", "--no-edit");
    git(r.repo, "push", "-q", "origin", "main");
    await writeFile(
      join(r.repo, "package.json"),
      pkg({
        name: "@owlvisions/ptah",
        dependencies: { zod: "4.6.7", a: "1.0.0" },
      }),
    );
    await writeFile(join(r.repo, "README.md"), "PTAH readme\n");
    await writeFile(join(r.repo, "shared.txt"), "ptah tweak\n");
    git(r.repo, "commit", "-qam", "ptah identity");
    git(r.repo, "push", "-q", "origin", "main");
    await r.upstreamCommit(
      "package.json",
      pkg({ version: "1.1.0", dependencies: { zod: "4.6.6", a: "2.0.0" } }),
    );
    await r.upstreamCommit("README.md", "REA readme 2\n");
    await r.upstreamCommit("shared.txt", "rea fix\n");

    const result = await syncUpstream({
      repo: r.repo,
      upstream: r.upstream,
      validation: [],
      push: true,
    });
    assert.equal(result.status, "pushed", JSON.stringify(result));
    const show = (path) =>
      git(
        r.dir,
        "--git-dir",
        join(r.dir, "origin.git"),
        "show",
        `main:${path}`,
      );
    assert.equal(show("README.md"), "PTAH readme");
    assert.equal(show("shared.txt"), "rea fix");
    const merged = JSON.parse(show("package.json"));
    assert.equal(merged.name, "@owlvisions/ptah");
    assert.equal(merged.version, "1.1.0");
    assert.deepEqual(merged.dependencies, { zod: "4.6.7", a: "2.0.0" });
    const rules = Object.fromEntries(
      result.resolution.decisions.map((item) => [item.path, item.rule]),
    );
    assert.deepEqual(rules, {
      "README.md": "ours",
      "package.json": "package-json",
      "shared.txt": "theirs",
    });
  } finally {
    await r.cleanup();
  }
});

void test("merge policy assigns one rule per path and keeps the newer dependency", () => {
  assert.equal(conflictRule("scripts/ptah-engine.mjs"), "ours");
  assert.equal(conflictRule("docs/PTAH-AGENTS.md"), "ours");
  assert.equal(conflictRule("package-lock.json"), "regenerate");
  assert.equal(conflictRule("licenses/npm-runtime-notices.txt"), "regenerate");
  assert.equal(conflictRule("src/domain/offsetDateTime.test.ts"), "theirs");
  assert.equal(newerVersion("4.6.7", "4.6.6"), "4.6.7");
  assert.equal(newerVersion("^1.2.0", "1.10.0"), "1.10.0");
  assert.equal(newerVersion("1.0.0-beta", "1.0.0"), "1.0.0");
  assert.equal(newerVersion("github:x/y", "1.0.0"), undefined);
  const base = JSON.stringify({
    name: "rea-agents",
    files: ["a"],
    bin: { rea: "r" },
  });
  const { text, decisions } = mergePackageJson(
    base,
    JSON.stringify({
      name: "@owlvisions/ptah",
      files: ["a", "p"],
      bin: { rea: "r", ptah: "p" },
    }),
    JSON.stringify({
      name: "rea-agents-next",
      files: ["a", "u"],
      bin: { rea: "r2" },
    }),
  );
  const merged = JSON.parse(text);
  assert.equal(merged.name, "@owlvisions/ptah");
  assert.deepEqual(merged.files, ["a", "u", "p"]);
  assert.deepEqual(merged.bin, { rea: "r2", ptah: "p" });
  assert.ok(
    decisions.some((item) => item.path === "name" && item.kept === "ptah"),
  );
});
