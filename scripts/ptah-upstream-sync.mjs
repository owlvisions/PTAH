/**
 * Merge the latest REA upstream into PTAH's default branch automatically.
 *
 * The merge happens in a temporary detached worktree, never in the caller's
 * checkout. Conflicts abort without changing any branch. A clean merge is
 * validated in that worktree and only then pushed, without force, so a branch
 * that moved meanwhile is retried on the next run instead of overwritten.
 */
import { spawn } from "node:child_process";
import {
  access,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
  REGENERATE_COMMANDS,
  conflictRule,
  mergePackageJson,
} from "./ptah-merge-policy.mjs";
import { dirname, isAbsolute, join } from "node:path";

export const DEFAULT_UPSTREAM = "https://github.com/morluto/rea.git";
export const DEFAULT_VALIDATION = Object.freeze([
  ["npm", "run", "check:fast"],
  ["npm", "run", "test:ptah"],
  ["npm", "run", "build:cached"],
  ["npm", "run", "test:fast"],
]);

function run(command, args, options = {}) {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", (error) =>
      resolveRun({ code: 127, stdout, stderr: `${stderr}${error.message}` }),
    );
    child.once("close", (code) =>
      resolveRun({ code: code ?? 1, stdout, stderr }),
    );
  });
}

async function git(cwd, args, { allowFailure = false } = {}) {
  const result = await run("git", args, { cwd });
  if (result.code !== 0 && !allowFailure)
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  return result;
}

const firstLine = (text) => text.trim().split("\n")[0];

const GIT_IDENTITY = [
  "-c",
  "user.name=PTAH upstream sync",
  "-c",
  "user.email=ptah-upstream-sync@users.noreply.github.com",
];

async function stage(worktree, path, index) {
  const shown = await git(worktree, ["show", `:${index}:${path}`], {
    allowFailure: true,
  });
  return shown.code === 0 ? shown.stdout : undefined;
}

/** Take one side of a conflicted path, deleting it when that side removed it. */
async function takeSide(worktree, path, side) {
  const index = side === "ours" ? 2 : 3;
  if ((await stage(worktree, path, index)) === undefined)
    await git(worktree, ["rm", "-q", "--", path]);
  else {
    await git(worktree, ["checkout", `--${side}`, "--", path]);
    await git(worktree, ["add", "--", path]);
  }
}

/**
 * Resolve conflicts with the PTAH merge policy, rebuild generated files, and
 * commit the merge. Returns the per-path decisions; `resolved` is false when
 * a step failed or conflict markers remain.
 */
async function resolveConflicts(worktree, conflicts, options, log) {
  const decisions = [];
  let regenerate = false;
  for (const path of conflicts) {
    const rule = conflictRule(path);
    if (rule === "package-json") {
      const [baseText, oursText, theirsText] = await Promise.all(
        [1, 2, 3].map((index) => stage(worktree, path, index)),
      );
      const merged = mergePackageJson(baseText, oursText, theirsText);
      await writeFile(join(worktree, path), merged.text);
      await git(worktree, ["add", "--", path]);
      decisions.push({ path, rule, fields: merged.decisions });
    } else {
      await takeSide(worktree, path, rule === "ours" ? "ours" : "theirs");
      regenerate ||= rule === "regenerate";
      decisions.push({ path, rule });
    }
  }
  const resolution = { resolved: false, decisions, installed: false };
  if (regenerate) {
    for (const [command, ...args] of options.regenerate ??
      REGENERATE_COMMANDS) {
      log(`regenerating: ${command} ${args.join(" ")}`);
      const outcome = await run(command, args, { cwd: worktree });
      if (outcome.code !== 0) {
        resolution.failedStep = [command, ...args].join(" ");
        resolution.output = `${outcome.stdout}\n${outcome.stderr}`
          .trim()
          .slice(-4000);
        return resolution;
      }
    }
    resolution.installed = true;
    await git(worktree, ["add", "-u"]);
  }
  const markers = await git(
    worktree,
    ["grep", "-l", "-E", "^(<<<<<<<|>>>>>>>) ", "--", ...conflicts],
    { allowFailure: true },
  );
  if (markers.stdout.trim()) {
    resolution.markers = markers.stdout.trim().split("\n");
    return resolution;
  }
  await git(worktree, [...GIT_IDENTITY, "commit", "--no-edit", "-q"]);
  resolution.resolved = true;
  return resolution;
}

const succeeded = async (cwd, args) =>
  (await git(cwd, args, { allowFailure: true })).code === 0;
const lines = (text) => text.split("\n").filter(Boolean);

/** Point `upstream` at the REA URL, fetch both sides, and record their tips. */
async function fetchTips(repo, remote, branch, upstreamUrl) {
  const remotes = lines((await git(repo, ["remote"])).stdout);
  await git(
    repo,
    remotes.includes("upstream")
      ? ["remote", "set-url", "upstream", upstreamUrl]
      : ["remote", "add", "upstream", upstreamUrl],
  );
  await git(repo, ["fetch", "--no-tags", remote, branch]);
  await git(repo, ["fetch", "--no-tags", "upstream", "main"]);
  const tip = async (ref) =>
    firstLine((await git(repo, ["rev-parse", ref])).stdout);
  return {
    base: await tip(`${remote}/${branch}`),
    upstream: await tip("upstream/main"),
  };
}

/** Merge upstream in the worktree, resolving conflicts with the PTAH policy. */
async function mergeInWorktree(worktree, upstream, options, log) {
  const message = `chore: merge REA upstream ${upstream.slice(0, 12)} into PTAH`;
  if (
    await succeeded(worktree, [
      ...GIT_IDENTITY,
      "merge",
      "--no-edit",
      "-m",
      message,
      upstream,
    ])
  )
    return { merged: true };
  const conflicts = lines(
    (
      await git(worktree, ["diff", "--name-only", "--diff-filter=U"], {
        allowFailure: true,
      })
    ).stdout,
  );
  const resolution =
    options.resolve === false
      ? undefined
      : await resolveConflicts(worktree, conflicts, options, log);
  if (resolution?.resolved) return { merged: true, resolution };
  await git(worktree, ["merge", "--abort"], { allowFailure: true });
  return { merged: false, conflicts, resolution };
}

/** Run validation in the worktree; returns the failure, or undefined on success. */
async function validateWorktree(
  worktree,
  { changed, resolution },
  options,
  log,
) {
  const validation = options.validation ?? DEFAULT_VALIDATION;
  if (!validation.length) return undefined;
  const lockfile = await access(join(worktree, "package-lock.json")).then(
    () => true,
    () => false,
  );
  // Reuse installed dependencies unless the merge changed the lockfile.
  const installed = resolution?.installed === true;
  const reuse =
    installed ||
    (options.nodeModules !== undefined &&
      !changed.includes("package-lock.json"));
  if (reuse && !installed)
    await symlink(options.nodeModules, join(worktree, "node_modules"), "dir");
  const steps =
    lockfile && !reuse
      ? [["npm", "ci", "--ignore-scripts"], ...validation]
      : validation;
  for (const [command, ...args] of steps) {
    log(`validating: ${command} ${args.join(" ")}`);
    const outcome = await run(command, args, { cwd: worktree });
    if (outcome.code !== 0)
      return {
        failedStep: [command, ...args].join(" "),
        output: `${outcome.stdout}\n${outcome.stderr}`.trim().slice(-4000),
      };
  }
  return undefined;
}

/** One sync at a time per repository; a lock left by a dead process is reclaimed. */
async function acquireLock(repo) {
  const common = firstLine(
    (await git(repo, ["rev-parse", "--git-common-dir"])).stdout,
  );
  const path = join(
    isAbsolute(common) ? common : join(repo, common),
    "ptah-upstream-sync.lock",
  );
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await writeFile(path, String(process.pid), { flag: "wx" });
      return path;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const owner = Number(await readFile(path, "utf8").catch(() => "0"));
      let alive = false;
      try {
        alive = owner > 0 && process.kill(owner, 0);
      } catch {
        alive = false;
      }
      if (alive) return undefined;
      await rm(path, { force: true });
    }
  }
  return undefined;
}

/**
 * Fast-forward the local checkout to the synced branch so tools registered
 * from it run current code. Never merges, rebases, or touches local edits.
 */
async function updateLocalCheckout(repo, remote, branch) {
  await git(repo, ["fetch", "--no-tags", remote, branch], {
    allowFailure: true,
  });
  const dirty = (
    await git(repo, ["status", "--porcelain", "--untracked-files=no"])
  ).stdout.trim();
  if (dirty) return "skipped-local-changes";
  const head = firstLine((await git(repo, ["rev-parse", "HEAD"])).stdout);
  const tip = firstLine(
    (await git(repo, ["rev-parse", `${remote}/${branch}`])).stdout,
  );
  if (head === tip) return "current";
  if (!(await succeeded(repo, ["merge-base", "--is-ancestor", head, tip])))
    return "skipped-diverged";
  await git(repo, ["merge", "--ff-only", "-q", tip]);
  return "fast-forwarded";
}

/**
 * Run one sync. Returns a structured result whose `status` is one of
 * up-to-date, not-bootstrapped, conflict, validation-failed, merged (dry run),
 * pushed, push-rejected, or busy (another sync holds the lock). With
 * `updateLocal`, `local` reports how the caller's checkout was updated.
 */
export async function syncUpstream(options) {
  const lock =
    options.lock === false ? undefined : await acquireLock(options.repo);
  if (options.lock !== false && lock === undefined) return { status: "busy" };
  try {
    const result = await runSync(options);
    if (options.updateLocal)
      result.local = await updateLocalCheckout(
        options.repo,
        options.remote ?? "origin",
        options.branch ?? "main",
      );
    return result;
  } finally {
    if (lock) await rm(lock, { force: true });
  }
}

async function runSync(options) {
  const { repo } = options;
  const branch = options.branch ?? "main";
  const remote = options.remote ?? "origin";
  const log = options.log ?? (() => {});
  log(`fetching ${remote}/${branch} and upstream/main`);
  const { base, upstream } = await fetchTips(
    repo,
    remote,
    branch,
    options.upstream ?? DEFAULT_UPSTREAM,
  );
  const result = { base, upstream, branch };
  if (!(await succeeded(repo, ["merge-base", base, upstream])))
    return { ...result, status: "not-bootstrapped" };
  if (await succeeded(repo, ["merge-base", "--is-ancestor", upstream, base]))
    return { ...result, status: "up-to-date" };

  const worktree = await mkdtemp(join(tmpdir(), "ptah-upstream-sync-"));
  await git(repo, ["worktree", "add", "--detach", worktree, base]);
  try {
    const merge = await mergeInWorktree(worktree, upstream, options, log);
    if (merge.resolution) result.resolution = merge.resolution;
    if (!merge.merged)
      return { ...result, status: "conflict", conflicts: merge.conflicts };
    const merged = firstLine(
      (await git(worktree, ["rev-parse", "HEAD"])).stdout,
    );
    const changed = lines(
      (await git(worktree, ["diff", "--name-only", base, merged])).stdout,
    );
    Object.assign(result, { merged, changedFiles: changed.length });
    const failure = await validateWorktree(
      worktree,
      { changed, resolution: merge.resolution },
      options,
      log,
    );
    if (failure) return { ...result, status: "validation-failed", ...failure };
    if (options.bundle) {
      // Hand the validated merge to a separate, write-permitted step without
      // giving the validating step any push credentials.
      await git(worktree, [
        "bundle",
        "create",
        options.bundle,
        "HEAD",
        `^${base}`,
      ]);
      result.bundle = options.bundle;
    }
    if (!options.push) return { ...result, status: "merged" };
    const push = await git(
      worktree,
      ["push", remote, `${merged}:refs/heads/${branch}`],
      {
        allowFailure: true,
      },
    );
    return push.code === 0
      ? { ...result, status: "pushed" }
      : { ...result, status: "push-rejected", output: push.stderr.trim() };
  } finally {
    await git(repo, ["worktree", "remove", "--force", worktree], {
      allowFailure: true,
    });
    await rm(worktree, { recursive: true, force: true });
  }
}

/** Install a systemd user timer that runs the sync periodically (Linux). */
export async function installSyncTimer({
  repo,
  interval = "hourly",
  node = process.execPath,
  home = homedir(),
}) {
  // Short intervals use a monotonic timer with 1 s accuracy (systemd's default
  // accuracy is one minute); anything else is a calendar expression.
  // OnActiveSec starts the first run when the timer is enabled: OnBootSec has
  // long passed on a running machine and OnUnitActiveSec needs a prior run.
  const monotonic = /^\d+(?:s|sec|m|min|h)$/u.test(interval);
  const schedule = monotonic
    ? `OnActiveSec=${interval}\nOnBootSec=${interval}\nOnUnitActiveSec=${interval}\nAccuracySec=1s`
    : `OnCalendar=${interval}\nPersistent=true\nRandomizedDelaySec=300`;
  const directory = join(home, ".config", "systemd", "user");
  await mkdir(directory, { recursive: true });
  const service = join(directory, "ptah-upstream-sync.service");
  const timer = join(directory, "ptah-upstream-sync.timer");
  await writeFile(
    service,
    `[Unit]\nDescription=Merge REA upstream into PTAH\n\n[Service]\nType=oneshot\nNice=10\nTimeoutStartSec=2h\nWorkingDirectory=${repo}\nEnvironment=PATH=${dirname(node)}:/usr/local/bin:/usr/bin:/bin\nExecStart=${node} ${join(repo, "scripts", "ptah.mjs")} upstream-sync --push --update-local\n`,
  );
  await writeFile(
    timer,
    `[Unit]\nDescription=Periodic PTAH upstream sync\n\n[Timer]\n${schedule}\n\n[Install]\nWantedBy=timers.target\n`,
  );
  return {
    service,
    timer,
    next: "systemctl --user daemon-reload && systemctl --user enable --now ptah-upstream-sync.timer",
  };
}
