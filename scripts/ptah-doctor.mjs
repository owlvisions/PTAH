/**
 * One readiness report for PTAH: runtime, analyzers, isolation, agent
 * registrations, and upstream sync state. Read-only: nothing is installed,
 * fetched, or modified.
 */
import { spawn } from "node:child_process";
import { detectIsolationSupport, discoverProviders } from "./ptah-engine.mjs";
import { AGENT_CLIENTS, inspectClient } from "./ptah-agents.mjs";
import { isSupportedPtahNodeVersion } from "./ptah-runtime.mjs";

function git(cwd, args) {
  return new Promise((resolveRun) => {
    const child = spawn("git", args, {
      cwd,
      stdio: ["ignore", "pipe", "ignore"],
    });
    let stdout = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.once("error", () => resolveRun({ code: 127, stdout: "" }));
    child.once("close", (code) => resolveRun({ code, stdout: stdout.trim() }));
  });
}

async function upstreamState(root) {
  const remote = await git(root, ["remote", "get-url", "upstream"]);
  if (remote.code !== 0)
    return {
      ok: true,
      configured: false,
      remediation:
        "Run `ptah upstream-sync` once to add the REA upstream remote.",
    };
  const behind = await git(root, [
    "rev-list",
    "--count",
    "HEAD..upstream/main",
  ]);
  const count = behind.code === 0 ? Number(behind.stdout) : null;
  return {
    ok: count === 0,
    configured: true,
    url: remote.stdout,
    upstreamCommitsNotMerged: count,
    note: "Counts against the last fetched upstream/main; run `ptah upstream-sync` to fetch and merge.",
    ...(count
      ? {
          remediation:
            "Run `ptah upstream-sync` (dry run) then `ptah upstream-sync --push`.",
        }
      : {}),
  };
}

/** Collect the readiness report; `ok` is false only for problems PTAH can name a fix for. */
export async function runDoctor({ root, packageJson }) {
  const nodeOk = isSupportedPtahNodeVersion(process.versions.node);
  const [providers, isolation, upstream] = await Promise.all([
    discoverProviders(),
    detectIsolationSupport(),
    upstreamState(root),
  ]);
  const agents = [];
  for (const client of AGENT_CLIENTS) {
    const state = await inspectClient(client);
    if (state.detected || state.registered)
      agents.push({
        id: state.id,
        registered: state.registered,
        current: state.current,
        skill: state.skill,
        issues: state.issues,
      });
  }
  const checks = {
    runtime: {
      ok: nodeOk,
      node: process.versions.node,
      required: packageJson.engines?.node ?? null,
      ...(nodeOk
        ? {}
        : { remediation: `Install Node.js ${packageJson.engines?.node}.` }),
    },
    analyzers: {
      ok: true,
      available: providers.providers
        .filter((item) => item.available)
        .map((item) => item.id),
      missing: providers.providers
        .filter((item) => !item.available)
        .map((item) => item.id),
    },
    isolation: { ok: true, ...isolation },
    agents: {
      ok: agents.every(
        (item) => item.registered && item.current && item.issues.length === 0,
      ),
      clients: agents,
      ...(agents.some((item) => !item.registered || !item.current)
        ? { remediation: "Run `ptah agents install` to preview, then `--yes`." }
        : {}),
    },
    upstream,
  };
  return { ok: Object.values(checks).every((check) => check.ok), checks };
}
