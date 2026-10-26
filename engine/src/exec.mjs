/**
 * Bounded execution of external analysis tools: fixed argv, never a shell,
 * a wall-clock timeout that kills the whole process group, capped output, and
 * a minimal environment. Callers re-hash the target to detect writes.
 */
import { spawn } from "node:child_process";
import { access, constants } from "node:fs/promises";
import { delimiter, isAbsolute, join } from "node:path";

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_OUTPUT = 4 * 1024 * 1024;

const executable = (path) =>
  access(path, constants.X_OK).then(
    () => true,
    () => false,
  );

/** Locate an executable on PATH without running it. */
export async function findExecutable(name, env = process.env) {
  if (isAbsolute(name)) return (await executable(name)) ? name : undefined;
  for (const directory of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    const candidate = join(directory, name);
    if (await executable(candidate)) return candidate;
  }
  return undefined;
}

/** Environment passed to tools: PATH, HOME, and a fixed locale, plus explicit additions. */
export function toolEnvironment(env = process.env, extra = {}) {
  return {
    PATH: env.PATH ?? "/usr/bin:/bin",
    HOME: env.HOME ?? "/tmp",
    LANG: "C",
    LC_ALL: "C",
    ...extra,
  };
}

/**
 * Run a tool with bounded resources.
 * @returns {Promise<{code: number|null, signal: string|null, timedOut: boolean, truncated: boolean, stdout: string, stderr: string, durationMs: number}>}
 */
export function runTool(command, args, options = {}) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string"))
    throw new TypeError("args must be an array of strings");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutput = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT;
  const started = process.hrtime.bigint();
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? toolEnvironment(),
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const chunks = { stdout: [], stderr: [] };
    const sizes = { stdout: 0, stderr: 0 };
    let truncated = false;
    let timedOut = false;
    const collect = (stream) => (chunk) => {
      const room = maxOutput - sizes[stream];
      if (room < chunk.length) truncated = true;
      if (room <= 0) return;
      const part = chunk.subarray(0, Math.min(room, chunk.length));
      chunks[stream].push(part);
      sizes[stream] += part.length;
    };
    child.stdout.on("data", collect("stdout"));
    child.stderr.on("data", collect("stderr"));
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        // Kill the process group so helpers the tool started cannot linger.
        if (process.platform !== "win32" && child.pid)
          process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, timeoutMs);
    const finish = (code, signal, error) => {
      clearTimeout(timer);
      const stderr = Buffer.concat(chunks.stderr).toString("utf8");
      resolveRun({
        code,
        signal,
        timedOut,
        truncated,
        stdout: Buffer.concat(chunks.stdout).toString("utf8"),
        stderr: error ? `${stderr}${error.message}` : stderr,
        durationMs: Number((process.hrtime.bigint() - started) / 1_000_000n),
      });
    };
    child.once("error", (error) => finish(null, null, error));
    child.once("close", (code, signal) => finish(code, signal));
  });
}
