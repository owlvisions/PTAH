/**
 * Path policy for requests arriving over MCP.
 *
 * MCP callers are models that read hostile targets, so a prompt injected into
 * analyzed content can ask for any path. Reads must not pull credentials into
 * the model's context, and writes must not clobber files PTAH does not own.
 * The CLI is driven by the user directly and does not apply this policy.
 */
import { lstat, readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

const HOME_CREDENTIAL_PATHS = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".azure",
  ".kube",
  ".docker",
  ".password-store",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  ".pgpass",
  join(".config", "gcloud"),
  join(".config", "gh"),
  join(".config", "op"),
  join(".local", "share", "keyrings"),
  join("Library", "Keychains"),
];
const SYSTEM_CREDENTIAL_PATHS = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];
const CREDENTIAL_NAMES =
  /^(?:\.env(?:\..+)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|.*\.(?:pem|key|p12|pfx|kdbx))$/iu;

const within = (path, root) => {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/** Resolve symlinks for the existing part of a path so policy sees the real location. */
async function canonical(path) {
  const absolute = resolve(path);
  try {
    return await realpath(absolute);
  } catch {
    const parent = dirname(absolute);
    if (parent === absolute) return absolute;
    return join(await canonical(parent), basename(absolute));
  }
}

/** Why a canonical path is a credential location, or undefined. */
export function credentialReason(path, home = homedir()) {
  for (const item of HOME_CREDENTIAL_PATHS)
    if (within(path, join(home, item)))
      return `${join("~", item)} holds credentials`;
  for (const item of SYSTEM_CREDENTIAL_PATHS)
    if (path === item) return `${item} holds credentials`;
  if (CREDENTIAL_NAMES.test(basename(path)))
    return `${basename(path)} looks like a secret or private key`;
  return undefined;
}

/**
 * @param {{ roots?: readonly string[], home?: string }} options
 *   roots: when non-empty, every path must lie inside one of them.
 */
export function createPathPolicy(options = {}) {
  const home = options.home ?? homedir();
  const rootsPromise = Promise.all((options.roots ?? []).map(canonical));

  async function check(path, name) {
    if (typeof path !== "string" || !path.trim())
      throw new TypeError(`${name} must be a non-empty file path`);
    const real = await canonical(path);
    const reason = credentialReason(real, home);
    if (reason)
      throw new Error(
        `${name} refused: ${reason}. PTAH's MCP server does not read or write credential locations; use the ptah CLI directly if this is intended.`,
      );
    const roots = await rootsPromise;
    if (roots.length && !roots.some((root) => within(real, root)))
      throw new Error(
        `${name} refused: ${path} is outside the allowed roots (${roots.join(", ")})`,
      );
    return real;
  }

  return {
    /** Validate a path the server will read. */
    read: (path, name) => check(path, name),
    /**
     * Validate a path the server will write. Only `.json` outputs are allowed,
     * never through a symlink, and an existing file must already be a PTAH
     * investigation or case bundle.
     */
    async write(path, name) {
      const real = await check(path, name);
      if (!real.toLowerCase().endsWith(".json"))
        throw new Error(
          `${name} refused: PTAH writes only .json investigation and case files`,
        );
      let info;
      try {
        info = await lstat(resolve(path));
      } catch (error) {
        if (error?.code === "ENOENT") return real;
        throw error;
      }
      if (info.isSymbolicLink() || !info.isFile())
        throw new Error(`${name} refused: ${path} is not a regular file`);
      let existing;
      try {
        existing = JSON.parse(await readFile(real, "utf8"));
      } catch {
        existing = undefined;
      }
      const investigation =
        existing?.schemaVersion !== undefined && existing?.target !== undefined;
      const caseBundle =
        typeof existing?.format === "string" &&
        existing?.integrity !== undefined;
      const ptahDocument = investigation || caseBundle;
      if (!ptahDocument)
        throw new Error(
          `${name} refused: ${path} exists and is not a PTAH investigation or case; choose a new file`,
        );
      return real;
    },
    roots: rootsPromise,
  };
}
