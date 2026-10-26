/**
 * Register PTAH's MCP server and agent skill with AI coding clients.
 *
 * Dependency-free like the rest of PTAH. Changes are planned first and only
 * applied on request; each edit touches the `ptah` entry alone, backs up the
 * previous file, and is written atomically. Paths and entry shapes follow the
 * client definitions already exercised by the inherited setup
 * (src/application/SupportedClients.ts, ClientConfigurationDocument.ts).
 */
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  rename,
  rm,
  rmdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENT_CLIENTS, defaultContext } from "./ptah-agent-clients.mjs";

export { AGENT_CLIENTS } from "./ptah-agent-clients.mjs";

export const SERVER_KEY = "ptah";
export const SKILL_NAME = "ptah";
const OWNERSHIP_MARKER = "ptah-mcp";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const SKILL_SOURCE = join(
  root,
  "integrations",
  "agent-skill",
  SKILL_NAME,
  "SKILL.md",
);

/** The command a client runs to start PTAH's stdio MCP server. */
export function serverCommand(launcher = "local", version = undefined) {
  if (launcher === "local")
    return [process.execPath, join(root, "scripts", "ptah-mcp.mjs")];
  if (launcher === "npx")
    return [
      "npx",
      "-y",
      `--package=@owlvisions/ptah${version ? `@${version}` : ""}`,
      "ptah-mcp",
    ];
  throw new Error("launcher must be local or npx");
}

/** Build the server entry for one client's dialect. */
export function serverEntry(client, command) {
  const [executable, ...args] = command;
  switch (client.entry) {
    case "typed":
      return { type: "stdio", command: executable, args };
    case "copilot":
      return { type: "stdio", command: executable, args, tools: ["*"] };
    case "opencode":
      return { type: "local", command: [...command], enabled: true };
    case "zed":
      return { source: "custom", command: executable, args, env: {} };
    default:
      return { command: executable, args };
  }
}

const tomlString = (value) => JSON.stringify(value);

/** Render the Codex `[mcp_servers.ptah]` table. */
export function tomlServerBlock(command) {
  const [executable, ...args] = command;
  return `[mcp_servers.${SERVER_KEY}]\ncommand = ${tomlString(executable)}\nargs = [${args.map(tomlString).join(", ")}]\n`;
}

const isOwnedValue = (value) =>
  JSON.stringify(value ?? "").includes(OWNERSHIP_MARKER);

const TOML_HEADER = /^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$/;
const isPtahTable = (name) => {
  const segments = name
    .split(".")
    .map((part) => part.trim().replace(/^"|"$/g, ""));
  return segments[0] === "mcp_servers" && segments[1] === SERVER_KEY;
};

/** Split a Codex TOML file into the PTAH table text and everything else. */
export function splitTomlServer(text) {
  const kept = [];
  const owned = [];
  let inPtah = false;
  for (const line of text.split(/\r?\n/)) {
    const header = TOML_HEADER.exec(line);
    if (header) inPtah = isPtahTable(header[1]);
    else if (!inPtah && /^\s*mcp_servers\s*\.\s*"?ptah"?\s*[.=]/.test(line))
      throw new Error(
        "config.toml defines mcp_servers.ptah with dotted keys; edit it by hand",
      );
    (inPtah ? owned : kept).push(line);
  }
  while (kept.length && kept.at(-1).trim() === "") kept.pop();
  return { rest: kept.join("\n"), table: owned.join("\n") };
}

async function readTextIfExists(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function parseJsonConfig(text, path) {
  if (text === undefined || text.trim() === "") return {};
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error("top level is not an object");
    return value;
  } catch (error) {
    throw new Error(
      `${path} is not plain JSON (${error.message}); comments or trailing commas are not rewritten. Add the entry by hand with: ptah agents print`,
    );
  }
}

/** Atomically replace a file, keeping a timestamped backup of the old one. */
async function writeWithBackup(path, content, { backup = true } = {}) {
  await mkdir(dirname(path), { recursive: true });
  let mode;
  let backupPath;
  try {
    mode = (await stat(path)).mode & 0o777;
    if (backup) {
      backupPath = `${path}.ptah-backup-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      await copyFile(path, backupPath);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const temporary = `${path}.ptah-tmp-${process.pid}`;
  await writeFile(temporary, content, { mode: mode ?? 0o600 });
  if (mode !== undefined) await chmod(temporary, mode);
  await rename(temporary, path);
  return backupPath;
}

/** Remove up to `levels` now-empty parent directories of a deleted file. */
async function removeEmptyParents(path, levels) {
  let directory = dirname(path);
  for (let level = 0; level < levels; level += 1) {
    try {
      await rmdir(directory);
    } catch {
      return;
    }
    directory = dirname(directory);
  }
}

/** Inspect one client's current PTAH registration without changing anything. */
export async function inspectClient(client, options = {}) {
  const context = options.context ?? defaultContext();
  const command = options.command ?? serverCommand(options.launcher);
  const configPath = client.config(context);
  const detected = await exists(client.marker(context));
  const text = await readTextIfExists(configPath);
  const report = {
    id: client.id,
    name: client.name,
    detected,
    configPath,
    registered: false,
    owned: false,
    current: false,
    skillPath: client.skills
      ? join(client.skills(context), SKILL_NAME, "SKILL.md")
      : null,
    skill: "not-applicable",
    issues: [],
    ...(client.note ? { note: client.note } : {}),
  };
  try {
    if (client.format === "toml") {
      const { table } = splitTomlServer(text ?? "");
      report.registered = table.trim() !== "";
      report.owned = table.includes(OWNERSHIP_MARKER);
      report.current = table.trim() === tomlServerBlock(command).trim();
    } else {
      const servers = parseJsonConfig(text, configPath)[client.serversKey];
      const entry =
        servers && typeof servers === "object"
          ? servers[SERVER_KEY]
          : undefined;
      report.registered = entry !== undefined;
      report.owned = isOwnedValue(entry);
      report.current =
        JSON.stringify(entry) === JSON.stringify(serverEntry(client, command));
    }
  } catch (error) {
    report.issues.push(error.message);
  }
  if (report.registered && !report.owned)
    report.issues.push(
      `a "${SERVER_KEY}" server that does not run ptah-mcp already exists; it is left untouched unless --force is given`,
    );
  if (report.owned && command[0] !== "npx" && !(await exists(command[1])))
    report.issues.push(`server script is missing: ${command[1]}`);
  if (report.skillPath) {
    const installed = await readTextIfExists(report.skillPath);
    const source = await readFile(SKILL_SOURCE, "utf8");
    report.skill =
      installed === undefined
        ? "missing"
        : installed === source
          ? "current"
          : /^name:\s*ptah\s*$/m.test(installed)
            ? "outdated"
            : "foreign";
  }
  return report;
}

/** Resolve `--client` selections; the default is every detected client. */
export async function selectClients(ids, context = defaultContext()) {
  if (ids === "all") return [...AGENT_CLIENTS];
  if (ids?.length) {
    const unknown = ids.filter(
      (id) => !AGENT_CLIENTS.some((client) => client.id === id),
    );
    if (unknown.length)
      throw new Error(
        `unknown client: ${unknown.join(", ")}. Supported: ${AGENT_CLIENTS.map((client) => client.id).join(", ")}`,
      );
    return AGENT_CLIENTS.filter((client) => ids.includes(client.id));
  }
  const detected = [];
  for (const client of AGENT_CLIENTS)
    if (await exists(client.marker(context))) detected.push(client);
  return detected;
}

/** Render the client's file with PTAH's entry set, or removed when `command` is undefined. */
function renderConfig(client, text, path, command) {
  if (client.format === "toml") {
    const { rest } = splitTomlServer(text ?? "");
    const prefix = rest.trim() === "" ? "" : `${rest}\n`;
    return command === undefined
      ? prefix
      : `${prefix && `${prefix}\n`}${tomlServerBlock(command)}`;
  }
  const document = parseJsonConfig(text, path);
  const servers = { ...document[client.serversKey] };
  if (command === undefined) delete servers[SERVER_KEY];
  else servers[SERVER_KEY] = serverEntry(client, command);
  const updated = { ...document, [client.serversKey]: servers };
  if (Object.keys(servers).length === 0) delete updated[client.serversKey];
  return `${JSON.stringify(updated, null, 2)}\n`;
}

/** Decide what install does for one client from its inspected state. */
function planInstall(state, force) {
  const unreadable = state.issues.find(
    (issue) =>
      issue.includes("not plain JSON") || issue.includes("dotted keys"),
  );
  if (unreadable) return { action: "blocked", reason: unreadable };
  if (state.registered && !state.owned && !force)
    return { action: "conflict", reason: state.issues.at(-1) };
  if (state.current) return { action: "unchanged" };
  return { action: state.registered ? "update" : "register" };
}

const SKILL_ACTIONS = {
  current: "unchanged",
  missing: "install",
  outdated: "update",
  foreign: "conflict",
};

async function installSkills(skillDirectories, options) {
  const source = await readFile(SKILL_SOURCE, "utf8");
  const skills = [];
  for (const [directory, status] of skillDirectories) {
    const item = {
      path: join(directory, "SKILL.md"),
      action: SKILL_ACTIONS[status],
    };
    if (item.action === "conflict" && !options.force)
      item.reason = "a different skill named ptah exists here";
    else if (options.apply && item.action !== "unchanged") {
      await writeWithBackup(item.path, source, {
        backup: status !== "missing",
      });
      item.applied = true;
    }
    skills.push(item);
  }
  return skills;
}

/**
 * Plan (and with `apply: true`, perform) registration for the given clients.
 * Returns one result per client plus the skill destinations touched.
 */
export async function installAgents(clients, options = {}) {
  const context = options.context ?? defaultContext();
  const command =
    options.command ?? serverCommand(options.launcher, options.version);
  const results = [];
  const skillDirectories = new Map();
  for (const client of clients) {
    const state = await inspectClient(client, { context, command });
    const result = {
      id: client.id,
      name: client.name,
      configPath: state.configPath,
      ...planInstall(state, options.force),
      ...(client.note ? { note: client.note } : {}),
    };
    if (
      options.apply &&
      (result.action === "register" || result.action === "update")
    ) {
      const text = await readTextIfExists(state.configPath);
      result.backup = await writeWithBackup(
        state.configPath,
        renderConfig(client, text, state.configPath, command),
      );
      result.applied = true;
    }
    if (options.skill !== false && state.skillPath)
      skillDirectories.set(dirname(state.skillPath), state.skill);
    results.push(result);
  }
  const skills = await installSkills(skillDirectories, options);
  return { applied: Boolean(options.apply), command, clients: results, skills };
}

/** Skill directories still serving a client that keeps PTAH registered. */
async function skillDirectoriesInUse(excludedIds, context) {
  const inUse = new Set();
  for (const client of AGENT_CLIENTS) {
    if (!client.skills || excludedIds.has(client.id)) continue;
    const state = await inspectClient(client, { context });
    if (state.registered && state.owned) inUse.add(dirname(state.skillPath));
  }
  return inUse;
}

async function removeSkills(clients, context, apply) {
  const inUse = await skillDirectoriesInUse(
    new Set(clients.map((client) => client.id)),
    context,
  );
  const directories = new Set(
    clients
      .filter((client) => client.skills)
      .map((client) => join(client.skills(context), SKILL_NAME)),
  );
  const skills = [];
  for (const directory of directories) {
    const path = join(directory, "SKILL.md");
    const text = await readTextIfExists(path);
    if (text === undefined) continue;
    const action = !/^name:\s*ptah\s*$/m.test(text)
      ? "conflict"
      : inUse.has(directory)
        ? "kept"
        : "remove";
    const item = { path, action };
    if (apply && action === "remove") {
      await rm(path);
      await removeEmptyParents(path, 3);
      item.applied = true;
    }
    skills.push(item);
  }
  return skills;
}

/** Decide what uninstall does for one client from its inspected state. */
function planUninstall(state, force) {
  if (!state.registered) return { action: "absent" };
  if (!state.owned && !force)
    return {
      action: "conflict",
      reason: "the ptah entry does not run ptah-mcp",
    };
  return { action: "remove" };
}

/** Remove PTAH's entry (and owned skill copies) from the given clients. */
export async function uninstallAgents(clients, options = {}) {
  const context = options.context ?? defaultContext();
  const results = [];
  for (const client of clients) {
    const state = await inspectClient(client, { context });
    const result = {
      id: client.id,
      name: client.name,
      configPath: state.configPath,
      ...planUninstall(state, options.force),
    };
    if (options.apply && result.action === "remove") {
      const text = await readTextIfExists(state.configPath);
      const content = renderConfig(client, text, state.configPath, undefined);
      // A file that held nothing but PTAH's entry is removed rather than emptied.
      if (content.trim() === "" || content.trim() === "{}") {
        await rm(state.configPath);
        await removeEmptyParents(state.configPath, 2);
        result.removedEmptyFile = true;
      } else result.backup = await writeWithBackup(state.configPath, content);
      result.applied = true;
    }
    results.push(result);
  }
  // A shared skill copy stays while any other client still has PTAH registered.
  const skills = await removeSkills(clients, context, options.apply);
  return { applied: Boolean(options.apply), clients: results, skills };
}

const GENERIC_DIALECTS = {
  vscode: { serversKey: "servers", entry: "typed" },
  opencode: { serversKey: "mcp", entry: "opencode" },
  json: { serversKey: "mcpServers", entry: "plain" },
};

/** Manual configuration snippet for a client or a generic dialect. */
export function renderSnippet(target, command = serverCommand()) {
  const client = AGENT_CLIENTS.find((item) => item.id === target);
  if (client?.format === "toml" || target === "toml")
    return tomlServerBlock(command);
  const dialect = client ?? GENERIC_DIALECTS[target];
  if (!dialect)
    throw new Error(
      `unknown client or dialect: ${target}. Use a client id or vscode, opencode, toml, json`,
    );
  return `${JSON.stringify({ [dialect.serversKey]: { [SERVER_KEY]: serverEntry(dialect, command) } }, null, 2)}\n`;
}

const BLOCK_START = "<!-- ptah:begin -->";
const BLOCK_END = "<!-- ptah:end -->";
const INSTRUCTION_FILES = ["AGENTS.md", "CLAUDE.md", "GEMINI.md"];
const INSTRUCTIONS = `${BLOCK_START}
## Program analysis with PTAH

This workspace has the \`ptah\` MCP server. For binaries, executables, APKs,
ASAR, WASM, firmware, or unknown files: start with \`ptah_triage\`, read
\`ptah_summary\`, then deepen the top open question (\`ptah_structure\`,
\`ptah_iocs\`, \`ptah_search\`, \`ptah_hexdump\`, \`ptah_static_analyze\`).
Record every finding with \`ptah_add_evidence\` (reproducible source; confidence
observed, derived, or inferred), claim only what cites evidence, run
\`ptah_lint\` and \`ptah_verify\` before answering, and answer from
\`ptah_report\`. Never execute the target. Keep investigations under
\`.ptah/\`.
${BLOCK_END}
`;

const withoutBlock = (text) => {
  const start = text.indexOf(BLOCK_START);
  const end = text.indexOf(BLOCK_END);
  if (start < 0 || end < start) return text;
  return `${text.slice(0, start)}${text.slice(end + BLOCK_END.length).replace(/^\n/u, "")}`;
};

/** The instruction file's text after adding or removing the PTAH block. */
function instructionText(text, remove) {
  const base = text === undefined ? "" : withoutBlock(text).trimEnd();
  // The block is separated by one blank line, so removal restores the original text.
  if (remove) return base && `${base}\n`;
  return `${base}${base ? "\n\n" : ""}${INSTRUCTIONS}`;
}

function instructionAction(text, next, remove) {
  if (text === next) return "unchanged";
  if (text === undefined) return remove ? "absent" : "create";
  return remove ? "remove" : "update";
}

/** Add, refresh, or remove the PTAH block in AGENTS.md, CLAUDE.md, and GEMINI.md. */
export async function workspaceInstructions(
  directory,
  { apply = false, remove = false } = {},
) {
  const results = [];
  for (const name of INSTRUCTION_FILES) {
    const path = join(directory, name);
    const text = await readTextIfExists(path);
    const next = instructionText(text, remove);
    const action = instructionAction(text, next, remove);
    const writes = action !== "unchanged" && action !== "absent";
    if (apply && writes) {
      if (next === "") await rm(path);
      else await writeWithBackup(path, next, { backup: text !== undefined });
    }
    results.push({
      path,
      action,
      ...(apply && writes ? { applied: true } : {}),
    });
  }
  return results;
}
