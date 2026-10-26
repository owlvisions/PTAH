/**
 * AI coding clients PTAH can register with: where each keeps its MCP servers,
 * which dialect it reads, and where it loads skills from. Paths follow the
 * definitions exercised by the inherited setup (src/application/SupportedClients.ts).
 */
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

const xdgConfigHome = ({ home, env }) =>
  env.XDG_CONFIG_HOME || join(home, ".config");
const appData = ({ home, env }) =>
  env.APPDATA || join(home, "AppData", "Roaming");
const sharedSkills = ({ home }) => join(home, ".agents", "skills");
const expandHome = (value, home) =>
  value === "~"
    ? home
    : value.startsWith("~/") || value.startsWith("~\\")
      ? join(home, value.slice(2))
      : isAbsolute(value)
        ? value
        : resolve(value);

const vscodeUser = (context) =>
  context.platform === "win32"
    ? join(appData(context), "Code", "User")
    : context.platform === "darwin"
      ? join(context.home, "Library", "Application Support", "Code", "User")
      : join(xdgConfigHome(context), "Code", "User");
const claudeDesktop = (context) =>
  context.platform === "win32"
    ? join(appData(context), "Claude")
    : context.platform === "darwin"
      ? join(context.home, "Library", "Application Support", "Claude")
      : join(xdgConfigHome(context), "Claude");
const claudeCodeHome = ({ home, env }) =>
  env.CLAUDE_CONFIG_DIR || join(home, ".claude");
const geminiHome = ({ home, env }) => env.GEMINI_CLI_HOME || home;
const qwenHome = ({ home, env }) =>
  env.QWEN_HOME ? expandHome(env.QWEN_HOME, home) : join(home, ".qwen");
const openCodeDirectory = (context) =>
  context.env.OPENCODE_CONFIG_DIR || join(xdgConfigHome(context), "opencode");

/**
 * Supported clients. `format` selects the file dialect, `serversKey` the
 * object holding servers, and `entry` the server entry shape.
 */
export const AGENT_CLIENTS = Object.freeze([
  {
    id: "claude_code",
    name: "Claude Code",
    format: "json",
    serversKey: "mcpServers",
    entry: "typed",
    config: ({ home, env }) =>
      join(env.CLAUDE_CONFIG_DIR || home, ".claude.json"),
    marker: claudeCodeHome,
    skills: (context) => join(claudeCodeHome(context), "skills"),
  },
  {
    id: "claude_desktop",
    name: "Claude Desktop",
    format: "json",
    serversKey: "mcpServers",
    entry: "plain",
    config: (context) =>
      join(claudeDesktop(context), "claude_desktop_config.json"),
    marker: claudeDesktop,
    skills: null,
    note: "Quit Claude Desktop before installing; it rewrites its config on exit. Upload the skill from Settings > Capabilities if wanted.",
  },
  {
    id: "codex",
    name: "OpenAI Codex",
    format: "toml",
    config: ({ home, env }) =>
      join(env.CODEX_HOME || join(home, ".codex"), "config.toml"),
    marker: ({ home, env }) => env.CODEX_HOME || join(home, ".codex"),
    skills: sharedSkills,
  },
  {
    id: "gemini_cli",
    name: "Gemini CLI",
    format: "json",
    serversKey: "mcpServers",
    entry: "plain",
    config: (context) => join(geminiHome(context), ".gemini", "settings.json"),
    marker: (context) => join(geminiHome(context), ".gemini"),
    skills: (context) => join(geminiHome(context), ".agents", "skills"),
  },
  {
    id: "copilot_vscode",
    name: "GitHub Copilot (VS Code)",
    format: "json",
    serversKey: "servers",
    entry: "typed",
    config: (context) => join(vscodeUser(context), "mcp.json"),
    marker: vscodeUser,
    skills: sharedSkills,
  },
  {
    id: "copilot_cli",
    name: "GitHub Copilot CLI",
    format: "json",
    serversKey: "mcpServers",
    entry: "copilot",
    config: ({ home, env }) =>
      join(env.COPILOT_HOME || join(home, ".copilot"), "mcp-config.json"),
    marker: ({ home, env }) => env.COPILOT_HOME || join(home, ".copilot"),
    skills: sharedSkills,
  },
  {
    id: "cursor",
    name: "Cursor",
    format: "json",
    serversKey: "mcpServers",
    entry: "plain",
    config: ({ home }) => join(home, ".cursor", "mcp.json"),
    marker: ({ home }) => join(home, ".cursor"),
    skills: sharedSkills,
  },
  {
    id: "windsurf",
    name: "Windsurf",
    format: "json",
    serversKey: "mcpServers",
    entry: "plain",
    config: ({ home }) => join(home, ".codeium", "windsurf", "mcp_config.json"),
    marker: ({ home }) => join(home, ".codeium", "windsurf"),
    skills: sharedSkills,
  },
  {
    id: "opencode",
    name: "OpenCode",
    format: "json",
    serversKey: "mcp",
    entry: "opencode",
    config: (context) => join(openCodeDirectory(context), "opencode.json"),
    marker: openCodeDirectory,
    skills: sharedSkills,
  },
  {
    id: "qwen_code",
    name: "Qwen Code",
    format: "json",
    serversKey: "mcpServers",
    entry: "plain",
    config: (context) => join(qwenHome(context), "settings.json"),
    marker: qwenHome,
    skills: sharedSkills,
  },
]);

export const defaultContext = () => ({
  home: homedir(),
  env: process.env,
  platform: process.platform,
});
