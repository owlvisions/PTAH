# Using PTAH from AI coding agents

`ptah agents` registers PTAH's MCP server (`ptah-mcp`) under the server name
`ptah` and installs the PTAH skill (`integrations/agent-skill/ptah/SKILL.md`)
for the agent clients below. The server name differs from the inherited REA
server (`rea`), so both can be registered side by side.

```sh
ptah agents list                         # status for every supported client
ptah agents install                      # preview for detected clients; writes nothing
ptah agents install --yes                # apply
ptah agents install --client codex,cursor --yes
ptah agents install --all --yes          # include clients not detected yet
ptah agents uninstall --client codex --yes
ptah agents print --client codex         # manual snippet
ptah agents print --client vscode|opencode|toml|json
```

From a source checkout, use `node scripts/ptah.mjs agents ...`.

## Supported clients

| Client                   | `--client`       | Configuration (Linux/macOS default)                                                      | Entry                              | Skill                   |
| ------------------------ | ---------------- | ---------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------- |
| Claude Code              | `claude_code`    | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`)                                     | `mcpServers.ptah` (`type: stdio`)  | `~/.claude/skills/ptah` |
| Claude Desktop           | `claude_desktop` | `~/.config/Claude/` or `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers.ptah`                  | upload manually         |
| OpenAI Codex             | `codex`          | `~/.codex/config.toml` (`$CODEX_HOME`)                                                   | `[mcp_servers.ptah]`               | `~/.agents/skills/ptah` |
| Gemini CLI               | `gemini_cli`     | `~/.gemini/settings.json` (`$GEMINI_CLI_HOME`)                                           | `mcpServers.ptah`                  | `~/.agents/skills/ptah` |
| GitHub Copilot (VS Code) | `copilot_vscode` | VS Code user `mcp.json`                                                                  | `servers.ptah` (`type: stdio`)     | `~/.agents/skills/ptah` |
| GitHub Copilot CLI       | `copilot_cli`    | `~/.copilot/mcp-config.json` (`$COPILOT_HOME`)                                           | `mcpServers.ptah` (`tools: ["*"]`) | `~/.agents/skills/ptah` |
| Cursor                   | `cursor`         | `~/.cursor/mcp.json`                                                                     | `mcpServers.ptah`                  | `~/.agents/skills/ptah` |
| Windsurf                 | `windsurf`       | `~/.codeium/windsurf/mcp_config.json`                                                    | `mcpServers.ptah`                  | `~/.agents/skills/ptah` |
| OpenCode                 | `opencode`       | `~/.config/opencode/opencode.json` (`$OPENCODE_CONFIG_DIR`)                              | `mcp.ptah` (`type: local`)         | `~/.agents/skills/ptah` |
| Qwen Code                | `qwen_code`      | `~/.qwen/settings.json` (`$QWEN_HOME`)                                                   | `mcpServers.ptah`                  | `~/.agents/skills/ptah` |

On Windows, VS Code and Claude Desktop use `%APPDATA%`. Paths and entry
shapes follow the client definitions already exercised by the inherited setup
(`src/application/SupportedClients.ts`). For any other MCP client (Zed,
Continue, Cline, JetBrains AI, ...), `ptah agents print` produces a snippet to
paste into that client's MCP settings.

## Launcher

By default the entry runs this checkout's server with the current Node.js:
`<node> <ptah-root>/scripts/ptah-mcp.mjs`. Rerun `ptah agents install --yes`
after moving the checkout or switching Node.js; `ptah agents list` reports a
missing server script. `--launcher npx` writes
`npx -y --package=@owlvisions/ptah@<version> ptah-mcp` instead; it works only
once that package is published to npm.

## Safety

- Install and uninstall preview by default; `--yes` applies.
- Only the `ptah` entry is edited. An existing `ptah` entry that does not run
  `ptah-mcp` is reported as a conflict and left unchanged unless `--force`.
- JSON with comments or trailing commas is never rewritten (reported as
  `blocked`); Codex `config.toml` is edited by replacing only the
  `[mcp_servers.ptah]` table.
- Every changed file is backed up next to itself as
  `<file>.ptah-backup-<timestamp>` and replaced atomically.
- The shared skill copy in `~/.agents/skills/ptah` is removed only when no
  remaining client still has PTAH registered. A different skill that happens
  to be named `ptah` is never overwritten without `--force`.
- Exit status 2 means at least one client was blocked or in conflict.

## What the agent gets

- **MCP tools** for identification (`ptah_fingerprint`, `ptah_inspect`,
  `ptah_strings`, `ptah_carve`, `ptah_asar`, `ptah_wasm`,
  `ptah_static_analyze`), for recording an investigation (`ptah_init`,
  `ptah_add_evidence`, `ptah_add_claim`, `ptah_add_question`,
  `ptah_set_claim_status`, `ptah_resolve_question`), and for checking and
  reporting (`ptah_plan`, `ptah_lint`, `ptah_verify`, `ptah_report`,
  `ptah_graph`, `ptah_diff`, case bundles). See `docs/PTAH-MCP.md`.
- **Server instructions** in the MCP handshake that state the evidence rules.
- **The PTAH skill**, which tells the agent when to use PTAH and the workflow:
  identify, record evidence with a reproducible source and honest confidence,
  claim only what is cited, track unknowns as questions, lint and verify, and
  answer from the report.

## Limits

Client configuration formats change; the shapes above are covered by
`scripts/tests/ptah-agents.test.mjs` against a sandboxed home directory, not by
launching each vendor's client. Claude Desktop must be closed during install
because it rewrites its configuration on exit.
