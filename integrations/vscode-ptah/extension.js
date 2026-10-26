/**
 * PTAH VS Code integration (skeleton, ESM). Spawns the PTAH CLI with fixed argv
 * and no shell; opens the loopback workbench in the external browser. Not published.
 */
import { spawn } from "node:child_process";
import path from "node:path";

function ptahCommand(config) {
  const repo = config.get("repositoryPath", "");
  return repo
    ? {
        command: process.execPath,
        prefix: [path.join(repo, "scripts", "ptah.mjs")],
      }
    : { command: "ptah", prefix: [] };
}

function runPtah(vscode, args, onJson) {
  const { command, prefix } = ptahCommand(
    vscode.workspace.getConfiguration("ptah"),
  );
  const child = spawn(command, [...prefix, ...args], {
    shell: false,
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  child.on("close", (code) => {
    if (code !== 0) {
      vscode.window.showErrorMessage(
        `PTAH failed (${code}): ${stderr.trim() || stdout.trim()}`,
      );
      return;
    }
    try {
      onJson(JSON.parse(stdout));
    } catch {
      vscode.window.showInformationMessage(stdout.trim());
    }
  });
  child.on("error", (error) =>
    vscode.window.showErrorMessage(`PTAH could not start: ${error.message}`),
  );
  return child;
}

export async function activate(context) {
  const vscode = await import("vscode");
  let ui = null;
  context.subscriptions.push(
    vscode.commands.registerCommand("ptah.openWorkbench", () => {
      const port = vscode.workspace
        .getConfiguration("ptah")
        .get("uiPort", 4177);
      if (!ui) {
        const { command, prefix } = ptahCommand(
          vscode.workspace.getConfiguration("ptah"),
        );
        ui = spawn(command, [...prefix, "ui", "--port", String(port)], {
          shell: false,
          windowsHide: true,
        });
        ui.on("close", () => (ui = null));
        context.subscriptions.push({ dispose: () => ui?.kill() });
      }
      vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${port}/`));
    }),
    vscode.commands.registerCommand("ptah.fingerprintActiveFile", () => {
      const file = vscode.window.activeTextEditor?.document.uri.fsPath;
      if (!file) return vscode.window.showWarningMessage("Open a file first.");
      runPtah(
        vscode,
        ["fingerprint", "--target", file, "--inspect"],
        (result) =>
          vscode.window.showInformationMessage(
            `${result.detectedFormat} · sha256 ${result.sha256.slice(0, 16)}… · entropy ${result.entropy?.bitsPerByte ?? "n/a"}`,
          ),
      );
    }),
    vscode.commands.registerCommand("ptah.lintInvestigation", () => {
      const file = vscode.window.activeTextEditor?.document.uri.fsPath;
      if (!file || !file.endsWith(".json"))
        return vscode.window.showWarningMessage(
          "Open an investigation JSON file first.",
        );
      runPtah(vscode, ["lint", "--input", file], (result) =>
        vscode.window.showInformationMessage(
          `PTAH lint: ${result.counts.error} error(s), ${result.counts.warning} warning(s), ${result.counts.info} info`,
        ),
      );
    }),
  );
}

export function deactivate() {}

export { ptahCommand };
