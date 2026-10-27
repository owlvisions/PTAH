/**
 * #48  HTML and SARIF report renderers for PTAH Engine evidence.
 *
 * renderHtmlReport(results, options) — self-contained single-file HTML with:
 *   - Target identity header (format, SHA-256, size)
 *   - Per-task evidence cards with collapsible raw data
 *   - Entropy heatmap bar (if EntropyInspector data is present)
 *   - Provider/confidence badges
 *   - Dark-mode via prefers-color-scheme
 *
 * renderSarifReport(results, options) — SARIF 2.1 JSON for IDE/CI ingestion.
 */

const HTML_ESCAPE = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) => HTML_ESCAPE[c]);
}

const CONFIDENCE_COLOR = {
  observed: "#22c55e",
  derived: "#3b82f6",
  inferred: "#f59e0b",
};
const STATUS_COLOR = {
  ok: "#22c55e",
  partial: "#f59e0b",
  unavailable: "#6b7280",
  failed: "#ef4444",
};

function badge(label, color) {
  return `<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;background:${color}22;color:${color};border:1px solid ${color}44">${esc(label)}</span>`;
}

function entropyBar(windows) {
  if (!windows?.length) return "";
  const cells = windows
    .map((w) => {
      const pct = Math.min(w.entropy / 8, 1);
      const r = Math.round(pct * 220);
      const g = Math.round((1 - pct) * 160);
      const b = 40;
      const title = `offset 0x${w.offset.toString(16)}: ${w.entropy} bits${w.packed ? " [PACKED]" : ""}`;
      return `<span title="${esc(title)}" style="display:inline-block;width:4px;height:20px;background:rgb(${r},${g},${b});opacity:${w.packed ? 1 : 0.7}"></span>`;
    })
    .join("");
  return `<div style="margin:8px 0"><small style="opacity:.6">Entropy heatmap (${windows.length} windows)</small><br>${cells}</div>`;
}

function evidenceCard(task, result) {
  const ev = result.evidence?.[0] ?? {};
  const provider = result.provider ?? ev.provider?.id ?? "—";
  const status = ev.status ?? "unknown";
  const confidence = ev.confidence ?? "inferred";
  const summary = ev.summary ?? "";
  const dataJson = JSON.stringify(ev.data ?? {}, null, 2);
  const lims = (ev.limitations ?? []).map((l) => `<li>${esc(l)}</li>`).join("");
  const entropy = ev.data?.windows ? entropyBar(ev.data.windows) : "";
  const cardId = `card-${esc(task)}`;
  return `<div style="border:1px solid var(--border);border-radius:6px;margin:12px 0;overflow:hidden">
  <div style="padding:10px 14px;background:var(--surface2);display:flex;gap:8px;align-items:center;cursor:pointer"
       onclick="toggleCard('${cardId}')">
    <strong style="flex:1">${esc(task)}</strong>
    ${badge(status, STATUS_COLOR[status] ?? "#6b7280")}
    ${badge(confidence, CONFIDENCE_COLOR[confidence] ?? "#6b7280")}
    <span style="opacity:.5;font-size:11px">${esc(provider)}</span>
  </div>
  <div id="${cardId}" style="padding:12px 14px">
    <p style="margin:0 0 8px">${esc(summary)}</p>
    ${entropy}
    ${lims ? `<ul style="margin:4px 0;padding-left:18px;font-size:12px;opacity:.7">${lims}</ul>` : ""}
    <details style="margin-top:8px">
      <summary style="font-size:12px;cursor:pointer;opacity:.6">Raw data</summary>
      <pre style="margin:6px 0;font-size:11px;overflow:auto;max-height:300px;background:var(--code-bg);padding:8px;border-radius:4px">${esc(dataJson)}</pre>
    </details>
  </div>
</div>`;
}

/**
 * Render a self-contained HTML report from engine results.
 * @param {object} target - {path, format, sha256, size}
 * @param {Record<string, {evidence: Evidence[], provider: string}>} results - task → result map
 * @param {object} [options] - {title, timestamp}
 */
export function renderHtmlReport(target, results, options = {}) {
  const title = options.title ?? `PTAH Report — ${target.path ?? "target"}`;
  const ts = options.timestamp ?? new Date().toISOString();
  const cards = Object.entries(results)
    .map(([task, result]) => evidenceCard(task, result))
    .join("\n");
  const sha = target.sha256 ?? "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;--border:#2e3450;--text:#e2e8f0;--code-bg:#0d0f16;color-scheme:dark}
@media(prefers-color-scheme:light){:root{--bg:#f8fafc;--surface:#fff;--surface2:#f1f5f9;--border:#e2e8f0;--text:#1e293b;--code-bg:#f8fafc;color-scheme:light}}
*{box-sizing:border-box;margin:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:24px;font-size:14px}
header{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
h1{font-size:18px;font-weight:700;margin-bottom:4px}
.meta{font-size:12px;opacity:.6}
.sha{font-family:monospace;font-size:11px;opacity:.5;word-break:break-all}
</style>
<script>
function toggleCard(id){const el=document.getElementById(id);el.style.display=el.style.display==='none'?'':'none';}
</script>
</head>
<body>
<header>
  <h1>${esc(title)}</h1>
  <div class="meta">${esc(ts)} · format: ${esc(target.format ?? "?")} · size: ${target.size ?? "?"} bytes</div>
  <div class="sha">SHA-256: ${esc(sha)}</div>
</header>
<main>
${cards}
</main>
<footer style="margin-top:32px;font-size:11px;opacity:.4;border-top:1px solid var(--border);padding-top:12px">
  Generated by PTAH Engine — evidence-first program analysis
</footer>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// SARIF 2.1 export
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Render engine results as SARIF 2.1.0 JSON.
 * Each evidence item with status "failed" or "partial" becomes a SARIF result.
 */
export function renderSarifReport(target, results, options = {}) {
  const runs = [];
  const sarifResults = [];
  for (const [task, result] of Object.entries(results)) {
    for (const ev of result.evidence ?? []) {
      if (ev.status === "failed" || ev.status === "partial") {
        sarifResults.push({
          ruleId: `ptah/${task}`,
          level: ev.status === "failed" ? "error" : "warning",
          message: { text: ev.summary ?? `${task} returned ${ev.status}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: target.path ?? "" },
              },
            },
          ],
          properties: {
            confidence: ev.confidence,
            provider: ev.provider?.id ?? result.provider,
          },
        });
      }
    }
  }
  return {
    version: "2.1.0",
    $schema:
      "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    runs: [
      {
        tool: {
          driver: {
            name: "ptah-engine",
            version: "0.1.0",
            informationUri: "https://github.com/owlvisions/PTAH",
            rules: Object.keys(results).map((task) => ({
              id: `ptah/${task}`,
              name: task,
              shortDescription: { text: `PTAH engine ${task} analysis` },
            })),
          },
        },
        artifacts: [
          {
            location: { uri: target.path ?? "" },
            hashes: { "sha-256": target.sha256 ?? "" },
          },
        ],
        results: sarifResults,
        properties: {
          generatedAt: options.timestamp ?? new Date().toISOString(),
        },
      },
    ],
  };
}
