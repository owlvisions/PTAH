/**
 * Additional report formats: SARIF 2.1.0 for code-scanning tools and IDEs,
 * and a self-contained HTML page. Content originates in hostile targets, so
 * HTML output escapes every value and forbids scripts with a CSP.
 */
import {
  buildEvidenceReport,
  lintInvestigation,
  validateInvestigation,
} from "./ptah-engine.mjs";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const LEVEL_BY_STATUS = {
  verified: "error",
  supported: "warning",
  hypothesis: "note",
  rejected: "none",
};

/** Render claims and lint findings as a SARIF 2.1.0 log. */
export function renderSarif(input, options = {}) {
  const investigation = validateInvestigation(input);
  const artifact = {
    location: { uri: investigation.target.id },
    hashes: { "sha-256": investigation.target.sha256 },
  };
  const location = [
    {
      physicalLocation: {
        artifactLocation: { uri: investigation.target.id, index: 0 },
      },
    },
  ];
  const evidenceById = new Map(
    investigation.evidence.map((item) => [item.id, item]),
  );
  const results = investigation.claims.map((claim) => {
    const status = claim.status ?? "hypothesis";
    const cited = claim.evidenceIds.map((id) => evidenceById.get(id));
    return {
      ruleId: "ptah/claim",
      level: LEVEL_BY_STATUS[status] ?? "note",
      message: {
        text: `${claim.text} [${status}; evidence: ${cited.map((item) => `${item.id} (${item.confidence})`).join(", ")}]`,
      },
      locations: location,
      partialFingerprints: { claimId: claim.id },
      properties: {
        status,
        evidence: cited.map(({ id, kind, confidence, source, summary }) => ({
          id,
          kind,
          confidence,
          source,
          summary,
        })),
      },
    };
  });
  const lint = lintInvestigation(investigation).findings.filter(
    (item) => item.severity !== "info",
  );
  for (const finding of lint)
    results.push({
      ruleId: `ptah/lint/${finding.code}`,
      level: finding.severity === "error" ? "error" : "warning",
      message: { text: `${finding.subject}: ${finding.message}` },
      locations: location,
    });
  const ruleIds = [...new Set(results.map((item) => item.ruleId))];
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "PTAH",
            informationUri: "https://github.com/owlvisions/PTAH",
            version: options.version ?? "0.0.0",
            rules: ruleIds.map((id) => ({
              id,
              shortDescription: {
                text:
                  id === "ptah/claim"
                    ? "Evidence-backed claim about the target"
                    : `PTAH investigation lint: ${id.split("/").at(-1)}`,
              },
            })),
          },
        },
        artifacts: [artifact],
        results,
      },
    ],
  };
}

const escapeHtml = (value) =>
  String(value).replace(
    /[&<>"']/gu,
    (character) => `&#${character.charCodeAt(0)};`,
  );

/** Render a self-contained HTML report; no scripts, every value escaped. */
export function renderHtmlReport(input) {
  const investigation = validateInvestigation(input);
  const report = buildEvidenceReport(investigation);
  const evidenceRows = investigation.evidence
    .map(
      (item) =>
        `<tr id="ev-${escapeHtml(item.id)}"><td><code>${escapeHtml(item.id)}</code></td><td>${escapeHtml(item.kind)}</td><td class="c-${escapeHtml(item.confidence)}">${escapeHtml(item.confidence)}</td><td>${escapeHtml(item.summary)}</td><td><code>${escapeHtml(item.source)}</code></td></tr>`,
    )
    .join("\n");
  const claims = report.claims
    .map(
      (claim) =>
        `<li><span class="s-${escapeHtml(claim.status)}">${escapeHtml(claim.status)}</span> ${escapeHtml(claim.text)} — ${claim.evidence.map((item) => `<a href="#ev-${escapeHtml(item.id)}">${escapeHtml(item.id)}</a>`).join(", ")}</li>`,
    )
    .join("\n");
  const questions = investigation.questions
    .map(
      (item) =>
        `<li>${item.resolved ? "✓" : "?"} ${escapeHtml(item.text)}${item.resolution ? ` — ${escapeHtml(item.resolution.reason)}` : ""}</li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PTAH report — ${escapeHtml(investigation.target.id)}</title>
<style>
:root{--bg:#fff;--fg:#1b1b1f;--muted:#5b5b66;--line:#e2e2e8;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#111114;--fg:#ececf1;--muted:#a1a1ad;--line:#2c2c33;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:24px 16px}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem}code{font-size:.85em;word-break:break-all}
.meta{color:var(--muted)}table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}
td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.c-observed,.s-verified{color:var(--ok)}.c-derived,.s-supported{color:var(--warn)}.c-inferred,.s-hypothesis{color:var(--muted)}.s-rejected{color:var(--bad);text-decoration:line-through}
</style>
</head>
<body>
<h1>PTAH report — ${escapeHtml(investigation.target.id)}</h1>
<p class="meta">SHA-256 <code>${escapeHtml(investigation.target.sha256)}</code> · ${report.summary.evidenceCount} evidence · ${report.summary.claimCount} claims · ${report.summary.unresolvedQuestionCount} open questions</p>
<h2>Claims</h2>
<ul>${claims || "<li>No claims recorded.</li>"}</ul>
<h2>Open and resolved questions</h2>
<ul>${questions || "<li>No questions recorded.</li>"}</ul>
<h2>Evidence</h2>
<table><thead><tr><th>ID</th><th>Kind</th><th>Confidence</th><th>Summary</th><th>Source</th></tr></thead>
<tbody>
${evidenceRows}
</tbody></table>
</body>
</html>
`;
}
