import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import {
  createInvestigationForTarget,
  saveInvestigation,
  validateInvestigation,
  buildEvidenceReport,
  buildEvidenceGraph,
  planNextAction,
  analyzeTarget,
  attachAnalysisEvidence,
  createInvestigationCase,
  importInvestigationCase,
  renderEvidenceReportMarkdown,
  recordHistory,
  lintInvestigation,
  investigationStats,
  inspectTarget,
  diffInvestigations,
  detectIsolationSupport,
  STATIC_ANALYZER_IDS,
  renderEvidenceGraph,
} from "./ptah-engine.mjs";
import {
  extractStrings,
  findEmbeddedSignatures,
  parseAsarHeader,
  parseWasmSections,
} from "./ptah-analysis.mjs";

const MAX_JOBS = 50;
const JOB_RETENTION_MS = 30 * 60 * 1000;

const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
const MAX_JSON_BYTES = 1024 * 1024;
const HTML_PATH = new URL("../web/ptah/index.html", import.meta.url);

function sendJson(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  response.end(body);
}

async function readBody(request, limit) {
  const declared = Number(request.headers["content-length"] ?? 0);
  if (declared > limit)
    throw Object.assign(new Error(`request body exceeds ${limit} bytes`), {
      statusCode: 413,
    });
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit)
      throw Object.assign(new Error(`request body exceeds ${limit} bytes`), {
        statusCode: 413,
      });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(request, limit = MAX_JSON_BYTES) {
  const bytes = await readBody(request, limit);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw Object.assign(new Error("request body must be valid JSON"), {
      statusCode: 400,
    });
  }
}

function sanitizeFilename(value) {
  const base = basename(typeof value === "string" ? value : "target.bin")
    .replace(/[^a-zA-Z0-9._ -]/g, "_")
    .trim()
    .slice(0, 100);
  return base && base !== "." && base !== ".." ? base : "target.bin";
}

function tokenMatches(candidate, expected) {
  if (typeof candidate !== "string") return false;
  const given = Buffer.from(candidate);
  const wanted = Buffer.from(expected);
  return given.length === wanted.length && timingSafeEqual(given, wanted);
}

export async function createPtahUiServer(options = {}) {
  const sessionToken = randomBytes(32).toString("hex");
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost")
    throw new TypeError("PTAH UI only supports loopback binding");
  const workspace =
    options.workspace ?? (await mkdtemp(join(tmpdir(), "ptah-ui-")));
  let targetPath;
  let investigationPath = join(workspace, "investigation.json");
  let investigation;
  const persist = async (candidate, action = undefined, details = {}) => {
    const validated = validateInvestigation(
      action ? recordHistory(candidate, action, details) : candidate,
    );
    await saveInvestigation(investigationPath, validated);
    investigation = validated;
    return investigation;
  };
  const jobs = new Map();
  const pruneJobs = () => {
    const now = Date.now();
    for (const [id, job] of jobs)
      if (job.status !== "running" && now - job.finishedAt > JOB_RETENTION_MS)
        jobs.delete(id);
    while (jobs.size > MAX_JOBS) {
      const oldest = [...jobs.values()]
        .filter((job) => job.status !== "running")
        .sort((a, b) => a.createdAt - b.createdAt)[0];
      if (!oldest) break;
      jobs.delete(oldest.id);
    }
  };
  const publicJob = (job) => ({
    id: job.id,
    kind: job.kind,
    provider: job.provider,
    status: job.status,
    createdAt: new Date(job.createdAt).toISOString(),
    finishedAt: job.finishedAt ? new Date(job.finishedAt).toISOString() : null,
    progress: job.progress,
    result: job.result ?? null,
    error: job.error ?? null,
  });
  const startAnalyzeJob = (body) => {
    pruneJobs();
    if (
      [...jobs.values()].filter((job) => job.status === "running").length >= 4
    )
      throw Object.assign(new Error("too many running jobs; cancel or wait"), {
        statusCode: 429,
      });
    if (!STATIC_ANALYZER_IDS.includes(body.provider))
      throw Object.assign(
        new Error(`provider must be one of ${STATIC_ANALYZER_IDS.join(", ")}`),
        { statusCode: 400 },
      );
    const controller = new AbortController();
    const job = {
      id: randomUUID(),
      kind: "analyze",
      provider: body.provider,
      status: "running",
      createdAt: Date.now(),
      finishedAt: null,
      progress: { phase: "starting" },
      controller,
    };
    jobs.set(job.id, job);
    void (async () => {
      try {
        job.progress = { phase: "analyzing" };
        const analysis = await analyzeTarget(targetPath, body.provider, {
          timeoutMs: body.timeoutMs ?? 5000,
          maxOutputBytes: body.maxOutputBytes ?? 16384,
          env: options.env ?? process.env,
          isolation: body.isolation ?? "auto",
          signal: controller.signal,
        });
        if (analysis.status === "ok" && !analysis.targetChanged) {
          job.progress = { phase: "recording-evidence" };
          const evidenceId =
            body.evidenceId ??
            `ev-${body.provider}-${analysis.outputSha256.slice(0, 10)}`;
          await persist(
            attachAnalysisEvidence(investigation, analysis, evidenceId),
            "evidence-added",
            { evidenceId, kind: "static-analysis", provider: body.provider },
          );
          analysis.evidence = { id: evidenceId, recorded: true };
        }
        job.result = analysis;
        job.status =
          analysis.status === "cancelled"
            ? "cancelled"
            : analysis.status === "ok" && !analysis.targetChanged
              ? "succeeded"
              : "failed";
      } catch (error) {
        job.status = controller.signal.aborted ? "cancelled" : "failed";
        job.error = error instanceof Error ? error.message : String(error);
      } finally {
        job.finishedAt = Date.now();
        job.progress = { phase: "done" };
      }
    })();
    return job;
  };
  const server = createServer(async (request, response) => {
    try {
      const hostHeader = request.headers.host ?? "";
      const hostName = hostHeader.startsWith("[")
        ? hostHeader.slice(1, hostHeader.indexOf("]"))
        : hostHeader.split(":")[0];
      if (!["127.0.0.1", "localhost", "::1"].includes(hostName))
        return sendJson(response, 403, {
          error: "loopback Host header required",
        });
      // Cross-site pages can send "simple" POSTs to loopback without a
      // preflight; every state change must prove it came from this page.
      if (request.method !== "GET" && request.method !== "HEAD") {
        const origin = request.headers.origin;
        if (
          !tokenMatches(request.headers["x-ptah-token"], sessionToken) ||
          (origin !== undefined && origin !== `http://${hostHeader}`)
        )
          return sendJson(response, 403, {
            error: "missing or invalid PTAH session token",
          });
      }
      if (request.method === "GET" && request.url === "/") {
        const html = Buffer.from(
          (await readFile(HTML_PATH, "utf8")).replace(
            "</head>",
            `<meta name="ptah-token" content="${sessionToken}" />\n</head>`,
          ),
        );
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-length": html.length,
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "content-security-policy":
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        });
        response.end(html);
        return;
      }
      if (request.method === "GET" && request.url === "/api/state") {
        return sendJson(response, 200, {
          initialized: Boolean(investigation),
          investigation: investigation ?? null,
          target: investigation
            ? {
                name: basename(targetPath),
                sha256: investigation.target.sha256,
              }
            : null,
        });
      }
      if (request.method === "POST" && request.url === "/api/init") {
        const bytes = await readBody(
          request,
          options.maxUploadBytes ?? MAX_UPLOAD_BYTES,
        );
        if (bytes.length === 0)
          return sendJson(response, 400, { error: "target upload is empty" });
        const name = sanitizeFilename(request.headers["x-target-name"]);
        targetPath = join(
          workspace,
          `target-${Date.now()}-${Math.random().toString(16).slice(2)}-${name}`,
        );
        await writeFile(targetPath, bytes, { flag: "wx", mode: 0o600 });
        const candidate = await createInvestigationForTarget(targetPath, name);
        await persist(candidate, "init", { targetId: name });
        return sendJson(response, 201, {
          initialized: true,
          target: {
            name,
            sha256: investigation.target.sha256,
            sizeBytes: bytes.length,
          },
          investigation,
        });
      }
      if (request.method === "POST" && request.url?.startsWith("/api/")) {
        const body = await readJson(
          request,
          request.url === "/api/import-case" || request.url === "/api/diff"
            ? (options.maxCaseBytes ?? MAX_UPLOAD_BYTES)
            : MAX_JSON_BYTES,
        );
        if (request.url === "/api/import-case") {
          if (!investigation || !targetPath)
            return sendJson(response, 409, {
              error: "upload the matching target before importing a case",
            });
          const imported = await importInvestigationCase(body, targetPath);
          await persist(imported, "case-imported", {
            evidenceCount: imported.evidence.length,
          });
          return sendJson(response, 200, {
            status: "imported",
            investigation,
            target: {
              name: investigation.target.id,
              sha256: investigation.target.sha256,
            },
          });
        }
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        if (request.url === "/api/evidence") {
          const id = body.id;
          const candidate = {
            ...investigation,
            evidence: [
              ...investigation.evidence,
              {
                id,
                kind: body.kind,
                summary: body.summary,
                source: body.source,
                confidence: body.confidence ?? "observed",
                targetSha256: investigation.target.sha256,
              },
            ],
          };
          await persist(candidate, "evidence-added", { evidenceId: id });
          return sendJson(response, 201, { investigation });
        }
        if (request.url === "/api/claim") {
          const candidate = {
            ...investigation,
            claims: [
              ...investigation.claims,
              {
                id: body.id,
                text: body.text,
                evidenceIds: Array.isArray(body.evidenceIds)
                  ? body.evidenceIds
                  : [],
                status: body.status ?? "hypothesis",
              },
            ],
          };
          await persist(candidate, "claims-added", { id: body.id });
          return sendJson(response, 201, { investigation });
        }
        if (request.url === "/api/question") {
          const candidate = {
            ...investigation,
            questions: [
              ...investigation.questions,
              {
                id: body.id,
                text: body.text,
                priority: body.priority ?? 50,
                requiredEvidenceKinds: body.requiredEvidenceKinds ?? [],
                resolved: false,
              },
            ],
          };
          await persist(candidate, "questions-added", { id: body.id });
          return sendJson(response, 201, { investigation });
        }
        if (request.url === "/api/action") {
          const candidate = {
            ...investigation,
            actions: [
              ...investigation.actions,
              {
                id: body.id,
                name: body.name,
                produces: body.produces ?? [],
                cost: body.cost ?? 1,
              },
            ],
          };
          await persist(candidate, "actions-added", { id: body.id });
          return sendJson(response, 201, { investigation });
        }
        if (request.url === "/api/jobs") {
          const job = startAnalyzeJob(body);
          return sendJson(response, 202, publicJob(job));
        }
        if (/^\/api\/jobs\/[0-9a-f-]+\/cancel$/u.test(request.url)) {
          const job = jobs.get(request.url.split("/")[3]);
          if (!job) return sendJson(response, 404, { error: "unknown job" });
          if (job.status === "running") job.controller.abort();
          return sendJson(response, 200, publicJob(job));
        }
        if (request.url === "/api/diff") {
          return sendJson(
            response,
            200,
            diffInvestigations(investigation, body),
          );
        }
        if (request.url === "/api/analyze") {
          const analysis = await analyzeTarget(targetPath, body.provider, {
            timeoutMs: body.timeoutMs ?? 5000,
            maxOutputBytes: body.maxOutputBytes ?? 16384,
            env: options.env ?? process.env,
            isolation: body.isolation ?? "auto",
          });
          if (analysis.status === "ok" && !analysis.targetChanged) {
            const evidenceId =
              body.evidenceId ??
              `ev-${body.provider}-${analysis.outputSha256.slice(0, 10)}`;
            await persist(
              attachAnalysisEvidence(investigation, analysis, evidenceId),
              "evidence-added",
              { evidenceId, kind: "static-analysis", provider: body.provider },
            );
            analysis.evidence = { id: evidenceId, recorded: true };
          }
          return sendJson(
            response,
            analysis.status === "ok" && !analysis.targetChanged ? 200 : 502,
            { analysis, investigation },
          );
        }
        return sendJson(response, 404, { error: "unknown API route" });
      }
      if (request.method === "GET" && request.url === "/api/report") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, buildEvidenceReport(investigation));
      }
      if (request.method === "GET" && request.url === "/api/lint") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, lintInvestigation(investigation));
      }
      if (request.method === "GET" && request.url === "/api/stats") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, investigationStats(investigation));
      }
      if (request.method === "GET" && request.url === "/api/jobs") {
        pruneJobs();
        return sendJson(response, 200, {
          jobs: [...jobs.values()]
            .sort((a, b) => b.createdAt - a.createdAt)
            .map(publicJob),
        });
      }
      if (
        request.method === "GET" &&
        /^\/api\/jobs\/[0-9a-f-]+$/u.test(request.url)
      ) {
        const job = jobs.get(request.url.split("/")[3]);
        if (!job) return sendJson(response, 404, { error: "unknown job" });
        return sendJson(response, 200, publicJob(job));
      }
      if (request.method === "GET" && request.url === "/api/isolation") {
        return sendJson(
          response,
          200,
          await detectIsolationSupport(options.env ?? process.env),
        );
      }
      if (request.method === "GET" && request.url === "/api/carve") {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(
          response,
          200,
          await findEmbeddedSignatures(targetPath),
        );
      }
      if (request.method === "GET" && request.url === "/api/asar") {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, await parseAsarHeader(targetPath));
      }
      if (request.method === "GET" && request.url === "/api/wasm") {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, await parseWasmSections(targetPath));
      }
      if (request.method === "GET" && request.url === "/api/inspect") {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, await inspectTarget(targetPath));
      }
      if (request.method === "GET" && request.url?.startsWith("/api/strings")) {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        const params = new URL(request.url, "http://127.0.0.1").searchParams;
        const bounded = (name, fallback, max) => {
          const raw = params.get(name);
          const value = raw === null ? fallback : Number(raw);
          if (!Number.isInteger(value) || value < 1 || value > max)
            throw Object.assign(
              new Error(`${name} must be an integer between 1 and ${max}`),
              { statusCode: 400 },
            );
          return value;
        };
        return sendJson(
          response,
          200,
          await extractStrings(targetPath, {
            minLength: Math.max(2, bounded("minLength", 6, 256)),
            maxResults: bounded("maxResults", 200, 2000),
            maxBytes: bounded("maxBytes", 16 * 1024 * 1024, 128 * 1024 * 1024),
          }),
        );
      }
      if (
        request.method === "GET" &&
        (request.url === "/api/graph.dot" || request.url === "/api/graph.mmd")
      ) {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        const format = request.url.endsWith(".dot") ? "dot" : "mermaid";
        const text = Buffer.from(renderEvidenceGraph(investigation, format));
        response.writeHead(200, {
          "content-type": `text/${format === "dot" ? "vnd.graphviz" : "plain"}; charset=utf-8`,
          "content-length": text.length,
          "content-disposition": `attachment; filename="ptah-graph.${format === "dot" ? "dot" : "mmd"}"`,
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(text);
        return;
      }
      if (request.method === "GET" && request.url === "/api/report.md") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        const markdown = Buffer.from(
          renderEvidenceReportMarkdown(investigation),
        );
        response.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "content-length": markdown.length,
          "content-disposition": 'attachment; filename="ptah-report.md"',
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(markdown);
        return;
      }
      if (request.method === "GET" && request.url === "/api/graph") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, buildEvidenceGraph(investigation));
      }
      if (request.method === "GET" && request.url === "/api/plan") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        return sendJson(response, 200, planNextAction(investigation));
      }
      if (request.method === "GET" && request.url === "/api/download") {
        if (!investigation)
          return sendJson(response, 409, { error: "upload a target first" });
        const data = Buffer.from(
          `${JSON.stringify(createInvestigationCase(investigation), null, 2)}\n`,
        );
        response.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "content-length": data.length,
          "content-disposition": 'attachment; filename="ptah-case.json"',
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(data);
        return;
      }
      // ── Engine endpoints (#46/#47) ──────────────────────────────────────────
      if (request.method === "GET" && request.url === "/api/engine/providers") {
        const { createDefaultRegistry } =
          await import("../engine/src/index.mjs");
        const registry = createDefaultRegistry();
        const { providers, routes } = await registry.probe();
        return sendJson(response, 200, {
          providers,
          formatCount: Object.keys(routes).length,
        });
      }
      if (request.method === "GET" && request.url === "/api/engine/matrix") {
        const { createDefaultRegistry, renderMatrixMarkdown } =
          await import("../engine/src/index.mjs");
        const registry = createDefaultRegistry();
        await registry.probe();
        return sendJson(response, 200, {
          matrix: renderMatrixMarkdown(registry),
        });
      }
      if (request.method === "POST" && request.url === "/api/engine/analyze") {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        const body = await readBody(request);
        const tasks = body.tasks ?? [
          "manifest",
          "sections",
          "symbols",
          "importsExports",
          "strings",
        ];
        const {
          createDefaultRegistry,
          createEngine,
          renderHtmlReport,
          EntropyInspector,
          CryptoInspector,
        } = await import("../engine/src/index.mjs");
        const registry = createDefaultRegistry();
        const engine = createEngine({ registry });
        const attestation = {
          ownership: "owner",
          purpose: "interoperability",
          statement: "ptah-ui",
        };
        const session = await engine.open(targetPath, attestation);
        const results = await session.runAll(tasks, {});
        // Also run entropy and crypto inspectors
        try {
          const entropyResult = await session.run("sections", {
            provider: "entropy-inspector",
          });
          if (entropyResult.provider) results["entropy"] = entropyResult;
        } catch {
          /* optional */
        }
        try {
          const cryptoResult = await session.run("resources", {
            provider: "crypto-inspector",
          });
          if (cryptoResult.provider) results["crypto"] = cryptoResult;
        } catch {
          /* optional */
        }
        const htmlReport = renderHtmlReport(session.target, results, {
          title: `PTAH Engine — ${session.target.path}`,
        });
        return sendJson(response, 200, {
          target: {
            format: session.target.format,
            sha256: session.target.sha256,
            size: session.target.size,
          },
          results: Object.fromEntries(
            Object.entries(results).map(([task, r]) => [
              task,
              {
                provider: r.provider,
                status: r.evidence[0]?.status,
                summary: r.evidence[0]?.summary,
                data: r.evidence[0]?.data,
                confidence: r.evidence[0]?.confidence,
              },
            ]),
          ),
          htmlReport,
        });
      }
      if (
        request.method === "GET" &&
        request.url === "/api/engine/report.html"
      ) {
        if (!targetPath)
          return sendJson(response, 409, { error: "upload a target first" });
        const { createDefaultRegistry, createEngine, renderHtmlReport } =
          await import("../engine/src/index.mjs");
        const registry = createDefaultRegistry();
        const engine = createEngine({ registry });
        const attestation = {
          ownership: "owner",
          purpose: "interoperability",
          statement: "ptah-ui",
        };
        const session = await engine.open(targetPath, attestation);
        const results = await session.runAll(
          ["manifest", "sections", "symbols", "importsExports", "strings"],
          {},
        );
        const html = renderHtmlReport(session.target, results);
        const buf = Buffer.from(html);
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-length": buf.length,
          "content-disposition":
            'attachment; filename="ptah-engine-report.html"',
        });
        response.end(buf);
        return;
      }
      sendJson(response, 404, { error: "not found" });
    } catch (error) {
      sendJson(response, error?.statusCode ?? 400, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });
  return {
    server,
    workspace,
    sessionToken,
    async close() {
      await new Promise((resolveClose, rejectClose) =>
        server.close((error) => (error ? rejectClose(error) : resolveClose())),
      );
      if (!options.workspace)
        await rm(workspace, { recursive: true, force: true });
    },
  };
}
