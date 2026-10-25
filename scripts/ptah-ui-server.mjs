import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createInvestigationForTarget, saveInvestigation, validateInvestigation,
  buildEvidenceReport, buildEvidenceGraph, planNextAction, analyzeTarget, attachAnalysisEvidence,
} from './ptah-engine.mjs';

const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
const MAX_JSON_BYTES = 1024 * 1024;
const HTML_PATH = new URL('../web/ptah/index.html', import.meta.url);

function sendJson(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  response.end(body);
}

async function readBody(request, limit) {
  const declared = Number(request.headers['content-length'] ?? 0);
  if (declared > limit) throw Object.assign(new Error(`request body exceeds ${limit} bytes`), { statusCode: 413 });
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error(`request body exceeds ${limit} bytes`), { statusCode: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(request) {
  const bytes = await readBody(request, MAX_JSON_BYTES);
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { throw Object.assign(new Error('request body must be valid JSON'), { statusCode: 400 }); }
}

function sanitizeFilename(value) {
  const base = basename(typeof value === 'string' ? value : 'target.bin')
    .replace(/[^a-zA-Z0-9._ -]/g, '_').trim().slice(0, 100);
  return base && base !== '.' && base !== '..' ? base : 'target.bin';
}

export async function createPtahUiServer(options = {}) {
  const host = options.host ?? '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') throw new TypeError('PTAH UI only supports loopback binding');
  const workspace = options.workspace ?? await mkdtemp(join(tmpdir(), 'ptah-ui-'));
  let targetPath;
  let investigationPath = join(workspace, 'investigation.json');
  let investigation;
  const persist = async (candidate) => {
    const validated = validateInvestigation(candidate);
    await saveInvestigation(investigationPath, validated);
    investigation = validated;
    return investigation;
  };
  const server = createServer(async (request, response) => {
    try {
      const hostHeader = request.headers.host ?? '';
      const hostName = hostHeader.startsWith('[') ? hostHeader.slice(1, hostHeader.indexOf(']')) : hostHeader.split(':')[0];
      if (!['127.0.0.1', 'localhost', '::1'].includes(hostName)) return sendJson(response, 403, { error: 'loopback Host header required' });
      if (request.method === 'GET' && request.url === '/') {
        const html = await readFile(HTML_PATH);
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': html.length,
          'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" });
        response.end(html);
        return;
      }
      if (request.method === 'GET' && request.url === '/api/state') {
        return sendJson(response, 200, { initialized: Boolean(investigation), investigation: investigation ?? null,
          target: investigation ? { name: basename(targetPath), sha256: investigation.target.sha256 } : null });
      }
      if (request.method === 'POST' && request.url === '/api/init') {
        const bytes = await readBody(request, options.maxUploadBytes ?? MAX_UPLOAD_BYTES);
        if (bytes.length === 0) return sendJson(response, 400, { error: 'target upload is empty' });
        const name = sanitizeFilename(request.headers['x-target-name']);
        targetPath = join(workspace, `target-${Date.now()}-${Math.random().toString(16).slice(2)}-${name}`);
        await writeFile(targetPath, bytes, { flag: 'wx', mode: 0o600 });
        const candidate = await createInvestigationForTarget(targetPath, name);
        await persist(candidate);
        return sendJson(response, 201, { initialized: true, target: { name, sha256: investigation.target.sha256, sizeBytes: bytes.length }, investigation });
      }
      if (request.method === 'POST' && request.url?.startsWith('/api/')) {
        const body = await readJson(request);
        if (!investigation) return sendJson(response, 409, { error: 'upload a target first' });
        if (request.url === '/api/evidence') {
          const id = body.id;
          const candidate = { ...investigation, evidence: [...investigation.evidence, {
            id, kind: body.kind, summary: body.summary, source: body.source,
            confidence: body.confidence ?? 'observed', targetSha256: investigation.target.sha256,
          }] };
          await persist(candidate);
          return sendJson(response, 201, { investigation });
        }
        if (request.url === '/api/claim') {
          const candidate = { ...investigation, claims: [...investigation.claims, { id: body.id, text: body.text,
            evidenceIds: Array.isArray(body.evidenceIds) ? body.evidenceIds : [], status: body.status ?? 'hypothesis' }] };
          await persist(candidate);
          return sendJson(response, 201, { investigation });
        }
        if (request.url === '/api/question') {
          const candidate = { ...investigation, questions: [...investigation.questions, { id: body.id, text: body.text,
            priority: body.priority ?? 50, requiredEvidenceKinds: body.requiredEvidenceKinds ?? [], resolved: false }] };
          await persist(candidate);
          return sendJson(response, 201, { investigation });
        }
        if (request.url === '/api/action') {
          const candidate = { ...investigation, actions: [...investigation.actions, { id: body.id, name: body.name,
            produces: body.produces ?? [], cost: body.cost ?? 1 }] };
          await persist(candidate);
          return sendJson(response, 201, { investigation });
        }
        if (request.url === '/api/analyze') {
          const analysis = await analyzeTarget(targetPath, body.provider, { timeoutMs: body.timeoutMs ?? 5000, maxOutputBytes: body.maxOutputBytes ?? 16384, env: options.env ?? process.env });
          if (analysis.status === 'ok' && !analysis.targetChanged) {
            const evidenceId = body.evidenceId ?? `ev-${body.provider}-${analysis.outputSha256.slice(0, 10)}`;
            await persist(attachAnalysisEvidence(investigation, analysis, evidenceId));
            analysis.evidence = { id: evidenceId, recorded: true };
          }
          return sendJson(response, analysis.status === 'ok' && !analysis.targetChanged ? 200 : 502, { analysis, investigation });
        }
        return sendJson(response, 404, { error: 'unknown API route' });
      }
      if (request.method === 'GET' && request.url === '/api/report') {
        if (!investigation) return sendJson(response, 409, { error: 'upload a target first' });
        return sendJson(response, 200, buildEvidenceReport(investigation));
      }
      if (request.method === 'GET' && request.url === '/api/graph') {
        if (!investigation) return sendJson(response, 409, { error: 'upload a target first' });
        return sendJson(response, 200, buildEvidenceGraph(investigation));
      }
      if (request.method === 'GET' && request.url === '/api/plan') {
        if (!investigation) return sendJson(response, 409, { error: 'upload a target first' });
        return sendJson(response, 200, planNextAction(investigation));
      }
      if (request.method === 'GET' && request.url === '/api/download') {
        if (!investigation) return sendJson(response, 409, { error: 'upload a target first' });
        const data = Buffer.from(`${JSON.stringify(investigation, null, 2)}\n`);
        response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': data.length,
          'content-disposition': 'attachment; filename="ptah-investigation.json"', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        response.end(data);
        return;
      }
      sendJson(response, 404, { error: 'not found' });
    } catch (error) {
      sendJson(response, error?.statusCode ?? 400, { error: error instanceof Error ? error.message : String(error) });
    }
  });
  return {
    server,
    workspace,
    async close() {
      await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
      if (!options.workspace) await rm(workspace, { recursive: true, force: true });
    },
  };
}
