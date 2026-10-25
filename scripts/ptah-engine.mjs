/**
 * Dependency-free PTAH investigation primitives (v1).
 * This is an additive migration slice, not a replacement for REA's existing
 * Evidence Ledger. Inputs are treated as untrusted JSON and validated here.
 */
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { basename, delimiter, extname, join, resolve } from 'node:path';
import { constants, access, stat, open, writeFile, mkdir, rename, unlink } from 'node:fs/promises';
import { spawn } from 'node:child_process';

export const INVESTIGATION_SCHEMA_VERSION = 1;

const MAGIC_SIGNATURES = [
  { format: 'ELF', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { format: 'DOS MZ header (PE format not confirmed)', bytes: [0x4d, 0x5a] },
  { format: 'Mach-O 32-bit', bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { format: 'Mach-O 64-bit', bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { format: 'Mach-O 64-bit (reversed)', bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { format: 'WebAssembly', bytes: [0x00, 0x61, 0x73, 0x6d] },
  { format: 'Java class', bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { format: 'DEX', bytes: [0x64, 0x65, 0x78, 0x0a] },
  { format: 'ZIP container (format not uniquely identified)', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { format: 'ZIP empty archive (format not uniquely identified)', bytes: [0x50, 0x4b, 0x05, 0x06] },
  { format: 'ZIP spanning archive (format not uniquely identified)', bytes: [0x50, 0x4b, 0x07, 0x08] },
  { format: 'SQLite database', bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65] },
];

function detectFormat(header, filePath) {
  const signature = MAGIC_SIGNATURES.find(({ bytes }) => bytes.every((byte, index) => header[index] === byte));
  if (signature) return signature.format;
  const extension = extname(filePath).toLowerCase();
  const knownExtensions = new Map([
    ['.apk', 'Android APK (extension only; signature not confirmed)'],
    ['.dex', 'Dalvik DEX (extension only; signature not confirmed)'],
    ['.wasm', 'WebAssembly (extension only; signature not confirmed)'],
    ['.dll', 'Windows DLL (extension only; signature not confirmed)'],
    ['.exe', 'Windows executable (extension only; signature not confirmed)'],
    ['.so', 'Shared library (extension only; signature not confirmed)'],
    ['.dylib', 'macOS dynamic library (extension only; signature not confirmed)'],
    ['.asar', 'Electron ASAR archive (extension only; signature not confirmed)'],
    ['.jar', 'Java archive (extension only; signature not confirmed)'],
    ['.pck', 'Godot PCK (extension only; signature not confirmed)'],
  ]);
  return knownExtensions.get(extension) ?? 'Unknown (no recognized magic signature)';
}

/** Fingerprint a target file without executing or modifying it. */
export async function fingerprintTarget(filePath) {
  const absolutePath = resolve(filePath);
  const fileStat = await stat(absolutePath);
  if (!fileStat.isFile()) throw new TypeError('target must be a regular file');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(absolutePath)) hash.update(chunk);
  const headerHandle = await open(absolutePath, 'r');
  const header = Buffer.alloc(16);
  let headerLength = 0;
  try { headerLength = (await headerHandle.read(header, 0, 16, 0)).bytesRead; }
  finally { await headerHandle.close(); }
  const finalStat = await stat(absolutePath);
  if (fileStat.size !== finalStat.size || fileStat.mtimeMs !== finalStat.mtimeMs || fileStat.ino !== finalStat.ino) {
    throw new Error('target changed while it was being fingerprinted; retry against a stable file');
  }
  return {
    id: basename(absolutePath),
    path: absolutePath,
    sizeBytes: fileStat.size,
    modifiedAt: fileStat.mtime.toISOString(),
    sha256: hash.digest('hex'),
    detectedFormat: detectFormat(header.subarray(0, headerLength), absolutePath),
    executed: false,
    modified: false,
  };
}

/** Create a new investigation tied to the actual target bytes. */
export async function createInvestigationForTarget(filePath, id = undefined) {
  if (id !== undefined && (typeof id !== 'string' || id.trim().length === 0)) throw new TypeError('target id must be a non-empty string when supplied');
  const fingerprint = await fingerprintTarget(filePath);
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: { id: id?.trim() || fingerprint.id, sha256: fingerprint.sha256 },
    evidence: [],
    claims: [],
    questions: [],
    actions: [],
  };
}

/** Validate and atomically persist an investigation JSON file. */
export async function saveInvestigation(filePath, document) {
  const validated = validateInvestigation(document);
  const absolutePath = resolve(filePath);
  const { dirname } = await import('node:path');
  await mkdir(dirname(absolutePath), { recursive: true });
  const temporaryPath = `${absolutePath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(validated, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  try {
    await rename(temporaryPath, absolutePath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
  return absolutePath;
}

const CONFIDENCE = new Set(['observed', 'derived', 'inferred']);
const EVIDENCE_KINDS = new Set([
  'static-analysis', 'runtime-observation', 'decompilation', 'symbol',
  'network-observation', 'filesystem-observation', 'documentation', 'test-result', 'other',
]);

export function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requireString(value, path) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

function requireArray(value, path) {
  if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
  return value;
}

function uniqueIds(items, path) {
  const seen = new Set();
  for (const item of items) {
    requireString(item.id, `${path}[].id`);
    if (seen.has(item.id)) throw new TypeError(`${path} contains duplicate id: ${item.id}`);
    seen.add(item.id);
  }
  return seen;
}

/** Validate a portable, versioned investigation document. */
export function validateInvestigation(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new TypeError('investigation must be an object');
  }
  if (document.schemaVersion !== INVESTIGATION_SCHEMA_VERSION) {
    throw new TypeError(`schemaVersion must be ${INVESTIGATION_SCHEMA_VERSION}`);
  }
  if (!document.target || typeof document.target !== 'object') {
    throw new TypeError('target must be an object');
  }
  requireString(document.target.id, 'target.id');
  requireString(document.target.sha256, 'target.sha256');
  if (!/^[a-f0-9]{64}$/i.test(document.target.sha256)) {
    throw new TypeError('target.sha256 must be a 64-character hexadecimal SHA-256 digest');
  }

  const evidence = requireArray(document.evidence ?? [], 'evidence');
  const claims = requireArray(document.claims ?? [], 'claims');
  const questions = requireArray(document.questions ?? [], 'questions');
  const actions = requireArray(document.actions ?? [], 'actions');
  const evidenceIds = uniqueIds(evidence, 'evidence');
  const claimIds = uniqueIds(claims, 'claims');
  uniqueIds(questions, 'questions');
  uniqueIds(actions, 'actions');

  for (const item of evidence) {
    requireString(item.summary, `evidence.${item.id}.summary`);
    requireString(item.source, `evidence.${item.id}.source`);
    requireString(item.kind, `evidence.${item.id}.kind`);
    if (!EVIDENCE_KINDS.has(item.kind)) throw new TypeError(`evidence.${item.id}.kind is unsupported: ${item.kind}`);
    if (!CONFIDENCE.has(item.confidence)) throw new TypeError(`evidence.${item.id}.confidence must be observed, derived, or inferred`);
    requireString(item.targetSha256, `evidence.${item.id}.targetSha256`);
    if (!/^[a-f0-9]{64}$/i.test(item.targetSha256)) {
      throw new TypeError(`evidence.${item.id}.targetSha256 must be a 64-character hexadecimal SHA-256 digest`);
    }
    if (item.targetSha256.toLowerCase() !== document.target.sha256.toLowerCase()) {
      throw new TypeError(`evidence.${item.id} belongs to a different target digest; stale or cross-target evidence is not accepted`);
    }
  }
  for (const claim of claims) {
    requireString(claim.text, `claims.${claim.id}.text`);
    const refs = requireArray(claim.evidenceIds, `claims.${claim.id}.evidenceIds`);
    if (refs.length === 0) throw new TypeError(`claims.${claim.id} must cite at least one evidence item`);
    for (const id of refs) if (!evidenceIds.has(id)) throw new TypeError(`claims.${claim.id} references missing evidence: ${id}`);
    if (claim.status && !['hypothesis', 'supported', 'verified', 'rejected'].includes(claim.status)) {
      throw new TypeError(`claims.${claim.id}.status is invalid`);
    }
  }
  for (const question of questions) {
    requireString(question.text, `questions.${question.id}.text`);
    const kinds = requireArray(question.requiredEvidenceKinds ?? [], `questions.${question.id}.requiredEvidenceKinds`);
    for (const kind of kinds) if (!EVIDENCE_KINDS.has(kind)) throw new TypeError(`questions.${question.id} has unsupported evidence kind: ${kind}`);
    if (question.priority !== undefined && (!Number.isFinite(question.priority) || question.priority < 0 || question.priority > 100)) {
      throw new TypeError(`questions.${question.id}.priority must be between 0 and 100`);
    }
  }
  for (const action of actions) {
    requireString(action.name, `actions.${action.id}.name`);
    const produces = requireArray(action.produces ?? [], `actions.${action.id}.produces`);
    for (const kind of produces) if (!EVIDENCE_KINDS.has(kind)) throw new TypeError(`actions.${action.id} produces unsupported evidence kind: ${kind}`);
    if (action.cost !== undefined && (!Number.isFinite(action.cost) || action.cost <= 0)) {
      throw new TypeError(`actions.${action.id}.cost must be a positive number`);
    }
  }
  return { ...document, evidence, claims, questions, actions };
}

/** Verify a saved investigation and optionally re-hash the current target bytes. */
export async function verifyInvestigation(input, targetPath = undefined) {
  const investigation = validateInvestigation(input);
  const result = {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    valid: true,
    evidenceCount: investigation.evidence.length,
    claimCount: investigation.claims.length,
    target: { id: investigation.target.id, expectedSha256: investigation.target.sha256 },
    targetChecked: targetPath !== undefined,
    targetMatches: null,
  };
  if (targetPath !== undefined) {
    const actual = await fingerprintTarget(targetPath);
    result.target.actualSha256 = actual.sha256;
    result.target.path = actual.path;
    result.targetMatches = actual.sha256.toLowerCase() === investigation.target.sha256.toLowerCase();
    result.valid = result.targetMatches;
    if (!result.targetMatches) result.error = 'target digest mismatch: investigation was created for different bytes';
  }
  return result;
}

/** Return claims with explicit evidence references and conservative support labels. */
export function buildEvidenceReport(input) {
  const investigation = validateInvestigation(input);
  const evidenceById = new Map(investigation.evidence.map((item) => [item.id, item]));
  const claims = investigation.claims.map((claim) => {
    const evidence = claim.evidenceIds.map((id) => evidenceById.get(id));
    const observed = evidence.some((item) => item.confidence === 'observed');
    const inferredOnly = evidence.every((item) => item.confidence === 'inferred');
    const label = claim.status === 'verified' ? 'verified' : observed ? 'evidence-backed' : inferredOnly ? 'inference-only' : 'derived-support';
    return { id: claim.id, text: claim.text, status: claim.status ?? 'hypothesis', supportLabel: label,
      evidence: evidence.map(({ id, kind, source, confidence, summary }) => ({ id, kind, source, confidence, summary })) };
  });
  return {
    schemaVersion: INVESTIGATION_SCHEMA_VERSION,
    target: investigation.target,
    summary: { evidenceCount: investigation.evidence.length, claimCount: claims.length,
      questionCount: investigation.questions.length, unresolvedQuestionCount: investigation.questions.filter((q) => !q.resolved).length },
    claims,
  };
}

/** Build a portable directed graph from target, evidence, claims, and questions. */
export function buildEvidenceGraph(input) {
  const investigation = validateInvestigation(input);
  const nodes = [{ id: `target:${investigation.target.id}`, type: 'target', label: investigation.target.id, sha256: investigation.target.sha256 }];
  const edges = [];
  for (const item of investigation.evidence) {
    const id = `evidence:${item.id}`;
    nodes.push({ id, type: 'evidence', label: item.summary, kind: item.kind, confidence: item.confidence, source: item.source });
    edges.push({ from: `target:${investigation.target.id}`, to: id, type: 'contains-evidence' });
  }
  for (const claim of investigation.claims) {
    const id = `claim:${claim.id}`;
    nodes.push({ id, type: 'claim', label: claim.text, status: claim.status ?? 'hypothesis' });
    for (const evidenceId of claim.evidenceIds) edges.push({ from: `evidence:${evidenceId}`, to: id, type: 'supports' });
  }
  for (const question of investigation.questions) {
    const id = `question:${question.id}`;
    const missing = (question.requiredEvidenceKinds ?? []).filter((kind) => !investigation.evidence.some((item) => item.kind === kind));
    nodes.push({ id, type: 'question', label: question.text, resolved: question.resolved === true, priority: question.priority ?? 50, missingEvidenceKinds: missing });
    for (const evidence of investigation.evidence) {
      if ((question.requiredEvidenceKinds ?? []).includes(evidence.kind)) {
        edges.push({ from: `evidence:${evidence.id}`, to: id, type: 'informs' });
      }
    }
  }
  return { schemaVersion: INVESTIGATION_SCHEMA_VERSION, targetSha256: investigation.target.sha256, nodes, edges };
}

/**
 * Choose a deterministic next action to address the highest-priority missing
 * evidence. This is deliberately rule-based; model-based planning can be
 * layered on top later without making budgets or provenance implicit.
 */
export function planNextAction(input, budget = {}) {
  const investigation = validateInvestigation(input);
  const maxCalls = budget.maxCalls ?? 1;
  const maxCost = budget.maxCost ?? Number.POSITIVE_INFINITY;
  if (!Number.isInteger(maxCalls) || maxCalls < 0) throw new TypeError('budget.maxCalls must be a non-negative integer');
  if (!(maxCost > 0)) throw new TypeError('budget.maxCost must be positive');
  if (maxCalls === 0) return { status: 'budget-exhausted', reason: 'maxCalls is zero', selectedAction: null, candidates: [] };

  const existingKinds = new Set(investigation.evidence.map((item) => item.kind));
  const unresolved = investigation.questions.filter((q) => !q.resolved)
    .map((q) => ({ ...q, missingKinds: (q.requiredEvidenceKinds ?? []).filter((kind) => !existingKinds.has(kind)) }))
    .filter((q) => q.missingKinds.length > 0)
    .sort((a, b) => (b.priority ?? 50) - (a.priority ?? 50) || a.id.localeCompare(b.id));

  if (unresolved.length === 0) return { status: 'no-action-needed', reason: 'No unresolved question has a missing required evidence kind.', selectedAction: null, candidates: [] };

  const topQuestion = unresolved[0];
  const candidates = investigation.actions.map((action) => {
    const produces = action.produces ?? [];
    const matches = produces.filter((kind) => topQuestion.missingKinds.includes(kind));
    const cost = action.cost ?? 1;
    return { action, matches, cost, score: matches.length * (topQuestion.priority ?? 50) / cost };
  }).filter((candidate) => candidate.matches.length > 0 && candidate.cost <= maxCost)
    .sort((a, b) => b.score - a.score || a.cost - b.cost || a.action.id.localeCompare(b.action.id));

  if (candidates.length === 0) return { status: 'blocked', reason: 'No available action can produce the missing evidence within the supplied cost budget.', questionId: topQuestion.id, missingEvidenceKinds: topQuestion.missingKinds, selectedAction: null, candidates: [] };
  const selected = candidates[0];
  return { status: 'planned', questionId: topQuestion.id, question: topQuestion.text,
    missingEvidenceKinds: topQuestion.missingKinds, selectedAction: { id: selected.action.id, name: selected.action.name,
      produces: selected.matches, estimatedCost: selected.cost, score: selected.score },
    candidates: candidates.map(({ action, matches, cost, score }) => ({ id: action.id, name: action.name, matches, estimatedCost: cost, score })) };
}


const PROVIDER_CATALOG = [
  { id: 'node', label: 'Node.js runtime', commands: ['node'], probeArgs: ['--version'], areas: ['javascript', 'electron', 'cli'] },
  { id: 'java', label: 'Java runtime', commands: ['java'], probeArgs: ['-version'], areas: ['android', 'jadx', 'ghidra'] },
  { id: 'ghidra', label: 'Ghidra headless analyzer', commands: ['analyzeHeadless'], probeArgs: ['-help'], areas: ['native-binary', 'firmware'] },
  { id: 'jadx', label: 'JADX Android decompiler', commands: ['jadx'], probeArgs: ['--version'], areas: ['android', 'dex'] },
  { id: 'adb', label: 'Android Debug Bridge', commands: ['adb'], probeArgs: ['version'], areas: ['android-runtime', 'device-analysis'] },
  { id: 'frida', label: 'Frida instrumentation', commands: ['frida', 'frida-ps'], probeArgs: ['--version'], areas: ['runtime-observation', 'instrumentation'] },
  { id: 'apktool', label: 'Apktool', commands: ['apktool'], probeArgs: ['--version'], areas: ['android', 'resources'] },
  { id: 'dotnet', label: '.NET runtime', commands: ['dotnet'], probeArgs: ['--version'], areas: ['dotnet', 'managed-binaries'] },
  { id: 'python', label: 'Python runtime', commands: ['python3', 'python'], probeArgs: ['--version'], areas: ['python', 'automation'] },
  { id: 'objdump', label: 'GNU objdump', commands: ['objdump'], probeArgs: ['--version'], areas: ['native-binary', 'disassembly'] },
  { id: 'llvm-objdump', label: 'LLVM objdump', commands: ['llvm-objdump'], probeArgs: ['--version'], areas: ['native-binary', 'disassembly'] },
  { id: 'radare2', label: 'radare2', commands: ['r2'], probeArgs: ['-v'], areas: ['native-binary', 'disassembly'] },
  { id: 'wasm-tools', label: 'WebAssembly tools', commands: ['wasm-tools'], probeArgs: ['--version'], areas: ['wasm'] },
  { id: 'docker', label: 'Docker', commands: ['docker'], probeArgs: ['--version'], areas: ['isolated-analysis', 'reproducible-environments'] },
];

/** Discover external tools from PATH without launching them. */
export async function discoverProviders(env = process.env) {
  const pathEntries = (env.PATH ?? '').split(delimiter).filter(Boolean);
  const windows = process.platform === 'win32';
  const extensions = windows ? (env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  const providers = [];
  for (const provider of PROVIDER_CATALOG) {
    const foundCommands = [];
    for (const command of provider.commands) {
      let foundPath;
      for (const directory of pathEntries) {
        for (const extension of extensions) {
          const candidate = join(directory, windows && !extname(command) ? `${command}${extension}` : command);
          try {
            await access(candidate, constants.X_OK);
            foundPath = candidate;
            break;
          } catch { /* try next PATH candidate */ }
        }
        if (foundPath) break;
      }
      if (foundPath) foundCommands.push({ command, path: foundPath });
    }
    providers.push({ ...provider, available: foundCommands.length > 0, foundCommands });
  }
  return { schemaVersion: 1, detection: 'PATH presence only; tools were not executed', providers,
    summary: { detected: providers.filter((provider) => provider.available).length, total: providers.length } };
}


/**
 * Execute a fixed, non-targeting version/help probe with strict time/output bounds.
 * This does not execute the analyzed target. The caller must explicitly opt in.
 */
export async function probeExecutable(executable, args = [], options = {}) {
  requireString(executable, 'executable');
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) throw new TypeError('args must be an array of strings');
  const timeoutMs = Math.min(10_000, Math.max(100, Number.isFinite(options.timeoutMs) ? options.timeoutMs : 3_000));
  const maxOutputBytes = Math.min(65_536, Math.max(256, Number.isInteger(options.maxOutputBytes) ? options.maxOutputBytes : 8_192));
  const startedAt = Date.now();
  return await new Promise((resolveProbe) => {
    let settled = false;
    let timedOut = false;
    let stdout = '';
    let stderr = '';
    let outputTruncated = false;
    const append = (current, chunk) => {
      const next = current + chunk.toString('utf8');
      if (Buffer.byteLength(next) > maxOutputBytes) {
        outputTruncated = true;
        return Buffer.from(next).subarray(0, maxOutputBytes).toString('utf8');
      }
      return next;
    };
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CI: '1', NO_COLOR: '1', TERM: 'dumb' },
    });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveProbe({ executable, args, durationMs: Date.now() - startedAt, ...result,
        stdout: stdout.slice(0, maxOutputBytes), stderr: stderr.slice(0, maxOutputBytes), outputTruncated });
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.once('error', (error) => finish({ status: 'error', exitCode: null, signal: null, error: error.message }));
    child.once('close', (code, signal) => finish({ status: timedOut ? 'timeout' : code === 0 ? 'ok' : 'nonzero', exitCode: code, signal,
      ...(timedOut ? { error: `probe exceeded ${timeoutMs}ms timeout` } : {}) }));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
      setTimeout(() => finish({ status: 'timeout', exitCode: null, signal: 'SIGKILL', error: `probe exceeded ${timeoutMs}ms timeout` }), 100).unref?.();
    }, timeoutMs);
    timer.unref?.();
  });
}

/** Probe discovered tools using fixed, non-targeting version/help arguments. */
export async function probeProviders(env = process.env, options = {}) {
  const discovery = await discoverProviders(env);
  const catalog = new Map(PROVIDER_CATALOG.map((provider) => [provider.id, provider]));
  const providers = [];
  for (const provider of discovery.providers) {
    const definition = catalog.get(provider.id);
    if (!provider.available) {
      providers.push({ ...provider, probe: { status: 'not-found', reason: 'No executable found on PATH' } });
      continue;
    }
    const command = provider.foundCommands[0];
    const probeArgs = definition.probeArgs ?? ['--version'];
    const probe = await probeExecutable(command.path, probeArgs, options);
    providers.push({ ...provider, probe: { ...probe, command: command.command, path: command.path } });
  }
  const statuses = providers.map((provider) => provider.probe.status);
  return {
    schemaVersion: 1,
    detection: 'Explicit bounded version/help probes; analyzed target was not supplied or executed',
    safety: { shell: false, timeoutMs: Math.min(10_000, Math.max(100, Number.isFinite(options.timeoutMs) ? options.timeoutMs : 3_000)),
      maxOutputBytes: Math.min(65_536, Math.max(256, Number.isInteger(options.maxOutputBytes) ? options.maxOutputBytes : 8_192)) },
    providers,
    summary: { total: providers.length, detected: providers.filter((provider) => provider.available).length,
      probed: providers.filter((provider) => !['not-found'].includes(provider.probe.status)).length,
      successful: statuses.filter((status) => status === 'ok').length,
      failed: statuses.filter((status) => ['error', 'nonzero', 'timeout'].includes(status)).length },
  };
}


/**
 * Run a fixed-argument static metadata inspection on a target file. Only
 * allow-listed objdump-family adapters are accepted; no shell is involved.
 * This executes the analyzer, never the target, and re-hashes the target after
 * the run to flag any unexpected byte changes.
 */
export async function analyzeTarget(targetPath, providerId, options = {}) {
  if (!['objdump', 'llvm-objdump', 'wasm-tools'].includes(providerId)) {
    throw new TypeError(`unsupported static analyzer: ${providerId}; allowed: objdump, llvm-objdump, wasm-tools`);
  }
  const before = await fingerprintTarget(targetPath);
  if (providerId === 'wasm-tools' && before.detectedFormat !== 'WebAssembly') {
    throw new TypeError(`wasm-tools validate requires a confirmed WebAssembly magic signature; detected: ${before.detectedFormat}`);
  }
  const discovery = await discoverProviders(options.env ?? process.env);
  const provider = discovery.providers.find((item) => item.id === providerId);
  if (!provider?.available) throw new Error(`provider not found on PATH: ${providerId}`);
  const command = provider.foundCommands[0];
  const args = providerId === 'wasm-tools' ? ['validate', before.path] : ['-f', '-h', '--', before.path];
  const execution = await probeExecutable(command.path, args, options);
  const after = await fingerprintTarget(before.path);
  const targetChanged = before.sha256 !== after.sha256;
  return {
    schemaVersion: 1,
    provider: { id: providerId, command: command.command, path: command.path },
    target: { path: before.path, id: before.id, sha256Before: before.sha256, sha256After: after.sha256,
      sizeBytes: before.sizeBytes, detectedFormat: before.detectedFormat },
    execution: { ...execution, command: command.command, path: command.path },
    status: targetChanged ? 'target-changed-during-analysis' : execution.status,
    outputSha256: sha256Text(`${execution.stdout}\n${execution.stderr}`),
    targetChanged,
    targetExecuted: false,
    analysisKind: providerId === 'wasm-tools' ? 'wasm-validation' : 'static-file-metadata',
    limitations: [
      'The analyzer process is bounded by wall-clock timeout and captured-output limits, but OS-level CPU/memory/filesystem sandboxing is not provided by this adapter.',
      'A nonzero analyzer exit is reported as a failure and must not be treated as successful analysis.',
      'This adapter extracts file/object metadata and section headers; it is not full disassembly or semantic analysis.',
    ],
  };
}


/** Attach a successful static-analysis result to a matching investigation. */
export function attachAnalysisEvidence(input, analysis, evidenceId) {
  const investigation = validateInvestigation(input);
  requireString(evidenceId, 'evidenceId');
  if (!analysis || analysis.status !== 'ok' || analysis.targetChanged === true) {
    throw new TypeError('only successful analysis of an unchanged target can be recorded as evidence');
  }
  if (analysis.target?.sha256After?.toLowerCase() !== investigation.target.sha256.toLowerCase()) {
    throw new TypeError('analysis target digest does not match this investigation; refusing cross-target evidence');
  }
  if (investigation.evidence.some((item) => item.id === evidenceId)) throw new TypeError(`evidence id already exists: ${evidenceId}`);
  investigation.evidence.push({
    id: evidenceId,
    kind: 'static-analysis',
    summary: `${analysis.provider.id} static file-metadata analysis succeeded; output SHA-256 ${analysis.outputSha256}`,
    source: `provider:${analysis.provider.id}; target:${analysis.target.path}; output-sha256:${analysis.outputSha256}`,
    confidence: 'observed',
    targetSha256: investigation.target.sha256,
  });
  return validateInvestigation(investigation);
}
