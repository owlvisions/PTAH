/**
 * Advanced analyzers (beyond REA). These are cross-cutting: they work on raw
 * bytes, dependency manifests, or a pair of targets rather than one format's
 * tasks, so they sit beside the provider contract and each returns Evidence.
 *
 * Built-in analyzers (secrets, dependencies/CVE, deep diff) need no external
 * tool. Tool analyzers (YARA, Capstone, Unicorn) detect their tool and, when
 * absent, return `unavailable` evidence saying how to enable it rather than
 * failing. Emulation executes CPU code and is gated on explicit consent.
 */
import { readFile } from "node:fs/promises";
import { canonicalJson, sha256 } from "./canonical.mjs";
import { createEvidence } from "./evidence.mjs";
import { readTargetBytes } from "./bytes.mjs";
import { findExecutable, runTool, toolEnvironment } from "./exec.mjs";

const builtin = (argv) => ({
  id: "ptah-analyzer",
  tool: "ptah",
  version: "0.1.0",
  argv,
});

/** Secret patterns; values are never stored, only a preview + SHA-256. */
const SECRETS = [
  ["aws-access-key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu],
  ["github-token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/gu],
  ["slack-token", /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/gu],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}\b/gu],
  ["stripe-key", /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/gu],
  [
    "private-key-block",
    /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----/gu,
  ],
  [
    "jwt",
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  ],
];

function redact(value) {
  return {
    preview:
      value.length <= 8
        ? `${value.slice(0, 2)}\u2026`
        : `${value.slice(0, 4)}\u2026${value.slice(-2)}`,
    length: value.length,
    sha256: sha256(value),
  };
}

/** Scan a target for embedded secrets; emits findings with redacted values. */
export async function scanSecrets(target, context = {}) {
  const { bytes } = await readTargetBytes(target.path, context.maxBytes);
  const text = bytes.toString("latin1");
  const findings = [];
  const seen = new Set();
  for (const [type, pattern] of SECRETS)
    for (const match of text.matchAll(pattern)) {
      const masked = redact(match[0]);
      if (seen.has(masked.sha256)) continue;
      seen.add(masked.sha256);
      findings.push({ type, offset: match.index, ...masked });
    }
  return [
    createEvidence({
      task: "resources",
      targetSha256: target.sha256,
      provider: builtin(["<builtin>", "secrets"]),
      confidence: "observed",
      status: "ok",
      summary: `${findings.length} embedded secret patterns (values redacted)`,
      data: { kind: "secrets", valuesRedacted: true, findings },
      rawSha256: sha256(canonicalJson(findings)),
      limitations: [
        "Secret values are never stored; only a preview and digest are reported.",
      ],
    }),
  ];
}

/** Parse the dependency manifests PTAH understands into {ecosystem,name,version}. */
export function parseDependencies(name, text) {
  const components = [];
  if (name === "package-lock.json" || name === "package.json") {
    const doc = JSON.parse(text);
    const packages = doc.packages ?? {};
    for (const [path, info] of Object.entries(packages)) {
      if (!path || !info?.version) continue;
      components.push({
        ecosystem: "npm",
        name: path.replace(/^node_modules\//u, ""),
        version: info.version,
      });
    }
    for (const [dep, version] of Object.entries({
      ...doc.dependencies,
      ...doc.devDependencies,
    }))
      if (typeof version === "string")
        components.push({
          ecosystem: "npm",
          name: dep,
          version: version.replace(/^[^\d]*/u, ""),
        });
  } else if (name === "requirements.txt") {
    for (const line of text.split("\n")) {
      const match = /^([A-Za-z0-9_.-]+)\s*==\s*([\w.]+)/u.exec(line.trim());
      if (match)
        components.push({
          ecosystem: "pypi",
          name: match[1].toLowerCase(),
          version: match[2],
        });
    }
  } else if (name === "go.sum") {
    for (const line of text.split("\n")) {
      const match = /^(\S+)\s+v(\S+?)(?:\/go\.mod)?\s/u.exec(line);
      if (match)
        components.push({ ecosystem: "go", name: match[1], version: match[2] });
    }
  }
  const seen = new Set();
  return components.filter(
    (c) =>
      c.name &&
      !seen.has(`${c.name}@${c.version}`) &&
      seen.add(`${c.name}@${c.version}`),
  );
}

/** Match components against an offline advisory set: [{ecosystem,name,range:[lo,hi),id,severity}]. */
export function matchAdvisories(components, advisories) {
  const inRange = (v, lo, hi) =>
    compareVersions(v, lo) >= 0 && (hi === null || compareVersions(v, hi) < 0);
  const hits = [];
  for (const component of components)
    for (const advisory of advisories)
      if (
        advisory.ecosystem === component.ecosystem &&
        advisory.name === component.name &&
        inRange(component.version, advisory.range[0], advisory.range[1])
      )
        hits.push({
          ...component,
          advisory: advisory.id,
          severity: advisory.severity ?? "unknown",
        });
  return hits;
}

function compareVersions(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}

/**
 * Scan a dependency manifest for known-vulnerable versions against a
 * caller-supplied offline advisory set (no network).
 */
export async function scanDependencies(target, context = {}) {
  const text = await readFile(target.path, "utf8");
  const components = parseDependencies(target.name, text);
  const hits = matchAdvisories(components, context.advisories ?? []);
  return [
    createEvidence({
      task: "manifest",
      targetSha256: target.sha256,
      provider: builtin(["<builtin>", "dependencies"]),
      confidence: context.advisories ? "observed" : "derived",
      status: "ok",
      summary: `${components.length} dependencies; ${hits.length} match the advisory set`,
      data: { kind: "dependencies", components, vulnerabilities: hits },
      rawSha256: sha256(canonicalJson(components)),
      limitations: context.advisories
        ? []
        : [
            "No advisory set was provided; only the dependency inventory is reported, not CVEs.",
          ],
    }),
  ];
}

/** Deterministic deep diff of two targets: identity, size, and byte-window changes. */
export async function deepDiff(a, b, context = {}) {
  const [left, right] = await Promise.all([
    readTargetBytes(a.path, context.maxBytes),
    readTargetBytes(b.path, context.maxBytes),
  ]);
  const identical = a.sha256 === b.sha256;
  const window = 4096;
  const regions = [];
  if (!identical) {
    const min = Math.min(left.bytes.length, right.bytes.length);
    for (
      let offset = 0;
      offset < min && regions.length < 1000;
      offset += window
    )
      if (
        !left.bytes
          .subarray(offset, offset + window)
          .equals(right.bytes.subarray(offset, offset + window))
      )
        regions.push({ offset, length: Math.min(window, min - offset) });
  }
  return [
    createEvidence({
      task: "resources",
      targetSha256: a.sha256,
      provider: builtin(["<builtin>", "diff"]),
      confidence: "observed",
      status: "ok",
      summary: identical
        ? "Targets are byte-identical"
        : `${regions.length} differing ${window}-byte regions; sizes ${left.bytes.length} vs ${right.bytes.length}`,
      data: {
        kind: "diff",
        identical,
        other: b.sha256,
        sizes: [left.size, right.size],
        changedRegions: regions,
        tailChanged: left.bytes.length !== right.bytes.length,
      },
      rawSha256: sha256(`${a.sha256}:${b.sha256}`),
    }),
  ];
}

const SAFE_RULE_PATH = /^[\w./-]+$/u;

/** YARA scan with a caller-supplied rules file. Tool analyzer; degrades if absent. */
export async function yaraScan(target, rulesPath, context = {}) {
  const env = context.env ?? process.env;
  const yara = await findExecutable("yara", env);
  if (!yara)
    return [
      unavailable(
        target,
        "resources",
        "YARA is not installed; install yara to enable rule scanning",
      ),
    ];
  if (!SAFE_RULE_PATH.test(rulesPath))
    throw new TypeError("rules path contains unsupported characters");
  const result = await runTool(yara, ["-w", "-s", rulesPath, target.path], {
    timeoutMs: context.timeoutMs ?? 60_000,
    maxOutputBytes: 4 * 1024 * 1024,
    env: toolEnvironment(env),
  });
  if (result.code !== 0 && result.stderr.trim())
    throw new Error(`yara failed: ${result.stderr.trim().slice(0, 200)}`);
  const matches = [];
  for (const line of result.stdout.split("\n")) {
    const match = /^(\w+)\s+(\S.*)$/u.exec(line);
    if (match && !line.startsWith("0x")) matches.push({ rule: match[1] });
  }
  return [
    createEvidence({
      task: "resources",
      targetSha256: target.sha256,
      provider: {
        id: "yara",
        tool: "yara",
        version: null,
        argv: ["yara", "-w", "-s", "<rules>", "<target>"],
      },
      confidence: "observed",
      status: "ok",
      summary: `${matches.length} YARA rules matched: ${matches.map((m) => m.rule).join(", ") || "none"}`,
      data: { kind: "yara", matches },
      rawSha256: sha256(result.stdout),
    }),
  ];
}

/** Capstone disassembly of a raw byte range. Tool analyzer (python capstone). */
export async function capstoneDisassemble(target, context = {}) {
  const env = context.env ?? process.env;
  const python = await findExecutable("python3", env);
  if (!python)
    return [
      unavailable(
        target,
        "disassemble",
        "python3 is required for the Capstone analyzer",
      ),
    ];
  const arch = context.arch ?? "x86-64";
  const archMap = {
    "x86-64": "CS_ARCH_X86,CS_MODE_64",
    x86: "CS_ARCH_X86,CS_MODE_32",
    arm64: "CS_ARCH_ARM64,CS_MODE_ARM",
    arm: "CS_ARCH_ARM,CS_MODE_ARM",
  };
  if (!archMap[arch]) throw new TypeError(`unsupported arch: ${arch}`);
  const offset = context.offset ?? 0;
  const length = Math.min(context.length ?? 4096, 1024 * 1024);
  const { bytes } = await readTargetBytes(target.path, offset + length);
  const slice = bytes.subarray(offset, offset + length).toString("hex");
  const script = `import capstone,sys,json\nmd=capstone.Cs(${archMap[arch]
    .split(",")
    .map((c) => `capstone.${c}`)
    .join(
      ",",
    )})\nout=[{"a":i.address,"m":i.mnemonic,"o":i.op_str} for i in md.disasm(bytes.fromhex(sys.argv[1]),${offset})]\nprint(json.dumps(out[:20000]))`;
  const result = await runTool(python, ["-I", "-c", script, slice], {
    timeoutMs: context.timeoutMs ?? 30_000,
    maxOutputBytes: 8 * 1024 * 1024,
    env: toolEnvironment(env),
  });
  if (result.code !== 0)
    return [
      unavailable(
        target,
        "disassemble",
        `capstone unavailable: ${result.stderr.trim().slice(0, 160)}`,
      ),
    ];
  const ops = JSON.parse(result.stdout).map((i) => ({
    address: i.a,
    mnemonic: i.m,
    operands: i.o,
  }));
  return [
    createEvidence({
      task: "disassemble",
      targetSha256: target.sha256,
      provider: {
        id: "capstone",
        tool: "capstone",
        version: null,
        argv: ["capstone", arch, `<${length}B@${offset}>`],
      },
      confidence: "observed",
      status: "ok",
      summary: `${ops.length} ${arch} instructions from ${length} bytes at ${offset}`,
      data: { arch, instructions: ops },
      rawSha256: sha256(result.stdout),
    }),
  ];
}

/**
 * Bounded CPU emulation via Unicorn (python). Executes code, so it is gated on
 * context.consent === true; without it, refuses. Unicorn emulates the CPU only
 * (no OS/syscalls), within a fixed memory map and instruction budget.
 */
export async function emulate(target, context = {}) {
  if (context.consent !== true)
    return [
      unavailable(
        target,
        "disassemble",
        "emulation executes code and requires context.consent === true",
      ),
    ];
  const env = context.env ?? process.env;
  const python = await findExecutable("python3", env);
  if (!python)
    return [
      unavailable(
        target,
        "disassemble",
        "python3 with the unicorn module is required",
      ),
    ];
  const offset = context.offset ?? 0;
  const length = Math.min(context.length ?? 256, 64 * 1024);
  const steps = Math.min(context.maxInstructions ?? 1000, 1_000_000);
  const { bytes } = await readTargetBytes(target.path, offset + length);
  const code = bytes.subarray(offset, offset + length).toString("hex");
  const script = `import sys,json\nfrom unicorn import *\nfrom unicorn.x86_const import *\ncode=bytes.fromhex(sys.argv[1]);base=0x1000000\nmu=Uc(UC_ARCH_X86,UC_MODE_64);mu.mem_map(base,0x10000);mu.mem_write(base,code)\nn=[0]\ndef hook(u,a,s,d):\n n[0]+=1\n if n[0]>${steps}:u.emu_stop()\nmu.hook_add(UC_HOOK_CODE,hook)\ntry:\n mu.emu_start(base,base+len(code),count=${steps})\nexcept Exception as e:\n print(json.dumps({"steps":n[0],"stopped":str(e),"rax":mu.reg_read(UC_X86_REG_RAX)}));sys.exit(0)\nprint(json.dumps({"steps":n[0],"rax":mu.reg_read(UC_X86_REG_RAX),"rip":mu.reg_read(UC_X86_REG_RIP)-base}))`;
  const result = await runTool(python, ["-I", "-c", script, code], {
    timeoutMs: context.timeoutMs ?? 15_000,
    maxOutputBytes: 65536,
    env: toolEnvironment(env),
  });
  if (result.code !== 0)
    return [
      unavailable(
        target,
        "disassemble",
        `unicorn unavailable: ${result.stderr.trim().slice(0, 160)}`,
      ),
    ];
  const state = JSON.parse(result.stdout);
  return [
    createEvidence({
      task: "disassemble",
      targetSha256: target.sha256,
      provider: {
        id: "unicorn",
        tool: "unicorn",
        version: null,
        argv: ["unicorn", "x86-64", `<${length}B@${offset}>`],
      },
      confidence: "observed",
      status: "ok",
      summary: `Emulated ${state.steps} x86-64 instructions in an isolated CPU; rax=${state.rax}`,
      data: { kind: "emulation", ...state },
      rawSha256: sha256(result.stdout),
      limitations: [
        "CPU-only emulation (no OS or syscalls) within a fixed memory map and instruction budget.",
      ],
    }),
  ];
}

/** Detect-and-degrade adapters for engines not installed here. */
export async function probeOptionalEngine(id, context = {}) {
  const env = context.env ?? process.env;
  const commands = {
    angr: "python3",
    frida: "frida",
    diffoscope: "diffoscope",
    semgrep: "semgrep",
  };
  const path = await findExecutable(commands[id] ?? id, env);
  if (id === "angr" && path) {
    const probe = await runTool(path, ["-I", "-c", "import angr"], {
      timeoutMs: 15_000,
      env: toolEnvironment(env),
    });
    return {
      id,
      available: probe.code === 0,
      reason:
        probe.code === 0 ? null : "the angr Python module is not installed",
    };
  }
  return {
    id,
    available: Boolean(path),
    reason: path ? null : `${id} is not installed`,
  };
}

function unavailable(target, task, reason) {
  return createEvidence({
    task,
    targetSha256: target.sha256,
    provider: builtin(["<unavailable>"]),
    confidence: "inferred",
    status: "unavailable",
    summary: `Analyzer unavailable: ${reason}`,
    data: { reason },
    limitations: [
      "Absence of a result is not evidence of absence in the target.",
    ],
  });
}

/** Catalog for doctor and the capability matrix. */
export const ADVANCED_ANALYZERS = Object.freeze([
  { id: "secrets", kind: "builtin", beyondRea: false, run: scanSecrets },
  {
    id: "dependencies",
    kind: "builtin",
    beyondRea: true,
    run: scanDependencies,
  },
  { id: "diff", kind: "builtin", beyondRea: true },
  { id: "yara", kind: "tool", beyondRea: true },
  { id: "capstone", kind: "tool", beyondRea: true, run: capstoneDisassemble },
  { id: "unicorn", kind: "tool", beyondRea: true, run: emulate },
  { id: "angr", kind: "tool", beyondRea: true, optional: true },
  { id: "frida", kind: "tool", beyondRea: true, optional: true, dynamic: true },
  { id: "diffoscope", kind: "tool", beyondRea: true, optional: true },
  { id: "adb", kind: "tool", beyondRea: false, optional: true, dynamic: true },
  { id: "gdb", kind: "tool", beyondRea: false, optional: true, dynamic: true },
  { id: "cutter", kind: "tool", beyondRea: false, optional: true },
  {
    id: "sigrok-cli",
    kind: "tool",
    beyondRea: false,
    optional: true,
    dynamic: true,
  },
]);
