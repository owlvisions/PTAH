/**
 * String- and import-derived intelligence: indicators of compromise, secret
 * detection (never echoing secret values), behavioral capability inference,
 * and a small declarative rule engine.
 *
 * Indicators and secrets are observations (the bytes are present). Capability
 * matches are inferences from names; callers must record them as `inferred`.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { extractStrings } from "./ptah-analysis.mjs";
import { analyzeStructure } from "./ptah-binary.mjs";
import { parseHexPattern, searchTarget } from "./ptah-bytes.mjs";

const MAX_STRINGS = 50_000;
const FILE_SUFFIXES =
  /\.(?:dll|exe|so|sys|ocx|dat|bin|txt|log|ini|cfg|json|xml|html?|js|css|png|jpe?g|gif|ico|h|c|cpp|cs|py|rs|go|java|class|o|a|lib|pdb|tmp|bak|zip|gz|mui|manifest)$/iu;

const INDICATORS = [
  ["url", /\b(?:https?|ftp|wss?):\/\/[^\s"'<>`{}|\\^]{3,2048}/giu],
  [
    "email",
    /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/gu,
  ],
  ["ipv4", /\b(?:\d{1,3}\.){3}\d{1,3}\b/gu],
  ["ipv6", /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/giu],
  ["domain", /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/giu],
  [
    "windows-path",
    /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/gu,
  ],
  [
    "registry-key",
    /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U))\\[^\s"']{2,512}/gu,
  ],
  [
    "unix-path",
    /(?<![\w.])\/(?:etc|usr|bin|sbin|tmp|var|home|root|proc|dev|opt|lib|Library|Applications|System)\/[\w./-]{1,512}/gu,
  ],
];

const GENERIC_TLDS = new Set(
  "com net org edu gov mil int info biz io co ai app dev xyz online site top club cloud tech me tv cc ws mobi name pro shop store live news blog space website icu vip win bid loan work click link page today world digital network email agency solutions services systems software zone onion".split(
    " ",
  ),
);
const COUNTRY_TLDS = new Set(
  "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw".split(
    " ",
  ),
);

/** A plausible registered domain: known TLD, consistent case, and a real second-level label. */
function plausibleDomain(value) {
  if (value !== value.toLowerCase() && value !== value.toUpperCase())
    return false;
  const labels = value.toLowerCase().split(".");
  const tld = labels.at(-1);
  // Compound public suffixes such as co.uk or com.au: judge the label before them.
  const compound =
    labels.length >= 3 &&
    /^(?:co|com|net|org|gov|ac|edu)$/u.test(labels.at(-2));
  const second = (compound ? labels.at(-3) : labels.at(-2)) ?? "";
  if (GENERIC_TLDS.has(tld))
    return second.length >= 1 && !/^\d+$/u.test(second);
  return COUNTRY_TLDS.has(tld) && second.length >= 3 && /[a-z]/u.test(second);
}

function acceptIndicator(type, value) {
  if (type === "ipv4")
    return (
      isIP(value) === 4 &&
      !value.startsWith("0.") &&
      value !== "255.255.255.255"
    );
  if (type === "ipv6") return isIP(value) === 6;
  if (type === "domain")
    return !FILE_SUFFIXES.test(value) && plausibleDomain(value);
  return true;
}

async function targetStrings(filePath, options = {}) {
  return extractStrings(filePath, {
    minLength: options.minLength ?? 5,
    maxResults: MAX_STRINGS,
    maxBytes: options.maxBytes ?? 64 * 1024 * 1024,
  });
}

/** Extract network, file-system, and registry indicators with their offsets. */
export async function extractIndicators(filePath, options = {}) {
  const strings = await targetStrings(filePath, options);
  const found = new Map();
  for (const item of strings.strings)
    for (const [type, pattern] of INDICATORS)
      for (const match of item.text.matchAll(pattern)) {
        const value = match[0].replace(/[.,;:)\]]+$/u, "");
        if (!acceptIndicator(type, value)) continue;
        // ".data.rel.ro" is a section name, not a domain.
        if (type === "domain" && item.text[(match.index ?? 0) - 1] === ".")
          continue;
        // "version 1.2.3.4" is a version number, not an address.
        if (
          type === "ipv4" &&
          /\b(?:version|ver|v)\s*$/iu.test(item.text.slice(0, match.index))
        )
          continue;
        // A URL's or email's host is not reported again as a bare domain.
        if (
          type === "domain" &&
          [...found.values()].some(
            (entry) =>
              (entry.type === "url" || entry.type === "email") &&
              entry.value.includes(value),
          )
        )
          continue;
        const key = `${type}:${value}`;
        if (!found.has(key)) found.set(key, { type, value, offsets: [] });
        const entry = found.get(key);
        if (entry.offsets.length < 10) entry.offsets.push(item.offset);
      }
  const indicators = [...found.values()].slice(0, options.maxResults ?? 1000);
  const counts = {};
  for (const item of indicators)
    counts[item.type] = (counts[item.type] ?? 0) + 1;
  return {
    path: strings.path,
    scannedBytes: strings.scannedBytes,
    stringsTruncated: strings.truncated,
    counts,
    indicators,
  };
}

const SECRETS = [
  ["aws-access-key-id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu],
  ["github-token", /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/gu],
  ["github-fine-grained-token", /\bgithub_pat_[A-Za-z0-9_]{60,255}\b/gu],
  ["slack-token", /\bxox[abprs]-[A-Za-z0-9-]{10,200}\b/gu],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}\b/gu],
  ["stripe-secret-key", /\b(?:sk|rk)_live_[0-9A-Za-z]{16,99}\b/gu],
  ["openai-api-key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,200}\b/gu],
  ["anthropic-api-key", /\bsk-ant-[A-Za-z0-9_-]{32,200}\b/gu],
  [
    "private-key",
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/gu,
  ],
  [
    "jwt",
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  ],
  [
    "password-assignment",
    /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["']?[^\s"']{6,128}/giu,
  ],
];

/** Mask a secret so its presence is reportable without exposing it. */
export function redact(value) {
  return {
    preview:
      value.length <= 8
        ? `${value.slice(0, 2)}…`
        : `${value.slice(0, 4)}…${value.slice(-2)}`,
    length: value.length,
    sha256: createHash("sha256").update(value).digest("hex"),
  };
}

/** Find embedded credentials; values are redacted and identified by digest only. */
export async function findSecrets(filePath, options = {}) {
  const strings = await targetStrings(filePath, options);
  const findings = [];
  const seen = new Set();
  for (const item of strings.strings)
    for (const [type, pattern] of SECRETS)
      for (const match of item.text.matchAll(pattern)) {
        const masked = redact(match[0]);
        if (seen.has(masked.sha256)) continue;
        seen.add(masked.sha256);
        findings.push({
          type,
          offset: item.offset + (match.index ?? 0),
          encoding: item.encoding,
          ...masked,
        });
      }
  return {
    path: strings.path,
    scannedBytes: strings.scannedBytes,
    count: findings.length,
    findings,
    valuesRedacted: true,
  };
}

/** Behavior catalog: API names and strings that suggest a capability. */
const CAPABILITIES = [
  {
    id: "network-communication",
    attack: "T1071",
    any: [
      /^(?:socket|connect|send|recv|WSAStartup|WSASocket\w*|getaddrinfo|gethostbyname|InternetOpen\w*|InternetConnect\w*|HttpSendRequest\w*|WinHttp\w+|curl_easy_\w+|URLDownloadToFile\w*)$/u,
    ],
  },
  {
    id: "file-download",
    attack: "T1105",
    any: [
      /^(?:URLDownloadToFile\w*|InternetReadFile|WinHttpReadData)$/u,
      /\bcurl\s+-[a-zA-Z]*o\b|\bwget\s+http/u,
    ],
  },
  {
    id: "process-execution",
    attack: "T1059",
    any: [
      /^(?:CreateProcess\w*|ShellExecute\w*|WinExec|system|popen|execve|execvp|posix_spawn\w*|fork)$/u,
      /\bcmd\.exe\s+\/c\b|\/bin\/sh\s+-c\b|powershell(?:\.exe)?\s+-/iu,
    ],
  },
  {
    id: "process-injection",
    attack: "T1055",
    all: [
      /^(?:VirtualAllocEx|NtAllocateVirtualMemory)$/u,
      /^(?:WriteProcessMemory|NtWriteVirtualMemory)$/u,
      /^(?:CreateRemoteThread\w*|NtCreateThreadEx|QueueUserAPC|SetThreadContext)$/u,
    ],
  },
  {
    id: "dynamic-api-resolution",
    attack: "T1027.007",
    all: [/^(?:LoadLibrary\w*|dlopen)$/u, /^(?:GetProcAddress|dlsym)$/u],
  },
  {
    id: "registry-persistence",
    attack: "T1547.001",
    all: [
      /^Reg(?:SetValue|CreateKey)\w*$/u,
      /\\CurrentVersion\\Run(?:Once)?\b/iu,
    ],
  },
  {
    id: "service-persistence",
    attack: "T1543.003",
    any: [
      /^(?:CreateService\w*|ChangeServiceConfig\w*)$/u,
      /\bsystemctl\s+enable\b|\/etc\/systemd\/system\//u,
    ],
  },
  {
    id: "scheduled-task",
    attack: "T1053",
    any: [/\bschtasks(?:\.exe)?\s+\/create\b/iu, /\bcrontab\b|\/etc\/cron/u],
  },
  {
    id: "anti-debugging",
    attack: "T1622",
    any: [
      /^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString\w*)$/u,
      /PTRACE_TRACEME|\/proc\/self\/status/u,
    ],
  },
  {
    id: "keylogging",
    attack: "T1056.001",
    any: [
      /^(?:SetWindowsHookEx\w*|GetAsyncKeyState|GetKeyboardState|GetRawInputData)$/u,
    ],
  },
  {
    id: "screen-capture",
    attack: "T1113",
    all: [
      /^(?:BitBlt|GetDC|GetWindowDC)$/u,
      /^(?:CreateCompatibleBitmap|GetDIBits)$/u,
    ],
  },
  {
    id: "credential-access",
    attack: "T1555",
    any: [
      /^(?:CredEnumerate\w*|CryptUnprotectData|LsaRetrievePrivateData)$/u,
      /Login Data|logins\.json|\\Microsoft\\Credentials\\/u,
    ],
  },
  {
    id: "cryptography",
    attack: "T1486",
    any: [
      /^(?:Crypt(?:Encrypt|Decrypt|GenKey|DeriveKey)|BCrypt(?:Encrypt|Decrypt|GenerateSymmetricKey)|EVP_(?:Encrypt|Decrypt|Cipher)\w*|AES_\w+)$/u,
    ],
  },
  {
    id: "privilege-adjustment",
    attack: "T1134",
    any: [
      /^(?:AdjustTokenPrivileges|OpenProcessToken|ImpersonateLoggedOnUser|setuid|setreuid)$/u,
    ],
  },
  {
    id: "file-deletion",
    attack: "T1070.004",
    any: [/^(?:DeleteFile\w*|unlink|remove)$/u],
  },
  {
    id: "system-discovery",
    attack: "T1082",
    any: [
      /^(?:GetComputerName\w*|GetSystemInfo|GetVersionEx\w*|uname|gethostname|sysctl)$/u,
    ],
  },
];

/** Infer behavioral capabilities from imports and strings; every match lists its evidence. */
export async function inferCapabilities(filePath, options = {}) {
  let imports = [];
  try {
    imports = (await analyzeStructure(filePath, options)).imports.map(
      (name) => name.split("!").at(-1).split("@")[0],
    );
  } catch {
    imports = [];
  }
  const strings = (await targetStrings(filePath, options)).strings.map((item) =>
    item.text.trim(),
  );
  const corpus = [...new Set([...imports, ...strings])];
  const capabilities = [];
  for (const rule of CAPABILITIES) {
    const patterns = rule.all ?? rule.any;
    const hits = patterns.map((pattern) =>
      corpus.filter((item) => pattern.test(item)).slice(0, 8),
    );
    const matched = rule.all
      ? hits.every((list) => list.length > 0)
      : hits.some((list) => list.length > 0);
    if (matched)
      capabilities.push({
        id: rule.id,
        attack: rule.attack,
        confidence: "inferred",
        evidence: [...new Set(hits.flat())].slice(0, 12),
      });
  }
  return {
    path: filePath,
    importsExamined: imports.length,
    stringsExamined: strings.length,
    capabilities,
    limitations: [
      "Capabilities are inferred from names present in the file, not from observed behavior; dead code, decoys, and resolved-at-runtime APIs are not distinguished.",
    ],
  };
}

function validateRule(rule, index) {
  if (!rule || typeof rule !== "object" || typeof rule.id !== "string")
    throw new TypeError(`rule ${index} needs a string id`);
  const strings = Object.entries(rule.strings ?? {});
  if (strings.length === 0 || strings.length > 64)
    throw new TypeError(`rule ${rule.id} needs 1 to 64 strings`);
  for (const [name, spec] of strings) {
    const kinds = ["text", "hex", "regex"].filter(
      (kind) => spec?.[kind] !== undefined,
    );
    if (kinds.length !== 1)
      throw new TypeError(
        `rule ${rule.id} string ${name} needs exactly one of text, hex, regex`,
      );
    if (spec.hex !== undefined) parseHexPattern(spec.hex);
    if (
      spec.regex !== undefined &&
      (typeof spec.regex !== "string" || spec.regex.length > 512)
    )
      throw new TypeError(
        `rule ${rule.id} string ${name} regex must be at most 512 characters`,
      );
  }
  const condition = rule.condition ?? "any";
  if (
    !(
      condition === "any" ||
      condition === "all" ||
      (Number.isInteger(condition) &&
        condition >= 1 &&
        condition <= strings.length)
    )
  )
    throw new TypeError(
      `rule ${rule.id} condition must be any, all, or a count`,
    );
  return { ...rule, condition, strings };
}

/**
 * Match declarative rules: `{ id, description?, strings: { name: { text | hex | regex } },
 * condition: "any" | "all" | N }`. Regexes run against extracted strings only.
 */
export async function matchRules(filePath, rulesInput, options = {}) {
  const document =
    typeof rulesInput === "string"
      ? JSON.parse(await readFile(rulesInput, "utf8"))
      : rulesInput;
  const rules = (
    Array.isArray(document) ? document : (document.rules ?? [])
  ).map(validateRule);
  // Untrusted callers (MCP) may not supply regexes: a backtracking pattern could stall the server.
  if (
    options.allowRegex === false &&
    rules.some((rule) =>
      rule.strings.some(([, spec]) => spec.regex !== undefined),
    )
  )
    throw new TypeError(
      "regex rule strings are not accepted here; use text or hex",
    );
  if (rules.length === 0 || rules.length > 500)
    throw new TypeError("provide 1 to 500 rules");
  const strings = (await targetStrings(filePath, options)).strings;
  const results = [];
  for (const rule of rules) {
    const matched = {};
    for (const [name, spec] of rule.strings) {
      if (spec.regex !== undefined) {
        const pattern = new RegExp(spec.regex, "u");
        const hit = strings.find((item) =>
          pattern.test(item.text.slice(0, 4096)),
        );
        if (hit) matched[name] = [hit.offset];
      } else {
        const search = await searchTarget(
          filePath,
          spec.hex !== undefined ? { hex: spec.hex } : { text: spec.text },
          { maxResults: 5, maxBytes: options.maxBytes },
        );
        if (search.count)
          matched[name] = search.matches.map((match) => match.offset);
      }
    }
    const count = Object.keys(matched).length;
    const required =
      rule.condition === "any"
        ? 1
        : rule.condition === "all"
          ? rule.strings.length
          : rule.condition;
    results.push({
      id: rule.id,
      description: rule.description ?? null,
      matched: count >= required,
      matchedStrings: matched,
    });
  }
  return {
    path: filePath,
    rules: results.length,
    matches: results.filter((item) => item.matched),
    results,
  };
}
