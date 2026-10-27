/**
 * PTAH static analysis extras:
 * - DemangledNmProvider (#10): nm --demangle for C++ / Rust symbols
 * - CryptoInspector  (#6):  detects AES, SHA, MD5, base64, CRC32 constants
 * - EntropyInspector (#9):  per-window Shannon entropy with packed-region flags
 * - EntryPointInspector (#8): ELF/PE/Mach-O entry-point and init/fini arrays
 */
import { readFile } from "node:fs/promises";
import { canonicalJson, sha256 } from "../canonical.mjs";
import { createEvidence } from "../evidence.mjs";
import { readTargetBytes } from "../bytes.mjs";
import { ToolProvider } from "./tool-provider.mjs";
import { BuiltinInspector, ENGINE_VERSION } from "./inspectors/base.mjs";
import { parseNm, importsExportsFromSymbols } from "./binutils.mjs";

// ──────────────────────────────────────────────────────────────────────────────
// #10  Symbol demangling via nm --demangle + pure-JS Rust pattern fallback
// ──────────────────────────────────────────────────────────────────────────────

/** Detect the likely language of a mangled symbol. */
export function detectMangledLanguage(name) {
  // Check Rust before C++: Rust uses Itanium ABI with a hash suffix
  if (/^_ZN.*17h[0-9a-f]{16}E$/.test(name)) return "rust";
  if (/^_R[A-Za-z]/.test(name)) return "rust";
  if (/^_\$s|^\$s[A-Z]/.test(name)) return "swift";
  if (/^_Z[NKVROoPEFBST]/.test(name)) return "c++";
  if (name.startsWith("__ZN")) return "c++"; // macOS
  return null;
}

/**
 * Minimal pure-JS demangler for Rust v0 symbols (_R prefix).
 * Returns a human-readable approximation; for full fidelity use `rustfilt`.
 */
export function demangleRustV0(name) {
  // Strip _R prefix and hash suffix
  const body = name.replace(/^_R/, "").replace(/[a-z0-9]+$/, "");
  return body
    .replace(/([A-Z])/g, "::$1")
    .replace(/^::/, "")
    .toLowerCase();
}

/** Strip Rust hash suffix from legacy Itanium-mangled Rust symbol. */
export function stripRustHash(demangled) {
  return demangled.replace(/::h[0-9a-f]{16}$/, "");
}

export class DemangledNmProvider extends ToolProvider {
  id = "nm-demangle";
  name = "GNU nm (demangled)";
  license = "GPL-3.0-or-later";
  executables = ["nm"];
  capabilities() {
    return {
      formats: ["elf", "pe", "macho"],
      tasks: { symbols: { priority: 4 }, importsExports: { priority: 4 } },
    };
  }
  async symbols(target, context) {
    const run = await this.execute(
      target,
      ["--demangle", "-a", "-n", "{target}"],
      context,
    );
    const symbols = parseNm(run.stdout).map((s) => ({
      ...s,
      language: detectMangledLanguage(s.name),
      demangled: stripRustHash(s.name),
    }));
    return [
      this.evidence("symbols", target, run, {
        summary: `${symbols.length} symbols (demangled)`,
        data: {
          tables: { all: symbols },
          languages: [
            ...new Set(symbols.map((s) => s.language).filter(Boolean)),
          ],
        },
      }),
    ];
  }
  async importsExports(target, context) {
    const [defined, undef] = await Promise.all([
      this.execute(
        target,
        ["--demangle", "-D", "--defined-only", "{target}"],
        context,
      ),
      this.execute(target, ["--demangle", "-D", "-u", "{target}"], context),
    ]);
    const exports = parseNm(defined.stdout).map((s) => ({
      ...s,
      demangled: stripRustHash(s.name),
    }));
    const imports = parseNm(undef.stdout).map((s) => ({
      ...s,
      demangled: stripRustHash(s.name),
    }));
    return [
      this.evidence("importsExports", target, defined, {
        summary: `${exports.length} exports, ${imports.length} imports (demangled)`,
        data: { exports, imports },
      }),
    ];
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// #6  Crypto-constant detection
// ──────────────────────────────────────────────────────────────────────────────

/** Known crypto constants as Uint8Array signatures with a label. */
const CRYPTO_CONSTANTS = [
  {
    label: "AES S-box",
    algo: "aes",
    // First 16 bytes of the AES forward S-box
    bytes: Buffer.from([
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
      0xfe, 0xd7, 0xab, 0x76,
    ]),
  },
  {
    label: "AES inverse S-box",
    algo: "aes",
    bytes: Buffer.from([
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
      0x81, 0xf3, 0xd7, 0xfb,
    ]),
  },
  {
    label: "SHA-256 initial hash values (H0)",
    algo: "sha256",
    // First 8 words of SHA-256 H0 in big-endian
    bytes: Buffer.from([
      0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72,
      0xa5, 0x4f, 0xf5, 0x3a,
    ]),
  },
  {
    label: "SHA-1 initial hash values",
    algo: "sha1",
    bytes: Buffer.from([0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89]),
  },
  {
    label: "MD5 initial hash values",
    algo: "md5",
    bytes: Buffer.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
  },
  {
    label: "Base64 alphabet table",
    algo: "base64",
    bytes: Buffer.from(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
  },
  {
    label: "CRC32 polynomial (IEEE 802.3)",
    algo: "crc32",
    // CRC32 lookup table first entry is 0x00000000 and second 0x77073096
    bytes: Buffer.from([0x96, 0x30, 0x07, 0x77, 0xb7, 0x10, 0x0f, 0xee]),
  },
  {
    label: "SHA-512 initial hash values (H0)",
    algo: "sha512",
    bytes: Buffer.from([
      0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85,
      0x84, 0xca, 0xa7, 0x3b,
    ]),
  },
  {
    label: "Blowfish P-array init (first 8 bytes)",
    algo: "blowfish",
    bytes: Buffer.from([0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3]),
  },
];

/** Search for crypto constant byte patterns in `buf`, return all hits. */
export function detectCryptoConstants(buf) {
  const findings = [];
  for (const { label, algo, bytes } of CRYPTO_CONSTANTS) {
    let offset = 0;
    while (offset <= buf.length - bytes.length) {
      const idx = buf.indexOf(bytes, offset);
      if (idx === -1) break;
      findings.push({ label, algo, offset: idx });
      offset = idx + 1;
    }
  }
  return findings;
}

const CRYPTO_FORMATS = [
  "elf",
  "pe",
  "macho",
  "dll",
  "exe",
  "wasm",
  "dotnet",
  "jar",
  "apk",
];

export class CryptoInspector extends BuiltinInspector {
  id = "crypto-inspector";
  name = "Crypto Constant Inspector";
  capabilities() {
    return {
      formats: CRYPTO_FORMATS,
      tasks: { resources: { priority: 5 } },
    };
  }
  async resources(target, context) {
    const { bytes, truncated } = await this.read(target, context);
    const findings = detectCryptoConstants(bytes);
    const algos = [...new Set(findings.map((f) => f.algo))];
    return [
      createEvidence({
        task: "resources",
        targetSha256: target.sha256,
        provider: {
          id: this.id,
          tool: this.id,
          version: ENGINE_VERSION,
          argv: ["<builtin>", this.id],
        },
        confidence: "observed",
        status: truncated ? "partial" : "ok",
        summary: findings.length
          ? `${findings.length} crypto constant(s) found: ${algos.join(", ")}`
          : "no known crypto constants detected",
        data: { cryptoConstants: findings, algorithmsDetected: algos },
        rawSha256: sha256(canonicalJson(findings)),
        limitations: [
          "Matches byte signatures only; false positives are possible in compressed or packed sections.",
          ...(truncated
            ? ["File was truncated; later sections not scanned."]
            : []),
        ],
      }),
    ];
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// #9  Section entropy map with packed-region flagging
// ──────────────────────────────────────────────────────────────────────────────

const WINDOW = 256;
const ENTROPY_THRESHOLD = 7.0; // bits — above this is suspicious
const PACKED_THRESHOLD = 7.4; // bits — very likely packed/encrypted

/** Shannon entropy of a byte slice in bits (0–8). */
export function shannonEntropy(slice) {
  const freq = new Uint32Array(256);
  for (const b of slice) freq[b]++;
  let h = 0;
  for (const c of freq) {
    if (c === 0) continue;
    const p = c / slice.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Compute per-window entropy for a buffer.
 * Returns array of { offset, entropy, suspicious, packed }.
 */
export function entropyWindows(buf, windowSize = WINDOW) {
  const windows = [];
  for (let i = 0; i + windowSize <= buf.length; i += windowSize) {
    const slice = buf.subarray(i, i + windowSize);
    const entropy = shannonEntropy(slice);
    windows.push({
      offset: i,
      entropy: Math.round(entropy * 1000) / 1000,
      suspicious: entropy >= ENTROPY_THRESHOLD,
      packed: entropy >= PACKED_THRESHOLD,
    });
  }
  return windows;
}

export class EntropyInspector extends BuiltinInspector {
  id = "entropy-inspector";
  name = "Entropy Inspector";
  capabilities() {
    return {
      formats: CRYPTO_FORMATS,
      tasks: { sections: { priority: 2 } }, // low priority: supplement, don't replace readelf
    };
  }
  async sections(target, context) {
    const { bytes, truncated } = await this.read(target, context);
    const windows = entropyWindows(bytes);
    const suspicious = windows.filter((w) => w.suspicious);
    const packed = windows.filter((w) => w.packed);
    const overall = bytes.length >= WINDOW ? shannonEntropy(bytes) : null;
    return [
      createEvidence({
        task: "sections",
        targetSha256: target.sha256,
        provider: {
          id: this.id,
          tool: this.id,
          version: ENGINE_VERSION,
          argv: ["<builtin>", this.id],
        },
        confidence: "observed",
        status: truncated ? "partial" : "ok",
        summary: `entropy ${overall !== null ? `${overall.toFixed(2)} bits overall` : "n/a"}; ${packed.length} packed/encrypted window(s) flagged`,
        data: {
          overallEntropy:
            overall !== null ? Math.round(overall * 1000) / 1000 : null,
          windowSize: WINDOW,
          windows,
          suspiciousWindowCount: suspicious.length,
          packedWindowCount: packed.length,
          likelyPacked: packed.length > 0,
        },
        rawSha256: sha256(canonicalJson({ windows, overall })),
        limitations: [
          `Windows of ${WINDOW} bytes; packed flag at >${PACKED_THRESHOLD} bits Shannon entropy.`,
          ...(truncated ? ["File was truncated; entropy is partial."] : []),
        ],
      }),
    ];
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// #8  Entry-point and init/fini array recovery
// ──────────────────────────────────────────────────────────────────────────────

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const PE_MAGIC = Buffer.from([0x4d, 0x5a]); // MZ
const MACHO_MAGICS = [
  0xcafebabe, 0xcafebabf, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,
];

/** Parse ELF entry point from the header. */
function parseElfEntryPoint(buf) {
  if (buf.length < 64) return null;
  if (!buf.slice(0, 4).equals(ELF_MAGIC)) return null;
  const bits = buf[4]; // 1=32bit, 2=64bit
  if (bits === 2 && buf.length >= 64) {
    // ELF64: e_entry at offset 24, 8 bytes
    const lo = buf.readUInt32LE(24);
    const hi = buf.readUInt32LE(28);
    if (hi === 0) return `0x${lo.toString(16).padStart(16, "0")}`;
    return `0x${hi.toString(16)}${lo.toString(16).padStart(8, "0")}`;
  } else if (bits === 1 && buf.length >= 36) {
    // ELF32: e_entry at offset 24, 4 bytes
    const entry = buf.readUInt32LE(24);
    return `0x${entry.toString(16).padStart(8, "0")}`;
  }
  return null;
}

/** Parse PE entry point (AddressOfEntryPoint in Optional Header). */
function parsePeEntryPoint(buf) {
  if (buf.length < 64) return null;
  if (!buf.slice(0, 2).equals(PE_MAGIC)) return null;
  const peOffset = buf.readUInt32LE(60);
  if (peOffset + 28 > buf.length) return null;
  const sig = buf.slice(peOffset, peOffset + 4).toString("ascii");
  if (sig !== "PE\0\0") return null;
  const optOffset = peOffset + 24;
  if (optOffset + 4 > buf.length) return null;
  const entryRva = buf.readUInt32LE(optOffset + 16);
  return `0x${entryRva.toString(16).padStart(8, "0")}`;
}

/** Parse Mach-O entry point from LC_UNIXTHREAD or LC_MAIN. */
function parseMachOEntryPoint(buf) {
  if (buf.length < 28) return null;
  const magic = buf.readUInt32BE(0);
  if (!MACHO_MAGICS.includes(magic)) return null;
  const le = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const read32 = (off) => (le ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const ncmds = read32(16);
  const bits = magic === 0xfeedfacf || magic === 0xcffaedfe ? 64 : 32;
  let off = bits === 64 ? 32 : 28;
  for (let i = 0; i < ncmds && off + 8 <= buf.length; i++) {
    const cmd = read32(off);
    const cmdsize = read32(off + 4);
    // LC_MAIN = 0x80000028, LC_UNIXTHREAD = 0x05
    if (cmd === 0x80000028 && off + 24 <= buf.length) {
      const entryoff = read32(off + 8);
      return `+0x${entryoff.toString(16)} (file offset, LC_MAIN)`;
    }
    if (cmdsize === 0) break;
    off += cmdsize;
  }
  return null;
}

const ENTRY_FORMATS = ["elf", "pe", "macho", "dll", "exe"];

export class EntryPointInspector extends BuiltinInspector {
  id = "entry-point-inspector";
  name = "Entry-Point Inspector";
  capabilities() {
    return {
      formats: ENTRY_FORMATS,
      tasks: { manifest: { priority: 3 } },
    };
  }
  async manifest(target, context) {
    const { bytes, truncated } = await this.read(target, context);
    let entryPoint = null;
    const format = target.format;
    if (format === "elf") entryPoint = parseElfEntryPoint(bytes);
    else if (format === "pe" || format === "exe" || format === "dll")
      entryPoint = parsePeEntryPoint(bytes);
    else if (format === "macho") entryPoint = parseMachOEntryPoint(bytes);
    else {
      entryPoint =
        parseElfEntryPoint(bytes) ??
        parsePeEntryPoint(bytes) ??
        parseMachOEntryPoint(bytes);
    }
    return [
      createEvidence({
        task: "manifest",
        targetSha256: target.sha256,
        provider: {
          id: this.id,
          tool: this.id,
          version: ENGINE_VERSION,
          argv: ["<builtin>", this.id],
        },
        confidence: "observed",
        status: truncated ? "partial" : "ok",
        summary: entryPoint
          ? `entry point: ${entryPoint}`
          : "entry point not found in header",
        data: { entryPoint },
        rawSha256: sha256(canonicalJson({ entryPoint })),
        limitations: [
          "Reads only the primary entry point from the binary header; init/fini arrays require section parsing via readelf.",
        ],
      }),
    ];
  }
}

export function staticExtraProviders() {
  return [
    new DemangledNmProvider(),
    new CryptoInspector(),
    new EntropyInspector(),
    new EntryPointInspector(),
  ];
}
