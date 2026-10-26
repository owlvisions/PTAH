/**
 * Built-in inspectors for bytecode and embedded-runtime formats: EVM runtime
 * bytecode, IL2CPP global-metadata, and a toolchain detector that identifies
 * Go, Rust, Flutter/Dart, and PyInstaller inside native containers. Written
 * from scratch; no external tool.
 */
import { Reader } from "../../bytes.mjs";
import { BuiltinInspector } from "./base.mjs";

/** Minimal EVM opcode table for the fields PTAH reports. */
const PUSH1 = 0x60;
const PUSH32 = 0x7f;

/** EVM runtime bytecode: accepts hex (with/without 0x) or raw bytes. */
export function parseEvm(bytes) {
  let code = bytes;
  const asText = bytes.toString("latin1").trim();
  if (/^(?:0x)?[0-9a-fA-F]+$/u.test(asText) && asText.length % 2 === 0)
    code = Buffer.from(asText.replace(/^0x/u, ""), "hex");
  const selectors = new Set();
  let instructions = 0;
  let truncated = false;
  for (let i = 0; i < code.length; i += 1) {
    const op = code[i];
    instructions += 1;
    if (op >= PUSH1 && op <= PUSH32) {
      const size = op - PUSH1 + 1;
      // A PUSH4 feeds the function-selector comparison in the dispatcher.
      if (size === 4 && i + 4 < code.length)
        selectors.add(code.toString("hex", i + 1, i + 5));
      i += size;
    }
    if (instructions > 2_000_000) {
      truncated = true;
      break;
    }
  }
  // Solidity appends CBOR metadata; its last 2 bytes are the CBOR length.
  let metadataLength = null;
  if (code.length > 2) {
    const declared = code.readUInt16BE(code.length - 2);
    if (declared > 0 && declared + 2 <= code.length) metadataLength = declared;
  }
  const hasMetadata =
    metadataLength !== null && code.includes(Buffer.from("solc"));
  return {
    byteLength: code.length,
    instructions,
    functionSelectors: [...selectors].sort(),
    hasMetadata,
    truncated,
  };
}

/** IL2CPP global-metadata.dat: magic 0xFAB11BAF and version. */
export function parseIl2cpp(bytes) {
  const r = new Reader(bytes, { littleEndian: true });
  if (r.u32() !== 0xfab11baf)
    throw new RangeError("not an IL2CPP global-metadata.dat");
  const version = r.u32();
  const known = [24, 27, 29, 31, 39];
  return {
    version,
    recognizedVersion: known.includes(version),
    stringLiteralOffset: r.u32(),
    stringLiteralCount: r.u32(),
  };
}

const GO_MAGIC = `${String.fromCharCode(0xff)} Go buildinf:`;
const PYINSTALLER_COOKIE = Buffer.from([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);

const TOOLCHAIN = [
  [
    "go",
    (text) => text.includes(GO_MAGIC),
    (bytes) => {
      const at = bytes.indexOf(GO_MAGIC, 0, "latin1");
      const version =
        at >= 0
          ? new Reader(bytes).cstringAt(
              bytes.indexOf(Buffer.from("go1."), at),
              64,
            )
          : null;
      return { goVersion: /go1\.[\d.]+/u.exec(version ?? "")?.[0] ?? null };
    },
  ],
  [
    "rust",
    (text) =>
      /rustc version |\/rustc\/|RUST_BACKTRACE|cargo\/registry/u.test(text),
    (bytes) => ({
      rustc:
        /rustc version ([\d.]+)/u.exec(bytes.toString("latin1"))?.[1] ?? null,
    }),
  ],
  [
    "flutter",
    (text) =>
      /libflutter|kDartVmSnapshotData|kDartIsolateSnapshotData|flutter_assets/u.test(
        text,
      ),
    () => ({ engine: "dart/flutter" }),
  ],
  [
    "pyinstaller",
    (text, bytes) =>
      bytes.includes(PYINSTALLER_COOKIE) || /\bpyi-|PyInstaller/u.test(text),
    (bytes) => ({
      python: /python(\d\.\d+)/u.exec(bytes.toString("latin1"))?.[1] ?? null,
    }),
  ],
];

/** Which toolchains a native container was built with, from embedded markers. */
export function detectToolchains(bytes) {
  const text = bytes.toString("latin1");
  const found = [];
  for (const [name, matches, extract] of TOOLCHAIN)
    if (matches(text, bytes))
      found.push({ toolchain: name, ...extract(bytes) });
  return found;
}

export class EvmInspector extends BuiltinInspector {
  id = "evm-inspector";
  name = "PTAH EVM inspector";
  capabilities() {
    return {
      formats: ["evm"],
      tasks: { manifest: { priority: 7 }, disassemble: { priority: 7 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const e = parseEvm(bytes);
      return {
        summary: `EVM bytecode: ${e.instructions} instructions, ${e.functionSelectors.length} function selectors${e.hasMetadata ? ", solc metadata" : ""}`,
        data: e,
      };
    });
  }
  async disassemble(target, context) {
    return this.inspect("disassemble", target, context, (bytes) => {
      const e = parseEvm(bytes);
      return {
        summary: `${e.instructions} EVM instructions; selectors ${e.functionSelectors.slice(0, 8).join(", ")}`,
        data: {
          functionSelectors: e.functionSelectors,
          instructionCount: e.instructions,
        },
        confidence: "derived",
      };
    });
  }
}

export class Il2cppInspector extends BuiltinInspector {
  id = "il2cpp-inspector";
  name = "PTAH IL2CPP metadata inspector";
  capabilities() {
    return {
      formats: ["il2cpp-metadata"],
      tasks: { manifest: { priority: 7 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const m = parseIl2cpp(bytes);
      return {
        summary: `IL2CPP global-metadata version ${m.version}${m.recognizedVersion ? "" : " (unrecognized)"}: ${m.stringLiteralCount} string literals`,
        data: m,
        limitations: m.recognizedVersion
          ? []
          : [
              "Metadata version is outside the set PTAH recognizes (24, 27, 29, 31, 39); offsets may differ.",
            ],
      };
    });
  }
}

export class ToolchainInspector extends BuiltinInspector {
  id = "toolchain-inspector";
  name = "PTAH toolchain detector";
  capabilities() {
    // Low manifest priority for native containers: a fallback, or selected by id.
    return {
      formats: ["elf", "pe", "macho"],
      tasks: { manifest: { priority: 1 } },
    };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const toolchains = detectToolchains(bytes);
      return {
        summary: toolchains.length
          ? `Built with: ${toolchains.map((t) => t.toolchain).join(", ")}`
          : "No Go/Rust/Flutter/PyInstaller markers found",
        data: { toolchains },
        confidence: "inferred",
        limitations: [
          "Toolchain is inferred from embedded markers, which can be stripped or spoofed.",
        ],
      };
    });
  }
}

export const bytecodeProviders = () => [
  new EvmInspector(),
  new Il2cppInspector(),
  new ToolchainInspector(),
];
