/**
 * APK signature inspector: locates the APK Signing Block before the ZIP
 * end-of-central-directory and reports which signature schemes are present
 * (v2 = 0x7109871a, v3 = 0xf05368c0, v3.1 = 0x1b93ad61, stamp = 0x6dff800d).
 * Also reports whether a v1 (JAR) signature is present. Built-in; no tool.
 */
import { Reader } from "../../bytes.mjs";
import { BuiltinInspector } from "./base.mjs";
import { parseZipEntries } from "./formats2.mjs";

const SCHEME = {
  0x7109871a: "v2",
  0xf05368c0: "v3",
  0x1b93ad61: "v3.1",
  0x6dff800d: "source-stamp",
};
const MAGIC = "APK Sig Block 42";

/** Parse the APK Signing Block; returns the scheme ids found, or null if absent. */
export function parseApkSigningBlock(bytes) {
  const eocd = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new RangeError("no ZIP end-of-central-directory");
  const cdOffset = new Reader(bytes, {
    littleEndian: true,
    offset: eocd + 16,
  }).u32();
  // The magic sits in the last 16 bytes of the block, just before the central directory.
  if (
    cdOffset < 32 ||
    bytes.toString("latin1", cdOffset - 16, cdOffset) !== MAGIC
  )
    return null;
  const r = new Reader(bytes, { littleEndian: true, offset: cdOffset - 24 });
  const blockSize = r.u64();
  const blockStart = cdOffset - 8 - blockSize;
  if (blockStart < 0)
    throw new RangeError("APK Signing Block size exceeds file");
  const scan = new Reader(bytes, {
    littleEndian: true,
    offset: blockStart + 8,
  });
  const schemes = [];
  while (scan.pos + 12 <= cdOffset - 24) {
    const pairLen = scan.u64();
    if (pairLen < 4 || scan.pos + pairLen > cdOffset - 8) break;
    const id = scan.u32();
    schemes.push({
      id: `0x${id.toString(16)}`,
      scheme: SCHEME[id] ?? "unknown",
    });
    scan.seek(scan.pos + pairLen - 4);
  }
  return { schemes, blockSize };
}

export class ApkSignatureInspector extends BuiltinInspector {
  id = "apk-signature-inspector";
  name = "PTAH APK signature inspector";
  capabilities() {
    return { formats: ["apk", "aab"], tasks: { manifest: { priority: 4 } } };
  }
  async manifest(target, context) {
    return this.inspect("manifest", target, context, (bytes) => {
      const block = parseApkSigningBlock(bytes);
      const v1 = parseZipEntries(bytes).some((e) =>
        /^META-INF\/.*\.(RSA|DSA|EC|SF)$/u.test(e.name),
      );
      const schemes = [
        ...(v1 ? [{ id: "v1", scheme: "v1" }] : []),
        ...(block?.schemes ?? []),
      ];
      return {
        summary: schemes.length
          ? `Signed with ${schemes.map((s) => s.scheme).join(", ")}`
          : "No APK signature found (unsigned)",
        data: {
          signed: schemes.length > 0,
          schemes,
          hasV1: v1,
          hasSigningBlock: block !== null,
        },
        confidence: "observed",
        limitations: [
          "Reports which signature schemes are present; it does not verify the certificate chain or that the signature is valid.",
        ],
      };
    });
  }
}

export const apkSignatureProviders = () => [new ApkSignatureInspector()];
