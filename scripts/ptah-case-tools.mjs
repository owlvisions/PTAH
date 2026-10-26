/**
 * Portable case protection: Ed25519 signatures, passphrase encryption,
 * gzip compression, and detection helpers. Dependency-free (node:crypto, node:zlib).
 *
 * Signatures authenticate the holder of a private key, not a person's identity.
 * Encryption protects confidentiality at rest; it does not hide the case format.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  INVESTIGATION_CASE_FORMAT,
  verifyInvestigationCase,
} from "./ptah-engine.mjs";

export const ENCRYPTED_CASE_FORMAT = "ptah-encrypted-case";
export const ENCRYPTED_CASE_VERSION = 1;
const MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024;
const SCRYPT = { N: 16384, r: 8, p: 1, keyLength: 32 };

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

function signedPayload(bundle) {
  const { signature: _ignored, ...rest } = bundle;
  return Buffer.from(canonical(rest));
}

function publicKeyFingerprint(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({
    type: "spki",
    format: "der",
  });
  return createHash("sha256").update(der).digest("hex");
}

/** Generate an Ed25519 key pair as PEM strings. */
export function generateCaseKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    algorithm: "ed25519",
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeySha256: publicKeyFingerprint(
      publicKey.export({ type: "spki", format: "pem" }),
    ),
  };
}

/** Sign a verified case bundle; the checksum must already be valid. */
export function signCase(bundle, privateKeyPem) {
  const verification = verifyInvestigationCase(bundle);
  if (!verification.valid)
    throw new Error(
      "case checksum mismatch; refusing to sign a corrupt bundle",
    );
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519")
    throw new TypeError("private key must be Ed25519");
  const publicKeyPem = createPublicKey(privateKey).export({
    type: "spki",
    format: "pem",
  });
  const { signature: _previous, ...unsigned } = bundle;
  const signature = cryptoSign(null, signedPayload(unsigned), privateKey);
  return {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      publicKeySha256: publicKeyFingerprint(publicKeyPem),
      payloadSha256: bundle.integrity.payloadSha256,
      value: signature.toString("base64"),
      note: "Authenticates the holder of the signing key; it does not identify a person or organisation by itself.",
    },
  };
}

/** Verify a bundle's signature against a public key; returns a structured result rather than throwing. */
export function verifyCaseSignature(bundle, publicKeyPem = undefined) {
  const signature = bundle?.signature;
  if (!signature)
    return { present: false, verified: null, reason: "bundle is not signed" };
  if (signature.algorithm !== "ed25519")
    return {
      present: true,
      verified: false,
      reason: `unsupported signature algorithm: ${signature.algorithm}`,
    };
  if (publicKeyPem === undefined)
    return {
      present: true,
      verified: null,
      publicKeySha256: signature.publicKeySha256,
      reason: "no public key supplied; signature not checked",
    };
  let publicKey;
  try {
    publicKey = createPublicKey(publicKeyPem);
  } catch (error) {
    return {
      present: true,
      verified: false,
      reason: `invalid public key: ${error.message}`,
    };
  }
  const expectedFingerprint = publicKeyFingerprint(publicKeyPem);
  if (expectedFingerprint !== signature.publicKeySha256)
    return {
      present: true,
      verified: false,
      publicKeySha256: signature.publicKeySha256,
      reason: "signature was made with a different key",
    };
  if (signature.payloadSha256 !== bundle.integrity?.payloadSha256)
    return {
      present: true,
      verified: false,
      reason: "signed payload digest differs from bundle integrity digest",
    };
  let ok = false;
  try {
    ok = cryptoVerify(
      null,
      signedPayload(bundle),
      publicKey,
      Buffer.from(signature.value, "base64"),
    );
  } catch {
    ok = false;
  }
  return {
    present: true,
    verified: ok,
    publicKeySha256: signature.publicKeySha256,
    reason: ok
      ? "signature valid for supplied key"
      : "signature does not match bundle contents",
  };
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 8)
    throw new TypeError("passphrase must be a string of at least 8 characters");
}

/** Encrypt a case bundle with AES-256-GCM using a scrypt-derived key. */
export function encryptCase(bundle, passphrase) {
  requirePassphrase(passphrase);
  if (bundle?.format !== INVESTIGATION_CASE_FORMAT)
    throw new TypeError(
      `only ${INVESTIGATION_CASE_FORMAT} bundles can be encrypted`,
    );
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, SCRYPT.keyLength, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
  });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(bundle));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: ENCRYPTED_CASE_FORMAT,
    formatVersion: ENCRYPTED_CASE_VERSION,
    kdf: {
      name: "scrypt",
      salt: salt.toString("base64"),
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
    },
    cipher: "aes-256-gcm",
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    payloadSha256: bundle.integrity?.payloadSha256 ?? null,
    note: "Confidentiality only. Verify the decrypted bundle's checksum and signature separately.",
  };
}

/** Decrypt an encrypted case envelope; throws on wrong passphrase or tampering. */
export function decryptCase(envelope, passphrase) {
  requirePassphrase(passphrase);
  if (envelope?.format !== ENCRYPTED_CASE_FORMAT)
    throw new TypeError(`not a ${ENCRYPTED_CASE_FORMAT} envelope`);
  if (envelope.formatVersion !== ENCRYPTED_CASE_VERSION)
    throw new TypeError(
      `unsupported encrypted case version: ${envelope.formatVersion}`,
    );
  if (envelope.kdf?.name !== "scrypt" || envelope.cipher !== "aes-256-gcm")
    throw new TypeError("unsupported KDF or cipher");
  const { N, r, p } = envelope.kdf;
  // Bound every cost parameter: r and p multiply CPU time, so an unbounded
  // value in a hostile envelope would stall decryption indefinitely.
  if (
    ![N, r, p].every((v) => Number.isInteger(v) && v > 0) ||
    N > 2 ** 20 ||
    (N & (N - 1)) !== 0 ||
    r > 16 ||
    p > 4
  )
    throw new TypeError("scrypt parameters out of accepted range");
  const iv = Buffer.from(envelope.iv ?? "", "base64");
  const authTag = Buffer.from(envelope.authTag ?? "", "base64");
  // GCM accepts truncated tags unless the length is pinned; a short tag makes
  // forging a modified case feasible.
  if (iv.length !== 12 || authTag.length !== 16)
    throw new TypeError(
      "encrypted case has an invalid IV or authentication tag length",
    );
  const key = scryptSync(
    passphrase,
    Buffer.from(envelope.kdf.salt, "base64"),
    SCRYPT.keyLength,
    {
      N,
      r,
      p,
      maxmem: 256 * 1024 * 1024,
    },
  );
  const decipher = createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);
  let plaintext;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new Error("decryption failed: wrong passphrase or tampered envelope");
  }
  const bundle = JSON.parse(plaintext.toString("utf8"));
  if (bundle?.format !== INVESTIGATION_CASE_FORMAT)
    throw new Error("decrypted content is not a case bundle");
  return bundle;
}

export const isGzip = (bytes) =>
  bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;

/** Compress serialized case JSON. */
export function compressCase(bundle) {
  return gzipSync(Buffer.from(`${JSON.stringify(bundle, null, 2)}\n`), {
    level: 9,
  });
}

/** Parse case bytes that may be gzip-compressed and/or encrypted. */
export function parseCaseBytes(bytes, options = {}) {
  let data = bytes;
  let compressed = false;
  if (isGzip(bytes)) {
    data = gunzipSync(bytes, { maxOutputLength: MAX_DECOMPRESSED_BYTES });
    compressed = true;
  }
  let document = JSON.parse(data.toString("utf8"));
  let encrypted = false;
  if (document?.format === ENCRYPTED_CASE_FORMAT) {
    if (options.passphrase === undefined)
      throw new Error(
        "case is encrypted; supply a passphrase via PTAH_CASE_PASSPHRASE",
      );
    document = decryptCase(document, options.passphrase);
    encrypted = true;
  }
  return { document, compressed, encrypted };
}
