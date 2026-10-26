/**
 * Bounded byte reading for built-in inspectors. Targets are hostile, so every
 * read is range-checked, tables are capped, and a malformed structure yields a
 * RangeError the inspector turns into an anomaly rather than a crash.
 */
import { open, stat } from "node:fs/promises";
import { resolve } from "node:path";

export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

/** Read up to `maxBytes` of a regular file; reports if it was truncated. */
export async function readTargetBytes(filePath, maxBytes = DEFAULT_MAX_BYTES) {
  const path = resolve(filePath);
  const info = await stat(path);
  if (!info.isFile()) throw new TypeError("target must be a regular file");
  const length = Math.min(info.size, maxBytes);
  const handle = await open(path, "r");
  try {
    const bytes = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const { bytesRead } = await handle.read(bytes, read, length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    return {
      path,
      bytes: bytes.subarray(0, read),
      size: info.size,
      truncated: info.size > length,
    };
  } finally {
    await handle.close();
  }
}

/** A bounds-checked cursor over a buffer, little- or big-endian. */
export class Reader {
  constructor(bytes, { littleEndian = true, offset = 0 } = {}) {
    this.bytes = bytes;
    this.le = littleEndian;
    this.pos = offset;
  }
  get length() {
    return this.bytes.length;
  }
  remaining() {
    return this.bytes.length - this.pos;
  }
  require(width) {
    if (this.pos + width > this.bytes.length)
      throw new RangeError(
        `read of ${width} at ${this.pos} exceeds ${this.bytes.length}`,
      );
  }
  seek(pos) {
    if (pos < 0 || pos > this.bytes.length)
      throw new RangeError(`seek to ${pos} out of range`);
    this.pos = pos;
    return this;
  }
  u8() {
    this.require(1);
    return this.bytes[this.pos++];
  }
  u16() {
    this.require(2);
    const v = this.le
      ? this.bytes.readUInt16LE(this.pos)
      : this.bytes.readUInt16BE(this.pos);
    this.pos += 2;
    return v;
  }
  u32() {
    this.require(4);
    const v = this.le
      ? this.bytes.readUInt32LE(this.pos)
      : this.bytes.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }
  u64() {
    this.require(8);
    const v = this.le
      ? this.bytes.readBigUInt64LE(this.pos)
      : this.bytes.readBigUInt64BE(this.pos);
    this.pos += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER))
      throw new RangeError(`u64 at ${this.pos - 8} exceeds safe integer range`);
    return Number(v);
  }
  bytesOf(length) {
    this.require(length);
    const slice = this.bytes.subarray(this.pos, this.pos + length);
    this.pos += length;
    return slice;
  }
  ascii(length) {
    return this.bytesOf(length).toString("latin1");
  }
  /** A NUL-terminated string starting at `at` (absolute), capped at `max`. */
  cstringAt(at, max = 4096) {
    if (at < 0 || at >= this.bytes.length) return "";
    const end = this.bytes.indexOf(0, at);
    const stop = Math.min(end < 0 ? this.bytes.length : end, at + max);
    return this.bytes.toString("utf8", at, stop);
  }
}
