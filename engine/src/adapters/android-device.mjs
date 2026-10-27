/**
 * Android device analyzer over adb. Host capability (operates on a connected
 * device, not a file), so it is a standalone analyzer, not a format provider.
 * It runs real adb commands and degrades cleanly to an empty device list when
 * none is attached. Pulling an APK is static (copies the file); nothing on the
 * device is modified.
 */
import { findExecutable, runTool, toolEnvironment } from "../exec.mjs";

const SERIAL = /^[\w.:-]{1,128}$/u;
const PACKAGE = /^[A-Za-z][\w.]{0,255}$/u;

/** `adb devices -l`: one line per attached device after the header. */
export function parseAdbDevices(text) {
  const devices = [];
  for (const line of text.split("\n").slice(1)) {
    const match =
      /^(\S+)\s+(device|offline|unauthorized|bootloader)\b(.*)$/u.exec(
        line.trim(),
      );
    if (match)
      devices.push({
        serial: match[1],
        state: match[2],
        info: match[3].trim() || null,
      });
  }
  return devices;
}

async function adb(args, env) {
  const path = await findExecutable("adb", env);
  if (!path) return { available: false };
  const result = await runTool(path, args, {
    timeoutMs: 30_000,
    maxOutputBytes: 4 * 1024 * 1024,
    env: toolEnvironment(env),
  });
  return { available: true, ...result };
}

/** List attached Android devices (real adb query; empty when none). */
export async function listAndroidDevices(context = {}) {
  const run = await adb(["devices", "-l"], context.env ?? process.env);
  if (!run.available)
    return { available: false, reason: "adb is not installed", devices: [] };
  return { available: true, devices: parseAdbDevices(run.stdout) };
}

/** Installed packages on a device, or a clear reason when none is usable. */
export async function listDevicePackages(context = {}) {
  const env = context.env ?? process.env;
  const { devices, available } = await listAndroidDevices(context);
  if (!available) return { ok: false, reason: "adb is not installed" };
  const ready = devices.find((d) => d.state === "device");
  if (!ready)
    return {
      ok: false,
      reason: devices.length
        ? "no device in the 'device' state"
        : "no device attached",
      devices,
    };
  const serial = context.serial ?? ready.serial;
  if (!SERIAL.test(serial))
    throw new TypeError("device serial contains unsupported characters");
  const run = await adb(
    ["-s", serial, "shell", "pm", "list", "packages", "-f"],
    env,
  );
  const packages = run.stdout
    .split("\n")
    .map((l) => /^package:(\S+\.apk)=([\w.]+)$/u.exec(l.trim()))
    .filter(Boolean)
    .map((m) => ({ apkPath: m[1], package: m[2] }));
  return { ok: true, serial, packages };
}

/** Which adb commands pulling a package's APK would run (planned, not executed unless apply). */
export function planApkPull(serial, pkg) {
  if (!SERIAL.test(serial))
    throw new TypeError("device serial contains unsupported characters");
  if (!PACKAGE.test(pkg))
    throw new TypeError("package name contains unsupported characters");
  return {
    pathCommand: ["adb", "-s", serial, "shell", "pm", "path", pkg],
    note: "pulling copies the APK off the device for static analysis; nothing on the device is modified",
  };
}
