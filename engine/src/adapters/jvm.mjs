/**
 * Android and JVM adapters: aapt2 (manifest/badging), apktool (manifest and
 * resources), and JADX (decompilation to pseudocode). Each maps its tool's
 * output into PTAH evidence; raw trees never leave the adapter.
 */
import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { compareCodePoints } from "../canonical.mjs";
import { ToolProvider } from "./tool-provider.mjs";

const MAX_CLASS_BYTES = 512 * 1024;
const MAX_CLASSES = 4000;

/** aapt2 `dump badging`: one-line "key: a='x' b='y'" and "key:'value'" records. */
export function parseBadging(text) {
  const result = {
    permissions: [],
    features: [],
    activities: [],
    services: [],
    libraries: [],
  };
  for (const line of text.split("\n")) {
    const pkg =
      /^package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'/u.exec(
        line,
      );
    if (pkg)
      Object.assign(result, {
        package: pkg[1],
        versionCode: pkg[2],
        versionName: pkg[3],
      });
    const named = (prefix) =>
      new RegExp(`^${prefix}: name='([^']*)'`, "u").exec(line)?.[1];
    for (const [prefix, key] of [
      ["uses-permission", "permissions"],
      ["uses-feature", "features"],
      ["launchable-activity", "activities"],
    ]) {
      const value = named(prefix);
      if (value) result[key].push(value);
    }
    const sdk = /^(sdkVersion|targetSdkVersion):'([^']*)'/u.exec(line);
    if (sdk) result[sdk[1]] = sdk[2];
    const label = /^application-label:'([^']*)'/u.exec(line);
    if (label) result.label = label[1];
  }
  return result;
}

async function listFiles(dir, limit, maxBytes) {
  const files = [];
  let bytes = 0;
  const walk = async (current) => {
    for (const entry of (await readdir(current, { withFileTypes: true })).sort(
      (a, b) => compareCodePoints(a.name, b.name),
    )) {
      if (files.length >= limit || bytes >= maxBytes) return;
      const path = join(current, entry.name);
      if (entry.isDirectory()) await walk(path);
      else {
        const info = await readFile(path).catch(() => null);
        if (!info) continue;
        bytes += info.length;
        files.push({
          path: relative(dir, path),
          bytes: info.length,
          text: info.length <= MAX_CLASS_BYTES ? info.toString("utf8") : null,
        });
      }
    }
  };
  await walk(dir);
  return { files, truncated: files.length >= limit || bytes >= maxBytes };
}

export class Aapt2Provider extends ToolProvider {
  id = "aapt2";
  name = "Android Asset Packaging Tool 2";
  license = "Apache-2.0";
  executables = ["aapt2"];
  versionArgs = ["version"];
  capabilities() {
    return { formats: ["apk"], tasks: { manifest: { priority: 7 } } };
  }
  async manifest(target, context) {
    const run = await this.execute(
      target,
      ["dump", "badging", "{target}"],
      context,
    );
    const badging = parseBadging(run.stdout);
    return [
      this.evidence("manifest", target, run, {
        summary: `${badging.package ?? "unknown package"} ${badging.versionName ?? ""} (code ${badging.versionCode ?? "?"}); ${badging.permissions.length} permissions, target SDK ${badging.targetSdkVersion ?? "?"}`,
        data: badging,
      }),
    ];
  }
}

export class ApktoolProvider extends ToolProvider {
  id = "apktool";
  name = "Apktool";
  license = "Apache-2.0";
  executables = ["apktool"];
  capabilities() {
    return {
      formats: ["apk", "aab"],
      tasks: { manifest: { priority: 5 }, resources: { priority: 6 } },
    };
  }
  async #decode(target, context) {
    return this.executeToDir(
      target,
      ["d", "-q", "-f", "-o", "{outdir}", "{target}"],
      async (dir) => {
        const manifest = await readFile(
          join(dir, "AndroidManifest.xml"),
          "utf8",
        ).catch(() => null);
        const yml = await readFile(join(dir, "apktool.yml"), "utf8").catch(
          () => "",
        );
        const resources = await listFiles(
          join(dir, "res"),
          5000,
          8 * 1024 * 1024,
        ).catch(() => ({ files: [], truncated: false }));
        return { manifest, yml, resources };
      },
      { ...context, timeoutMs: context.timeoutMs ?? 120_000 },
    );
  }
  async manifest(target, context) {
    const run = await this.#decode(target, context);
    const xml = run.output.manifest ?? "";
    const permissions = [
      ...xml.matchAll(/uses-permission[^>]*android:name="([^"]*)"/gu),
    ].map((m) => m[1]);
    const activities = [
      ...xml.matchAll(/<activity[^>]*android:name="([^"]*)"/gu),
    ].map((m) => m[1]);
    const services = [
      ...xml.matchAll(/<service[^>]*android:name="([^"]*)"/gu),
    ].map((m) => m[1]);
    const exported = [
      ...xml.matchAll(
        /<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*android:name="([^"]*)"|<(activity|service|receiver|provider)[^>]*android:name="([^"]*)"[^>]*android:exported="true"/gu,
      ),
    ].map((m) => m[2] ?? m[4]);
    const pkg = /package="([^"]*)"/u.exec(xml)?.[1] ?? null;
    return [
      this.evidence("manifest", target, run, {
        summary: `${pkg ?? "unknown package"}: ${permissions.length} permissions, ${activities.length} activities, ${services.length} services, ${exported.length} exported components`,
        data: {
          package: pkg,
          manifest: xml,
          permissions,
          activities,
          services,
          exportedComponents: exported,
        },
        limitations: run.output.manifest
          ? []
          : ["apktool produced no AndroidManifest.xml."],
      }),
    ];
  }
  async resources(target, context) {
    const run = await this.#decode(target, context);
    const files = run.output.resources.files.map(({ path, bytes }) => ({
      path,
      bytes,
    }));
    return [
      this.evidence("resources", target, run, {
        summary: `${files.length} decoded resource files`,
        data: { files },
        partial: run.output.resources.truncated,
        limitations: run.output.resources.truncated
          ? ["Resource listing hit the file or byte cap and is partial."]
          : [],
      }),
    ];
  }
}

export class JadxProvider extends ToolProvider {
  id = "jadx";
  name = "JADX";
  license = "Apache-2.0";
  executables = ["jadx"];
  capabilities() {
    return {
      formats: ["apk", "aab", "dex", "jar", "java-class"],
      tasks: { decompile: { priority: 7 }, strings: { priority: 4 } },
    };
  }
  async #run(target, context) {
    return this.executeToDir(
      target,
      ["--log-level", "ERROR", "--no-res", "-d", "{outdir}", "{target}"],
      async (dir) =>
        listFiles(join(dir, "sources"), MAX_CLASSES, 32 * 1024 * 1024),
      {
        ...context,
        timeoutMs: context.timeoutMs ?? 180_000,
        maxOutputBytes: 1024 * 1024,
      },
    );
  }
  async decompile(target, context) {
    const run = await this.#run(target, context);
    const classes = run.output.files
      .filter((file) => file.path.endsWith(".java") && file.text)
      .map((file) => ({ path: file.path, bytes: file.bytes, code: file.text }));
    return [
      this.evidence("decompile", target, run, {
        summary: `Recovered ${classes.length} source files`,
        data: { language: "java", classes },
        confidence: "derived",
        partial: run.output.truncated,
        limitations: [
          "Decompiled pseudocode is a reconstruction, not the original source.",
        ],
      }),
    ];
  }
  async strings(target, context) {
    const run = await this.#run(target, context);
    const found = new Map();
    for (const file of run.output.files)
      for (const match of (file.text ?? "").matchAll(
        /"((?:[^"\\]|\\.){4,200})"/gu,
      ))
        if (!found.has(match[1]))
          found.set(match[1], { value: match[1], source: file.path });
    const strings = [...found.values()].slice(0, 20_000);
    return [
      this.evidence("strings", target, run, {
        summary: `${strings.length} distinct string literals in decompiled code`,
        data: { strings },
        confidence: "derived",
        limitations: [
          "Literals are read from decompiled code, not raw bytes; obfuscated or runtime-built strings are not captured.",
        ],
      }),
    ];
  }
}

export const jvmProviders = () => [
  new Aapt2Provider(),
  new ApktoolProvider(),
  new JadxProvider(),
];
