/**
 * .NET adapter over monodis: assembly manifest, type/method tables (as
 * symbols and exports), referenced assemblies (imports), and CIL disassembly.
 */
import { ToolProvider } from "./tool-provider.mjs";

/** monodis --assembly: an indented "Key: value" block. */
export function parseAssembly(text) {
  const info = {};
  for (const line of text.split("\n")) {
    const match = /^(Name|Version|Flags|Culture|Hash Algoritm):\s*(.*)$/u.exec(
      line.trim(),
    );
    if (match)
      info[
        match[1] === "Hash Algoritm" ? "hashAlgorithm" : match[1].toLowerCase()
      ] = match[2].trim();
  }
  return info;
}

/** monodis --typedef: "n: Namespace.Type (flist=.., flags=0x.., extends=0x..)". */
export function parseTypedef(text) {
  const types = [];
  for (const line of text.split("\n")) {
    const match =
      /^\s*\d+:\s*(\S.*?)\s*\(flist=\d+,\s*mlist=\d+,\s*flags=0x([0-9a-f]+)/u.exec(
        line,
      );
    if (match && match[1] !== "(null)")
      types.push({
        name: match[1],
        flags: Number.parseInt(match[2], 16),
        public: (Number.parseInt(match[2], 16) & 0x7) !== 0,
      });
  }
  return types;
}

/** monodis --method: methods grouped under "########## Type" headers. */
export function parseMethods(text) {
  const methods = [];
  let type = null;
  for (const line of text.split("\n")) {
    const header = /^#{3,}\s*(\S.*)$/u.exec(line);
    if (header) {
      type = header[1].trim();
      continue;
    }
    const match =
      /^\s*\d+:\s*(?:(instance|static)\s+)?(?:default\s+)?(\S.*?)\s+'?([A-Za-z_.<>][\w.<>`]*)'?\s*\(([^)]*)\)/u.exec(
        line,
      );
    if (match)
      methods.push({
        type,
        name: match[3],
        returnType: match[2],
        static: match[1] !== "instance",
        signature: `${match[3]}(${match[4].trim()})`,
      });
  }
  return methods;
}

/** monodis --assemblyref: numbered blocks with a Name line. */
export function parseAssemblyRef(text) {
  const refs = [];
  let current;
  for (const line of text.split("\n")) {
    if (/^\d+:\s*Version=/u.test(line.trim())) {
      current = { version: line.trim().replace(/^\d+:\s*Version=/u, "") };
      continue;
    }
    const name = /^Name=(.*)$/u.exec(line.trim());
    if (name && current) {
      current.name = name[1];
      refs.push(current);
      current = undefined;
    }
  }
  return refs;
}

export class MonodisProvider extends ToolProvider {
  id = "monodis";
  name = "Mono CIL Disassembler";
  license = "MIT";
  executables = ["monodis"];
  versionArgs = ["--version"];
  async isAvailable(context = {}) {
    // monodis has no --version; treat discovery on PATH as availability.
    const state = await super.isAvailable(context);
    return state.available ? { available: true, version: null } : state;
  }
  capabilities() {
    return {
      formats: ["dotnet"],
      tasks: {
        manifest: { priority: 6 },
        symbols: { priority: 6 },
        importsExports: { priority: 6 },
        disassemble: { priority: 6 },
      },
    };
  }
  async manifest(target, context) {
    const run = await this.execute(target, ["--assembly", "{target}"], context);
    const info = parseAssembly(run.stdout);
    return [
      this.evidence("manifest", target, run, {
        summary: `Assembly ${info.name ?? "?"} version ${info.version ?? "?"}`,
        data: info,
      }),
    ];
  }
  async symbols(target, context) {
    const run = await this.execute(target, ["--typedef", "{target}"], context);
    const types = parseTypedef(run.stdout);
    return [
      this.evidence("symbols", target, run, {
        summary: `${types.length} types (${types.filter((t) => t.public).length} public)`,
        data: { types },
      }),
    ];
  }
  async importsExports(target, context) {
    const refs = await this.execute(
      target,
      ["--assemblyref", "{target}"],
      context,
    );
    const typeRun = await this.execute(
      target,
      ["--typedef", "{target}"],
      context,
    );
    const imports = parseAssemblyRef(refs.stdout).map((ref) => ({
      name: ref.name,
      version: ref.version,
    }));
    const exports = parseTypedef(typeRun.stdout)
      .filter((type) => type.public)
      .map((type) => ({ name: type.name, type: "type" }));
    return [
      this.evidence(
        "importsExports",
        target,
        {
          ...refs,
          provider: {
            ...refs.provider,
            argv: [...refs.provider.argv, "&&", ...typeRun.provider.argv],
          },
        },
        {
          summary: `References ${imports.length} assemblies; exposes ${exports.length} public types`,
          data: {
            libraries: imports.map((item) => item.name),
            imports,
            exports,
          },
        },
      ),
    ];
  }
  async disassemble(target, context) {
    const methodRun = await this.execute(
      target,
      ["--method", "{target}"],
      context,
    );
    const il = await this.execute(target, ["{target}"], context);
    const methods = parseMethods(methodRun.stdout);
    return [
      this.evidence(
        "disassemble",
        target,
        {
          ...il,
          provider: {
            ...il.provider,
            argv: [...methodRun.provider.argv, "&&", ...il.provider.argv],
          },
        },
        {
          summary: `CIL for ${methods.length} methods`,
          data: {
            language: "cil",
            methods,
            listing: il.stdout.slice(0, 200_000),
          },
          confidence: "derived",
          partial: il.stdout.length > 200_000,
        },
      ),
    ];
  }
}

export const dotnetProviders = () => [new MonodisProvider()];
