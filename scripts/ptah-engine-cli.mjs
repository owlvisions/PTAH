/**
 * `ptah engine` — reach the standalone PTAH Engine (engine/) from the CLI.
 * Subcommands: a task name (manifest/sections/symbols/importsExports/strings/
 * disassemble/decompile/resources), `matrix`, `benchmark`, `providers`,
 * `crossvalidate`. Analysis needs an attestation: --ownership and --purpose,
 * or the shorthand --i-own-this (owner + interoperability).
 */
import {
  OWNERSHIP,
  PURPOSES,
  benchmark,
  createDefaultRegistry,
  createEngine,
  renderMatrixMarkdown,
} from "../engine/src/index.mjs";

const TASKS = [
  "manifest",
  "sections",
  "symbols",
  "importsExports",
  "strings",
  "disassemble",
  "decompile",
  "resources",
];

function attestation(cli) {
  if (cli.args.includes("--i-own-this"))
    return {
      ownership: "owner",
      purpose: "interoperability",
      statement: "ptah engine --i-own-this",
    };
  const ownership = cli.option("--ownership");
  const purpose = cli.option("--purpose");
  if (!ownership || !purpose)
    throw new Error(
      `analysis needs --ownership (${OWNERSHIP.join("|")}) and --purpose (${PURPOSES.join("|")}), or --i-own-this`,
    );
  return {
    ownership,
    purpose,
    statement: cli.option("--statement") ?? "ptah engine",
  };
}

/** Run a `ptah engine` invocation. `cli` supplies option parsing and emit. */
export async function runEngineCli(cli) {
  // args[1] is the subcommand only when it is not a flag (default = analyze).
  const sub =
    cli.args[1] && !cli.args[1].startsWith("--") ? cli.args[1] : undefined;
  const registry = createDefaultRegistry();

  if (sub === "providers") {
    const { providers, routes } = await registry.probe();
    return cli.emit({
      providers: providers.map((p) => ({
        id: p.id,
        kind: p.kind,
        formats: p.formats,
        available: p.available,
        version: p.version,
      })),
      routes,
    });
  }
  if (sub === "matrix")
    return cli.emit(
      renderMatrixMarkdown(await registry.probe().then(() => registry)),
    );
  if (sub === "benchmark") {
    const target = cli.required("--target");
    const engine = createEngine({ registry });
    const report = await benchmark({
      engine,
      targets: [{ path: target }],
      attestation: attestation(cli),
    });
    return cli.emit(report);
  }

  const target = cli.required("--target");
  const engine = createEngine({ registry });
  const session = await engine.open(target, attestation(cli));
  const context = { provider: cli.option("--provider") };

  if (sub === "crossvalidate") {
    const task = cli.required("--task");
    return cli.emit(await session.crossValidate(task, context));
  }
  if (sub === undefined || sub === "analyze") {
    // Default: run the standard read-only tasks and report the best evidence each.
    const results = await session.runAll(
      cli.option("--task")
        ? [cli.option("--task")]
        : ["manifest", "sections", "symbols", "importsExports", "strings"],
      context,
    );
    return cli.emit({
      target: { ...session.target, path: undefined },
      results: Object.fromEntries(
        Object.entries(results).map(([task, r]) => [
          task,
          {
            provider: r.provider,
            status: r.evidence[0].status,
            summary: r.evidence[0].summary,
          },
        ]),
      ),
    });
  }
  if (!TASKS.includes(sub))
    throw new Error(
      `unknown engine subcommand: ${sub}. Use a task (${TASKS.join(", ")}), matrix, benchmark, providers, crossvalidate.`,
    );
  const result = await session.run(sub, context);
  cli.emit({
    provider: result.provider,
    cached: result.cached,
    attempts: result.attempts,
    evidence: result.evidence,
  });
  if (result.evidence[0].status === "unavailable") cli.exitCode?.(2);
}
