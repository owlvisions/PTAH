#!/usr/bin/env node
import { createPtahUiServer } from "./ptah-ui-server.mjs";

const args = process.argv.slice(2);
function option(name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] !== undefined
    ? args[index + 1]
    : fallback;
}
const port = Number(option("--port", "4177"));
const host = option("--host", "127.0.0.1");
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  process.stderr.write("PTAH UI: --port must be an integer from 0 to 65535\n");
  process.exit(1);
}
try {
  const app = await createPtahUiServer({ host });
  app.server.listen(port, host, () => {
    const address = app.server.address();
    process.stdout.write(`PTAH local UI: http://${host}:${address.port}/\n`);
    process.stdout.write(
      "Loopback only. Uploaded targets are stored in a temporary workspace and deleted when this server stops. Press Ctrl+C to stop.\n",
    );
  });
  const shutdown = async () => {
    try {
      await app.close();
      process.exit(0);
    } catch (error) {
      process.stderr.write(`PTAH UI shutdown failed: ${error.message}\n`);
      process.exit(1);
    }
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
} catch (error) {
  process.stderr.write(
    `PTAH UI failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
}
