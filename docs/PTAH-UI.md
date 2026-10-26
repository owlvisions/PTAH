# PTAH local GUI

Run `node scripts/ptah-ui.mjs` or `ptah ui` to start the local investigation workbench. The default address is `http://127.0.0.1:4177/`; use `--port 0` to ask the operating system for an available port. The server binds only to loopback and rejects non-loopback Host headers.

The UI can upload a target, initialize an investigation, import a checksummed case bundle after confirming the uploaded target bytes match its recorded digest, add evidence and claims, record open questions and candidate actions, run an allow-listed `objdump`/`llvm-objdump`/`wasm-tools` metadata inspection or WebAssembly validation (the latter requires a confirmed WebAssembly signature), and view reports, graphs, plans, lint findings, metrics, format details with entropy, bounded strings, and an exported investigation case bundle. Every mutation made through the workbench is appended to the investigation's hash-chained history. Invalid checksums and mismatched targets are rejected without replacing the current investigation. The UI never launches the target program. Analyzer execution is bounded by wall-clock timeout and output limits, but is not OS-sandboxed.

Uploaded files and investigation records are stored in a private temporary directory with restrictive file permissions and deleted when the server stops normally. This is a single-user, local workbench; do not expose it to a network or use it as a multi-user service. Abrupt termination may leave a temporary directory behind. The full GUI is an early utility layer, not a replacement for the legacy REA interface.

Run its integration tests with `npm run test:ptah`; tests start the server on an ephemeral loopback port and exercise upload, evidence creation, report, export, loopback binding, and upload-size limits.
