# Security Policy

## PTAH responsible disclosure

PTAH (بتاح) is the primary product in this repository; the REA runtime beneath it follows the same policy. Report PTAH issues privately through the repository's **Security** tab (GitHub private vulnerability reporting). Please include: the PTAH commit or package version, the command or MCP tool involved (`ptah …`, `ptah-mcp`, `ptah ui`), the operating system, whether bubblewrap/prlimit isolation was applied (`ptah isolation`), and a minimal reproduction that does **not** include proprietary targets. Remove case bundles, private keys (`ptah-case-signing.key`), and passphrases from reports.

In-scope examples: a way to make an analyzer adapter execute the analysed target; escaping the allow-listed argv or shell-free execution; bypassing checksum, signature, or history-chain validation; the loopback workbench accepting non-loopback requests; path traversal in MCP `--root` resources; passphrase or key leakage. Out of scope: vulnerabilities in third-party analyzers themselves (report those upstream), and the absence of OS isolation when `ptah isolation` reports bubblewrap unavailable — that is a documented, honestly reported limitation rather than a bypass.

Timeline: acknowledgement within 7 days, assessment within 14 days, and coordinated disclosure after a fix is published on `main`. Reporters are credited unless they ask otherwise.

## Supported versions

Security fixes are provided for the latest published version of REA. Upgrade to the latest release before reporting a problem that may already have been resolved.

## Reporting a vulnerability

Do not disclose vulnerabilities, proof-of-concept exploits, credentials,
private binaries, Hopper documents, or private Ghidra projects in a public
issue.

Use **Report a vulnerability** in the repository's **Security** tab as the preferred way to submit the report privately. If GitHub private reporting is unavailable to you, email [morluto@outlook.com](mailto:morluto@outlook.com). Do not open a public issue to request a private contact channel.

Include the affected REA version, operating system/distribution, selected
provider and version, impact, reproduction conditions, and any suggested
mitigation in the private report. Remove credentials, proprietary binaries,
Hopper documents, Ghidra project contents, socket capability tokens, and
unrelated local paths from logs or examples.

The maintainer will acknowledge the report, assess its scope, and coordinate
remediation and disclosure timing with the reporter. Please allow time for
provider-dependent behavior to be reproduced safely.

## Security boundary

REA authenticates its Hopper and Ghidra bridges with per-session random
capability tokens. POSIX uses current-user Unix sockets; Windows Ghidra uses
authenticated loopback TCP with a private NTFS runtime whose DACL admits only
the current user and SYSTEM. See [Windows Ghidra P0](docs/windows-ghidra-p0.md#private-runtime-transport-and-lifecycle).
Tokens are transferred through private session descriptors rather than process
arguments or environment variables.
This is not a sandbox and does not protect against malicious processes already
running as the same operating-system user. Opening an untrusted binary
delegates parsing and analysis to the selected local provider with that user's
permissions.

Ghidra sessions use a packaged Java `HeadlessScript`, an isolated temporary
project, and private home, cache, and runtime directories. REA imports only the
requested target, bounds startup and protocol messages, requests bounded CPU
and heap settings, and deletes the temporary project when the session closes.
These controls limit accidental persistence and resource use; they do not make
Ghidra a sandbox. REA does not open or modify user-owned Ghidra projects.

`GHIDRA_INSTALL_DIR` and optional `JAVA_HOME` identify user-managed
installations. Setup can add those values to detected client configuration only
after showing its plan and receiving approval. REA does not download, install,
upgrade, or modify Ghidra or Java.

On Linux, REA accepts release metadata only from Hopper's HTTPS endpoint, restricts package URLs to Hopper's public download origin, bounds the package size, and compares the downloaded bytes with Hopper's published checksum before requesting installation. The published SHA-1 value is a corruption check, not a modern package signature; HTTPS origin validation remains part of the trust boundary. Dependency installation is delegated without shell evaluation to `apt-get`, `dnf`, or `pacman`, directly as root or through `pkexec`. REA never invokes `sudo`.

## PTAH hardening notes

- The local workbench (`ptah ui`) requires a per-session token on every state-changing request and rejects foreign `Origin` headers, so other websites cannot drive it through the browser.
- The MCP server applies a path policy to every tool argument (credential locations refused, writes limited to PTAH-owned `.json` files, optional `--workspace` confinement); see `docs/PTAH-MCP.md`.
- Encrypted cases require a full 16-byte AES-GCM authentication tag and bounded scrypt parameters.
