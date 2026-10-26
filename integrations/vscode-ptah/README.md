# PTAH Workbench — VS Code integration (skeleton)

An unpublished VS Code extension skeleton that launches the loopback-only PTAH workbench and runs `ptah fingerprint --inspect` / `ptah lint` on the active file. It spawns the PTAH CLI with fixed arguments and no shell.

Install for development: open this folder in VS Code and press F5 (Extension Development Host). Set `ptah.repositoryPath` to a PTAH checkout, or install `ptah` on PATH. Not published to the Marketplace; `package.json` and `extension.js` are validated by `npm run test:ptah`.
