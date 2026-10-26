/** The default provider set; later stages add adapters here. */
import { binutilsProviders } from "./adapters/binutils.mjs";
import { jvmProviders } from "./adapters/jvm.mjs";
import { wasmProviders } from "./adapters/wasm-tool.mjs";
import { dotnetProviders } from "./adapters/dotnet.mjs";
import { firmwareProviders } from "./adapters/firmware.mjs";
import { networkProviders } from "./adapters/network.mjs";
import { radare2Providers } from "./adapters/radare2.mjs";
import { ghidraProviders } from "./adapters/ghidra.mjs";
import { licensedEngineProviders } from "./adapters/licensed-engines.mjs";
import { inspectorProviders } from "./adapters/inspectors/index.mjs";
import { CapabilityRegistry } from "./registry.mjs";

/** Every adapter PTAH ships, grouped so stages and docs can enumerate them. */
export function defaultProviders() {
  return [
    ...binutilsProviders(),
    ...jvmProviders(),
    ...wasmProviders(),
    ...dotnetProviders(),
    ...firmwareProviders(),
    ...networkProviders(),
    ...radare2Providers(),
    ...ghidraProviders(),
    ...licensedEngineProviders(),
    ...inspectorProviders(),
  ];
}

export function createDefaultRegistry() {
  const registry = new CapabilityRegistry();
  for (const provider of defaultProviders()) registry.register(provider);
  return registry;
}
