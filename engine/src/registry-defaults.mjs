/** The default provider set; later stages add adapters here. */
import { binutilsProviders } from "./adapters/binutils.mjs";
import { CapabilityRegistry } from "./registry.mjs";

export function createDefaultRegistry() {
  const registry = new CapabilityRegistry();
  for (const provider of binutilsProviders()) registry.register(provider);
  return registry;
}
