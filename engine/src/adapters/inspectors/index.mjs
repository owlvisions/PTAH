/** All built-in inspectors (PTAH's own format parsers, no external tool). */
import { machoProviders } from "./macho.mjs";
import { containerProviders } from "./containers.mjs";
import { bytecodeProviders } from "./bytecode.mjs";

export function inspectorProviders() {
  return [...machoProviders(), ...containerProviders(), ...bytecodeProviders()];
}
