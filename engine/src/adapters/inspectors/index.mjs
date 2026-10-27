/** All built-in inspectors (PTAH's own format parsers, no external tool). */
import { machoProviders } from "./macho.mjs";
import { containerProviders } from "./containers.mjs";
import { bytecodeProviders } from "./bytecode.mjs";
import { formats2Providers } from "./formats2.mjs";
import { apkSignatureProviders } from "./apk-signature.mjs";

export function inspectorProviders() {
  return [
    ...machoProviders(),
    ...containerProviders(),
    ...bytecodeProviders(),
    ...formats2Providers(),
    ...apkSignatureProviders(),
  ];
}
