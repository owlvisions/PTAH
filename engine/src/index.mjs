/** Public API of the PTAH Engine. */
export { canonicalJson, sha256 } from "./canonical.mjs";
export {
  CONFIDENCE,
  STATUS,
  TASKS,
  EvidenceError,
  createEvidence,
  unavailableEvidence,
  validateEvidence,
} from "./evidence.mjs";
export { identifyTarget, checkDrift } from "./target.mjs";
export { runTool, findExecutable, toolEnvironment } from "./exec.mjs";
export {
  OWNERSHIP,
  PURPOSES,
  PolicyRefusal,
  recordAttestation,
  evaluateTarget,
} from "./policy.mjs";
export {
  AnalysisProvider,
  UnsupportedTask,
  PROVIDER_KINDS,
  contractProblems,
} from "./provider.mjs";
export { CapabilityRegistry } from "./registry.mjs";
export { createEngine, TargetDrift } from "./engine.mjs";
export { createDefaultRegistry } from "./registry-defaults.mjs";
export {
  ReadelfProvider,
  ObjdumpProvider,
  NmProvider,
  parseReadelfHeader,
  parseReadelfSections,
  parseReadelfSymbols,
  parseReadelfDynamic,
  parseObjdumpDisassembly,
  parseObjdumpSections,
  parseNm,
  importsExportsFromSymbols,
} from "./adapters/binutils.mjs";
export { defaultProviders } from "./registry-defaults.mjs";
export {
  Aapt2Provider,
  ApktoolProvider,
  JadxProvider,
  jvmProviders,
  parseBadging,
} from "./adapters/jvm.mjs";
export {
  WasmObjdumpProvider,
  wasmProviders,
  parseWasmObjdumpDetails,
  parseWasmDisassembly,
} from "./adapters/wasm-tool.mjs";
export {
  MonodisProvider,
  dotnetProviders,
  parseAssembly,
  parseTypedef,
  parseMethods,
  parseAssemblyRef,
} from "./adapters/dotnet.mjs";
export {
  BinwalkProvider,
  UnblobProvider,
  firmwareProviders,
  parseBinwalkCsv,
} from "./adapters/firmware.mjs";
export {
  TsharkProvider,
  networkProviders,
  parseTsharkFields,
} from "./adapters/network.mjs";
export {
  Radare2Provider,
  RizinProvider,
  radare2Providers,
  mapInfo,
} from "./adapters/radare2.mjs";
export { GhidraProvider, ghidraProviders } from "./adapters/ghidra.mjs";
export {
  IdaProvider,
  HopperProvider,
  JebProvider,
  KunaProvider,
  licensedEngineProviders,
} from "./adapters/licensed-engines.mjs";
export { inspectorProviders } from "./adapters/inspectors/index.mjs";
export {
  MachoInspector,
  machoProviders,
} from "./adapters/inspectors/macho.mjs";
export {
  parseGguf,
  parseSafetensors,
  parseSqlite,
  parseGodotPck,
  parseBeam,
  containerProviders,
} from "./adapters/inspectors/containers.mjs";
export {
  parseEvm,
  parseIl2cpp,
  detectToolchains,
  bytecodeProviders,
} from "./adapters/inspectors/bytecode.mjs";
export {
  scanSecrets,
  scanDependencies,
  parseDependencies,
  matchAdvisories,
  deepDiff,
  yaraScan,
  capstoneDisassemble,
  emulate,
  probeOptionalEngine,
  ADVANCED_ANALYZERS,
  detectLicenses,
  scanLicenses,
  generateCycloneDx,
  exportSbom,
  fuzzyHash,
} from "./analyzers.mjs";
export {
  capabilityMatrix,
  coverageSummary,
  renderMatrixMarkdown,
  BASELINE_FORMATS,
  BEYOND_BASELINE,
} from "./matrix.mjs";
export {
  benchmark,
  benchmarkEvidence,
  renderBenchmarkMarkdown,
} from "./benchmark.mjs";
export {
  baselineMetrics,
  compareInspections,
  renderHeadToHead,
} from "./compare-baseline.mjs";
export {
  parseZipEntries,
  parseAsar,
  parseIps,
  parsePyc,
  formats2Providers,
  ArchiveInspector,
  AsarInspector,
  IpsInspector,
  PycInspector,
} from "./adapters/inspectors/formats2.mjs";
export {
  parseApkSigningBlock,
  apkSignatureProviders,
  ApkSignatureInspector,
} from "./adapters/inspectors/apk-signature.mjs";
export {
  GdbProvider,
  gdbProviders,
  parseGdbFunctions,
  parseGdbSections,
} from "./adapters/gdb.mjs";
export {
  listAndroidDevices,
  listDevicePackages,
  planApkPull,
  parseAdbDevices,
} from "./adapters/android-device.mjs";
export {
  DemangledNmProvider,
  CryptoInspector,
  EntropyInspector,
  EntryPointInspector,
  staticExtraProviders,
  detectCryptoConstants,
  detectMangledLanguage,
  demangleRustV0,
  stripRustHash,
  shannonEntropy,
  entropyWindows,
} from "./adapters/static-extra.mjs";
export { DiskCache, attachDiskCache } from "./disk-cache.mjs";
export { renderHtmlReport, renderSarifReport } from "./report.mjs";
export { loadPlugin, loadPlugins } from "./plugin.mjs";
