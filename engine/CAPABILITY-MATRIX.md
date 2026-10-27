# PTAH Engine capability matrix

Providers: 27 (11 tool, 7 engine, 9 builtin). Formats: 21. Advanced analyzers: 9.

The PTAH column is read from the engine's registry. The REA column marks whether REA is documented to cover that format (parity) or not (beyond REA); it is not a measurement of REA.

| Format          | Task           | PTAH providers                                       | Kinds                 | vs REA |
| --------------- | -------------- | ---------------------------------------------------- | --------------------- | ------ |
| aab             | decompile      | jeb, jadx                                            | engine, tool          | parity |
| aab             | manifest       | apktool                                              | tool                  | parity |
| aab             | resources      | apktool                                              | tool                  | parity |
| aab             | strings        | jadx                                                 | tool                  | parity |
| apk             | decompile      | jeb, jadx                                            | engine, tool          | parity |
| apk             | manifest       | aapt2, apktool                                       | tool                  | parity |
| apk             | resources      | apktool                                              | tool                  | parity |
| apk             | strings        | jadx                                                 | tool                  | parity |
| beam            | manifest       | beam-inspector                                       | builtin               | parity |
| beam            | sections       | beam-inspector                                       | builtin               | parity |
| bin             | resources      | unblob, binwalk                                      | tool                  | parity |
| dex             | decompile      | jeb, ghidra, jadx                                    | engine, tool          | parity |
| dex             | disassemble    | radare2, rizin                                       | engine                | parity |
| dex             | importsExports | radare2, rizin                                       | engine                | parity |
| dex             | manifest       | radare2, rizin                                       | engine                | parity |
| dex             | sections       | radare2, rizin                                       | engine                | parity |
| dex             | strings        | radare2, jadx, rizin                                 | engine, tool          | parity |
| dex             | symbols        | radare2, rizin, ghidra                               | engine                | parity |
| dotnet          | disassemble    | monodis                                              | tool                  | parity |
| dotnet          | importsExports | monodis                                              | tool                  | parity |
| dotnet          | manifest       | monodis                                              | tool                  | parity |
| dotnet          | symbols        | monodis                                              | tool                  | parity |
| elf             | decompile      | ida, ghidra, hopper                                  | engine                | parity |
| elf             | disassemble    | objdump, radare2, rizin                              | engine, tool          | parity |
| elf             | importsExports | readelf, radare2, nm, rizin                          | engine, tool          | parity |
| elf             | manifest       | readelf, radare2, rizin, toolchain-inspector         | builtin, engine, tool | parity |
| elf             | sections       | readelf, objdump, radare2, rizin                     | engine, tool          | parity |
| elf             | strings        | radare2, rizin                                       | engine                | parity |
| elf             | symbols        | readelf, radare2, ida, nm, rizin, ghidra, kuna       | engine, tool          | parity |
| evm             | disassemble    | evm-inspector                                        | builtin               | parity |
| evm             | manifest       | evm-inspector                                        | builtin               | parity |
| gguf            | manifest       | gguf-inspector                                       | builtin               | parity |
| godot-pck       | manifest       | godot-pck-inspector                                  | builtin               | parity |
| godot-pck       | resources      | godot-pck-inspector                                  | builtin               | parity |
| il2cpp-metadata | manifest       | il2cpp-inspector                                     | builtin               | parity |
| jar             | decompile      | jadx                                                 | tool                  | parity |
| jar             | strings        | jadx                                                 | tool                  | parity |
| java-class      | decompile      | jadx                                                 | tool                  | parity |
| java-class      | strings        | jadx                                                 | tool                  | parity |
| macho           | decompile      | ida, ghidra, hopper                                  | engine                | parity |
| macho           | disassemble    | radare2, rizin                                       | engine                | parity |
| macho           | importsExports | macho-inspector, radare2, rizin                      | builtin, engine       | parity |
| macho           | manifest       | macho-inspector, radare2, rizin, toolchain-inspector | builtin, engine       | parity |
| macho           | sections       | macho-inspector, radare2, rizin                      | builtin, engine       | parity |
| macho           | strings        | radare2, rizin                                       | engine                | parity |
| macho           | symbols        | macho-inspector, radare2, ida, rizin, ghidra, kuna   | builtin, engine       | parity |
| pcap            | resources      | tshark                                               | tool                  | parity |
| pcapng          | resources      | tshark                                               | tool                  | parity |
| pe              | decompile      | ida, ghidra, hopper                                  | engine                | parity |
| pe              | disassemble    | objdump, radare2, rizin                              | engine, tool          | parity |
| pe              | importsExports | radare2, nm, rizin                                   | engine, tool          | parity |
| pe              | manifest       | radare2, rizin, toolchain-inspector                  | builtin, engine       | parity |
| pe              | sections       | objdump, radare2, rizin                              | engine, tool          | parity |
| pe              | strings        | radare2, rizin                                       | engine                | parity |
| pe              | symbols        | radare2, ida, nm, rizin, ghidra, kuna                | engine, tool          | parity |
| safetensors     | manifest       | safetensors-inspector                                | builtin               | parity |
| sqlite          | manifest       | sqlite-inspector                                     | builtin               | parity |
| unknown         | resources      | unblob, binwalk                                      | tool                  | parity |
| wasm            | disassemble    | wasm-objdump                                         | tool                  | parity |
| wasm            | importsExports | wasm-objdump                                         | tool                  | parity |
| wasm            | sections       | wasm-objdump                                         | tool                  | parity |

## Beyond REA

- Formats PTAH adds: none
- Capabilities PTAH adds: dependencies, diff, yara, capstone, unicorn, angr, frida, diffoscope
