# PTAH Engine benchmark

Measured on this machine: 18/18 tasks produced evidence across 6 formats in 6245 ms. Providers used: aapt2, apktool, jadx, monodis, objdump, radare2, readelf, tshark, unblob, wasm-objdump.

| Target      | Format  | Task           | Provider     | Status      | Evidence | Fallbacks | ms   |
| ----------- | ------- | -------------- | ------------ | ----------- | -------- | --------- | ---- |
| true        | elf     | manifest       | readelf      | ok          | 1        | 0         | 1146 |
| true        | elf     | sections       | readelf      | ok          | 1        | 0         | 5    |
| true        | elf     | symbols        | readelf      | ok          | 1        | 0         | 6    |
| true        | elf     | importsExports | readelf      | ok          | 1        | 0         | 4    |
| true        | elf     | strings        | radare2      | ok          | 1        | 0         | 37   |
| true        | elf     | disassemble    | objdump      | ok          | 1        | 0         | 38   |
| sample.apk  | apk     | manifest       | aapt2        | ok          | 1        | 0         | 10   |
| sample.apk  | apk     | resources      | apktool      | ok          | 1        | 0         | 2122 |
| sample.apk  | apk     | decompile      | jadx         | ok          | 1        | 0         | 1476 |
| sample.wasm | wasm    | sections       | wasm-objdump | ok          | 1        | 0         | 3    |
| sample.wasm | wasm    | importsExports | wasm-objdump | ok          | 1        | 0         | 2    |
| sample.wasm | wasm    | disassemble    | wasm-objdump | ok          | 1        | 0         | 3    |
| sample.dll  | dotnet  | manifest       | monodis      | ok          | 1        | 0         | 3    |
| sample.dll  | dotnet  | symbols        | monodis      | ok          | 1        | 0         | 3    |
| sample.dll  | dotnet  | importsExports | monodis      | ok          | 1        | 0         | 7    |
| sample.dll  | dotnet  | disassemble    | monodis      | ok          | 1        | 0         | 17   |
| sample.bin  | unknown | resources      | unblob       | ok          | 1        | 0         | 1247 |
| sample.pcap | pcap    | resources      | tshark       | ok          | 1        | 0         | 111  |
| ij.json     | unknown | manifest       | -            | unavailable | 1        | 0         | 0    |
| ij.json     | unknown | sections       | -            | unavailable | 1        | 0         | 0    |
| ij.json     | unknown | symbols        | -            | unavailable | 1        | 0         | 0    |
| ij.json     | unknown | importsExports | -            | unavailable | 1        | 0         | 0    |
| ij.json     | unknown | strings        | -            | unavailable | 1        | 0         | 0    |
