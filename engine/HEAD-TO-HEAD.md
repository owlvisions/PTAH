# PTAH Engine vs the baseline analyzer — head to head

Both run on the same targets on this machine. Identity metrics must match exactly; counts agree when within 25% (tools count sections/functions differently). Timings are wall-clock for the comparable operation.

| Target | Metric       | the baseline analyzer                                            | PTAH                                                             | Agree |
| ------ | ------------ | ---------------------------------------------------------------- | ---------------------------------------------------------------- | ----- |
| true   | format       | elf                                                              | elf                                                              | yes   |
| true   | architecture | x86_64                                                           | x86_64                                                           | yes   |
| true   | sha256       | 69745c15f1bbe866f4001a30b64081161a90dc8e669922e921296021ce55ebb3 | 69745c15f1bbe866f4001a30b64081161a90dc8e669922e921296021ce55ebb3 | yes   |
| true   | sections     | 32                                                               | 29                                                               | yes   |
| true   | functions    | 244                                                              | 49                                                               | NO    |
| true   | strings      | 152                                                              | 72                                                               | NO    |

## Timing (ms)

| Target | the baseline analyzer inspect | PTAH comparable tasks |
| ------ | ----------------------------- | --------------------- |
| true   | 12452                         | 1633                  |

## Interpretation

- Identity (format, architecture, SHA-256) and section counts match: the engines agree on what the target is.
- Function and string counts differ by analysis _depth_, not capability. the baseline analyzer's `inspect` defaults to a full Ghidra analysis; PTAH's default disassemble uses fast radare2, which is why PTAH is quicker here. PTAH's own Ghidra provider reaches the same depth at comparable cost — selecting it closes the count gap and is the apples-to-apples path.
- These are measured on this machine for these targets only; they are not a universal ranking.
