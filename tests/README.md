# nanoMIPS instruction tests

Run with Ghidra 12.1.2 and Python 3:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC python3 tests/run_instruction_tests.py
```

Or run the same command locally in Docker:

```sh
docker build -f Dockerfile.test -t nanomips-instruction-tests .
docker run --rm nanomips-instruction-tests
```

GitHub Actions runs the `test` Docker build target. Buildx caches the Ghidra
and Gradle setup layers between runs, while a unique build argument runs the
tests on every workflow execution.

The runner builds this checkout and compiles its SLEIGH language in an isolated
extension directory. `instruction_cases.tsv` has one byte vector for each of
the 259 top-level SLEIGH instruction constructors. The test checks the exact
constructor, size, mnemonic, and flow type; a source inventory check catches
added, removed, or reordered forms. The `constructor` IDs in the TSV files are
stable locators from the original fixture snapshot; the runner compares each
decoded instruction with the current source line at the same constructor
position, so source edits may change line numbers without changing case IDs.
The 201 sampled vectors come from observed
firmware instructions; the other 58 were assembled from the SLEIGH grammar
and checked against the intended constructor. `flow_cases.tsv` adds six
target and p-code checks for direct branches and a return. It also checks the
expected p-code branch opcode for every flow constructor.

`semantic_cases.tsv` runs one instruction at a time in Ghidra's emulator and
compares the resulting PC, registers, and memory with reference values. It
covers both outcomes of 18 conditional branches, arithmetic and bit operations,
PC-relative addresses and calls, and direct and indexed loads and stores. Rows
marked `xfail` assert a specific ISA mismatch while the relevant issue is open.
`sequence_cases.tsv` runs eight two-instruction paths that cover calls and
returns, both outcomes of a branch, stack save/restore, and multi-register
stores followed by loads.
`known_issues.tsv` checks structural failures that cannot be expressed as a
successful emulator step. An unexpected pass requires reviewing and removing
the corresponding expected-failure entry.

`spec_properties.py` generates deterministic ISA-based vectors for encoded
`EXTW` shift values and zero/nonzero link registers in both 32-bit `JALRC`
forms. It also relocates each fixed flow fixture three times and checks that
PC-relative targets move with the instruction. Every constructor fixture is
additionally decoded at two new addresses; those metamorphic checks require
the same size, constructor, flow category, and p-code operations, with direct
targets shifted by the address delta. The field and link expectations come
from the nanoMIPS32 ISA manual; relocation checks compare against the fixed
fixtures. `property_xfails.tsv` names current defects; the
normal test run requires their exact known-bad result and flags unexpected
passes. To see the tests fail against those defects, run with
`NANOMIPS_STRICT_PROPERTIES=1` in the environment. Remove an entry from
`property_xfails.tsv` when its implementation is fixed.
The EXTW operand property has no expected failure after the shift-field fix;
20 state scenarios also check the resulting 64-to-32-bit extraction.

For the six optional CRC32 forms, a reference callback implements the ISA's
bitwise reversed-polynomial recurrence. Six fixed cases plus 24 generated
seed/message pairs compare the emulator result with independently calculated
CRC values. This checks ordinary CRC operation when the CPU feature is
present; it does not check the absent-feature reserved-instruction exception.

The ADDIUPC vectors encode both widths from the ISA fields and check zero,
positive, negative, and boundary displacements. SDBBP tests check a debug
break marker for both widths, without modeling CP0 debug entry. RDHWR state
tests cover CPUNum, Count, and UserLocal when access is allowed; guest and
privilege checks are not modeled. SAVE/RESTORE cases also use another stack
address.

Run `python3 tests/coverage.py` for the per-constructor depth. In the current
suite, 259 constructors have decoder checks, 199 have at least one passing
fixed state scenario, four have an expected failing state scenario, and 56
have only decoder or structural checks. The emulator cannot execute several custom
userops, and this suite does not validate privileged exceptions, MMU/EVA
translation, cache effects, reservation races, or every operand and mode in
the nanoMIPS ISA manual. A passing case establishes only its stated scenario.
