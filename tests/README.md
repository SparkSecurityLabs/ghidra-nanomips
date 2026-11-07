# nanoMIPS instruction tests

Run with Ghidra 12.1.2 and Python 3:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC python3 tests/run_instruction_tests.py
```

Or run the same command in Docker, as GitHub Actions does:

```sh
docker build -f Dockerfile.test -t nanomips-instruction-tests .
docker run --rm nanomips-instruction-tests
```

The runner builds this checkout and compiles its SLEIGH language in an isolated
extension directory. `instruction_cases.tsv` has one byte vector for each of
the 253 top-level SLEIGH instruction constructors. The test checks the exact
constructor, size, mnemonic, and flow type; a source inventory check catches
added, removed, or reordered forms. The `constructor` IDs in the TSV files are
stable locators from the original fixture snapshot; the runner compares each
decoded instruction with the current source line at the same constructor
position, so source edits may change line numbers without changing case IDs.
The 201 sampled vectors come from observed
firmware instructions; the other 52 were assembled from the SLEIGH grammar
and checked against the intended constructor. `flow_cases.tsv` adds six
target and p-code checks for direct branches and a return. It also checks the
expected p-code branch opcode for every flow constructor.

`semantic_cases.tsv` runs one instruction at a time in Ghidra's emulator and
compares the resulting PC, registers, and memory with reference values. It
covers both outcomes of 18 conditional branches, arithmetic and bit operations,
PC-relative addresses and calls, and direct and indexed loads and stores. Rows
marked `xfail` assert a specific ISA mismatch while the relevant issue is open.
`known_issues.tsv` checks structural failures that cannot be expressed as a
successful emulator step. An unexpected pass requires reviewing and removing
the corresponding expected-failure entry.

Run `python3 tests/coverage.py` for the per-constructor depth. In the current
suite, 253 constructors have decoder checks, 190 have at least one passing
state scenario, four have an expected failing state scenario, and 59 have only
decoder or structural checks. The emulator cannot execute several custom
userops, and this suite does not validate privileged exceptions, MMU/EVA
translation, cache effects, reservation races, or every operand and mode in
the nanoMIPS ISA manual. A passing case establishes only its stated scenario.
