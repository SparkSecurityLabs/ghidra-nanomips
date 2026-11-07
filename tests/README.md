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
new or moved constructors. The 201 sampled vectors come from observed
firmware instructions; the other 52 were assembled from the SLEIGH grammar
and checked against the intended constructor. `flow_cases.tsv` adds six
target and p-code checks for direct branches and a return.

These are decoder and regression tests. A passing case does not prove that its
p-code implements the ISA correctly. Known semantic issues, including the
conditional trap and paired-word cases, need independent reference assertions
before their fixes are merged.
