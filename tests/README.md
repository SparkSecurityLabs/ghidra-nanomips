# nanoMIPS flow tests

Run with Ghidra 12.1.2 and Python 3:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC python3 tests/run_flow_tests.py
```

The runner builds this checkout, compiles its SLEIGH language in a temporary
extension directory, and checks the six instruction examples in
`flow_cases.tsv` with Ghidra's headless disassembler. Each case checks its
decoded size, mnemonic, flow type, flow target, and p-code control-flow
operation. This is an initial regression set for direct branches and returns;
it does not claim full instruction coverage.
