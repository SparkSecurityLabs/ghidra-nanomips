#!/usr/bin/env python3
"""List the depth of the current nanoMIPS instruction tests."""

import csv
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent
with (root / "instruction_cases.tsv").open() as handle:
    instructions = list(csv.DictReader(handle, delimiter="\t"))
with (root / "semantic_cases.tsv").open() as handle:
    scenarios = list(csv.DictReader(handle, delimiter="\t"))
with (root / "known_issues.tsv").open() as handle:
    issues = list(csv.DictReader(handle, delimiter="\t"))

counts = Counter(row["constructor"] for row in scenarios if row["status"] == "pass")
expected_failures = Counter(row["constructor"] for row in scenarios if row["status"] == "xfail")
known = {}
for row in issues:
    known.setdefault(row["constructor"], set()).add(row["issue"])

print("constructor\tmnemonic\tdecode\tpassing_scenarios\texpected_failures\tknown_issues")
for row in instructions:
    name = row["constructor"]
    print(f"{name}\t{row['mnemonic']}\tyes\t{counts[name]}\t"
          f"{expected_failures[name]}\t{','.join(sorted(known.get(name, set())))}")
