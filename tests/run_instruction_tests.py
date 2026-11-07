#!/usr/bin/env python3
"""Check every nanoMIPS instruction constructor with this checkout's language."""

import csv
import getpass
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"]).resolve()
FLOW_CASES = []
for line in (ROOT / "tests/flow_cases.tsv").read_text().splitlines():
    if line and not line.startswith("#"):
        address, encoded, mnemonic, flow, target, op = line.split()
        FLOW_CASES.append((int(address, 16), bytes.fromhex(encoded), mnemonic, flow, target, op))

with (ROOT / "tests/instruction_cases.tsv").open() as handle:
    CASES = list(csv.DictReader(handle, delimiter="\t"))
with (ROOT / "tests/semantic_cases.tsv").open() as handle:
    SEMANTIC_CASES = list(csv.DictReader(handle, delimiter="\t"))
with (ROOT / "tests/sequence_cases.tsv").open() as handle:
    SEQUENCE_CASES = list(csv.DictReader(handle, delimiter="\t"))
with (ROOT / "tests/known_issues.tsv").open() as handle:
    KNOWN_ISSUES = list(csv.DictReader(handle, delimiter="\t"))
source = []
for filename in ("nanomips.sinc", "nanomips_mt.sinc"):
    for line_number, line in enumerate((ROOT / "data/languages" / filename).read_text().splitlines(), 1):
        match = re.match(r"^:([A-Z][A-Z0-9.]*)\b", line)
        if match:
            source.append((f"{filename}:{line_number}", match.group(1)))
if [row["mnemonic"] for row in CASES] != [mnemonic for _, mnemonic in source]:
    raise SystemExit("instruction cases do not match the SLEIGH constructor inventory")


def run(command, **kwargs):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise SystemExit(result.stdout)


run([str(ROOT / "gradlew"), f"-PGHIDRA_INSTALL_DIR={GHIDRA}", "buildExtension", "--console=plain"], cwd=ROOT)
archives = list((ROOT / "dist").glob("*.zip"))
if len(archives) != 1:
    raise SystemExit(f"expected one extension archive, found {len(archives)}")

with tempfile.TemporaryDirectory(prefix="nanomips-flow-") as scratch:
    scratch = Path(scratch)
    home = scratch / "home"
    home.mkdir()
    properties = dict(line.split("=", 1) for line in (GHIDRA / "Ghidra/application.properties").read_text().splitlines() if line.startswith(("application.version=", "application.release.name=")))
    settings = home / ".config" / f"{getpass.getuser()}-ghidra" / f"ghidra_{properties['application.version']}_{properties['application.release.name']}" / "Extensions"
    settings.mkdir(parents=True)
    with zipfile.ZipFile(archives[0]) as archive:
        archive.extractall(settings)
    languages = list(settings.glob("*/data/languages/nanomips.slaspec"))
    if len(languages) != 1:
        raise SystemExit(f"expected one nanoMIPS language, found {len(languages)}")
    language = languages[0].parent
    run([str(GHIDRA / "support/sleigh"), "nanomips.slaspec", "nanomips.sla"],
        cwd=language)

    instruction_addresses = [0x2000 + 8*i for i in range(len(CASES))]
    vectors = [(address, bytes.fromhex(row["bytes"])) for address, row in zip(instruction_addresses, CASES)]
    vectors += [(address, encoded) for address, encoded, *_ in FLOW_CASES]
    vectors += [(int(row["constructor"], 0), bytes.fromhex(row["bytes"]))
                for row in SEQUENCE_CASES]
    first = min(address for address, _ in vectors)
    last = max(0x4100, *(address + len(encoded) for address, encoded in vectors))
    image = bytearray(last - first)
    for address, encoded in vectors:
        image[address - first:address - first + len(encoded)] = encoded
    binary = scratch / "instructions.bin"
    binary.write_bytes(image)
    output = scratch / "actual.tsv"
    semantic_output = scratch / "semantics.tsv"
    sequence_output = scratch / "sequences.tsv"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    run([str(GHIDRA / "support/analyzeHeadless"), str(scratch), "FlowTests",
         "-import", str(binary), "-loader", "BinaryLoader", "-loader-baseAddr", hex(first),
         "-processor", "nanomips:LE:32:default", "-noanalysis", "-scriptPath", str(ROOT / "tests"),
         "-postScript", "ProbeFlow.java", str(output), *(hex(address) for address, _ in vectors),
         "-postScript", "ProbeSemantics.java", str(ROOT / "tests/instruction_cases.tsv"),
         str(ROOT / "tests/semantic_cases.tsv"), str(semantic_output),
         "-postScript", "ProbeSemantics.java", str(ROOT / "tests/instruction_cases.tsv"),
         str(ROOT / "tests/sequence_cases.tsv"), str(sequence_output)],
        env=env)

    actual = {int(fields[0], 16): fields[1:] for fields in (row.split("\t") for row in output.read_text().splitlines())}
    failures = []
    flow_opcode = {"CONDITIONAL_JUMP": "CBRANCH", "UNCONDITIONAL_JUMP": "BRANCH",
                   "UNCONDITIONAL_CALL": "CALL", "COMPUTED_JUMP": "BRANCHIND",
                   "COMPUTED_CALL": "CALLIND"}
    exact_assembly = {"nanomips.sinc:1427": "DIV a2,a2,a6",
                      "nanomips.sinc:1437": "DIVU a1,a1,a2"}
    for address, row, (source_id, _) in zip(instruction_addresses, CASES, source):
        fields = actual.get(address, [])
        encoded = bytes.fromhex(row["bytes"])
        if len(fields) != 6:
            failures.append(f"{row['constructor']}: missing decode: {fields}")
            continue
        length, assembly, flow_type, flows, pcode, constructor = fields
        if (int(length) != len(encoded) or assembly.split()[0] != row["mnemonic"]
                or flow_type != row["flow"] or constructor != source_id
                or (row["constructor"] in exact_assembly
                    and assembly != exact_assembly[row["constructor"]])
                or (not pcode and row["mnemonic"] != "NOP")
                or (row["flow"] in flow_opcode and flow_opcode[row["flow"]] not in pcode.split(","))
                or (row["mnemonic"] in {"TEQ", "TNE"}
                    and not {"CBRANCH", "CALLOTHER"}.issubset(pcode.split(",")))
                or (row["flow"] == "TERMINATOR" and row["mnemonic"] in {"JRC", "RESTORE.JRC"}
                    and "RETURN" not in pcode.split(","))):
            failures.append(f"{row['constructor']}: {fields}")
    for address, encoded, mnemonic, flow, target, op in FLOW_CASES:
        fields = actual.get(address, [])
        if len(fields) != 6:
            failures.append(f"{address:#x}: missing decode: {fields}")
            continue
        length, assembly, flow_type, flows, pcode, constructor = fields
        wanted_target = "" if target == "-" else f"{int(target, 16):08x}"
        if (int(length) != len(encoded) or assembly.split()[0] != mnemonic
                or flow_type != flow or flows != wanted_target
                or op not in pcode.split(",")):
            failures.append(f"{address:#x}: {fields}")
    for issue in KNOWN_ISSUES:
        address = instruction_addresses[next(i for i, row in enumerate(CASES)
                                             if row["constructor"] == issue["constructor"])]
        _, assembly, _, _, pcode, _ = actual[address]
        check = issue["check"]
        observed = (len(assembly.split()) == 1 if check == "operands_missing"
                    else "CBRANCH" not in pcode.split(",") if check == "unconditional_trap"
                    else "UNIMPLEMENTED" in pcode.split(",") if check == "unimplemented"
                    else False)
        if not observed:
            failures.append(f"{issue['issue']} no longer reproduced at {issue['constructor']}")
    semantic_rows = list(csv.DictReader(semantic_output.open(), delimiter="\t"))
    sequence_rows = list(csv.DictReader(sequence_output.open(), delimiter="\t"))
    if len(semantic_rows) != len(SEMANTIC_CASES):
        failures.append("missing semantic execution results")
    if len(sequence_rows) != len(SEQUENCE_CASES):
        failures.append("missing sequence execution results")
    address_by_id = {row["constructor"]: address for address, row in zip(instruction_addresses, CASES)}
    for expected, result in zip(SEMANTIC_CASES + SEQUENCE_CASES, semantic_rows + sequence_rows):
        address = (int(expected["constructor"], 0) if expected["constructor"].startswith("0x")
                   else address_by_id[expected["constructor"]])
        fields = actual[address]
        target = fields[3]
        wanted_pc = (address + int(fields[0]) if expected["pc"] == "next"
                     else int(target, 16) if expected["pc"] == "target"
                     else int(expected["pc"], 0))
        wanted_regs = {name: int(value, 0) & 0xffffffff for name, value in
                       (entry.split("=", 1) for entry in expected["registers_out"].split(";")
                        if entry != "-")}
        got_regs = {name: int(value, 16) & 0xffffffff for name, value in
                    (entry.split("=", 1) for entry in result["registers"].split(";") if entry)}
        wanted_memory = "" if expected["memory_out"] == "-" else expected["memory_out"].lower()
        observed = (result["case"] == expected["case"] and result["ok"] == "true"
                    and int(result["pc"] or "0", 16) == wanted_pc
                    and got_regs == wanted_regs and result["memory"].lower() == wanted_memory)
        if expected["status"] == "pass" and not observed:
            failures.append(f"{expected['case']}: {result}")
        if expected["status"] == "xfail":
            current_regs = {name: int(value, 0) & 0xffffffff for name, value in
                            (entry.split("=", 1) for entry in expected["current_registers"].split(";"))}
            if (observed or result["ok"] != "true" or int(result["pc"] or "0", 16) != wanted_pc
                    or got_regs != current_regs
                    or result["memory"].lower() != expected["current_memory"].lower()):
                failures.append(f"{expected['case']}: expected known failure, got {result}")
    for failure in failures:
        print("FAIL", failure)
    print(f"{len(CASES)} constructor cases, {len(FLOW_CASES)} flow cases, "
          f"{len(SEMANTIC_CASES)} semantic scenarios, {len(SEQUENCE_CASES)} sequences, "
          f"{sum(row['status'] == 'xfail' for row in SEMANTIC_CASES)} expected value failures, "
          f"{len(KNOWN_ISSUES)} known structural failures checked; "
          f"{len(failures)} failures")
    if failures:
        raise SystemExit(1)
