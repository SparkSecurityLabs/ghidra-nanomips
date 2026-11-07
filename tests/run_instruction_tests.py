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
from spec_properties import (addiupc_scenarios, branch_offset_scenarios,
                             cases as property_cases, crc32_scenarios,
                             extw_scenarios,
                             register_scenarios, rotate_scenarios, rotx_scenarios,
                             relocated_decodes, relocated_flows)


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
SEMANTIC_CASES += list(crc32_scenarios())
SEMANTIC_CASES += list(register_scenarios())
with (ROOT / "tests/sequence_cases.tsv").open() as handle:
    SEQUENCE_CASES = list(csv.DictReader(handle, delimiter="\t"))
with (ROOT / "tests/known_issues.tsv").open() as handle:
    KNOWN_ISSUES = list(csv.DictReader(handle, delimiter="\t"))
with (ROOT / "tests/property_xfails.tsv").open() as handle:
    PROPERTY_XFAILS = {row["property"]: row for row in csv.DictReader(handle, delimiter="\t")}
PROPERTY_CASES = (property_cases() + relocated_flows(FLOW_CASES)
                  + relocated_decodes(CASES) + list(branch_offset_scenarios(CASES)))
ROTX_CASES = list(rotx_scenarios())
ROTX_ADDRESSES = [0x8000 + 8*i for i in range(len(ROTX_CASES))]
ROTATE_CASES = list(rotate_scenarios())
ROTATE_ADDRESSES = [0x8100 + 8*i for i in range(len(ROTATE_CASES))]
ADDIUPC_CASES = list(addiupc_scenarios())
ADDIUPC_ADDRESSES = [0x9000 + 8*i for i in range(len(ADDIUPC_CASES))]
EXTW_STATE_CASES = list(extw_scenarios())
EXTW_STATE_ADDRESSES = [0x9100 + 8*i for i in range(len(EXTW_STATE_CASES))]
SEMANTIC_CASES += [
    {"case": f"rotx_{shift}_{shiftx}_{stripe}_{index}",
     "constructor": hex(address), "registers_in": f"t0={value:#x}",
     "registers_out": f"a0={expected:#x}", "pc": "next",
     "memory_in": "-", "memory_out": "-", "status": "pass",
     "current_registers": "-", "current_memory": "-"}
    for index, (address, (_, value, expected, (shift, shiftx, stripe)))
    in enumerate(zip(ROTX_ADDRESSES, ROTX_CASES))]
SEMANTIC_CASES += [
    {"case": f"{mnemonic.lower()}_{amount}_{index}", "constructor": hex(address),
     "registers_in": registers_in, "registers_out": registers_out, "pc": "next",
     "memory_in": "-", "memory_out": "-", "status": "pass",
     "current_registers": "-", "current_memory": "-"}
    for index, (address, (_, mnemonic, registers_in, registers_out, amount))
    in enumerate(zip(ROTATE_ADDRESSES, ROTATE_CASES))]
SEMANTIC_CASES += [
    {"case": f"addiupc_{bits}_{offset}", "constructor": hex(address),
     "registers_in": "-", "registers_out": f"a2={(address + bits // 8 + offset) & 0xffffffff:#x}",
     "pc": "next", "memory_in": "-", "memory_out": "-", "status": "pass",
     "current_registers": "-", "current_memory": "-"}
    for address, (bits, offset, _) in zip(ADDIUPC_ADDRESSES, ADDIUPC_CASES)]
SEMANTIC_CASES += [
    {"case": f"extw_state_{shift}_{index}", "constructor": hex(address),
     "registers_in": f"a1={rs:#x};a2={rt:#x}",
     "registers_out": f"a0={expected:#x}", "pc": "next", "memory_in": "-",
     "memory_out": "-", "status": "pass", "current_registers": "-",
     "current_memory": "-"}
    for index, (address, (_, shift, rs, rt, expected))
    in enumerate(zip(EXTW_STATE_ADDRESSES, EXTW_STATE_CASES))]
STRICT_PROPERTIES = os.environ.get("NANOMIPS_STRICT_PROPERTIES") == "1"
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
    property_addresses = [0x6000 + 8*i for i in range(len(PROPERTY_CASES))]
    vectors += [(address, encoded) for address, (_, encoded, _, _) in
                zip(property_addresses, PROPERTY_CASES)]
    vectors += [(address, encoded) for address, (encoded, _, _, _) in
                zip(ROTX_ADDRESSES, ROTX_CASES)]
    vectors += [(address, encoded) for address, (encoded, _, _, _, _) in
                zip(ROTATE_ADDRESSES, ROTATE_CASES)]
    vectors += [(address, encoded) for address, (_, _, encoded) in
                zip(ADDIUPC_ADDRESSES, ADDIUPC_CASES)]
    vectors += [(address, encoded) for address, (encoded, _, _, _, _) in
                zip(EXTW_STATE_ADDRESSES, EXTW_STATE_CASES)]
    first = min(address for address, _ in vectors)
    last = max(0x4100, *(address + len(encoded) for address, encoded in vectors))
    image = bytearray(last - first)
    for address, encoded in vectors:
        image[address - first:address - first + len(encoded)] = encoded
    binary = scratch / "instructions.bin"
    binary.write_bytes(image)
    output = scratch / "actual.tsv"
    semantic_output = scratch / "semantics.tsv"
    semantic_input = scratch / "semantic_cases.tsv"
    with semantic_input.open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=SEMANTIC_CASES[0], delimiter="\t")
        writer.writeheader()
        writer.writerows(SEMANTIC_CASES)
    sequence_output = scratch / "sequences.tsv"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    run([str(GHIDRA / "support/analyzeHeadless"), str(scratch), "FlowTests",
         "-import", str(binary), "-loader", "BinaryLoader", "-loader-baseAddr", hex(first),
         "-processor", "nanomips:LE:32:default", "-noanalysis", "-scriptPath", str(ROOT / "tests"),
         "-postScript", "ProbeFlow.java", str(output), *(hex(address) for address, _ in vectors),
         "-postScript", "ProbeSemantics.java", str(ROOT / "tests/instruction_cases.tsv"),
         str(semantic_input), str(semantic_output),
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
    expected_property_failures = 0
    for address, (name, encoded, kind, expected) in zip(property_addresses, PROPERTY_CASES):
        fields = actual.get(address, [])
        if len(fields) != 6 or int(fields[0]) != len(encoded):
            failures.append(f"{name}: missing or wrong-sized decode: {fields}")
            continue
        _, assembly, flow_type, _, pcode, _ = fields
        mnemonic = ("EXTW" if kind == "last_operand" else
                    expected[1] if kind == "relocated_flow" else
                    expected[0] if kind == "branch_target" else
                    CASES[expected]["mnemonic"] if kind == "relocated_decode" else
                    "JALRC.HB" if "_hb_" in name else "JALRC")
        if assembly.split()[0] != mnemonic:
            failures.append(f"{name}: wrong mnemonic: {assembly}")
            continue
        if kind == "last_operand":
            try:
                observed = int(assembly.rsplit(",", 1)[1], 0)
            except (IndexError, ValueError):
                failures.append(f"{name}: missing numeric operand: {assembly}")
                continue
            correct = observed == expected
            xfail = PROPERTY_XFAILS.get("extw_shift") if expected != 31 else None
        elif kind == "link_flow":
            observed = flow_type
            wanted_op = ("RETURN" if expected == "TERMINATOR" else
                         "BRANCHIND" if expected == "COMPUTED_JUMP" else "CALLIND")
            correct = observed == expected and wanted_op in pcode.split(",")
            xfail = PROPERTY_XFAILS.get("zero_link_flow") if expected == "COMPUTED_JUMP" else None
        elif kind == "relocated_flow":
            source_address, _, wanted_flow, source_target, wanted_op = expected
            wanted_target = ("" if source_target == "-" else
                             f"{address + int(source_target, 16) - source_address:08x}")
            observed = (flow_type, fields[3], pcode)
            correct = (flow_type == wanted_flow and fields[3] == wanted_target
                       and wanted_op in pcode.split(","))
            xfail = None
        elif kind == "branch_target":
            _, wanted_flow, offset = expected
            wanted_target = f"{(address + len(encoded) + offset) & 0xffffffff:08x}"
            wanted_op = "CBRANCH" if wanted_flow == "CONDITIONAL_JUMP" else (
                "CALL" if wanted_flow == "UNCONDITIONAL_CALL" else "BRANCH")
            observed = (flow_type, fields[3], pcode)
            correct = (flow_type == wanted_flow and fields[3] == wanted_target
                       and wanted_op in pcode.split(","))
            xfail = None
        else:
            original_address = instruction_addresses[expected]
            original = actual[original_address]
            old_flows = original[3].split(",") if original[3] else []
            wanted_flows = ",".join(
                f"{int(flow, 16) + address - original_address:08x}"
                for flow in old_flows)
            observed = fields
            correct = (fields[0] == original[0] and flow_type == original[2]
                       and fields[3] == wanted_flows and pcode == original[4]
                       and fields[5] == original[5])
            xfail = None
        if xfail:
            expected_property_failures += 1
            if STRICT_PROPERTIES and not correct:
                failures.append(f"{name}: expected {expected}, got {fields} ({xfail['issue']})")
            elif not STRICT_PROPERTIES and (correct or str(observed) != xfail["current"]):
                failures.append(f"{name}: expected {xfail['issue']} mismatch, got {fields}")
        elif not correct:
            failures.append(f"{name}: expected {expected}, got {fields}")
    for address in ROTX_ADDRESSES:
        fields = actual.get(address, [])
        if len(fields) != 6 or fields[1].split()[0] != "ROTX":
            failures.append(f"{address:#x}: missing ROTX decode: {fields}")
    for address, (_, mnemonic, _, _, _) in zip(ROTATE_ADDRESSES, ROTATE_CASES):
        fields = actual.get(address, [])
        if len(fields) != 6 or fields[1].split()[0] != mnemonic:
            failures.append(f"{address:#x}: missing {mnemonic} decode: {fields}")
    for address in ADDIUPC_ADDRESSES:
        fields = actual.get(address, [])
        if len(fields) != 6 or fields[1].split()[0] != "ADDIUPC":
            failures.append(f"{address:#x}: missing ADDIUPC decode: {fields}")
    for address in EXTW_STATE_ADDRESSES:
        fields = actual.get(address, [])
        if len(fields) != 6 or fields[1].split()[0] != "EXTW":
            failures.append(f"{address:#x}: missing EXTW decode: {fields}")
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
        wanted_pc = (address if expected["pc"] == "self" else
                     address + int(fields[0]) if expected["pc"] == "next"
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
        if expected["status"] == "overflow" and (not observed or result["error"] != "overflow"):
            failures.append(f"{expected['case']}: expected overflow, got {result}")
        if expected["status"] == "debug_break" and (not observed or result["error"] != "debug_break"):
            failures.append(f"{expected['case']}: expected debug break, got {result}")
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
          f"{len(PROPERTY_CASES)} generated property cases ({expected_property_failures} expected failures), "
          f"{sum(row['status'] == 'xfail' for row in SEMANTIC_CASES)} expected value failures, "
          f"{len(KNOWN_ISSUES)} known structural failures checked; "
          f"{len(failures)} failures")
    if failures:
        raise SystemExit(1)
