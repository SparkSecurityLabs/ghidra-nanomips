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
source = []
for filename in ("nanomips.sinc", "nanomips_mt.sinc"):
    for line_number, line in enumerate((ROOT / "data/languages" / filename).read_text().splitlines(), 1):
        match = re.match(r"^:([A-Z][A-Z0-9.]*)\b", line)
        if match:
            source.append((f"{filename}:{line_number}", match.group(1)))
if [(row["constructor"], row["mnemonic"]) for row in CASES] != source:
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
    first = min(address for address, _ in vectors)
    last = max(address + len(encoded) for address, encoded in vectors)
    image = bytearray(last - first)
    for address, encoded in vectors:
        image[address - first:address - first + len(encoded)] = encoded
    binary = scratch / "instructions.bin"
    binary.write_bytes(image)
    output = scratch / "actual.tsv"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    run([str(GHIDRA / "support/analyzeHeadless"), str(scratch), "FlowTests",
         "-import", str(binary), "-loader", "BinaryLoader", "-loader-baseAddr", hex(first),
         "-processor", "nanomips:LE:32:default", "-noanalysis", "-scriptPath", str(ROOT / "tests"),
         "-postScript", "ProbeFlow.java", str(output), *(hex(address) for address, _ in vectors)],
        env=env)

    actual = {int(fields[0], 16): fields[1:] for fields in (row.split("\t") for row in output.read_text().splitlines())}
    failures = []
    for address, row in zip(instruction_addresses, CASES):
        fields = actual.get(address, [])
        encoded = bytes.fromhex(row["bytes"])
        if len(fields) != 6:
            failures.append(f"{row['constructor']}: missing decode: {fields}")
            continue
        length, assembly, flow_type, flows, pcode, constructor = fields
        if (int(length) != len(encoded) or assembly.split()[0] != row["mnemonic"]
                or flow_type != row["flow"] or constructor != row["constructor"]
                or (not pcode and row["mnemonic"] != "NOP")):
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
    for failure in failures:
        print("FAIL", failure)
    print(f"{len(CASES)} constructor cases and {len(FLOW_CASES)} flow cases checked; "
          f"{len(failures)} failures")
    if failures:
        raise SystemExit(1)
