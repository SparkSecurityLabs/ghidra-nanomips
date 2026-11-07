#!/usr/bin/env python3
"""Check a small nanoMIPS flow corpus with this checkout's SLEIGH language."""

import getpass
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"]).resolve()
CASES = []
for line in (ROOT / "tests/flow_cases.tsv").read_text().splitlines():
    if line and not line.startswith("#"):
        address, encoded, mnemonic, flow, target, op = line.split()
        CASES.append((int(address, 16), bytes.fromhex(encoded), mnemonic, flow, target, op))


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
    language = settings / "upstream-ghidra-nanomips/data/languages"
    run([str(GHIDRA / "support/sleigh"), "nanomips.slaspec", "nanomips.sla"],
        cwd=language)

    first = min(case[0] for case in CASES)
    last = max(address + len(encoded) for address, encoded, *_ in CASES)
    image = bytearray(last - first)
    for address, encoded, *_ in CASES:
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
         "-postScript", "ProbeFlow.java", str(output), *(hex(case[0]) for case in CASES)],
        env=env)

    actual = {int(fields[0], 16): fields[1:] for fields in (row.split("\t") for row in output.read_text().splitlines())}
    failures = []
    for address, encoded, mnemonic, flow, target, op in CASES:
        fields = actual.get(address, [])
        if len(fields) != 5:
            failures.append(f"{address:#x}: missing decode: {fields}")
            continue
        length, assembly, flow_type, flows, pcode = fields
        wanted_target = "" if target == "-" else f"{int(target, 16):08x}"
        if (int(length) != len(encoded) or assembly.split()[0] != mnemonic
                or flow_type != flow or flows != wanted_target
                or op not in pcode.split(",")):
            failures.append(f"{address:#x}: {fields}")
    for failure in failures:
        print("FAIL", failure)
    print(f"{len(CASES) - len(failures)}/{len(CASES)} flow cases passed")
    if failures:
        raise SystemExit(1)
