#!/usr/bin/env python3
"""Manually test VC6 automatic PCH creation/reuse (requires a user-supplied compiler)."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runner", required=True, type=Path)
parser.add_argument("--compiler", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
runner, compiler = args.runner.resolve(), args.compiler.resolve()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
results = []
with tempfile.TemporaryDirectory(prefix="vc6-pch-") as temporary:
    work = Path(temporary)
    for name in ("pch.h", "repro.cpp"):
        shutil.copyfile(Path(__file__).parent / name, work / name)
    pch_state = None
    objects = []
    for mode in ("plain", "create", "reuse"):
        command = [str(runner), str(compiler), "/nologo", "/O2", "/c", "/Forepro.obj"]
        if mode != "plain":
            command += ["/YX", "/Fprepro.pch"]
        command += ["repro.cpp"]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=60)
        row = dict(mode=mode, command=command, returncode=result.returncode,
                   stdout=result.stdout, stderr=result.stderr)
        results.append(row)
        print(json.dumps(row), flush=True)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(f"{mode} failed")
        obj = (work / "repro.obj").read_bytes()
        (output / f"{mode}.obj").write_bytes(obj)
        # COFF TimeDateStamp is the only field excluded from the comparison.
        normalized = obj[:4] + bytes(4) + obj[8:]
        objects.append(normalized)
        row["normalized_object_sha256"] = hashlib.sha256(normalized).hexdigest()
        if mode != "plain":
            pch = work / "repro.pch"
            state = (pch.stat().st_mtime_ns, hashlib.sha256(pch.read_bytes()).hexdigest())
            if mode == "create":
                pch_state = state
                if pch.stat().st_size == 0:
                    raise SystemExit("empty PCH")
            elif state != pch_state:
                raise SystemExit("PCH was rewritten instead of reused")
            row["pch_sha256"] = state[1]
        (work / "repro.obj").unlink()
    if not all(obj == objects[0] for obj in objects):
        raise SystemExit("objects differ beyond the COFF timestamp")
(output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
print("PASS: PCH created and reused; all objects match excluding COFF timestamps")
