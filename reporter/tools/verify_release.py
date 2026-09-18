"""Gate publication on frozen GUI startup and actual report-generation checks."""
import argparse
import json
import subprocess
from pathlib import Path
from benchmark_startup import benchmark


def verify(staging, output):
    output.mkdir(parents=True, exist_ok=True)
    for name, executable in (("portable", staging / "OracleReport.exe"),
                             ("folder", staging / "OracleReport-FastStart/OracleReport.exe")):
        timing = benchmark(executable, output, 1, require_splash=name == "portable")
        if not timing["samples"][0]["drag_drop"]:
            raise RuntimeError("Drag/drop unavailable in " + name)
        (output / (name + "-startup.json")).write_text(json.dumps(timing, indent=2), encoding="utf-8")
        result_path = (output / (name + "-package.json")).resolve()
        process = subprocess.Popen([str(executable.resolve()), "--verify-package", str(result_path)])
        try:
            code = process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
            raise RuntimeError("Package check timed out: " + name)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if code or not result["ok"] or not result["compressed_catalog"]:
            raise RuntimeError("Package check failed: " + json.dumps(result, ensure_ascii=False))
        print(name + ": GUI, drag/drop, compressed catalog, HTML/DOCX and summary OK", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.staging.resolve(), args.output.resolve())
