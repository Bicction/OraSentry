"""Repeatable launch-to-splash and launch-to-ready timings, no fixed fake delay."""
import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path


def benchmark(executable, destination, runs, require_splash=False):
    executable = executable.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    samples = []
    for index in range(runs):
        trace = destination / ("startup-%d-%d.jsonl" % (time.time_ns(), index))
        environment = dict(os.environ, ORASENTRY_STARTUP_TRACE=str(trace.resolve()),
                           ORASENTRY_AUTOCLOSE_MS="300")
        launched_ms = time.time_ns() // 1000000
        process = subprocess.Popen([str(executable)], env=environment, cwd=str(executable.parent))
        try:
            code = process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            # Only terminate the process tree created by this benchmark.
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
            raise RuntimeError("Startup timed out: " + str(executable))
        events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
        stages = {entry["stage"]: entry for entry in events}
        if code or "ready" not in stages:
            raise RuntimeError("Startup failed: " + json.dumps(events, ensure_ascii=False))
        if require_splash and "splash_shown" not in stages:
            raise RuntimeError("Portable splash never became visible: " + str(trace))
        sample = {"run": index + 1, "ready_ms": stages["ready"]["timestamp_ms"] - launched_ms,
                  "splash_ms": (stages["splash_shown"]["timestamp_ms"] - launched_ms
                                if "splash_shown" in stages else None),
                  "drag_drop": stages["ready"]["drag_drop"], "trace": str(trace)}
        samples.append(sample)
        print(json.dumps(sample), flush=True)
    return {"executable": str(executable), "size_bytes": executable.stat().st_size,
            "samples": samples, "median_ready_ms": statistics.median(s["ready_ms"] for s in samples),
            "note": "Local repeated runs; caches/antivirus left unchanged. Not a controlled cold-start test."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--require-splash", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    report = benchmark(args.executable, args.output.resolve().parent, args.runs, args.require_splash)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
