#!/usr/bin/env python3
"""Record the real verifier retry with the one explicitly pinned dependency patch."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BASELINE = HERE.parents[1] / "baseline"
sys.path.insert(0, str(BASELINE))
import collect as common

BASE = "cc1955665e58d815950ef8387071af04ae6c4486"
PATCH = "a796eae54af4dda7f672c243a36fd9729d59944e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", nargs="?")
    args = parser.parse_args()
    repo = Path(common.output(["git", "rev-parse", "--show-toplevel"], HERE))
    crate = repo / common.CRATE
    subprocess.run(["git", "diff", "--exit-code", BASE, "--", "*.rs",
                    "verification/ecdsa-spartan2/baseline"], cwd=repo, check=True)
    inputs = common.source_hashes(repo)
    tools = common.identities()
    baseline_tools = json.loads((BASELINE / "artifacts/tool-identities.json").read_text())
    if tools != baseline_tools:
        raise RuntimeError("Pinned tool identities differ from the recorded baseline")
    native = Path(os.environ["EXPERIMENT_NATIVE_TARGET_DIR"]).resolve()
    miri = Path(os.environ["EXPERIMENT_MIRI_TARGET_DIR"]).resolve()
    if native == miri:
        raise RuntimeError("Native and Miri target directories must be distinct")
    if args.output_directory:
        dest = Path(args.output_directory).resolve()
        dest.mkdir(parents=True, exist_ok=False)
    else:
        (HERE / "runs").mkdir(exist_ok=True)
        dest = Path(tempfile.mkdtemp(prefix="retry-", dir=HERE / "runs"))
    stages = []

    def run(name, argv, target=None, json_stdout=False):
        env = os.environ.copy()
        if target is not None:
            env["CARGO_TARGET_DIR"] = str(target)
        start = time.monotonic()
        proc = subprocess.run(argv, cwd=crate, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE if json_stdout else subprocess.STDOUT)
        (dest / f"{name}.log").write_text(common.clean(proc.stdout + (proc.stderr or b"")))
        stage = {"name": name, "argv": argv, "cwd": str(crate), "exit_status": proc.returncode,
                 "log": f"{name}.log", "duration_seconds": round(time.monotonic() - start, 3)}
        if target is not None:
            stage["CARGO_TARGET_DIR"] = str(target)
        stages.append(stage)
        print(f"{name}: exit {proc.returncode}", flush=True)
        return proc

    common.write_json(dest / "tool-identities.json", tools)
    common.write_json(dest / "source-hashes.json", inputs)
    provenance = common.provenance()
    common.write_json(dest / "provenance.json", provenance)
    diff = subprocess.check_output(["git", "diff", "--unified=0", BASE, "--", f"{common.CRATE}/Cargo.toml",
                                    f"{common.CRATE}/Cargo.lock"], cwd=repo)
    (dest / "dependency-selection.diff").write_bytes(diff)
    graph = run("cargo-metadata", ["cargo", "metadata", "--locked", "--no-default-features",
                "--format-version", "1", "--offline"], native, json_stdout=True)
    if graph.returncode:
        raise RuntimeError("Could not resolve patched dependency graph")
    graph_path = dest / ".cargo-metadata.json"
    common.write_json(graph_path, json.loads(graph.stdout))
    (dest / "cargo-metadata.log").write_text("Resolved metadata used by input-integrity.json.\n" + common.clean(graph.stderr or b""))
    integrity = run("input-integrity", [sys.executable, str(HERE / "verify_inputs.py"),
                    str(repo), str(graph_path), str(dest)])
    if integrity.returncode:
        raise RuntimeError("Unexpected dependency/source inputs; see input-integrity.log")
    integrity_names = ("input-integrity.json", "fork-files.sha256", "spartan2-files.sha256")
    integrity_hashes = {name: common.sha(dest / name) for name in integrity_names}
    run("rust-tests", ["cargo", "test", "--locked", "--lib", "--no-default-features",
                      "--", "--nocapture"], native)
    llbc = dest / "ecdsa_spartan2.llbc"
    extraction = run("charon", ["charon", "cargo", "--preset=aeneas", "--sysroot", "miri",
                     "--start-from", common.TARGET, "--dest-file", str(llbc), "--", "--locked",
                     "--lib", "--no-default-features"], miri)
    if extraction.returncode == 0 and llbc.is_file():
        (dest / "aeneas.log").write_text("")
        validation = run("llbc-validation", [sys.executable, str(BASELINE / "summarize_llbc.py"),
                         str(llbc), str(dest), str(dest / "aeneas.log")])
        if validation.returncode:
            raise RuntimeError("Fresh extraction failed structural validation")
        (dest / "lean").mkdir()
        run("aeneas", ["aeneas", "-backend", "lean", "-core-models-lib", "-split-files",
                       "-specs", "hax", "-dest", str(dest / "lean"), str(llbc)])
        summary = run("llbc-summary", [sys.executable, str(BASELINE / "summarize_llbc.py"),
                      str(llbc), str(dest), str(dest / "aeneas.log")])
        if summary.returncode:
            raise RuntimeError("Could not summarize the actual translation attempt")
    else:
        stages.append({"name": "aeneas", "status": "skipped",
                       "reason": "No successful validated Charon extraction", "exit_status": None})
    compression = None
    if llbc.is_file():
        raw_hash = common.sha(llbc)
        zipped = llbc.with_suffix(".llbc.gz")
        with zipped.open("wb") as stream:
            subprocess.run(["gzip", "-n", "-c", str(llbc)], stdout=stream, check=True)
        compression = {"uncompressed_sha256": raw_hash, "compressed_sha256": common.sha(zipped),
                       "argv": ["gzip", "-n", "-c", str(llbc)]}
        llbc.unlink()
    with tempfile.TemporaryDirectory(prefix="halo-patch-input-recheck-") as recheck:
        verified = run("input-integrity-after", [sys.executable, str(HERE / "verify_inputs.py"),
                       str(repo), str(graph_path), recheck])
        if verified.returncode or any(common.sha(Path(recheck) / name) != digest
                                      for name, digest in integrity_hashes.items()):
            raise RuntimeError("Experiment inputs changed during execution")
    graph_path.unlink()
    if common.source_hashes(repo) != inputs or common.identities() != tools or common.provenance() != provenance:
        raise RuntimeError("Source, tools, pinned Lake manifest, or archive changed during execution")
    failed = any(s["exit_status"] != 0 for s in stages)
    test_log = (dest / "rust-tests.log").read_text()
    common.write_json(dest / "metadata.json", {
        "schema_version": 1, "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "baseline_commit": BASE, "halo2curves_commit": PATCH,
        "worktree_head_at_execution": common.output(["git", "rev-parse", "HEAD"], repo),
        "target": common.TARGET, "application_rust_sources_unchanged": True,
        "allowed_changes": [f"{common.CRATE}/Cargo.toml", f"{common.CRATE}/Cargo.lock"],
        "inputs_unchanged_during_capture": True, "harness_capture_status": "complete",
        "pipeline_status": "failed" if failed else "passed", "harness_exit_status": 1 if failed else 0,
        "stages": stages, "compression": compression,
        "generated_lean_files": sorted(str(p.relative_to(dest)) for p in (dest / "lean").rglob("*.lean")),
        "rust_test_result_lines": [line for line in test_log.splitlines() if line.startswith("test result:")],
        "rust_test_skip_messages": [line for line in test_log.splitlines() if "skipping" in line],
        "input_integrity_sha256": integrity_hashes,
        "scope": "Same verifier wrapper and extraction settings; one pinned dependency patch. Opaque calls and serialized declaration counts do not establish cryptographic correctness or exact reachable-body coverage.",
    })
    (dest / "commands.txt").write_text("\n\n".join(
        f"{s['name']} (exit {s['exit_status']})\n" + shlex.join(s["argv"])
        + (f"\nCARGO_TARGET_DIR={s['CARGO_TARGET_DIR']}" if "CARGO_TARGET_DIR" in s else "")
        for s in stages if "argv" in s) + "\n")
    files = sorted(p for p in dest.rglob("*") if p.is_file())
    (dest / "SHA256SUMS").write_text("".join(f"{common.sha(p)}  {p.relative_to(dest)}\n" for p in files))
    print(f"Evidence capture complete: {dest}\nPipeline: {'FAILED' if failed else 'PASSED'}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Experiment collection stopped: {error}", file=sys.stderr)
        sys.exit(2)
