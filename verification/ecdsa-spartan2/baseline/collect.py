#!/usr/bin/env python3
"""Capture the unmodified verifier baseline; a failed translation stays failed."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

BASE = "b395e09c225ff45b003f0087c28e2e208e22f944"
TARGET = "ecdsa_spartan2::prover::verify_linked"
CRATE = "wallet-unit-poc/ecdsa-spartan2"
HERE = Path(__file__).resolve().parent
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PROGRESS = re.compile(r"^(?:Applied prepasses|Translated [^:]+):\s+\[")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def output(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


def clean(raw):
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", text)
    text = ANSI.sub("", text).replace("\r", "\n")
    lines = [line.rstrip() for line in text.splitlines() if not PROGRESS.match(line)]
    text = "\n".join(lines).rstrip()
    return text + "\n" if text else ""


def source_hashes(repo):
    names = output(["git", "ls-files", "--", CRATE], repo).splitlines()
    return {name: sha(repo / name) for name in names
            if name.endswith(".rs") or Path(name).name in
            {"Cargo.toml", "Cargo.lock", "config.toml"}}


def check_sources(repo, hashes):
    for name, actual in hashes.items():
        original = subprocess.check_output(["git", "show", f"{BASE}:{name}"], cwd=repo)
        if hashlib.sha256(original).hexdigest() != actual:
            raise RuntimeError(f"Source identity drift: {name}")


def tool(path, argv):
    resolved = Path(path).resolve(strict=True)
    return {"binary": str(resolved), "sha256": sha(resolved),
            "version_argv": argv, "version": output(argv)}


def identities():
    extraction_chain = output(["charon", "toolchain-version"])
    extraction_root = Path(output(["charon", "toolchain-path"]))
    charon = Path(shutil.which("charon")).resolve()
    result = {
        "native_rustc": tool(output(["rustup", "which", "rustc"]), ["rustc", "-Vv"]),
        "native_cargo": tool(output(["rustup", "which", "cargo"]), ["cargo", "-V"]),
        "extraction_rustc": tool(extraction_root / "bin/rustc",
                                 [str(extraction_root / "bin/rustc"), "-Vv"]),
        "charon": tool(charon, ["charon", "version"]),
        "aeneas": tool(shutil.which("aeneas"), ["aeneas", "-version"]),
        "cargo_hax": tool(shutil.which("cargo-hax"), ["cargo", "hax", "--version"]),
        "lean": tool(output(["elan", "which", "lean"]), ["lean", "--version"]),
    }
    driver = charon.parent / "charon-driver"
    result["charon_driver"] = {"binary": str(driver.resolve()), "sha256": sha(driver)}
    result["extraction_rustc"]["toolchain"] = extraction_chain
    expected = {"native_rustc": "rustc 1.99.1", "charon": "61123872e0442f7dc7ffc48603158c368eddb22b",
                "aeneas": "build-2b9e3ea", "cargo_hax": "version=0.5.0", "lean": "version 4.35.0"}
    for name, version in expected.items():
        if version not in result[name]["version"]:
            raise RuntimeError(f"Tool identity drift: {name}")
    if extraction_chain != "nightly-2026-09-17":
        raise RuntimeError(f"Extraction compiler drift: {extraction_chain}")
    return result


def provenance():
    prepared = Path(os.environ["OPENAC_FORMAL_ENV"]).resolve().parent
    retained = prepared / "artifacts/openac-verifier-extraction"
    paths = [prepared / "start.md", prepared / "env.sh", prepared / "extract-openac.sh",
             retained / "regenerate.sh", retained / "metadata.json",
             prepared / "artifacts/openac-verifier-extraction.tar.gz",
             retained / "aeneas-translation-failure.log", prepared / "openac-aeneas-hax-models.log",
             prepared / "lean-check/lake-manifest.json"]
    hashes = {str(path): sha(path) for path in paths}
    return {"prepared_files_sha256": hashes,
            "historical_aeneas": {
                "recovery": "Exact argv supplied from the original setup chat by the delegating user.",
                "source_chat": "01a1c5b6-42f2-76ee-9f7c-5d19041ec0bc",
                "command_item": "exec-21ae7c86-31e8-406b-9d98-fc06cdc61ac0",
                "argv": ["aeneas", "-backend", "lean", "-core-models-lib", "-split-files",
                         "-specs", "hax", "-dest", "/workspace/formal-tools/openac-extraction/lean",
                         "/workspace/formal-tools/openac-extraction/ecdsa_spartan2.llbc"],
                "combined_log": "/workspace/formal-tools/openac-aeneas-hax-models.log",
                "archived_as": "aeneas-translation-failure.log",
                "archive_log_matches_retry": hashes[str(retained / "aeneas-translation-failure.log")]
                    == hashes[str(prepared / "openac-aeneas-hax-models.log")],
                "earlier_variant": "openac-aeneas.log omitted -core-models-lib -specs hax; not replayed.",
                "historical_numeric_exit_status": None,
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", nargs="?", help="Must not already exist")
    args = parser.parse_args()
    repo = Path(output(["git", "rev-parse", "--show-toplevel"], HERE))
    crate = repo / CRATE
    hashes = source_hashes(repo)
    check_sources(repo, hashes)
    tools = identities()
    origin = output(["git", "remote", "get-url", "origin"], repo)
    if origin != "https://github.com/alxkzmn/zkID.git":
        raise RuntimeError(f"Unexpected repository origin: {origin}")
    native = Path(os.environ["BASELINE_NATIVE_TARGET_DIR"]).resolve()
    miri = Path(os.environ["BASELINE_MIRI_TARGET_DIR"]).resolve()
    if native == miri:
        raise RuntimeError("Native and Miri Cargo targets must be distinct")
    if args.output_directory:
        dest = Path(args.output_directory).resolve()
        dest.mkdir(parents=True, exist_ok=False)
    else:
        runs = HERE / "runs"
        runs.mkdir(exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = Path(tempfile.mkdtemp(prefix=f"baseline-{stamp}-", dir=runs))
    stages = []

    def run(name, argv, log, target=None, json_stdout=False):
        env = os.environ.copy()
        if target is not None:
            env["CARGO_TARGET_DIR"] = str(target)
        start = time.monotonic()
        proc = subprocess.run(argv, cwd=crate, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE if json_stdout else subprocess.STDOUT)
        (dest / log).write_text(clean(proc.stdout + (proc.stderr or b"")))
        stage = {"name": name, "argv": argv, "cwd": str(crate), "exit_status": proc.returncode,
                 "log": log, "duration_seconds": round(time.monotonic() - start, 3)}
        if target is not None:
            stage["CARGO_TARGET_DIR"] = str(target)
        stages.append(stage)
        print(f"{name}: exit {proc.returncode}", flush=True)
        return proc

    captured_provenance = provenance()
    write_json(dest / "provenance.json", captured_provenance)
    write_json(dest / "source-hashes.json", hashes)
    write_json(dest / "tool-identities.json", tools)
    manifest_path = Path(os.environ["OPENAC_FORMAL_ENV"]).resolve().parent / "lean-check/lake-manifest.json"
    lake_manifest_hash = sha(manifest_path)
    lock = tomllib.loads((crate / "Cargo.lock").read_text())
    meta = run("cargo_metadata", ["cargo", "metadata", "--locked", "--no-default-features",
               "--format-version", "1", "--offline"], "cargo-metadata.log", native, json_stdout=True)
    if meta.returncode:
        raise RuntimeError(f"Cargo metadata infrastructure failure; see {dest}")
    graph = json.loads(meta.stdout)
    root = next(p for p in graph["packages"] if p["manifest_path"] == str(crate / "Cargo.toml"))
    root_node = next(n for n in graph["resolve"]["nodes"] if n["id"] == root["id"])
    if "native-witness" in root_node["features"]:
        raise RuntimeError("native-witness unexpectedly enabled")
    write_json(dest / "dependencies.json", {
        "root_package": root["id"], "root_enabled_features": root_node["features"],
        "cargo_feature_selection": ["--no-default-features"],
        "lockfile_sha256": sha(crate / "Cargo.lock"),
        "selected_lock_packages": [p for p in lock["package"]
            if p["name"] in {"spartan2", "halo2curves", "circom-scotia", "ecdsa-spartan2"}],
        "root_resolved_dependencies": root_node["deps"],
        "lake_manifest_sha256": lake_manifest_hash,
    })
    graph_path = dest / ".cargo-metadata.json"
    write_json(graph_path, graph)
    integrity = run("dependency_integrity", [sys.executable, str(HERE / "verify_dependencies.py"),
                    str(repo), str(graph_path), str(dest)], "dependency-integrity.log")
    if integrity.returncode:
        raise RuntimeError(f"Resolved dependency/configuration integrity failed; see {dest}")
    integrity_files = ("dependency-integrity.json", "spartan2-files.sha256", "halo2curves-files.sha256")
    integrity_hashes = {name: sha(dest / name) for name in integrity_files}
    # Keep the dependency identities rather than the verbose machine-path metadata dump.
    (dest / "cargo-metadata.log").write_text(
        "Cargo metadata captured and summarized in dependencies.json.\n" + clean(meta.stderr or b""))
    native_check = run("rust_tests", ["cargo", "test", "--locked", "--lib", "--no-default-features",
                       "--", "--nocapture"], "rust-tests.log", native)
    llbc = dest / "ecdsa_spartan2.llbc"
    extraction = run("charon", ["charon", "cargo", "--preset=aeneas", "--sysroot", "miri",
                     "--start-from", TARGET, "--dest-file", str(llbc), "--", "--locked", "--lib",
                     "--no-default-features"], "charon.log", miri)
    if extraction.returncode or not llbc.is_file():
        raise RuntimeError(f"Fresh Charon extraction failed; see {dest}")
    # Validate the fresh extraction before giving it to Aeneas. The summary is
    # refreshed with the real diagnostics after the translation attempt.
    (dest / "aeneas.log").write_text("")
    summary = run("coverage_validation", [sys.executable, str(HERE / "summarize_llbc.py"),
                  str(llbc), str(dest), str(dest / "aeneas.log")], "coverage-validation.log")
    if summary.returncode:
        raise RuntimeError(f"Extraction validation failed; see {dest}")
    lean = dest / "lean"
    lean.mkdir()
    aeneas = run("aeneas", ["aeneas", "-backend", "lean", "-core-models-lib", "-split-files",
                 "-specs", "hax", "-dest", str(lean), str(llbc)], "aeneas.log")
    summary = run("coverage_summary", [sys.executable, str(HERE / "summarize_llbc.py"),
                  str(llbc), str(dest), str(dest / "aeneas.log")], "coverage-summary.log")
    if summary.returncode:
        raise RuntimeError(f"Extraction validation failed; see {dest}")
    raw_hash = sha(llbc)
    zipped = dest / "ecdsa_spartan2.llbc.gz"
    with zipped.open("wb") as stream:
        subprocess.run(["gzip", "-n", "-c", str(llbc)], stdout=stream, check=True)
    compression = {"argv": ["gzip", "-n", "-c", str(llbc)], "stdout_file": zipped.name,
                   "uncompressed_sha256": raw_hash, "compressed_sha256": sha(zipped)}
    llbc.unlink()
    if source_hashes(repo) != hashes or sha(manifest_path) != lake_manifest_hash:
        raise RuntimeError("Source, lockfile, or pinned Lake manifest changed during collection")
    if provenance()["prepared_files_sha256"] != captured_provenance["prepared_files_sha256"]:
        raise RuntimeError("Prepared/retained provenance artifacts changed during collection")
    if identities() != tools:
        raise RuntimeError("Tool identities changed during collection")
    with tempfile.TemporaryDirectory(prefix="openac-baseline-input-recheck-") as recheck:
        integrity = run("dependency_integrity_after", [sys.executable, str(HERE / "verify_dependencies.py"),
                        str(repo), str(graph_path), recheck], "dependency-integrity-after.log")
        if integrity.returncode or any(sha(Path(recheck) / name) != digest
                                       for name, digest in integrity_hashes.items()):
            raise RuntimeError(f"Dependency/configuration identity changed during collection; see {dest}")
    graph_path.unlink()
    test_log = (dest / "rust-tests.log").read_text()
    skips = [line for line in test_log.splitlines() if re.search(r"\bskipping\b", line, re.IGNORECASE)]
    failed = any(s["exit_status"] != 0 for s in stages)
    write_json(dest / "metadata.json", {
        "schema_version": 1, "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": "https://github.com/alxkzmn/zkID", "source_commit": BASE,
        "worktree_head_at_execution": output(["git", "rev-parse", "HEAD"], repo),
        "worktree_branch": output(["git", "branch", "--show-current"], repo),
        "target": TARGET, "source_and_lock_unchanged": True,
        "harness_capture_status": "complete", "pipeline_status": "failed" if failed else "passed",
        "harness_exit_status": 1 if failed else 0, "stages": stages,
        "compression": compression, "generated_lean_files": [str(p.relative_to(dest)) for p in lean.rglob("*.lean")],
        "rust_test_result_lines": [line for line in test_log.splitlines() if line.startswith("test result:")],
        "rust_test_skip_messages": skips,
        "native_and_miri_caches_distinct": True,
        "resolved_dependency_integrity_before_after": {"unchanged": True, "evidence_sha256": integrity_hashes},
        "diagnostic_cleaning": "Strip ANSI/OSC controls, split carriage returns, remove named progress-bar lines and trailing whitespace/blank lines; retain diagnostics and stack traces.",
        "scope": "Wrapper extraction only; opaque cryptographic functions are not extracted implementations. No correctness proof.",
    })
    (dest / "commands.txt").write_text("\n\n".join(
        f"{s['name']} (exit {s['exit_status']})\ncwd: {s['cwd']}\n"
        + (f"CARGO_TARGET_DIR={s['CARGO_TARGET_DIR']}\n" if "CARGO_TARGET_DIR" in s else "")
        + shlex.join(s["argv"]) for s in stages) + "\n\n" + shlex.join(compression["argv"])
        + f" > {shlex.quote(str(zipped))}\n")
    files = sorted(p for p in dest.rglob("*") if p.is_file())
    (dest / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(dest)}\n" for p in files))
    print(f"Evidence capture complete: {dest}\nPipeline: {'FAILED' if failed else 'PASSED'}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Baseline collection stopped: {error}", file=sys.stderr)
        sys.exit(2)
