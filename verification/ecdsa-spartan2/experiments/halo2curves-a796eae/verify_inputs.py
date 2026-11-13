#!/usr/bin/env python3
"""Verify the narrowly scoped halo2curves experiment's actual resolved inputs."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib


BASE = "cc1955665e58d815950ef8387071af04ae6c4486"
REV = "a796eae54af4dda7f672c243a36fd9729d59944e"
URL = "https://github.com/alxkzmn/halo2curves.git"
SOURCE = f"git+{URL}?rev={REV}#{REV}"
CRATE = Path("wallet-unit-poc/ecdsa-spartan2")
HELPER = Path("verification/ecdsa-spartan2/baseline/verify_dependencies.py")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, "Git input verification command failed")
    return result.stdout


def base_bytes(repo, name):
    return git(repo, "show", f"{BASE}:{name}")


def source_contract(repo):
    names = [name.decode() for name in git(repo, "ls-tree", "-r", "--name-only", "-z", BASE, "--", str(CRATE)).split(b"\0") if name]
    pinned = [name for name in names if name.endswith(".rs") or "/.cargo/" in name]
    hashes = {}
    for name in pinned:
        path = repo / name
        require(path.is_file() and not path.is_symlink(), "Pinned application input missing or symlinked")
        raw = path.read_bytes()
        require(raw == base_bytes(repo, name), f"Application source/config changed: {name}")
        hashes[name] = sha(raw)
    actual_rs = {str(path.relative_to(repo)) for path in (repo / CRATE).rglob("*.rs")}
    require(actual_rs == {name for name in pinned if name.endswith(".rs")}, "Application Rust source inventory changed")
    manifest = CRATE / "Cargo.toml"
    original = tomllib.loads(base_bytes(repo, manifest).decode())
    expected = copy.deepcopy(original)
    require("patch" not in expected, "Unexpected patch already present in baseline manifest")
    patch = {"crates-io": {"halo2curves": {"git": URL, "rev": REV}}}
    expected["patch"] = patch
    actual = tomllib.loads((repo / manifest).read_text())
    require(actual == expected, "Root manifest differs beyond the exact pinned halo2curves patch")

    lock_path = CRATE / "Cargo.lock"
    original_lock = tomllib.loads(base_bytes(repo, lock_path).decode())
    expected_lock = copy.deepcopy(original_lock)
    changes = []
    for name, version in (("halo2curves", "0.9.0"), ("halo2derive", "0.2.0")):
        packages = [p for p in expected_lock["package"] if p["name"] == name and p["version"] == version]
        require(len(packages) == 1, "Expected halo package missing or duplicated in baseline lockfile")
        package = packages[0]
        require(package.get("source") == "registry+https://github.com/rust-lang/crates.io-index" and "checksum" in package,
                "Expected baseline registry package identity not found")
        changes.append({"name": name, "version": version, "source_before": package["source"],
                        "source_after": SOURCE, "removed_registry_checksum": package["checksum"]})
        package["source"] = SOURCE
        del package["checksum"]
    actual_lock = tomllib.loads((repo / lock_path).read_text())
    for lock in (expected_lock, actual_lock):
        lock["package"] = sorted(lock["package"], key=lambda p: json.dumps(p, sort_keys=True))
    require(actual_lock == expected_lock, "Cargo.lock semantic changes exceed the two expected source transitions")
    return actual_lock, {
        "baseline_commit": BASE, "unchanged_application_file_sha256": hashes,
        "manifest": {"path": str(manifest), "baseline_sha256": sha(base_bytes(repo, manifest)),
                     "actual_sha256": sha((repo / manifest).read_bytes()), "accepted_patch": patch},
        "lockfile": {"path": str(lock_path), "baseline_sha256": sha(base_bytes(repo, lock_path)),
                     "actual_sha256": sha((repo / lock_path).read_bytes()), "accepted_changes": changes},
    }


def configuration(crate, workspace, cargo_home, helpers):
    candidates = {cargo_home / "config", cargo_home / "config.toml"}
    for directory in (crate, *crate.parents):
        candidates.update((directory / ".cargo/config", directory / ".cargo/config.toml"))
    configs = []
    for path in sorted(candidates):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode())
        forbidden = set(data) & {"source", "patch", "replace", "paths", "registry", "registries", "include"}
        require(not forbidden, f"Cargo configuration contains override tables: {path}")
        require(not helpers.forbidden_compiler_keys(data), f"Cargo configuration contains compiler overrides: {path}")
        require(not any(helpers.override_environment_name(name) for name in data.get("env", {})),
                f"Cargo configuration defines override environment names: {path}")
        default_features = data.get("build", {}).get("default-features")
        require(default_features is None or isinstance(default_features, bool), "Unexpected build.default-features type")
        configs.append({"path": str(path), "sha256": sha(raw), "top_level_names": sorted(data),
                        "build_default_features": default_features})
    manifests = {crate / "Cargo.toml", workspace / "Cargo.toml"}
    manifests.update(directory / "Cargo.toml" for directory in crate.parents)
    manifest_evidence = []
    for path in sorted(manifests):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode())
        forbidden = set(data) & {"source", "patch", "replace", "paths"}
        if path == crate / "Cargo.toml":
            forbidden.discard("patch")  # Exact contents already checked by source_contract.
        require(not forbidden, f"Additional manifest overrides present: {path}")
        manifest_evidence.append({"path": str(path), "sha256": sha(raw), "top_level_names": sorted(data)})
    env_names = sorted(name for name in os.environ if helpers.override_environment_name(name))
    require(not env_names, "Override environment variables set (values omitted): " + ", ".join(env_names))
    return {"cargo_home": str(cargo_home), "configs": configs,
            "applicable_manifests": manifest_evidence, "override_environment_names": env_names}


def fork_integrity(package, derive):
    root = Path(package["manifest_path"]).resolve().parent
    require(Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() == root,
            "Resolved halo2curves manifest is not at the fork checkout root")
    require(Path(derive["manifest_path"]).resolve() == root / "derive/Cargo.toml",
            "halo2derive is not resolved from the same fork checkout")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    require(head == REV, "Resolved halo2curves checkout HEAD differs from the pinned patch")
    git(root, "diff", "--exit-code", "--no-ext-diff", "HEAD", "--")
    git(root, "diff", "--cached", "--exit-code", "--no-ext-diff", "HEAD", "--")
    untracked = set()
    for args in (("ls-files", "--others", "--exclude-standard", "-z"),
                 ("ls-files", "--others", "--ignored", "--exclude-standard", "-z")):
        untracked.update(p.decode() for p in git(root, *args).split(b"\0") if p)
    require(not (untracked - {".cargo-ok"}), "Fork checkout contains unexpected untracked or ignored inputs")
    status = [s for s in git(root, "status", "--porcelain=v1", "--untracked-files=all", "-z").decode().split("\0") if s]
    require(all(s == "?? .cargo-ok" for s in status), "Fork checkout has tracked or index changes")
    object_format = git(root, "rev-parse", "--show-object-format").decode().strip()
    require(object_format in {"sha1", "sha256"}, "Unsupported fork Git object format")
    hashes = {}
    for item in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not item:
            continue
        details, relative = item.split(b"\t", 1)
        mode, kind, blob = details.decode().split()
        name = relative.decode()
        path = root / name
        require(kind == "blob" and mode in {"100644", "100755"}
                and "\n" not in name and "\r" not in name
                and path.is_file() and not path.is_symlink(), "Unsupported or missing tracked fork input")
        raw = path.read_bytes()
        actual_blob = hashlib.new(object_format, f"blob {len(raw)}\0".encode() + raw).hexdigest()
        require(actual_blob == blob, "Fork working bytes differ from the pinned Git tree")
        hashes[name] = sha(raw)
    require(bool(hashes), "Fork checkout has no tracked files")
    return {"checkout": str(root), "head": head, "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
            "git_status": status, "allowed_untracked_markers": sorted(untracked), "git_object_format": object_format,
            "tracked_file_count": len(hashes), "tracked_bytes_match_head": True,
            "resolved_manifests": {p["name"]: p["manifest_path"] for p in (package, derive)},
            "file_manifest": "fork-files.sha256"}, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("cargo_metadata_json", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    helper_path = repo / HELPER
    helper_bytes = helper_path.read_bytes()
    require(helper_bytes == base_bytes(repo, HELPER), "Baseline dependency helpers changed")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(helper_path.parent))
    import verify_dependencies as helpers

    lock, contract = source_contract(repo)
    metadata = json.loads(args.cargo_metadata_json.read_text())
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    config = configuration(repo / CRATE, Path(metadata["workspace_root"]).resolve(), cargo_home, helpers)
    packages = {name: helpers.resolved_package(metadata, (repo / CRATE / "Cargo.toml").resolve(), name, version)
                for name, version in (("spartan2", "0.4.0"), ("halo2curves", "0.9.0"), ("halo2derive", "0.2.0"))}
    for name in ("halo2curves", "halo2derive"):
        require(packages[name].get("source") == SOURCE, f"Resolved {name} source does not match pinned Git revision")
        record = next(p for p in lock["package"] if p["name"] == name and p["version"] == packages[name]["version"])
        require(record.get("source") == SOURCE and "checksum" not in record, f"Unexpected locked {name} identity")
    spartan_lock = next(p for p in lock["package"] if p["name"] == "spartan2" and p["version"] == "0.4.0")
    spartan, spartan_hashes = helpers.verify_spartan(packages["spartan2"], spartan_lock)
    fork, fork_hashes = fork_integrity(packages["halo2curves"], packages["halo2derive"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for evidence, hashes in ((spartan, spartan_hashes), (fork, fork_hashes)):
        path = args.output_dir / evidence["file_manifest"]
        path.write_text("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)))
        evidence["file_manifest_sha256"] = sha(path.read_bytes())
    result = {"schema_version": 1, "status": "verified", "source_contract": contract,
              "baseline_helper_sha256": sha(helper_bytes), "cargo_configuration": config,
              "dependencies": {"spartan2": spartan, "halo2curves_fork": fork},
              "resolved_packages": {name: {key: package[key] for key in ("id", "version", "source", "manifest_path")}
                                    for name, package in packages.items()}}
    (args.output_dir / "input-integrity.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Experiment inputs verified: exact manifest/lock delta, clean pinned fork and unchanged Spartan2")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as error:
        print(f"Experiment input verification failed: {error}", file=sys.stderr)
        sys.exit(1)
