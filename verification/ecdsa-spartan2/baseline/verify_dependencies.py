#!/usr/bin/env python3
"""Verify the actual resolved cryptographic dependencies without changing them."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tomllib


CRATE = Path("wallet-unit-poc/ecdsa-spartan2")
SPARTAN_REV = "d687dbb639eccbdd21e62fecec97c5826bc4dbbf"
HALO_CHECKSUM = "f82f3e7809d6118c2afbde9667b3ba5c7621723df3729cc2157fac39121ecb62"
GENERATED_MARKERS = {".cargo-ok", ".cargo-checksum.json"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    return digest(path.read_bytes())


def git(directory, *arguments):
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    require(result.returncode == 0, "Git dependency integrity command failed")
    return result.stdout


def override_environment_name(name):
    explicit = {
        "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
    }
    prefixes = ("CARGO_SOURCE_", "CARGO_PATCH_", "CARGO_REPLACE_", "CARGO_REGISTRY_", "CARGO_REGISTRIES_")
    build = name.startswith("CARGO_BUILD_") and any(
        suffix in name for suffix in ("RUSTFLAGS", "RUSTC", "RUSTDOC", "WRAPPER")
    )
    target = name.startswith("CARGO_TARGET_") and any(
        suffix in name for suffix in ("RUSTFLAGS", "WRAPPER")
    )
    return name in explicit or name.startswith(prefixes) or build or target


def forbidden_compiler_keys(value, prefix=""):
    found = []
    if not isinstance(value, dict):
        return found
    forbidden = {"rustflags", "rustdocflags", "rustc", "rustdoc", "rustc-wrapper", "rustc-workspace-wrapper"}
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if key in forbidden:
            found.append(path)
        if isinstance(child, dict):
            found.extend(forbidden_compiler_keys(child, path))
    return found


def cargo_configuration(crate, workspace, cargo_home):
    paths = set()
    for directory in (crate, *crate.parents):
        paths.update((directory / ".cargo/config", directory / ".cargo/config.toml"))
    paths.update((cargo_home / "config", cargo_home / "config.toml"))
    configs = []
    for path in sorted(paths):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode("utf-8"))
        forbidden = sorted(set(data) & {"source", "patch", "replace", "paths", "registry", "registries", "include"})
        compiler = forbidden_compiler_keys(data)
        configured_env = sorted(
            name for name in data.get("env", {}) if override_environment_name(name)
        )
        require(not forbidden, f"Cargo configuration contains override tables: {path}: {', '.join(forbidden)}")
        require(not compiler, f"Cargo configuration contains compiler overrides: {path}: {', '.join(compiler)}")
        require(not configured_env, f"Cargo configuration defines override environment names: {path}: {', '.join(configured_env)}")
        default_features = data.get("build", {}).get("default-features")
        require(default_features is None or isinstance(default_features, bool),
                f"Unexpected build.default-features type in {path}")
        configs.append({
            "path": str(path), "sha256": digest(raw), "top_level_names": sorted(data),
            "build_default_features": default_features,
        })

    manifests = {crate / "Cargo.toml", workspace / "Cargo.toml"}
    manifests.update(directory / "Cargo.toml" for directory in crate.parents)
    manifest_evidence = []
    for path in sorted(manifests):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode("utf-8"))
        forbidden = sorted(set(data) & {"source", "patch", "replace", "paths"})
        require(not forbidden, f"Cargo manifest contains override tables: {path}: {', '.join(forbidden)}")
        manifest_evidence.append({
            "path": str(path), "sha256": digest(raw), "top_level_names": sorted(data),
        })
    environment_names = sorted(name for name in os.environ if override_environment_name(name))
    require(not environment_names,
            "Override environment variables are set (values omitted): " + ", ".join(environment_names))
    return {"cargo_home": str(cargo_home), "configs": configs,
            "applicable_manifests": manifest_evidence, "override_environment_names": environment_names}


def resolved_package(metadata, root_manifest, name, version):
    roots = [package for package in metadata["packages"]
             if Path(package["manifest_path"]).resolve() == root_manifest]
    require(len(roots) == 1, "Cargo metadata does not identify exactly one expected root manifest")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending = [roots[0]["id"]]
    reachable = set()
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        node = nodes.get(current)
        require(node is not None, "Cargo metadata resolve graph is incomplete")
        pending.extend(node.get("dependencies", [dep["pkg"] for dep in node.get("deps", [])]))
    packages = [package for package in metadata["packages"]
                if package["id"] in reachable and package["name"] == name
                and package["version"] == version]
    require(len(packages) == 1, f"Expected exactly one resolved {name} {version}")
    return packages[0]


def verify_spartan(package, lock):
    require(lock.get("source", "").rsplit("#", 1)[-1] == SPARTAN_REV,
            "Spartan2 Cargo.lock revision does not match the baseline")
    require(package.get("source") == lock.get("source"),
            "Resolved Spartan2 source does not match Cargo.lock")
    source = Path(package["manifest_path"]).resolve().parent
    checkout = Path(git(source, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    require(checkout == source, "Resolved Spartan2 manifest is not at the checkout root")
    head = git(source, "rev-parse", "HEAD").decode().strip()
    require(head == SPARTAN_REV, "Spartan2 checkout HEAD does not match Cargo.lock")
    git(source, "diff", "--exit-code", "--no-ext-diff", "HEAD", "--")
    git(source, "diff", "--cached", "--exit-code", "--no-ext-diff", "HEAD", "--")
    untracked = set()
    for args in (("ls-files", "--others", "--exclude-standard", "-z"),
                 ("ls-files", "--others", "--ignored", "--exclude-standard", "-z")):
        untracked.update(path.decode() for path in git(source, *args).split(b"\0") if path)
    require(not (untracked - {".cargo-ok"}), "Spartan2 checkout contains unexpected untracked inputs")
    status = git(source, "status", "--porcelain=v1", "--untracked-files=all", "-z").decode()
    status_entries = [entry for entry in status.split("\0") if entry]
    require(all(entry == "?? .cargo-ok" for entry in status_entries), "Spartan2 checkout is not clean")

    object_format = git(source, "rev-parse", "--show-object-format").decode().strip()
    require(object_format in {"sha1", "sha256"}, "Unsupported Git object format")
    hashes = {}
    for entry in git(source, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not entry:
            continue
        details, relative = entry.split(b"\t", 1)
        mode, kind, expected_blob = details.decode().split()
        name = relative.decode()
        require(kind == "blob" and mode in {"100644", "100755"}, "Unsupported tracked Spartan2 input type")
        require("\n" not in name and "\r" not in name, "Unsupported Spartan2 filename")
        path = source / name
        require(path.is_file() and not path.is_symlink(), "Spartan2 tracked input missing or symlinked")
        raw = path.read_bytes()
        blob = hashlib.new(object_format, f"blob {len(raw)}\0".encode() + raw).hexdigest()
        require(blob == expected_blob, "Spartan2 working bytes differ from committed Git blob")
        hashes[name] = digest(raw)
    require(bool(hashes), "Spartan2 checkout contains no tracked files")
    return {
        "package_id": package["id"], "version": package["version"],
        "manifest_path": str(source / "Cargo.toml"), "checkout": str(source),
        "head": head, "tree": git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "git_object_format": object_format, "git_status": status_entries,
        "allowed_untracked_markers": sorted(untracked), "tracked_file_count": len(hashes),
        "tracked_bytes_match_head": True, "file_manifest": "spartan2-files.sha256",
    }, hashes


def verify_halo(package, lock, cargo_home):
    require(lock.get("checksum") == HALO_CHECKSUM, "halo2curves Cargo.lock checksum does not match baseline")
    require(package.get("source") == lock.get("source"), "Resolved halo2curves source does not match Cargo.lock")
    source = Path(package["manifest_path"]).resolve().parent
    relative_source = source.relative_to(cargo_home / "registry/src")
    require(len(relative_source.parts) == 2 and relative_source.name == "halo2curves-0.9.0",
            "Unexpected resolved halo2curves registry source layout")
    archive = cargo_home / "registry/cache" / relative_source.parts[0] / "halo2curves-0.9.0.crate"
    archive_hash = file_hash(archive)
    require(archive_hash == lock["checksum"], "Published halo2curves archive differs from Cargo.lock checksum")
    expected = {}
    with tarfile.open(archive, "r:gz") as compressed:
        for member in compressed:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts
                    and name.parts[0] == "halo2curves-0.9.0", "Unsafe published crate member path")
            if member.isdir():
                continue
            require(member.isfile(), "Published crate contains a nonregular input")
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            require(relative not in expected and relative not in GENERATED_MARKERS
                    and "\n" not in relative and "\r" not in relative,
                    "Unexpected or duplicate published crate input")
            with compressed.extractfile(member) as stream:
                expected[relative] = digest(stream.read())
    require(bool(expected), "Published halo2curves archive contains no files")
    actual = {}
    for path in source.rglob("*"):
        require(not path.is_symlink(), "halo2curves source contains a symlink")
        if path.is_dir():
            continue
        require(path.is_file(), "halo2curves source contains a nonregular input")
        relative = path.relative_to(source).as_posix()
        if relative not in GENERATED_MARKERS:
            actual[relative] = file_hash(path)
    require(actual == expected, "Resolved halo2curves files differ from the checksum-verified published crate")

    checksum_path = source / ".cargo-checksum.json"
    checksum_evidence = {"present": checksum_path.is_file()}
    if checksum_path.is_file():
        raw = checksum_path.read_bytes()
        checksums = json.loads(raw)
        require(checksums.get("package") == archive_hash, "halo2curves Cargo checksum package identity mismatch")
        require(checksums.get("files") == expected, "halo2curves Cargo per-file checksum metadata mismatch")
        checksum_evidence.update({"sha256": digest(raw), "package_and_files_verified": True})
    return {
        "package_id": package["id"], "version": package["version"],
        "manifest_path": str(source / "Cargo.toml"), "source_directory": str(source),
        "archive_path": str(archive), "archive_sha256": archive_hash,
        "lock_checksum": lock["checksum"], "file_count": len(actual),
        "verification_method": "published crate checksum and complete extracted-file byte comparison",
        "cargo_checksum_metadata": checksum_evidence,
        "excluded_generated_markers": sorted(GENERATED_MARKERS),
        "file_manifest": "halo2curves-files.sha256",
    }, actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", type=Path)
    parser.add_argument("cargo_metadata_json", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    crate = repo / CRATE
    root_manifest = (crate / "Cargo.toml").resolve()
    metadata = json.loads(args.cargo_metadata_json.read_text())
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    workspace = Path(metadata["workspace_root"]).resolve()
    configuration = cargo_configuration(crate, workspace, cargo_home)
    lock_path = crate / "Cargo.lock"
    lock = tomllib.loads(lock_path.read_text())
    verified = {}
    manifests = {}
    for name, version in (("spartan2", "0.4.0"), ("halo2curves", "0.9.0")):
        selected = [package for package in lock["package"]
                    if package["name"] == name and package["version"] == version]
        require(len(selected) == 1, f"Expected one {name} {version} entry in Cargo.lock")
        package = resolved_package(metadata, root_manifest, name, version)
        if name == "spartan2":
            verified[name], manifests[name] = verify_spartan(package, selected[0])
        else:
            verified[name], manifests[name] = verify_halo(package, selected[0], cargo_home)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, hashes in manifests.items():
        manifest = args.output_dir / verified[name]["file_manifest"]
        manifest.write_text("".join(f"{hashes[path]}  {path}\n" for path in sorted(hashes)))
        verified[name]["file_manifest_sha256"] = file_hash(manifest)
    result = {"schema_version": 1, "status": "verified", "lockfile_sha256": file_hash(lock_path),
              "cargo_configuration": configuration, "dependencies": verified}
    (args.output_dir / "dependency-integrity.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Dependency integrity verified: Spartan2 and halo2curves")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"Dependency integrity failed: {error}", file=sys.stderr)
        sys.exit(1)
