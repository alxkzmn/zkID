#!/usr/bin/env python3
"""Validate verifier LLBC and summarize its serialized function declarations."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


TARGET = "ecdsa_spartan2::prover::verify_linked"
CURVE_NAMES = {
    "halo2curves::curve::CurveExt",
    "halo2curves::curve::CurveAffine",
    "halo2curves::curve::Coordinates",
}
DECLARATIONS = {
    "Type": "type_decls",
    "Fun": "fun_decls",
    "Global": "global_decls",
    "TraitDecl": "trait_decls",
    "TraitImpl": "trait_impls",
}


def name_of(declaration):
    """Keep paths readable without serializing entire generic impl signatures."""
    parts = []
    for part in declaration.get("item_meta", {}).get("name", []):
        if "Ident" in part:
            parts.append(str(part["Ident"][0]))
        elif "Impl" in part:
            implementation = part["Impl"]
            if isinstance(implementation, dict) and "Trait" in implementation:
                parts.append(f"{{impl trait#{implementation['Trait']}}}")
            else:
                parts.append("{impl}")
        elif "Builtin" in part:
            builtin = part["Builtin"][0]
            if isinstance(builtin, dict):
                kind, value = next(iter(builtin.items()))
                parts.append(f"{kind}[{value}]")
            else:
                parts.append(str(builtin))
        else:
            parts.append("{" + next(iter(part), "unknown") + "}")
    return "::".join(parts)


def body_kind(declaration):
    body = declaration.get("body")
    if isinstance(body, dict) and "Structured" in body:
        return "structured"
    if body == "Opaque" or isinstance(body, dict) and "Opaque" in body:
        return "opaque"
    return "other"


def span_data(span):
    """Unwrap the span encodings used in Charon's serialized item metadata."""
    if not isinstance(span, dict):
        return None
    if isinstance(span.get("data"), dict):
        return span["data"]
    if "file_id" in span:
        return span
    for key in ("Untagged", "Value"):
        value = span.get(key)
        if isinstance(value, list) and len(value) == 2:
            value = value[1]
        if isinstance(value, dict):
            return span_data(value)
    return None


def source_of(declaration, files):
    span = span_data(declaration.get("item_meta", {}).get("span"))
    if span is None:
        return None
    file_id = span.get("file_id")
    return {
        "file_id": file_id,
        "file": files.get(file_id),
        "begin": span.get("beg"),
        "end": span.get("end"),
    }


def declaration_summary(kind, declaration, files):
    result = {
        "kind": kind,
        "id": declaration["def_id"],
        "name": name_of(declaration),
        "source": source_of(declaration, files),
    }
    if kind == "Fun":
        result["body_kind"] = body_kind(declaration)
    return result


def generic_summary(declaration):
    generics = declaration.get("generics", {})
    return {
        "region_count": len(generics.get("regions", [])),
        "type_parameters": [x.get("name") for x in generics.get("types", []) if x],
        "const_parameters": [
            x.get("name") for x in generics.get("const_generics", []) if x
        ],
        "trait_clause_count": len(generics.get("trait_clauses", [])),
        "type_constraint_count": len(generics.get("trait_type_constraints", [])),
    }


def associated_type_names(declaration):
    result = []
    for associated in declaration.get("types", []):
        if associated:
            result.append(associated.get("skip_binder", associated).get("name"))
    return result


def direct_calls(body, lookup):
    """Count syntactic Call nodes with a direct Regular/Fun callee only."""
    counts = {}

    def visit(node):
        if isinstance(node, dict):
            call = node.get("Call")
            if isinstance(call, dict):
                function = call.get("call", {}).get("func", {}).get("Regular", {})
                function_id = function.get("kind", {}).get("Fun")
                if isinstance(function_id, int):
                    counts[function_id] = counts.get(function_id, 0) + 1
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(body)
    return [
        dict(lookup.get(("Fun", function_id), {
            "kind": "Fun", "id": function_id, "name": None,
            "source": None, "body_kind": "unknown",
        }), callsite_count=count)
        for function_id, count in sorted(counts.items())
    ]


def first_mixed_group(log):
    lines = log.splitlines()
    marker = "Detected groups of mixed mutually recursive definitions"
    start = next((i for i, line in enumerate(lines) if marker in line), None)
    if start is None:
        return {"found": False, "names": [], "lines": []}
    selected = []
    names = []
    declaration_pattern = re.compile(r"^- .*?\(Source:.*\):\s*(.+)$")
    for line in lines[start:]:
        if names and (line.startswith("# Group") or not line.strip()):
            break
        if selected and line.startswith("[Error]"):
            break
        selected.append(line)
        match = declaration_pattern.match(line)
        if match:
            names.append(match.group(1))
    return {"found": True, "names": names, "lines": selected}


def summarize(input_path, output_dir, log_path):
    raw = input_path.read_bytes()
    root = json.loads(raw)
    translated = root["translated"]
    options = translated["options"]
    functions = [item for item in translated["fun_decls"] if item is not None]
    targets = [item for item in functions if name_of(item) == TARGET]
    errors = []
    if root.get("has_errors") is not False:
        errors.append("LLBC has_errors must be false")
    for key, expected in (
        ("preset", "Aeneas"),
        ("sysroot", "miri"),
        ("start_from", [TARGET]),
    ):
        if options.get(key) != expected:
            errors.append(f"options.{key} must equal {expected!r}; got {options.get(key)!r}")
    if len(targets) != 1:
        errors.append(f"expected exactly one {TARGET} declaration; found {len(targets)}")
    else:
        if body_kind(targets[0]) != "structured":
            errors.append("target must have a Structured body")
        if targets[0].get("item_meta", {}).get("has_errors") is not False:
            errors.append("target item_meta.has_errors must be false")
    if errors:
        raise ValueError("; ".join(errors))

    files = {}
    for file in translated.get("files", []):
        if not file:
            continue
        name = file.get("name")
        if isinstance(name, dict):
            name = next(iter(name.values()), None)
        files[file["id"]] = name

    lookup = {}
    curves = []
    for kind, field in DECLARATIONS.items():
        for item in translated.get(field, []):
            if item is None:
                continue
            entry = declaration_summary(kind, item, files)
            lookup[(kind, item["def_id"])] = entry
            if entry["name"] in CURVE_NAMES:
                entry = dict(entry, generics=generic_summary(item))
                if kind == "TraitDecl":
                    entry["associated_types"] = associated_type_names(item)
                curves.append(entry)

    counts = {"total": len(functions), "structured": 0, "opaque": 0, "other": 0}
    structured = []
    spartan_verifiers = []
    for function in functions:
        kind = body_kind(function)
        counts[kind] += 1
        entry = lookup[("Fun", function["def_id"])]
        if kind == "structured":
            structured.append(entry)
        source_file = (entry.get("source") or {}).get("file")
        if (
            kind == "opaque"
            and isinstance(source_file, str)
            and source_file.endswith("/zk_spartan.rs")
            and entry["name"].split("::")[-1] == "verify"
        ):
            spartan_verifiers.append(entry)

    relevant_ids = {(entry["kind"], entry["id"]) for entry in curves + spartan_verifiers}
    relevant_ids.add(("Fun", targets[0]["def_id"]))
    group_field = "ordered_decls" if "ordered_decls" in translated else "declarations"
    groups = translated.get(group_field)
    relevant_groups = []
    if isinstance(groups, list):
        for index, group in enumerate(groups):
            group_kind, group_value = next(iter(group.items()))
            recursion, members = next(iter(group_value.items()))
            members = members if isinstance(members, list) else [members]
            ids = []
            for member in members:
                if group_kind == "Mixed":
                    ids.extend(member.items())
                else:
                    ids.append((group_kind, member))
            if group_kind == "Mixed" or any(key in relevant_ids for key in ids):
                relevant_groups.append({
                    "index": index,
                    "kind": group_kind,
                    "recursion": recursion,
                    "declarations": [
                        {key: entry[key] for key in ("kind", "id", "name")}
                        for kind, item_id in ids
                        for entry in [lookup.get((kind, item_id), {
                            "kind": kind, "id": item_id, "name": None,
                        })]
                    ],
                })

    diagnostic = first_mixed_group(log_path.read_text())
    target_calls = direct_calls(targets[0]["body"], lookup)
    spartan_verifier_ids = {item["id"] for item in spartan_verifiers}
    target_spartan_calls = [
        item for item in target_calls if item["id"] in spartan_verifier_ids
    ]
    result = {
        "input": str(input_path.resolve()),
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "charon_version": root.get("charon_version"),
        "extraction_validation": "passed",
        "has_errors": root["has_errors"],
        "options": {key: options[key] for key in ("preset", "sysroot", "start_from")},
        "name_format": "Rust path identifiers and builtin names; generic impl signatures abbreviated as {impl}; IDs disambiguate declarations",
        "metric_scope": "Counts describe serialized LLBC function declarations. Charon may retain auxiliary declarations for pretty-printing; these counts do not establish exact reachable-body coverage or runtime coverage.",
        "function_body_counts": counts,
        "structured_functions": structured,
        "target": dict(lookup[("Fun", targets[0]["def_id"])], status="structured", item_has_errors=False),
        "target_direct_calls_metric_scope": "Literal syntactic Call nodes in the target body with direct Regular/Fun callees, grouped by declaration ID. Generic signature references and drop function references are not calls; these counts do not establish dynamic execution counts or reachable runtime coverage.",
        "target_direct_calls": target_calls,
        "target_opaque_spartan_verification_calls": target_spartan_calls,
        "relevant_curve_declarations": curves,
        "opaque_spartan_verification_declarations": spartan_verifiers,
        "ordered_groups": {
            "serialized_field": group_field,
            "available": isinstance(groups, list),
            "total": len(groups) if isinstance(groups, list) else None,
            "selection": "all mixed groups and groups containing target or relevant declarations",
            "groups": relevant_groups,
        },
        "first_mixed_group_diagnostic": diagnostic,
    }
    text = [
        f"Input: {result['input']}",
        f"SHA256: {result['input_sha256']}",
        "Extraction validation: passed (not a Lean translation or correctness proof)",
        f"Serialized LLBC function declarations: {counts['total']}",
        f"Structured declaration bodies: {counts['structured']}; opaque declarations: {counts['opaque']}; other declaration bodies: {counts['other']}",
        f"Metric scope: {result['metric_scope']}",
        f"Target: {TARGET} (id {targets[0]['def_id']}, structured, no item errors)",
        f"Target source: {json.dumps(result['target']['source'], sort_keys=True)}",
        "",
        "Serialized function declarations with structured bodies (impl signatures abbreviated; IDs disambiguate):",
        *[f"- id {item['id']}: {item['name']}" for item in structured],
        "",
        "Opaque Spartan verification declarations:",
        *([f"- id {item['id']}: {item['name']}" for item in spartan_verifiers] or ["- none found"]),
        "",
        "Target direct Spartan verify callsites (syntactic Call nodes): "
        + ("; ".join(
            f"{item['callsite_count']} -> {item['body_kind']} id {item['id']}: {item['name']}"
            for item in target_spartan_calls
        ) or "none found"),
        f"Direct-call metric scope: {result['target_direct_calls_metric_scope']}",
        "",
        "Relevant halo2curves declarations:",
        *([f"- {item['kind']} id {item['id']}: {item['name']}" for item in curves] or ["- none found"]),
        "",
        "First mixed-group diagnostic names:",
        *([f"- {name}" for name in diagnostic["names"]] or ["- none found"]),
        "",
        "Foreign opaque functions have signatures only; their implementations are not extracted.",
    ]
    group_text = "\n".join(diagnostic["lines"]).rstrip() + "\n" if diagnostic["found"] else (
        "No mixed declaration group diagnostic was found in the supplied Aeneas log.\n"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "coverage.json").write_text(json.dumps(result, indent=2) + "\n")
    (output_dir / "coverage.txt").write_text("\n".join(text) + "\n")
    (output_dir / "declaration-groups.txt").write_text(group_text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_llbc", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("aeneas_clean_log", type=Path)
    args = parser.parse_args()
    try:
        summarize(args.input_llbc, args.output_directory, args.aeneas_clean_log)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(f"LLBC summary failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
