#!/usr/bin/env python3
"""Run the public CLI and prepare offline evidence views."""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from presentation import decode, interpret, read_bundle

HERE = Path(__file__).resolve().parent
PIN = "6f720a6429341b4c56f4290f80f86769d3eca366"
VERSION = "0.1.0"
BUNDLE_FILES = {"decision": "decision.jsonl", "control": "control.jsonl", "checkpoint": "checkpoints.jsonl", "anchor": "rekor-anchors.jsonl"}
EXPECTED_FILES = set(BUNDLE_FILES.values()) | {"gateway-keys.pub.json", "rekor-log.pub.pem"}
V2_FILES = {"bundle.json", "decision.jsonl", "control.jsonl", "checkpoints.jsonl", "gateway-keys.pub.json"}
LABS = ("connect-trip", "proxy-trip", "endpoint-optin-trip", "endpoint-misses-50", "evidence-failure-null-link",
        "f1-artifacts", "explicit-hardening-demo", "pre-go-artifact-append-failure", "terminal-missing-trip")
AGENTS = {"claude": "Claude Code", "codex": "Codex CLI", "gemini": "Gemini CLI"}


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def fixture_hashes():
    fixtures = HERE / "fixtures"
    expected = {f"bundle-{c}/{name}" for c in "ABCD" for name in EXPECTED_FILES} | {"gateway-keys.pub.json", "receipts.jsonl", "rekor-log.pub.pem"}
    manifest = {}
    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        sha, name = line.split("  ", 1)
        if name not in expected or name in manifest:
            raise ValueError(f"Unexpected fixture in checksum manifest: {name}")
        file = fixtures / name
        if file.is_symlink() or not file.is_file() or digest(file) != sha:
            raise ValueError(f"Pinned fixture checksum failed: {name}")
        manifest[name] = sha
    if manifest.keys() != expected:
        raise ValueError("Pinned fixture set incomplete")
    for c in "ABCD":
        path = fixtures / f"bundle-{c}"
        if path.is_symlink() or {item.name for item in path.iterdir()} != EXPECTED_FILES:
            raise ValueError(f"Unexpected content in bundle-{c}")
    return manifest


def receipt_keys(path):
    lines = path.read_bytes().splitlines()
    keys = set()
    for line in lines:
        value = decode(line)
        if "checkpoint_sequence" in value:
            keys.add((value["checkpoint_sequence"], value["statement_sha256"]))
        else:
            v = value.get("checkpoint", value)
            if "statement" in v:
                keys.add((v["statement"]["sequence"], v["statement_sha256"]))
    return len(lines), keys


def v2_cases():
    for agent, label in AGENTS.items():
        root = f"t-ih14-2026-11-05/{agent}"
        yield f"agent-{agent}", label, f"{root}/bundle", f"{root}/gateway-keys.pub.json", f"{root}/alarms.jsonl", False
    for lab in LABS:
        root = "v2-lab-2026-10-28"
        yield f"lab-{lab}", lab, f"{root}/bundles/{lab}", f"{root}/keys/{lab}.pub.json", f"{root}/receipts/{lab}.jsonl", lab in {"f1-artifacts", "pre-go-artifact-append-failure"}


def v2_hashes(fixtures, cases):
    expected = set()
    for _, _, bundle, key, receipt, artifacts in cases:
        names = V2_FILES | ({"artifacts.json"} if artifacts else set())
        expected.update({key, receipt, *(f"{bundle}/{name}" for name in names)})
        directory = fixtures / bundle
        if directory.is_symlink() or {item.name for item in directory.iterdir()} != names:
            raise ValueError(f"Unexpected content in {bundle}")
    manifest = {}
    for line in (HERE / "SHA256SUMS.v2").read_text().splitlines():
        sha, name = line.split("  ", 1)
        file = fixtures / name
        if name not in expected or name in manifest or file.is_symlink() or digest(file) != sha:
            raise ValueError(f"Unexpected or modified v2 fixture: {name}")
        manifest[name] = sha
    if manifest.keys() != expected:
        raise ValueError("Incomplete pinned v2 fixture set")
    return manifest


def compute(fixtures, manifest, binary, provenance, name, with_receipts, *, key="gateway-keys.pub.json",
            receipt="receipts.jsonl", log_key="rekor-log.pub.pem", version=1):
    args = [name, "--keys", key]
    inputs = sorted(p for p in manifest if p.startswith(name + "/")) + [key]
    if log_key:
        args += ["--log-key", log_key]
        inputs.append(log_key)
    if with_receipts:
        args += ["--receipts", receipt]
        inputs.append(receipt)
    p = subprocess.run([binary, *args], cwd=fixtures, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    stdout = p.stdout.decode("utf-8")
    result = interpret(stdout, p.returncode, anchors=bool(log_key), receipts=with_receipts, version=version)
    if result["verdict"] not in {"VALID", "INVALID"}:
        raise ValueError(f"Unrecognized public verifier output for {name}")
    argv = ["cybercircuit-verify", *args]
    return {**result, "bundle": name, "with_receipts": with_receipts, "provenance": provenance, "argv": argv,
            "command": shlex.join(argv), "inputs": [{"path": path, "sha256": manifest[path]} for path in inputs]}


def write(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", default="cybercircuit-verify")
    parser.add_argument("--verifier-version", required=True, choices=[VERSION])
    parser.add_argument("--verifier-commit", required=True, choices=[PIN])
    args = parser.parse_args()
    if os.environ.get("CHALLENGE_REVEALED") == "1":
        parser.error("no separately pinned public reveal document is configured; build A–D without CHALLENGE_REVEALED")
    executable = shutil.which(args.verifier)
    if not executable:
        parser.error("public cybercircuit-verify executable not found")
    binary = str(Path(executable).resolve(strict=True))
    fixtures = HERE / "fixtures"
    manifest = fixture_hashes()
    provenance = {"version": args.verifier_version, "commit": args.verifier_commit, "sha256": digest(Path(binary))}
    count, receipts = receipt_keys(fixtures / "receipts.jsonl")
    combined = {}
    for c in "ABCD":
        name = f"bundle-{c}"
        item = read_bundle(fixtures / name, c, name, decode((fixtures / "gateway-keys.pub.json").read_bytes()), count, receipts)
        item["results"] = {key: compute(fixtures, manifest, binary, provenance, name, enabled)
                           for key, enabled in [("without", False), ("with", True)]}
        combined[name] = item
    cases = list(v2_cases())
    v2_manifest = v2_hashes(fixtures, cases)
    for identifier, label, bundle, key, receipt, _ in cases:
        count, receipts = receipt_keys(fixtures / receipt)
        item = read_bundle(fixtures / bundle, label, identifier, decode((fixtures / key).read_bytes()), count, receipts)
        item["results"] = {mode: compute(fixtures, v2_manifest, binary, provenance, bundle, mode == "with",
                                        key=key, receipt=receipt, log_key=None, version=2) for mode in ("without", "with")}
        combined[identifier] = item
    output = HERE / "results"
    output.mkdir(exist_ok=True)
    for name, item in combined.items():
        for label, result in item["results"].items():
            write(output / f"{name}-{label}.json", result)
    write(output / "data.json", combined)
    print(f"Recorded {2 * len(combined)} public verifier runs.")


if __name__ == "__main__":
    main()
