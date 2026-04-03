#!/usr/bin/env python3
"""Apply org policy and repo overrides to produce a scan target matrix."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scripts.scanlib import (
    choose_target_paths,
    infer_build_context,
    load_yaml_file,
    merge_repo_config,
    sanitize_image_name,
    write_json_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery-file", required=True, help="Discovery JSON from discover_repos.py")
    parser.add_argument("--policy-file", required=True, help="Path to org policy YAML")
    parser.add_argument("--matrix-out", required=True, help="Path to write matrix JSON")
    parser.add_argument("--inventory-out", required=True, help="Path to write target inventory JSON")
    return parser.parse_args()


def build_targets(discovery_payload: dict, policy: dict) -> tuple[dict, dict]:
    registry_prefix = policy.get("default_registry_prefix", "localscan")
    max_targets = int(policy.get("max_dockerfiles_per_repo", 10))
    targets: list[dict] = []
    skipped: list[dict] = []

    for repo in discovery_payload.get("repos", []):
        if not repo.get("eligible"):
            skipped.append({"repository": repo["full_name"], "reason": repo.get("reason", "ineligible")})
            continue

        merged = merge_repo_config(policy, repo.get("repo_config"))
        if not merged.get("enabled", True):
            skipped.append({"repository": repo["full_name"], "reason": "disabled_by_repo_config"})
            continue

        dockerfiles = choose_target_paths(repo.get("discovered_dockerfiles", []), merged, max_targets)
        if not dockerfiles:
            skipped.append({"repository": repo["full_name"], "reason": "no_targets_after_policy"})
            continue

        build_contexts = merged.get("build_contexts", {})
        for dockerfile in dockerfiles:
            build_context = build_contexts.get(dockerfile) or build_contexts.get(Path(dockerfile).name) or infer_build_context(dockerfile)
            targets.append(
                {
                    "repository": repo["full_name"],
                    "ref": repo["default_branch"],
                    "dockerfile_path": dockerfile,
                    "build_context": build_context,
                    "image_name": sanitize_image_name(repo["full_name"], dockerfile, registry_prefix),
                    "policy_mode": merged.get("policy_mode", policy.get("default_policy_mode", "advisory")),
                    "severity_threshold": merged.get("severity_threshold", policy.get("default_severity_threshold", "critical")),
                    "ignore_unfixed": bool(merged.get("ignore_unfixed", True)),
                    "skip_secret_scan": bool(merged.get("skip_secret_scan", False)),
                    "skip_build": bool(merged.get("skip_build", False)),
                    "allowlist_cves": merged.get("allowlist_cves", []),
                }
            )

    matrix = {"include": targets}
    inventory = {
        "organization": discovery_payload.get("organization"),
        "target_count": len(targets),
        "targets": targets,
        "skipped": skipped,
    }
    return matrix, inventory


def main() -> int:
    args = parse_args()
    discovery_payload = json.loads(Path(args.discovery_file).read_text(encoding="utf-8"))
    policy = load_yaml_file(args.policy_file)
    matrix, inventory = build_targets(discovery_payload, policy)
    write_json_file(args.matrix_out, matrix)
    write_json_file(args.inventory_out, inventory)
    print(f"Prepared {inventory['target_count']} scan targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
