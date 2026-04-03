#!/usr/bin/env python3
"""Discover GitHub repositories in an organization that contain Dockerfiles."""

from __future__ import annotations

import argparse
import os
import sys
import sys
import urllib.error

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scripts.scanlib import (
    DEFAULT_REPO_CONFIG_PATH,
    GitHubClient,
    extract_tree_paths,
    fetch_repo_config,
    fetch_repo_tree,
    find_dockerfiles,
    load_yaml_file,
    should_skip_repo,
    utc_now_isoformat,
    write_json_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True, help="GitHub organization to inspect")
    parser.add_argument("--token", required=True, help="GitHub token or GitHub App token")
    parser.add_argument("--policy-file", required=True, help="Path to org policy YAML")
    parser.add_argument("--output", required=True, help="Path to write discovery JSON")
    parser.add_argument(
        "--repo-type",
        default="all",
        choices=["all", "public", "private", "member", "sources", "forks"],
        help="GitHub org repo listing filter",
    )
    return parser.parse_args()


def discover_repositories(org: str, client: GitHubClient, policy: dict, repo_type: str) -> dict:
    repos = client.paginated_json(f"/orgs/{org}/repos", params={"type": repo_type})
    config_path = policy.get("repo_config_path", DEFAULT_REPO_CONFIG_PATH)

    output = {
        "organization": org,
        "discovered_at": utc_now_isoformat(),
        "policy_snapshot": {
            "fork_policy": policy.get("fork_policy", "skip"),
            "archived_policy": policy.get("archived_policy", "skip"),
            "exclude_repos": policy.get("exclude_repos", []),
            "exclude_paths": policy.get("exclude_paths", []),
            "repo_config_path": config_path,
        },
        "repos": [],
    }

    for repo in repos:
        if should_skip_repo(repo, policy):
            output["repos"].append(
                {
                    "full_name": repo["full_name"],
                    "default_branch": repo.get("default_branch"),
                    "html_url": repo.get("html_url"),
                    "private": repo.get("private", False),
                    "archived": repo.get("archived", False),
                    "fork": repo.get("fork", False),
                    "eligible": False,
                    "reason": should_skip_repo(repo, policy),
                    "discovered_dockerfiles": [],
                    "repo_config": None,
                    "config_source": None,
                }
            )
            continue

        default_branch = repo.get("default_branch")
        if not default_branch:
            output["repos"].append(
                {
                    "full_name": repo["full_name"],
                    "default_branch": None,
                    "html_url": repo.get("html_url"),
                    "private": repo.get("private", False),
                    "archived": repo.get("archived", False),
                    "fork": repo.get("fork", False),
                    "eligible": False,
                    "reason": "missing_default_branch",
                    "discovered_dockerfiles": [],
                    "repo_config": None,
                    "config_source": None,
                }
            )
            continue

        try:
            tree_payload = fetch_repo_tree(client, repo["full_name"], default_branch)
            tree_paths = extract_tree_paths(tree_payload)
            dockerfiles = find_dockerfiles(tree_paths, policy.get("exclude_paths", []))
            repo_config, config_source = fetch_repo_config(client, repo["full_name"], default_branch, config_path)
            eligible = bool(dockerfiles) or bool(repo_config and repo_config.get("dockerfiles"))
            reason = "candidate" if eligible else "no_dockerfiles"
            if tree_payload.get("truncated"):
                reason = f"{reason};tree_truncated"
        except urllib.error.HTTPError as exc:
            dockerfiles = []
            repo_config = None
            config_source = None
            eligible = False
            reason = f"github_api_error:{exc.code}"

        output["repos"].append(
            {
                "full_name": repo["full_name"],
                "default_branch": default_branch,
                "html_url": repo.get("html_url"),
                "private": repo.get("private", False),
                "archived": repo.get("archived", False),
                "fork": repo.get("fork", False),
                "eligible": eligible,
                "reason": reason,
                "discovered_dockerfiles": dockerfiles,
                "repo_config": repo_config,
                "config_source": config_source,
            }
        )

    return output


def main() -> int:
    args = parse_args()
    policy = load_yaml_file(args.policy_file)
    client = GitHubClient(token=args.token)
    payload = discover_repositories(args.org, client, policy, args.repo_type)
    write_json_file(args.output, payload)
    eligible = sum(1 for repo in payload["repos"] if repo["eligible"])
    print(f"Discovered {eligible} eligible repositories in {args.org}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
