#!/usr/bin/env python3
"""Normalize scan outputs into per-target and org-wide summaries."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scripts.scanlib import (
    count_gitleaks_findings,
    count_hadolint_issues,
    evaluate_policy,
    filter_trivy_vulnerabilities,
    read_json_file,
    summarize_trivy_json,
    utc_now_isoformat,
    write_csv_file,
    write_json_file,
    write_text_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    single = subparsers.add_parser("scan-summary", help="Create a normalized summary for one scan target")
    single.add_argument("--repository", required=True)
    single.add_argument("--ref", required=True)
    single.add_argument("--dockerfile-path", required=True)
    single.add_argument("--image-name", required=True)
    single.add_argument("--policy-mode", required=True)
    single.add_argument("--severity-threshold", required=True)
    single.add_argument("--ignore-unfixed", required=True)
    single.add_argument("--build-status", required=True)
    single.add_argument("--artifact-bundle-name", required=True)
    single.add_argument("--allowlist-cves", default="[]")
    single.add_argument("--hadolint", required=True)
    single.add_argument("--trivy-image", required=True)
    single.add_argument("--trivy-config", required=True)
    single.add_argument("--gitleaks", required=True)
    single.add_argument("--sbom", required=True)
    single.add_argument("--output", required=True)
    single.add_argument("--markdown-output", required=True)

    aggregate = subparsers.add_parser("aggregate", help="Aggregate normalized scan summaries")
    aggregate.add_argument("--artifacts-dir", required=True)
    aggregate.add_argument("--output-json", required=True)
    aggregate.add_argument("--output-csv", required=True)
    aggregate.add_argument("--output-markdown", required=True)

    return parser.parse_args()


def render_scan_markdown(summary: dict) -> str:
    vuln_counts = summary["vuln_counts"]
    return "\n".join(
        [
            f"### {summary['repo']} :: {summary['dockerfile_path']}",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Policy Result | {summary['policy_result']} |",
            f"| Build Status | {summary['build_status']} |",
            f"| Critical | {vuln_counts['critical']} |",
            f"| High | {vuln_counts['high']} |",
            f"| Medium | {vuln_counts['medium']} |",
            f"| Low | {vuln_counts['low']} |",
            f"| Misconfigurations | {summary['misconfiguration_count']} |",
            f"| Dockerfile Lint Issues | {summary['hadolint_issues']} |",
            f"| Secret Findings | {summary['secret_findings']} |",
            f"| Suppressed CVEs | {sum(summary.get('suppressed_vuln_counts', {}).values())} |",
            "",
        ]
    )


def create_scan_summary(args: argparse.Namespace) -> int:
    hadolint = read_json_file(args.hadolint) or []
    trivy_image = read_json_file(args.trivy_image) or {}
    trivy_config = read_json_file(args.trivy_config) or {}
    gitleaks = read_json_file(args.gitleaks) or []
    sbom_path = args.sbom if Path(args.sbom).exists() else ""
    allowlist_cves = json.loads(args.allowlist_cves or "[]")

    hadolint_issues = count_hadolint_issues(hadolint)
    filtered_trivy_image, suppressed_vuln_counts = filter_trivy_vulnerabilities(trivy_image, allowlist_cves)
    trivy_image_summary = summarize_trivy_json(filtered_trivy_image)
    trivy_config_summary = summarize_trivy_json(trivy_config)
    secret_findings = count_gitleaks_findings(gitleaks)
    ignore_unfixed = args.ignore_unfixed.lower() == "true"

    policy_result = evaluate_policy(
        args.policy_mode,
        args.severity_threshold,
        ignore_unfixed,
        trivy_image_summary,
        trivy_config_summary,
        secret_findings,
        hadolint_issues,
        args.build_status,
    )

    summary = {
        "repo": args.repository,
        "ref": args.ref,
        "dockerfile_path": args.dockerfile_path,
        "image_name": args.image_name,
        "scan_time": utc_now_isoformat(),
        "vuln_counts": trivy_image_summary["vulnerability_counts"],
        "fixable_vuln_counts": trivy_image_summary["fixable_counts"],
        "suppressed_vuln_counts": suppressed_vuln_counts,
        "critical_with_fixes": trivy_image_summary["fixable_counts"].get("critical", 0),
        "policy_result": policy_result,
        "policy_mode": args.policy_mode,
        "severity_threshold": args.severity_threshold,
        "ignore_unfixed": ignore_unfixed,
        "allowlist_cves": allowlist_cves,
        "secret_findings": secret_findings,
        "hadolint_issues": hadolint_issues,
        "misconfiguration_count": trivy_config_summary["total_misconfigurations"],
        "misconfiguration_counts": trivy_config_summary["misconfiguration_counts"],
        "build_status": args.build_status,
        "sbom_artifact_path": sbom_path,
        "artifact_bundle_name": args.artifact_bundle_name,
    }

    write_json_file(args.output, summary)
    write_text_file(args.markdown_output, render_scan_markdown(summary))
    print(json.dumps(summary, indent=2))
    return 0


def render_aggregate_markdown(org_summary: dict) -> str:
    top = org_summary["top_risky_repos"]
    lines = [
        "# Org Container Security Summary",
        "",
        f"- Targets scanned: {org_summary['target_count']}",
        f"- Repositories covered: {org_summary['repository_count']}",
        f"- Policy warnings/failures: {org_summary['non_pass_count']}",
        f"- Critical vulnerabilities: {org_summary['vulnerability_totals']['critical']}",
        f"- High vulnerabilities: {org_summary['vulnerability_totals']['high']}",
        f"- Secret findings: {org_summary['secret_findings_total']}",
        "",
        "## Top Risky Repositories",
        "",
        "| Repository | Critical | High | Results |",
        "| --- | --- | --- | --- |",
    ]
    if not top:
        lines.append("| None | 0 | 0 | pass |")
    for item in top:
        lines.append(
            f"| {item['repo']} | {item['critical']} | {item['high']} | {item['policy_results']} |"
        )
    lines.append("")
    return "\n".join(lines)


def aggregate_scan_summaries(args: argparse.Namespace) -> int:
    artifacts_dir = Path(args.artifacts_dir)
    summaries = []
    for candidate in artifacts_dir.rglob("scan-summary.json"):
        payload = read_json_file(candidate)
        if payload:
            summaries.append(payload)

    vulnerability_totals = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})
    repo_rollup: dict[str, Counter] = defaultdict(Counter)
    rows = []
    non_pass_count = 0
    secret_findings_total = 0

    for summary in summaries:
        vuln_counts = summary.get("vuln_counts", {})
        for severity, count in vuln_counts.items():
            vulnerability_totals[severity] += int(count)
        repo = summary["repo"]
        repo_rollup[repo]["critical"] += int(vuln_counts.get("critical", 0))
        repo_rollup[repo]["high"] += int(vuln_counts.get("high", 0))
        repo_rollup[repo][summary["policy_result"]] += 1
        non_pass_count += 1 if summary["policy_result"] != "pass" else 0
        secret_findings_total += int(summary.get("secret_findings", 0))
        rows.append(
            {
                "repo": repo,
                "ref": summary["ref"],
                "dockerfile_path": summary["dockerfile_path"],
                "image_name": summary["image_name"],
                "policy_result": summary["policy_result"],
                "build_status": summary["build_status"],
                "critical": vuln_counts.get("critical", 0),
                "high": vuln_counts.get("high", 0),
                "medium": vuln_counts.get("medium", 0),
                "low": vuln_counts.get("low", 0),
                "secret_findings": summary.get("secret_findings", 0),
                "artifact_bundle_name": summary["artifact_bundle_name"],
            }
        )

    top_risky = []
    for repo, counts in repo_rollup.items():
        top_risky.append(
            {
                "repo": repo,
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "policy_results": ", ".join(
                    f"{state}:{counts[state]}" for state in ("fail", "warn", "pass") if counts.get(state)
                )
                or "pass",
            }
        )
    top_risky.sort(key=lambda item: (item["critical"], item["high"], item["repo"]), reverse=True)

    org_summary = {
        "target_count": len(summaries),
        "repository_count": len(repo_rollup),
        "non_pass_count": non_pass_count,
        "secret_findings_total": secret_findings_total,
        "vulnerability_totals": dict(vulnerability_totals),
        "top_risky_repos": top_risky[:10],
        "results": summaries,
    }

    write_json_file(args.output_json, org_summary)
    write_csv_file(
        args.output_csv,
        rows,
        [
            "repo",
            "ref",
            "dockerfile_path",
            "image_name",
            "policy_result",
            "build_status",
            "critical",
            "high",
            "medium",
            "low",
            "secret_findings",
            "artifact_bundle_name",
        ],
    )
    write_text_file(args.output_markdown, render_aggregate_markdown(org_summary))
    print(json.dumps(org_summary, indent=2))
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "scan-summary":
        return create_scan_summary(args)
    if args.command == "aggregate":
        return aggregate_scan_summaries(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
