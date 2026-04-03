#!/usr/bin/env python3
"""Shared helpers for repo discovery, target selection, and result normalization."""

from __future__ import annotations

import base64
import csv
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_REPO_CONFIG_PATH = ".github/security-container-scan.yml"


@dataclass
class GitHubClient:
    token: str
    api_url: str = "https://api.github.com"

    def request_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = self._build_url(path, params)
        request = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(request) as response:
            return json.load(response)

    def request_text(self, path: str, params: dict[str, Any] | None = None) -> str:
        url = self._build_url(path, params)
        request = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            payload = json.loads(body)
            content = payload.get("content", "")
            if payload.get("encoding") == "base64":
                return base64.b64decode(content).decode("utf-8")
            return content

    def paginated_json(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        query = dict(params or {})
        query.setdefault("per_page", 100)
        page = 1
        items: list[Any] = []
        while True:
            query["page"] = page
            batch = self.request_json(path, params=query)
            if not batch:
                break
            if isinstance(batch, dict):
                items.append(batch)
                break
            items.extend(batch)
            if len(batch) < query["per_page"]:
                break
            page += 1
        return items

    def _build_url(self, path: str, params: dict[str, Any] | None) -> str:
        encoded_path = urllib.parse.quote(path, safe="/:?=&")
        if params:
            return f"{self.api_url}{encoded_path}?{urllib.parse.urlencode(params)}"
        return f"{self.api_url}{encoded_path}"

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-scanner",
        }


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML document at {path} must be a mapping")
    return data


def load_yaml_text(text: str) -> dict[str, Any]:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML document must be a mapping")
    return data


def find_dockerfiles(paths: list[str], exclude_prefixes: list[str] | None = None) -> list[str]:
    exclude_prefixes = [prefix.strip("/") + "/" for prefix in (exclude_prefixes or []) if prefix]
    candidates: list[str] = []
    for path in paths:
        normalized = path.lstrip("./")
        lowered = normalized.lower()
        if os.path.basename(lowered) != "dockerfile":
            continue
        if any(normalized.startswith(prefix) for prefix in exclude_prefixes):
            continue
        candidates.append(normalized)
    return sorted(set(candidates))


def infer_build_context(dockerfile_path: str) -> str:
    parent = str(Path(dockerfile_path).parent).replace("\\", "/")
    return "." if parent in ("", ".") else parent


def sanitize_image_name(repository: str, dockerfile_path: str, registry_prefix: str) -> str:
    repo_name = repository.split("/")[-1].lower()
    suffix = Path(dockerfile_path).parent.as_posix().replace("/", "-").strip("-") or "root"
    suffix = re.sub(r"[^a-z0-9._-]+", "-", suffix.lower())
    registry_prefix = registry_prefix.rstrip("/")
    return f"{registry_prefix}/{repo_name}:{suffix}"


def should_skip_repo(repo: dict[str, Any], policy: dict[str, Any]) -> str | None:
    full_name = repo["full_name"]
    if repo.get("archived") and policy.get("archived_policy", "skip") == "skip":
        return "archived"
    if repo.get("fork") and policy.get("fork_policy", "skip") == "skip":
        return "fork"
    if full_name in set(policy.get("exclude_repos", [])):
        return "excluded_by_policy"
    return None


def merge_repo_config(policy: dict[str, Any], repo_config: dict[str, Any] | None) -> dict[str, Any]:
    repo_config = repo_config or {}
    defaults = {
        "enabled": True,
        "dockerfiles": [],
        "build_contexts": {},
        "severity_threshold": policy.get("default_severity_threshold", "critical"),
        "ignore_unfixed": policy.get("ignore_unfixed", True),
        "allowlist_cves": [],
        "skip_secret_scan": False,
        "skip_build": False,
        "policy_mode": policy.get("default_policy_mode", "advisory"),
    }
    merged = dict(defaults)
    merged.update(repo_config)
    return merged


def choose_target_paths(
    discovered_dockerfiles: list[str],
    merged_config: dict[str, Any],
    max_targets: int,
) -> list[str]:
    configured = [path.lstrip("./") for path in merged_config.get("dockerfiles", [])]
    source = configured or discovered_dockerfiles
    unique = []
    for path in source:
        if path and path not in unique:
            unique.append(path)
    return unique[:max_targets]


def fetch_repo_tree(client: GitHubClient, full_name: str, ref: str) -> dict[str, Any]:
    ref = urllib.parse.quote(ref, safe="")
    return client.request_json(f"/repos/{full_name}/git/trees/{ref}", params={"recursive": 1})


def fetch_repo_config(
    client: GitHubClient,
    full_name: str,
    ref: str,
    config_path: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        config_text = client.request_text(f"/repos/{full_name}/contents/{config_path}", params={"ref": ref})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        raise
    return load_yaml_text(config_text), config_path


def extract_tree_paths(tree_payload: dict[str, Any]) -> list[str]:
    return [entry["path"] for entry in tree_payload.get("tree", []) if entry.get("type") == "blob"]


def count_hadolint_issues(data: Any) -> int:
    return len(data) if isinstance(data, list) else 0


def summarize_trivy_json(data: Any) -> dict[str, Any]:
    counts = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})
    fixable = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})
    misconfigs = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})

    if not isinstance(data, dict):
        return {
            "vulnerability_counts": dict(counts),
            "fixable_counts": dict(fixable),
            "misconfiguration_counts": dict(misconfigs),
            "total_vulnerabilities": 0,
            "total_misconfigurations": 0,
        }

    for result in data.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = str(vulnerability.get("Severity", "unknown")).lower()
            counts[severity] += 1
            if vulnerability.get("FixedVersion"):
                fixable[severity] += 1
        for misconfiguration in result.get("Misconfigurations", []) or []:
            severity = str(misconfiguration.get("Severity", "unknown")).lower()
            misconfigs[severity] += 1

    return {
        "vulnerability_counts": dict(counts),
        "fixable_counts": dict(fixable),
        "misconfiguration_counts": dict(misconfigs),
        "total_vulnerabilities": sum(counts.values()),
        "total_misconfigurations": sum(misconfigs.values()),
    }


def filter_trivy_vulnerabilities(data: Any, allowlist_cves: list[str] | None = None) -> tuple[Any, dict[str, int]]:
    allowlist = {cve.strip().upper() for cve in (allowlist_cves or []) if cve and cve.strip()}
    suppressed = Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})
    if not allowlist or not isinstance(data, dict):
        return data, dict(suppressed)

    filtered = json.loads(json.dumps(data))
    for result in filtered.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities") or []
        kept = []
        for vulnerability in vulnerabilities:
            vuln_id = str(vulnerability.get("VulnerabilityID", "")).upper()
            if vuln_id in allowlist:
                severity = str(vulnerability.get("Severity", "unknown")).lower()
                suppressed[severity] += 1
                continue
            kept.append(vulnerability)
        result["Vulnerabilities"] = kept
    return filtered, dict(suppressed)


def utc_now_isoformat() -> str:
    return datetime.now(timezone.utc).isoformat()


def count_gitleaks_findings(data: Any) -> int:
    return len(data) if isinstance(data, list) else 0


def severity_exceeds_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(threshold.lower(), 0)


def evaluate_policy(
    policy_mode: str,
    severity_threshold: str,
    ignore_unfixed: bool,
    trivy_image_summary: dict[str, Any],
    trivy_config_summary: dict[str, Any],
    secret_findings: int,
    hadolint_issues: int,
    build_status: str,
) -> str:
    findings_present = (
        trivy_image_summary.get("total_vulnerabilities", 0) > 0
        or trivy_config_summary.get("total_misconfigurations", 0) > 0
        or secret_findings > 0
        or hadolint_issues > 0
        or build_status in {"build_failed", "auth_required"}
    )
    if policy_mode != "enforce":
        return "warn" if findings_present else "pass"

    vuln_source = (
        trivy_image_summary.get("fixable_counts", {})
        if ignore_unfixed
        else trivy_image_summary.get("vulnerability_counts", {})
    )
    for severity, count in vuln_source.items():
        if count and severity_exceeds_threshold(severity, severity_threshold):
            return "fail"
    for severity, count in trivy_config_summary.get("misconfiguration_counts", {}).items():
        if count and severity_exceeds_threshold(severity, severity_threshold):
            return "fail"
    if secret_findings > 0:
        return "fail"
    if hadolint_issues > 0 and severity_threshold in {"low", "medium"}:
        return "fail"
    if build_status == "auth_required":
        return "fail"
    return "pass"


def read_json_file(path: str | Path) -> Any:
    target = Path(path)
    if not target.exists():
        return None
    with open(target, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv_file(path: str | Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_text_file(path: str | Path, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(content)
