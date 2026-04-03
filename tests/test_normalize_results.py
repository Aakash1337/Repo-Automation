from __future__ import annotations

import argparse
import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_results import aggregate_scan_summaries, create_scan_summary
from scripts.scanlib import evaluate_policy, filter_trivy_vulnerabilities, summarize_trivy_json


class NormalizeResultsTests(unittest.TestCase):
    def test_summarize_trivy_json_counts_fixable_vulns(self) -> None:
        payload = {
            "Results": [
                {
                    "Target": "image",
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL", "FixedVersion": "1.2.3"},
                        {"Severity": "HIGH", "FixedVersion": ""},
                        {"Severity": "HIGH", "FixedVersion": "2.0.0"},
                    ],
                }
            ]
        }

        summary = summarize_trivy_json(payload)

        self.assertEqual(summary["vulnerability_counts"]["critical"], 1)
        self.assertEqual(summary["vulnerability_counts"]["high"], 2)
        self.assertEqual(summary["fixable_counts"]["critical"], 1)
        self.assertEqual(summary["fixable_counts"]["high"], 1)

    def test_enforce_mode_respects_ignore_unfixed(self) -> None:
        trivy_image = {
            "vulnerability_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "fixable_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "total_vulnerabilities": 1,
        }
        trivy_config = {
            "misconfiguration_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "total_misconfigurations": 0,
        }

        result = evaluate_policy(
            "enforce",
            "critical",
            True,
            trivy_image,
            trivy_config,
            secret_findings=0,
            hadolint_issues=0,
            build_status="built",
        )

        self.assertEqual(result, "pass")

    def test_filter_trivy_vulnerabilities_suppresses_allowlisted_cves(self) -> None:
        payload = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL", "FixedVersion": "1.0.0"},
                        {"VulnerabilityID": "CVE-2024-0002", "Severity": "HIGH", "FixedVersion": ""},
                    ]
                }
            ]
        }

        filtered, suppressed = filter_trivy_vulnerabilities(payload, ["CVE-2024-0002"])
        summary = summarize_trivy_json(filtered)

        self.assertEqual(summary["vulnerability_counts"]["critical"], 1)
        self.assertEqual(summary["vulnerability_counts"]["high"], 0)
        self.assertEqual(suppressed["high"], 1)

    def test_create_scan_summary_writes_expected_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hadolint_path = tmp / "hadolint.json"
            trivy_image_path = tmp / "trivy-image.json"
            trivy_config_path = tmp / "trivy-config.json"
            gitleaks_path = tmp / "gitleaks.json"
            sbom_path = tmp / "sbom.cdx.json"
            output_path = tmp / "scan-summary.json"
            markdown_path = tmp / "scan-summary.md"

            hadolint_path.write_text(json.dumps([{"code": "DL3008"}]), encoding="utf-8")
            trivy_image_path.write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Vulnerabilities": [
                                    {"Severity": "CRITICAL", "FixedVersion": "1.0.1", "VulnerabilityID": "CVE-2024-0001"},
                                    {"Severity": "HIGH", "FixedVersion": "", "VulnerabilityID": "CVE-2024-0002"},
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trivy_config_path.write_text(
                json.dumps({"Results": [{"Misconfigurations": [{"Severity": "MEDIUM"}]}]}),
                encoding="utf-8",
            )
            gitleaks_path.write_text(json.dumps([{"ruleID": "generic-api-key"}]), encoding="utf-8")
            sbom_path.write_text("{}", encoding="utf-8")

            args = argparse.Namespace(
                repository="acme/api",
                ref="main",
                dockerfile_path="Dockerfile",
                image_name="localscan/api:root",
                policy_mode="advisory",
                severity_threshold="critical",
                ignore_unfixed="true",
                build_status="built",
                artifact_bundle_name="scan-summary-acme-api-dockerfile",
                allowlist_cves='["CVE-2024-0002"]',
                hadolint=str(hadolint_path),
                trivy_image=str(trivy_image_path),
                trivy_config=str(trivy_config_path),
                gitleaks=str(gitleaks_path),
                sbom=str(sbom_path),
                output=str(output_path),
                markdown_output=str(markdown_path),
            )

            exit_code = create_scan_summary(args)

            self.assertEqual(exit_code, 0)
            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["repo"], "acme/api")
            self.assertEqual(summary["policy_result"], "warn")
            self.assertEqual(summary["critical_with_fixes"], 1)
            self.assertEqual(summary["vuln_counts"]["high"], 0)
            self.assertEqual(summary["suppressed_vuln_counts"]["high"], 1)
            self.assertEqual(summary["hadolint_issues"], 1)
            self.assertEqual(summary["secret_findings"], 1)
            self.assertEqual(summary["misconfiguration_count"], 1)
            self.assertEqual(summary["sbom_artifact_path"], str(sbom_path))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("acme/api :: Dockerfile", markdown)
            self.assertIn("| Policy Result | warn |", markdown)
            self.assertIn("| Suppressed CVEs | 1 |", markdown)

    def test_aggregate_scan_summaries_rolls_up_multiple_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            first_dir = tmp / "scan-1"
            second_dir = tmp / "scan-2"
            first_dir.mkdir()
            second_dir.mkdir()

            (first_dir / "scan-summary.json").write_text(
                json.dumps(
                    {
                        "repo": "acme/api",
                        "ref": "main",
                        "dockerfile_path": "Dockerfile",
                        "image_name": "localscan/api:root",
                        "policy_result": "warn",
                        "build_status": "built",
                        "secret_findings": 1,
                        "artifact_bundle_name": "bundle-1",
                        "vuln_counts": {"critical": 2, "high": 1, "medium": 0, "low": 0, "unknown": 0},
                    }
                ),
                encoding="utf-8",
            )
            (second_dir / "scan-summary.json").write_text(
                json.dumps(
                    {
                        "repo": "acme/web",
                        "ref": "main",
                        "dockerfile_path": "docker/Dockerfile",
                        "image_name": "localscan/web:docker",
                        "policy_result": "pass",
                        "build_status": "built",
                        "secret_findings": 0,
                        "artifact_bundle_name": "bundle-2",
                        "vuln_counts": {"critical": 0, "high": 3, "medium": 2, "low": 1, "unknown": 0},
                    }
                ),
                encoding="utf-8",
            )

            output_json = tmp / "org-scan-summary.json"
            output_csv = tmp / "org-scan-summary.csv"
            output_markdown = tmp / "org-scan-summary.md"

            args = argparse.Namespace(
                artifacts_dir=str(tmp),
                output_json=str(output_json),
                output_csv=str(output_csv),
                output_markdown=str(output_markdown),
            )

            exit_code = aggregate_scan_summaries(args)

            self.assertEqual(exit_code, 0)
            aggregate = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual(aggregate["target_count"], 2)
            self.assertEqual(aggregate["repository_count"], 2)
            self.assertEqual(aggregate["non_pass_count"], 1)
            self.assertEqual(aggregate["secret_findings_total"], 1)
            self.assertEqual(aggregate["vulnerability_totals"]["critical"], 2)
            self.assertEqual(aggregate["vulnerability_totals"]["high"], 4)
            self.assertEqual(aggregate["top_risky_repos"][0]["repo"], "acme/api")

            markdown = output_markdown.read_text(encoding="utf-8")
            self.assertIn("Targets scanned: 2", markdown)
            self.assertIn("| acme/api | 2 | 1 | warn:1 |", markdown)

            with output_csv.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["repo"], "acme/api")


if __name__ == "__main__":
    unittest.main()
