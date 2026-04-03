from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class V1SmokeTests(unittest.TestCase):
    def test_cli_smoke_path_builds_matrix_and_aggregates(self) -> None:
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            matrix_path = tmp / "matrix.json"
            inventory_path = tmp / "inventory.json"
            aggregate_json = tmp / "org-scan-summary.json"
            aggregate_csv = tmp / "org-scan-summary.csv"
            aggregate_markdown = tmp / "org-scan-summary.md"
            artifacts_dir = tmp / "downloaded"
            (artifacts_dir / "api").mkdir(parents=True)
            (artifacts_dir / "web").mkdir(parents=True)

            (artifacts_dir / "api" / "scan-summary.json").write_text(
                (root / "testdata/results/api-scan-summary.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (artifacts_dir / "web" / "scan-summary.json").write_text(
                (root / "testdata/results/web-scan-summary.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts/select_docker_targets.py"),
                    "--discovery-file",
                    str(root / "testdata/discovery/sample-discovery.json"),
                    "--policy-file",
                    str(root / "testdata/policy/org-scan-policy.test.yaml"),
                    "--matrix-out",
                    str(matrix_path),
                    "--inventory-out",
                    str(inventory_path),
                ],
                check=True,
                cwd=root,
            )

            subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts/normalize_results.py"),
                    "aggregate",
                    "--artifacts-dir",
                    str(artifacts_dir),
                    "--output-json",
                    str(aggregate_json),
                    "--output-csv",
                    str(aggregate_csv),
                    "--output-markdown",
                    str(aggregate_markdown),
                ],
                check=True,
                cwd=root,
            )

            matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            aggregate = json.loads(aggregate_json.read_text(encoding="utf-8"))
            markdown = aggregate_markdown.read_text(encoding="utf-8")

            self.assertEqual(len(matrix["include"]), 3)
            self.assertEqual(inventory["target_count"], 3)
            api_root = next(item for item in matrix["include"] if item["repository"] == "acme/api" and item["dockerfile_path"] == "Dockerfile")
            self.assertEqual(api_root["allowlist_cves"], ["CVE-2024-1111"])
            self.assertEqual(api_root["severity_threshold"], "high")
            self.assertEqual(aggregate["target_count"], 2)
            self.assertEqual(aggregate["non_pass_count"], 2)
            self.assertEqual(aggregate["vulnerability_totals"]["critical"], 1)
            self.assertEqual(aggregate["vulnerability_totals"]["high"], 2)
            self.assertIn("Top Risky Repositories", markdown)


if __name__ == "__main__":
    unittest.main()
