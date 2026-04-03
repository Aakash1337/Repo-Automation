from __future__ import annotations

import unittest

from scripts.scanlib import find_dockerfiles, infer_build_context, merge_repo_config, sanitize_image_name


class ScanLibTests(unittest.TestCase):
    def test_find_dockerfiles_filters_excluded_paths(self) -> None:
        paths = [
            "Dockerfile",
            "services/api/Dockerfile",
            "vendor/library/Dockerfile",
            "README.md",
        ]

        result = find_dockerfiles(paths, ["vendor/"])

        self.assertEqual(result, ["Dockerfile", "services/api/Dockerfile"])

    def test_infer_build_context(self) -> None:
        self.assertEqual(infer_build_context("Dockerfile"), ".")
        self.assertEqual(infer_build_context("services/api/Dockerfile"), "services/api")

    def test_merge_repo_config_defaults(self) -> None:
        policy = {"default_policy_mode": "advisory", "default_severity_threshold": "critical", "ignore_unfixed": True}

        merged = merge_repo_config(policy, {"skip_build": True})

        self.assertTrue(merged["enabled"])
        self.assertEqual(merged["severity_threshold"], "critical")
        self.assertTrue(merged["skip_build"])

    def test_sanitize_image_name(self) -> None:
        image = sanitize_image_name("acme/payments", "services/api/Dockerfile", "localscan")

        self.assertEqual(image, "localscan/payments:services-api")


if __name__ == "__main__":
    unittest.main()
