from __future__ import annotations

import unittest

from scripts.select_docker_targets import build_targets


class SelectDockerTargetsTests(unittest.TestCase):
    def test_build_targets_uses_repo_overrides(self) -> None:
        discovery_payload = {
            "organization": "acme",
            "repos": [
                {
                    "full_name": "acme/payments",
                    "default_branch": "main",
                    "eligible": True,
                    "reason": "candidate",
                    "discovered_dockerfiles": ["Dockerfile", "ops/Dockerfile"],
                    "repo_config": {
                        "dockerfiles": ["ops/Dockerfile"],
                        "build_contexts": {"ops/Dockerfile": "."},
                        "severity_threshold": "high",
                        "ignore_unfixed": False,
                        "skip_secret_scan": True,
                    },
                }
            ],
        }
        policy = {
            "default_registry_prefix": "localscan",
            "default_policy_mode": "advisory",
            "default_severity_threshold": "critical",
            "ignore_unfixed": True,
            "max_dockerfiles_per_repo": 10,
        }

        matrix, inventory = build_targets(discovery_payload, policy)

        self.assertEqual(inventory["target_count"], 1)
        target = matrix["include"][0]
        self.assertEqual(target["dockerfile_path"], "ops/Dockerfile")
        self.assertEqual(target["build_context"], ".")
        self.assertEqual(target["severity_threshold"], "high")
        self.assertFalse(target["ignore_unfixed"])
        self.assertTrue(target["skip_secret_scan"])

    def test_disabled_repo_is_skipped(self) -> None:
        discovery_payload = {
            "organization": "acme",
            "repos": [
                {
                    "full_name": "acme/disabled",
                    "default_branch": "main",
                    "eligible": True,
                    "reason": "candidate",
                    "discovered_dockerfiles": ["Dockerfile"],
                    "repo_config": {"enabled": False},
                }
            ],
        }
        policy = {"default_registry_prefix": "localscan", "max_dockerfiles_per_repo": 10}

        matrix, inventory = build_targets(discovery_payload, policy)

        self.assertEqual(matrix["include"], [])
        self.assertEqual(inventory["skipped"][0]["reason"], "disabled_by_repo_config")


if __name__ == "__main__":
    unittest.main()
