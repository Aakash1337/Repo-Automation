from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.discover_repos import discover_repositories


class FakeGitHubClient:
    def __init__(self, repos: list[dict]) -> None:
        self.repos = repos
        self.calls: list[tuple[str, dict]] = []

    def paginated_json(self, path: str, params: dict | None = None) -> list[dict]:
        self.calls.append((path, params or {}))
        return self.repos


class DiscoverRepositoriesTests(unittest.TestCase):
    def test_discover_repositories_filters_and_marks_candidates(self) -> None:
        repos = [
            {
                "full_name": "acme/api",
                "default_branch": "main",
                "html_url": "https://github.com/acme/api",
                "private": True,
                "archived": False,
                "fork": False,
            },
            {
                "full_name": "acme/forked",
                "default_branch": "main",
                "html_url": "https://github.com/acme/forked",
                "private": False,
                "archived": False,
                "fork": True,
            },
            {
                "full_name": "acme/archived",
                "default_branch": "main",
                "html_url": "https://github.com/acme/archived",
                "private": False,
                "archived": True,
                "fork": False,
            },
            {
                "full_name": "acme/config-only",
                "default_branch": "main",
                "html_url": "https://github.com/acme/config-only",
                "private": False,
                "archived": False,
                "fork": False,
            },
        ]
        client = FakeGitHubClient(repos)
        policy = {
            "fork_policy": "skip",
            "archived_policy": "skip",
            "exclude_repos": [],
            "exclude_paths": ["vendor/"],
            "repo_config_path": ".github/security-container-scan.yml",
        }

        def fake_tree(_client: FakeGitHubClient, full_name: str, _ref: str) -> dict:
            if full_name == "acme/api":
                return {
                    "tree": [
                        {"path": "Dockerfile", "type": "blob"},
                        {"path": "vendor/ignored/Dockerfile", "type": "blob"},
                    ]
                }
            if full_name == "acme/config-only":
                return {"tree": [{"path": "README.md", "type": "blob"}]}
            return {"tree": []}

        def fake_config(_client: FakeGitHubClient, full_name: str, _ref: str, _config_path: str) -> tuple[dict | None, str | None]:
            if full_name == "acme/config-only":
                return ({"dockerfiles": ["docker/app/Dockerfile"]}, ".github/security-container-scan.yml")
            return (None, None)

        with patch("scripts.discover_repos.fetch_repo_tree", side_effect=fake_tree), patch(
            "scripts.discover_repos.fetch_repo_config", side_effect=fake_config
        ):
            result = discover_repositories("acme", client, policy, "private")

        self.assertEqual(client.calls[0], ("/orgs/acme/repos", {"type": "private"}))
        self.assertEqual(len(result["repos"]), 4)

        api_repo = next(item for item in result["repos"] if item["full_name"] == "acme/api")
        self.assertTrue(api_repo["eligible"])
        self.assertEqual(api_repo["discovered_dockerfiles"], ["Dockerfile"])
        self.assertEqual(api_repo["reason"], "candidate")

        config_repo = next(item for item in result["repos"] if item["full_name"] == "acme/config-only")
        self.assertTrue(config_repo["eligible"])
        self.assertEqual(config_repo["repo_config"], {"dockerfiles": ["docker/app/Dockerfile"]})
        self.assertEqual(config_repo["config_source"], ".github/security-container-scan.yml")

        fork_repo = next(item for item in result["repos"] if item["full_name"] == "acme/forked")
        self.assertFalse(fork_repo["eligible"])
        self.assertEqual(fork_repo["reason"], "fork")

        archived_repo = next(item for item in result["repos"] if item["full_name"] == "acme/archived")
        self.assertFalse(archived_repo["eligible"])
        self.assertEqual(archived_repo["reason"], "archived")


if __name__ == "__main__":
    unittest.main()
