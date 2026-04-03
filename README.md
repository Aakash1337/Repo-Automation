# Repo Scanner

Centralized container security automation for GitHub organizations using GitHub Actions with support for Blacksmith, GitHub-hosted, or self-hosted runners.

This repository provides:

- org-wide repository discovery for repos containing Dockerfiles
- reusable container scanning workflows
- configurable runner backends for Blacksmith, GitHub-hosted, or self-hosted runners
- small-scale fast mode for ordinary repos using prewarmed self-hosted runners
- policy-driven target selection
- normalized per-scan and org-wide reports
- onboarding documentation for GitHub App authentication and rollout

## Repository Layout

- `.github/workflows/discover-and-dispatch.yml`: scheduled and manual orchestration workflow
- `.github/workflows/reusable-container-scan.yml`: reusable per-target scan workflow
- `config/org-scan-policy.yaml`: org-wide defaults and execution settings
- `scripts/`: discovery, selection, normalization, and helper scripts
- `testdata/`: smoke-test fixtures
- `tests/`: unit and CLI smoke tests
- `docs/onboarding.md`: setup and rollout guidance

## Quick Start

1. Create a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Run the automated test suite.
4. Run the V1 smoke test.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests -v
bash scripts/run_v1_smoke_test.sh
```

## GitHub Setup

Required secrets:

- `ORG_SCAN_APP_ID`
- `ORG_SCAN_APP_PRIVATE_KEY`

Optional secrets and variables for private registries:

- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`
- `REGISTRY_HOST`

See [Onboarding](docs/onboarding.md) for full setup details.

## Development Notes

- The reusable workflow supports `advisory` and `enforce` policy modes.
- Repository-level overrides can be defined in `.github/security-container-scan.yml`.
- Small-scale fast mode is intended for personal or small-team repos where Blacksmith is not available.

## Security Disclosure

If you discover a vulnerability in this automation, follow the process in [SECURITY.md](SECURITY.md).
