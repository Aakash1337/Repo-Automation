# Onboarding

## Purpose

This repository is the control plane for company-wide container security scanning. It discovers GitHub repositories with Dockerfiles, scans them on configurable GitHub Actions runners, and aggregates normalized security findings.

## Required GitHub Setup

Create and install a GitHub App with at least these permissions:

- Repository contents: `Read-only`
- Actions: `Read and write`
- Security events: `Read and write`
- Metadata: `Read-only`

Store the app credentials in this repository as:

- `ORG_SCAN_APP_ID`
- `ORG_SCAN_APP_PRIVATE_KEY`

Optional secrets for private registries:

- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`

Optional variables for private registries:

- `REGISTRY_HOST`

Optional repository or organization variables:

- `GITHUB_ORG`

## Runner Backends

The workflows support three execution modes:

- Blacksmith runners
- GitHub-hosted runners
- self-hosted GitHub Actions runners

Repository or organization variables control the backend:

- `DISCOVERY_RUNNER_LABEL`
- `SCAN_RUNNER_LABEL`
- `DOCKER_BUILDER_MODE`
- `TOOLING_MODE`
- `DOCKER_CACHE_MODE`
- `DOCKER_LOCAL_CACHE_DIR`

Recommended values:

- Blacksmith:
  - `DISCOVERY_RUNNER_LABEL=blacksmith-2vcpu-ubuntu-2404`
  - `SCAN_RUNNER_LABEL=blacksmith-4vcpu-ubuntu-2404`
  - `DOCKER_BUILDER_MODE=blacksmith`
- GitHub-hosted:
  - `DISCOVERY_RUNNER_LABEL=ubuntu-latest`
  - `SCAN_RUNNER_LABEL=ubuntu-latest`
  - `DOCKER_BUILDER_MODE=docker-buildx`
- Self-hosted:
  - `DISCOVERY_RUNNER_LABEL=self-hosted`
  - `SCAN_RUNNER_LABEL=self-hosted`
  - `DOCKER_BUILDER_MODE=docker-buildx`
- Small-scale fast mode:
  - `DISCOVERY_RUNNER_LABEL=repo-scanner-fast`
  - `SCAN_RUNNER_LABEL=repo-scanner-fast`
  - `DOCKER_BUILDER_MODE=docker-buildx`
  - `TOOLING_MODE=preinstalled`
  - `DOCKER_CACHE_MODE=local`
  - `DOCKER_LOCAL_CACHE_DIR=/var/lib/repo-scanner/buildx-cache`

## Blacksmith Setup

Install the Blacksmith GitHub integration for the organization and ensure the runner labels used in the workflows are available:

- `blacksmith-2vcpu-ubuntu-2404`
- `blacksmith-4vcpu-ubuntu-2404`

The reusable workflow uses:

- `useblacksmith/setup-docker-builder@v1`
- `useblacksmith/build-push-action@v2`

These provide Docker layer caching for repeated scans.

## Self-Hosted Alternative

For regular repositories or personal accounts where Blacksmith is not available, use a small self-hosted runner setup instead of trying to build a full Blacksmith clone.

Recommended minimal design:

- one or two ephemeral Linux VMs
- GitHub self-hosted runner service
- Docker Buildx with persistent local cache or `type=gha`
- a prebaked runner image with Trivy, Syft, Hadolint, and Gitleaks already installed

This keeps the speed benefits concentrated where they matter:

- warm Docker layers
- preinstalled tooling
- faster dependency downloads
- no repeated runner bootstrap on every job

## Small-Scale Fast Mode

This repo now includes a dedicated fast mode for ordinary repositories. It is designed for one VM or a small runner pool rather than an organization-wide hosted runner product.

Files:

- `docker/fast-runner.Dockerfile`
- `scripts/bootstrap_fast_runner.sh`

Recommended setup:

1. Create a Linux VM with enough local disk for Docker layers.
2. Run `scripts/bootstrap_fast_runner.sh` as root.
3. Install the GitHub self-hosted runner service on that VM.
4. Label the runner `repo-scanner-fast`.
5. Set the repository or organization variables shown above.

How it speeds things up:

- scanner binaries are preinstalled on the runner
- Docker Buildx uses a persistent local cache directory
- the workflow skips repeated tool download/setup steps
- the runner can be reused across personal or small-team repositories

## Exception Handling

Repository-level CVE suppressions are supported through `.github/security-container-scan.yml`.

Example:

```yaml
allowlist_cves:
  - CVE-2024-12345
  - CVE-2023-99999
```

Current behavior:

- allowlisted CVEs are removed from vulnerability totals and policy evaluation
- suppressed counts are still recorded in `scan-summary.json`
- suppression is applied only to image vulnerability results, not secrets or misconfigurations

## Private Registry Support

If images require access to private base images, set:

- `REGISTRY_HOST`
- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`

The reusable scan workflow logs in before building when those values are present.

## Repository Layout

- `.github/workflows/discover-and-dispatch.yml`: scheduled orchestration workflow
- `.github/workflows/reusable-container-scan.yml`: reusable target scan workflow
- `config/org-scan-policy.yaml`: organization defaults
- `scripts/discover_repos.py`: repository discovery via GitHub API
- `scripts/select_docker_targets.py`: target matrix generation
- `scripts/normalize_results.py`: per-target and org-wide result normalization

## Per-Repository Override File

Target repositories can optionally define:

- `.github/security-container-scan.yml`

Supported fields:

- `enabled`
- `dockerfiles`
- `build_contexts`
- `severity_threshold`
- `ignore_unfixed`
- `allowlist_cves`
- `skip_secret_scan`
- `skip_build`

An example file is included at `.github/security-container-scan.example.yml`.

## Local Validation

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
bash scripts/run_v1_smoke_test.sh
```

To test the reusable workflow manually, run it with `workflow_dispatch` and provide:

- `repository`
- `ref`
- `dockerfile_path`
- `build_context`
- `image_name`

## Expected Outputs

Per target:

- `scan-summary.json`
- `scan-summary.md`
- `sbom.cdx.json`
- `trivy-image.sarif`
- `trivy-config.sarif`
- raw JSON reports

Organization level:

- `org-scan-summary.json`
- `org-scan-summary.csv`
- `org-scan-summary.md`

## Rollout Notes

- Start with advisory mode in `config/org-scan-policy.yaml`.
- Pilot on a subset of repositories first by populating `exclude_repos` inversely or using manual workflow dispatch.
- After validating noise levels, tighten `default_severity_threshold` and switch selected repositories to `policy_mode: enforce`.
