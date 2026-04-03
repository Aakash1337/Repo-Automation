# Contributing

## Scope

This repository is the control plane for container security scanning automation. Contributions should improve reliability, security coverage, or operator usability without weakening default security posture.

## Workflow

1. Create a branch from `main`.
2. Make focused changes.
3. Run the local validation steps.
4. Open a pull request with test evidence and rollout impact.

## Required Validation

Run these before opening a pull request:

```bash
python3 -m unittest discover -s tests -v
bash scripts/run_v1_smoke_test.sh
python3 -m py_compile scripts/*.py tests/*.py
```

## Change Expectations

- Keep policy defaults secure by default.
- Preserve compatibility with GitHub-hosted, self-hosted, and Blacksmith runner modes.
- Add or update tests for behavior changes.
- Document any new secrets, variables, or operator steps in `docs/onboarding.md`.

## Pull Request Content

Each pull request should explain:

- what changed
- why it changed
- how it was tested
- whether rollout or secret changes are required
