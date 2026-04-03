#!/usr/bin/env bash
set -euo pipefail

# Provision a small self-hosted runner node for the repo-scanner fast mode.
# This script installs Docker, buildx, and the security scanners that the
# reusable workflow can reuse without downloading them on every run.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

RUNNER_USER="${RUNNER_USER:-${SUDO_USER:-runner}}"
CACHE_DIR="${CACHE_DIR:-/var/lib/repo-scanner/buildx-cache}"
TOOLS_DIR="${TOOLS_DIR:-/usr/local/bin}"
TRIVY_VERSION="${TRIVY_VERSION:-0.63.0}"
SYFT_VERSION="${SYFT_VERSION:-v1.24.0}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.3}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-v8.24.2}"
HADOLINT_VERSION="${HADOLINT_VERSION:-v2.12.0}"

ARCH="$(dpkg --print-architecture)"
case "${ARCH}" in
  amd64)
    HADOLINT_ARCH="x86_64"
    COSIGN_ARCH="x86_64"
    ;;
  arm64)
    HADOLINT_ARCH="arm64"
    COSIGN_ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl docker.io git jq python3 python3-pip tar

mkdir -p "${CACHE_DIR}"
chown -R "${RUNNER_USER}:${RUNNER_USER}" "${CACHE_DIR}"

install -m 0755 /dev/null "${TOOLS_DIR}/hadolint"
curl -fsSL "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-${HADOLINT_ARCH}" -o "${TOOLS_DIR}/hadolint"
chmod +x "${TOOLS_DIR}/hadolint"

curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C "${TOOLS_DIR}" gitleaks
rm -f /tmp/gitleaks.tar.gz

curl -fsSL "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/syft.tar.gz
tar -xzf /tmp/syft.tar.gz -C "${TOOLS_DIR}" syft
rm -f /tmp/syft.tar.gz

curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${COSIGN_ARCH}" -o "${TOOLS_DIR}/cosign"
chmod +x "${TOOLS_DIR}/cosign"

curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" -o /tmp/trivy.tar.gz
tar -xzf /tmp/trivy.tar.gz -C "${TOOLS_DIR}" trivy
rm -f /tmp/trivy.tar.gz

if ! docker buildx version >/dev/null 2>&1; then
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/buildx/releases/latest/download/buildx-linux-${ARCH}" -o /usr/local/lib/docker/cli-plugins/docker-buildx
  chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
fi

usermod -aG docker "${RUNNER_USER}" || true

cat <<EOF
Fast runner bootstrap complete.

Next steps:
1. Install and register the GitHub self-hosted runner service on this machine.
2. Label it with a dedicated tag such as "repo-scanner-fast".
3. Set repository or organization variables:
   DISCOVERY_RUNNER_LABEL=repo-scanner-fast
   SCAN_RUNNER_LABEL=repo-scanner-fast
   DOCKER_BUILDER_MODE=docker-buildx
   TOOLING_MODE=preinstalled
   DOCKER_CACHE_MODE=local
   DOCKER_LOCAL_CACHE_DIR=${CACHE_DIR}
EOF
