FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG HADOLINT_VERSION=v2.12.0
ARG GITLEAKS_VERSION=v8.24.2
ARG SYFT_VERSION=v1.24.0
ARG COSIGN_VERSION=v2.4.3
ARG TRIVY_VERSION=0.63.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        docker.io \
        git \
        jq \
        python3 \
        python3-pip \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) ARCH="x86_64" ;; \
      arm64) ARCH="arm64" ;; \
      *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-${ARCH}" -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_${TARGETARCH}.tar.gz" -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && curl -fsSL "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VERSION#v}_linux_${TARGETARCH}.tar.gz" -o /tmp/syft.tar.gz \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && rm /tmp/syft.tar.gz \
    && curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${ARCH}" -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TARGETARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

RUN docker buildx version >/dev/null 2>&1 || true

CMD ["/bin/bash"]
