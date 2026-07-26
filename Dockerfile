FROM debian:bookworm-slim

# ── Pinned versions — update these together with the checksums below ──────────
# To upgrade: download the new release, run sha256sum on the artifact, update ARG.
ARG KICS_VERSION=2.1.20
ARG KICS_CHECKSUM=8a5aa375ccfdc0ddd1114eddf1f9638ad7f6122e98d12a592207509dbe6d81f8

ARG SYFT_VERSION=v1.19.0
ARG SYFT_CHECKSUM=f3667d6abfa97a1e5614882f81e0a0b090f0047e0df7025b568fa87b6d95ac58

ARG GRYPE_VERSION=v0.112.0
ARG GRYPE_CHECKSUM=434bae8af635b6308d7a33ea842c6216dc382d4ec49fe3873f927b7805cc69e2

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Silence git ownership warnings inside containers
RUN git config --global safe.directory '*' \
    && git config --global advice.detachedHead false

# ── KICS binary — download, verify GPG signature, verify SHA256 ───────────────
# KICS publishes a GPG-signed checksums.txt alongside each release.
# We import their signing key, verify the checksums file signature, then
# verify the binary matches the checksum — giving us two independent checks.
# Supply chain note: KICS GitHub Actions and Docker Hub images were compromised
# in March–April 2026 (TeamPCP campaign). GitHub release tarballs for v2.1.20
# (published 2026-03-03, before the compromise windows) are independently verifiable
# via this GPG + SHA256 chain and do not depend on the affected distributions.
RUN curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics-signing-key.asc" \
        | gpg --batch --import \
    && curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/checksums.txt" \
        -o /tmp/kics-checksums.txt \
    && curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/checksums.txt.asc" \
        -o /tmp/kics-checksums.txt.asc \
    && gpg --batch --verify /tmp/kics-checksums.txt.asc /tmp/kics-checksums.txt \
    && curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/kics.tar.gz \
    && echo "${KICS_CHECKSUM}  /tmp/kics.tar.gz" | sha256sum -c - \
    && grep "kics_${KICS_VERSION}_linux_amd64.tar.gz" /tmp/kics-checksums.txt | sha256sum -c - \
    && tar -xzf /tmp/kics.tar.gz -C /usr/local/bin kics \
    && chmod +x /usr/local/bin/kics \
    && rm /tmp/kics.tar.gz /tmp/kics-checksums.txt /tmp/kics-checksums.txt.asc

# ── KICS query rules ─────────────────────────────────────────────────────────
# Sparse-clone at the exact matching version tag — rules are not in the binary.
# The git clone is pinned to the version tag; the commit SHA is validated by
# the git transfer protocol's object hash check.
RUN git clone \
      --depth=1 \
      --filter=blob:none \
      --sparse \
      --branch "v${KICS_VERSION}" \
      https://github.com/Checkmarx/kics.git \
      /opt/iac-rules \
    && git -C /opt/iac-rules sparse-checkout set assets/queries assets/libraries \
    && echo "Loaded $(ls /opt/iac-rules/assets/queries | wc -l | tr -d ' ') query platforms"

# ── Syft — download, verify SHA256 ──────────────────────────────────────────
# Anchore signs the checksums.txt via cosign/sigstore. That signature is
# verified in the publish CI (publish.yml) before this Dockerfile is built.
# Here we verify the downloaded .deb matches the hardcoded SHA256 checksum,
# providing a content-addressed pin that is independent of tag mutability.
RUN SYFT_VER="${SYFT_VERSION#v}" && \
    curl -fL \
        "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VER}_linux_amd64.deb" \
        -o /tmp/syft.deb \
    && echo "${SYFT_CHECKSUM}  /tmp/syft.deb" | sha256sum -c - \
    && dpkg -i /tmp/syft.deb \
    && rm /tmp/syft.deb

# ── Grype — download, verify SHA256 ─────────────────────────────────────────
# Same approach as Syft. Cosign signature verified in publish CI.
RUN GRYPE_VER="${GRYPE_VERSION#v}" && \
    curl -fL \
        "https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VER}_linux_amd64.deb" \
        -o /tmp/grype.deb \
    && echo "${GRYPE_CHECKSUM}  /tmp/grype.deb" | sha256sum -c - \
    && dpkg -i /tmp/grype.deb \
    && rm /tmp/grype.deb

# ── Zagware scanner entrypoint ────────────────────────────────────────────────
COPY src/scanner.py /usr/local/bin/zagware-scan
RUN chmod +x /usr/local/bin/zagware-scan

# ── Labels — link package to repo (GHCR inherits repo visibility from this) ──
LABEL org.opencontainers.image.source="https://github.com/zagware/zagware-scanner"
LABEL org.opencontainers.image.description="Zagware Security Scanner — IaC (KICS) + SCA (Grype) for CI pipelines"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV ZAGWARE_QUERIES_PATH=/opt/iac-rules/assets/queries

ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"]
