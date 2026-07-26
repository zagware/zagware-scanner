FROM debian:bookworm-slim

# ── Pinned versions — update together with the checksums below ────────────────
# To upgrade: download the new release artifact, run `sha256sum <file>`, update ARG.
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
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Silence git ownership warnings inside containers
RUN git config --global safe.directory '*' \
    && git config --global advice.detachedHead false

# ── KICS binary — download and verify SHA256 ──────────────────────────────────
# Supply chain note: KICS GitHub Actions and Docker Hub images were compromised
# in March–April 2026 (TeamPCP campaign). KICS v2.1.20 was published 2026-03-03,
# before those windows. We verify by hardcoded SHA256 (KICS_CHECKSUM) rather than
# the KICS GPG signature because downloading the signing key from the same endpoint
# as the binary gives no independent trust — both could be swapped together.
# The SHA256 value comes from us, verified against a known-good download, and
# committed to our source tree.
RUN curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/kics.tar.gz \
    && echo "${KICS_CHECKSUM}  /tmp/kics.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kics.tar.gz -C /usr/local/bin kics \
    && chmod +x /usr/local/bin/kics \
    && rm /tmp/kics.tar.gz

# ── KICS query rules ─────────────────────────────────────────────────────────
# Sparse-clone at the exact version tag — rules are not bundled in the binary.
RUN git clone \
      --depth=1 \
      --filter=blob:none \
      --sparse \
      --branch "v${KICS_VERSION}" \
      https://github.com/Checkmarx/kics.git \
      /opt/iac-rules \
    && git -C /opt/iac-rules sparse-checkout set assets/queries assets/libraries \
    && echo "Loaded $(ls /opt/iac-rules/assets/queries | wc -l | tr -d ' ') query platforms"

# ── Syft — download and verify SHA256 ────────────────────────────────────────
# Anchore's cosign signatures for checksums.txt are verified in publish.yml
# BEFORE this Dockerfile is built. Here we verify the .deb matches our pinned
# SHA256, giving a content-addressed guarantee independent of tag mutability.
RUN SYFT_VER="${SYFT_VERSION#v}" && \
    curl -fL \
        "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VER}_linux_amd64.deb" \
        -o /tmp/syft.deb \
    && echo "${SYFT_CHECKSUM}  /tmp/syft.deb" | sha256sum -c - \
    && dpkg -i /tmp/syft.deb \
    && rm /tmp/syft.deb

# ── Grype — download and verify SHA256 ───────────────────────────────────────
# Same approach as Syft. Cosign signature on checksums verified in publish CI.
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

# ── OCI labels — links package to repo; GHCR inherits repo visibility ─────────
LABEL org.opencontainers.image.source="https://github.com/zagware/zagware-scanner"
LABEL org.opencontainers.image.description="Zagware Security Scanner — IaC (KICS) + SCA (Grype) for CI pipelines"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV ZAGWARE_QUERIES_PATH=/opt/iac-rules/assets/queries

ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"]
