# Base image pinned by digest, not the mutable `bookworm-slim` tag -- the same
# argument Dockerfile:36-38 makes for pinning KICS's rules by commit SHA
# applies here: a repointed tag or compromised Docker Hub namespace (the
# TeamPCP vector cited below) would substitute ca-certificates (the CA bundle
# every checksum download in this file trusts), git (which clones untrusted PR
# branches at runtime) and python3 without changing a single tracked line. See
# SUP-10. Resolved via: skopeo inspect --raw docker://debian:bookworm-slim | ...
# or `docker manifest inspect debian:bookworm-slim`; re-pin deliberately on
# each Debian point release, not on every build.
ARG DEBIAN_DIGEST=sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# ── Builder stage: download and verify all binaries ──────────────────────────
# curl is only needed here; the final stage omits it to reduce attack surface.
FROM debian:bookworm-slim@${DEBIAN_DIGEST} AS builder

ARG KICS_VERSION=2.1.20
ARG KICS_CHECKSUM=8a5aa375ccfdc0ddd1114eddf1f9638ad7f6122e98d12a592207509dbe6d81f8
ARG KICS_RULES_COMMIT=e1f23cad9640f55b963f22a116b04906b8c16ac6

ARG SYFT_VERSION=v1.19.0
ARG SYFT_CHECKSUM=f3667d6abfa97a1e5614882f81e0a0b090f0047e0df7025b568fa87b6d95ac58

ARG GRYPE_VERSION=v0.112.0
ARG GRYPE_CHECKSUM=434bae8af635b6308d7a33ea842c6216dc382d4ec49fe3873f927b7805cc69e2

ARG BETTERLEAKS_VERSION=1.7.2
ARG BETTERLEAKS_CHECKSUM=ea9ed6a4aa2845ac2e00c0eafbc841057631321d53c061d5a435cf33e6e9ddaf

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# ── KICS binary — SHA256-verified (not GPG — see supply chain note below) ──────
# KICS GitHub Actions and Docker Hub images were compromised in March–April 2026
# (TeamPCP campaign). KICS v2.1.20 was published 2026-03-03, before those windows.
# We verify by hardcoded SHA256 rather than the KICS GPG signature because
# downloading the signing key from the same endpoint as the binary gives no
# independent trust — both could be swapped together.
RUN curl -fsSL \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/kics.tar.gz \
    && echo "${KICS_CHECKSUM}  /tmp/kics.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kics.tar.gz -C /tmp kics \
    && rm /tmp/kics.tar.gz

# ── KICS query rules — pinned to immutable commit SHA (not mutable tag) ────────
# The Checkmarx/kics repo was compromised in TeamPCP. A mutable tag could be
# force-updated to a malicious commit. We pin to the exact commit SHA that the
# v2.1.20 tag pointed to at build time. This is content-addressed (immune to
# tag rewrites and force-pushes) but NOT cryptographically authenticated --
# no automated check confirms this SHA came from Checkmarx rather than an
# attacker with write access at pin time. Re-verify manually before bumping
# KICS_RULES_COMMIT: `gh api repos/Checkmarx/kics/commits/<sha>` and confirm
# it matches the target release tag. See SUP-07/SUP-15.
RUN git init /tmp/iac-rules \
    && cd /tmp/iac-rules \
    && git remote add origin https://github.com/Checkmarx/kics.git \
    && git fetch --depth=1 origin ${KICS_RULES_COMMIT} \
    && git sparse-checkout init --cone \
    && git sparse-checkout set assets/queries assets/libraries \
    && git checkout ${KICS_RULES_COMMIT} \
    && rm -rf .git

# ── Syft — SHA256-verified .deb ───────────────────────────────────────────────
# Anchore's cosign signatures on checksums.txt are verified in publish.yml
# BEFORE this Dockerfile is built.
RUN SYFT_VER="${SYFT_VERSION#v}" && \
    curl -fL \
        "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VER}_linux_amd64.deb" \
        -o /tmp/syft.deb \
    && echo "${SYFT_CHECKSUM}  /tmp/syft.deb" | sha256sum -c - \
    && dpkg -i /tmp/syft.deb \
    && rm /tmp/syft.deb

# ── Grype — SHA256-verified .deb ──────────────────────────────────────────────
RUN GRYPE_VER="${GRYPE_VERSION#v}" && \
    curl -fL \
        "https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VER}_linux_amd64.deb" \
        -o /tmp/grype.deb \
    && echo "${GRYPE_CHECKSUM}  /tmp/grype.deb" | sha256sum -c - \
    && dpkg -i /tmp/grype.deb \
    && rm /tmp/grype.deb

# ── Betterleaks binary — SHA256-verified (release also cosign-signed; see
# publish.yml for the sigstore-bundle verification run before this build) ──────
RUN curl -fsSL \
        "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/betterleaks.tar.gz \
    && echo "${BETTERLEAKS_CHECKSUM}  /tmp/betterleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/betterleaks.tar.gz -C /tmp betterleaks \
    && rm /tmp/betterleaks.tar.gz

# ── Final stage: minimal runtime image (no curl) ──────────────────────────────
FROM debian:bookworm-slim@${DEBIAN_DIGEST}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git python3 \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root runtime user ──────────────────────────────────────────────────────
# This image clones and scans untrusted pull-request content (scanner.py's
# clone_branch()) and runs four third-party binaries -- kics, syft, grype,
# betterleaks -- directly over attacker-authored input (Terraform/YAML,
# lockfiles, arbitrary repo blobs). A parser bug in any of them must degrade to
# an unprivileged crash, not root-in-container. See SUP-06.
RUN groupadd --gid 1000 zagware \
    && useradd --uid 1000 --gid zagware --create-home --shell /usr/sbin/nologin zagware
ENV HOME=/home/zagware

# Scope git safe.directory to /tmp (where scanner clones repos) instead of '*'
# to preserve the CVE-2022-24765 ownership check for other paths. --system (not
# --global) so the setting applies to whichever user runs git -- the non-root
# USER below must not depend on root's own $HOME/.gitconfig.
RUN git config --system safe.directory '/tmp/*' \
    && git config --system advice.detachedHead false

# ── Copy verified binaries from builder (--chmod=755 makes them
# world-readable/executable so the non-root USER below can run them) ──────────
COPY --from=builder --chmod=755 /tmp/kics         /usr/local/bin/kics
COPY --from=builder --chmod=755 /tmp/iac-rules    /opt/iac-rules
COPY --from=builder --chmod=755 /usr/bin/syft     /usr/bin/syft
COPY --from=builder --chmod=755 /usr/bin/grype    /usr/bin/grype
COPY --from=builder --chmod=755 /tmp/betterleaks  /usr/local/bin/betterleaks

# ── Zagware scanner entrypoint ────────────────────────────────────────────────
COPY --chmod=755 src/scanner.py /usr/local/bin/zagware-scan

# ── OCI labels — links package to repo; GHCR inherits repo visibility ─────────
LABEL org.opencontainers.image.source="https://github.com/zagware/zagware-scanner"
LABEL org.opencontainers.image.description="Zagware Security Scanner — IaC (KICS) + SCA (Grype) + Secrets (betterleaks) for CI pipelines"
LABEL org.opencontainers.image.licenses="Apache-2.0 AND MIT"

ENV ZAGWARE_QUERIES_PATH=/opt/iac-rules/assets/queries
# The non-root USER below cannot write __pycache__/ next to scanner.py in
# /usr/local/bin -- redirect bytecode caching to a writable path instead of
# leaving it to fail (or silently skip caching, which py_compile.compile()
# does NOT do -- it raises). See SUP-06 and ci.yml's "Verify scanner
# entrypoint" step, which explicitly calls py_compile.compile().
ENV PYTHONPYCACHEPREFIX=/tmp/pycache

USER zagware
ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"]
