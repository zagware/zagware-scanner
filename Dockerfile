FROM debian:bookworm-slim

ARG KICS_VERSION=2.1.20

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

# ── IaC scanner binary ─────────────────────────────────────────────────────────
# The official binary release is a bare tar.gz containing only the binary.
RUN curl -fsSL \
    "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/scanner.tar.gz \
    && tar -xzf /tmp/scanner.tar.gz -C /usr/local/bin kics \
    && chmod +x /usr/local/bin/kics \
    && rm /tmp/scanner.tar.gz

# ── Query rules ────────────────────────────────────────────────────────────────
# The query rules (Rego files) are NOT bundled in the binary release;
# sparse-clone only the rules directories at the exact matching version tag.
RUN git clone \
      --depth=1 \
      --filter=blob:none \
      --sparse \
      --branch "v${KICS_VERSION}" \
      https://github.com/Checkmarx/kics.git \
      /opt/iac-rules \
    && git -C /opt/iac-rules sparse-checkout set assets/queries assets/libraries \
    && echo "Loaded $(ls /opt/iac-rules/assets/queries | wc -l | tr -d ' ') query platforms"

# ── Zagware IaC Scanner entrypoint ────────────────────────────────────────────
COPY src/scanner.py /usr/local/bin/zagware-scan
RUN chmod +x /usr/local/bin/zagware-scan

# ── Environment ────────────────────────────────────────────────────────────────
ENV ZAGWARE_QUERIES_PATH=/opt/iac-rules/assets/queries

ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"]
