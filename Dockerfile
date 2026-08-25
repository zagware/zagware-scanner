# Every base image is pinned by digest, not by a mutable tag. A repointed tag
# or compromised namespace (the TeamPCP vector cited below) would substitute
# ca-certificates (the CA bundle every checksum download here trusts), git
# (which clones untrusted PR branches at runtime), python3, or the Go toolchain
# that compiles KICS -- without changing a single tracked line. See SUP-10.
# Resolve with `docker buildx imagetools inspect <ref>`; re-pin deliberately,
# not on every build.

# Runtime base. Wolfi, not debian:bookworm-slim, and the reason is measurable
# rather than aesthetic: bookworm-slim contributed 105 critical/high CVEs, of
# which exactly ZERO were fixable -- 70 carried Debian's "won't fix" and 35 had
# no fix at all. `apt upgrade` could not have closed one of them; only leaving
# the distro could. 44 of those 105 came from perl, present solely because
# Debian's git depends on it, and 24 more from python 3.11. Wolfi's git needs
# no perl and it ships python 3.13, so the OS contribution drops to zero.
#
# Trade-off, recorded so it is a decision and not an accident: Chainguard's
# free tier publishes only :latest and garbage-collects older digests, so this
# pin can eventually become unpullable. That forces periodic re-pinning, which
# a rolling base wants anyway. Mirror the digest into our own registry if
# reproducible rebuilds of old tags ever become a hard requirement.
ARG WOLFI_DIGEST=sha256:a31344ab2cb8618db84f535eec56f76f6178b142cb92cb2e48676cc2dcebea72

# Debian is still used for the download/verify stage only: it has dpkg, which
# the Syft and Grype .deb artifacts need. Nothing from this stage's filesystem
# reaches the runtime image except the four verified binaries.
ARG DEBIAN_DIGEST=sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Go toolchain for the KICS build. The toolchain version is a security input,
# not an implementation detail -- KICS's go.mod declares go 1.26.2, and that
# exact stdlib is what the released binary was compiled against and what showed
# up as stdlib CVEs in scans of this image. The toolchain is re-pinned whenever
# a Go patch release closes stdlib advisories that appear in our own scans:
# 1.26.5 left five (GO-2026-5026/5972/5942/6088/6090), all fixed in 1.26.6, so
# this now tracks 1.26.7. Every stdlib finding attributed to `kics` is ours to
# clear here -- unlike the vendor-built binaries, where only the vendor's next
# release can move the number.
#
# The tag travels with the digest as GO_VERSION rather than being retyped at
# each FROM. It used to be a bare `golang:1.26.5` literal in three places --
# two FROMs here and the pullability check in tool-currency.yml -- none of
# which any test tied to GO_DIGEST, so a re-pin could leave a tag and a digest
# that disagree and nothing would say so.
ARG GO_VERSION=1.26.7
ARG GO_DIGEST=sha256:dc2521c2a906db43073b8b4d99f491b6341cf15610b6ebbab187c45153f9959e

# ── KICS: built from source at a pinned commit, not downloaded ────────────────
# Checkmarx stopped publishing release binaries after v2.1.20 -- v2.1.21 is a
# tag with zero assets, and v2.1.17 through v2.1.19 shipped none either. Pinning
# to the last release that happens to have a tarball means freezing on an
# artifact whose vendored dependencies only rot further.
#
# Building is also the stronger supply-chain position. TeamPCP compromised
# Checkmarx's GitHub Actions and Docker Hub in March-April 2026 -- their
# *release pipeline*. A source build at a content-addressed commit does not
# trust that pipeline at all, and publish.yml's SUP-15 step still proves the
# commit is what refs/tags/v${KICS_VERSION} resolves to.
#
# Measured effect: the v2.1.20 binary carried 23 critical/high in its vendored
# modules, mostly Go stdlib from the toolchain it was built with. The same code
# rebuilt with Go 1.26.7 carries 2 -- both containerd advisories (GO-2026-5064,
# GO-2026-5338), fixed only in the containerd/v2 module line that KICS does not
# use, so they have no fix available to us at all.
#
# One commit now yields BOTH the binary and the query rules, so they can no
# longer drift apart the way a separate binary pin and rules pin could.
FROM golang:${GO_VERSION}@${GO_DIGEST} AS kicsbuild

ARG KICS_VERSION=2.1.21
ARG KICS_RULES_COMMIT=3778c88b04d04c861c98234069010930079176c3

WORKDIR /src
# Fetch the commit directly rather than cloning a branch: content-addressed, so
# immune to tag rewrites and force-pushes.
RUN git init -q . \
    && git remote add origin https://github.com/Checkmarx/kics.git \
    && git fetch --depth=1 --quiet origin ${KICS_RULES_COMMIT} \
    && git checkout --quiet ${KICS_RULES_COMMIT}

# CGO_ENABLED=0 for a static binary -- the runtime base is a different libc
# from the build base, and static is what makes that safe.
# -trimpath keeps build paths out of the binary so the output is reproducible.
# `make build` is not used: it depends on `generate`, which needs a JRE for
# ANTLR. The generated sources are committed, so the documented plain-go-build
# path in docs/getting-started.md is sufficient and avoids pulling Java in.
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w \
            -X github.com/Checkmarx/kics/v2/internal/constants.SCMCommit=${KICS_RULES_COMMIT} \
            -X github.com/Checkmarx/kics/v2/internal/constants.Version=v${KICS_VERSION}" \
        -o /out/kics cmd/console/main.go \
    && /out/kics version

# Query rules from the same tree as the binary above.
RUN mkdir -p /out/iac-rules/assets \
    && cp -r assets/queries assets/libraries /out/iac-rules/assets/

# ── Download/verify stage: Syft, Grype, Betterleaks ───────────────────────────
# curl and dpkg are only needed here; the runtime image has neither.
FROM debian:bookworm-slim@${DEBIAN_DIGEST} AS builder

ARG SYFT_VERSION=v1.51.0
ARG SYFT_CHECKSUM=197b629b12b9d913e83ce0fcccfb27891bb2bfedb4d114a1913b8298cc0ad74f

# Grype v0.112.0 was four minor releases behind and carried 22 critical/high in
# its own vendored modules -- an unacceptable posture for a vulnerability
# scanner. v0.117.0 brings that to 8, and only one of those eight has a fix we
# could apply by bumping: the remaining seven are Go stdlib baked in by the
# go1.26.3 toolchain Anchore built with, plus one docker/docker advisory whose
# only patched module path is moby/moby/v2. Both wait on Anchore's next
# release; see "Our vulnerability posture" in README.md.
ARG GRYPE_VERSION=v0.117.0
ARG GRYPE_CHECKSUM=ded1af2d2946fc92863ba2278d91da64dabb2c7a33a0e703868311686bc98873

# 1.8.0 split generic-api-key into generic-api-key / generic-password /
# generic-credential-uri. betterleaks fingerprints are file:rule_id:line, so a
# consumer suppression pinned to an old generic-api-key finding stops matching
# and the finding returns as net-new once. Base and head are scanned with the
# same image, so the PR diff itself is unaffected. See CHANGELOG.
ARG BETTERLEAKS_VERSION=1.8.1
ARG BETTERLEAKS_CHECKSUM=efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a

# osv-scanner: cross-ecosystem advisory matching for the core image. Static Go
# binary, SHA256-pinned exactly like Syft/Grype. The release carries SLSA
# provenance (multiple.intoto.jsonl) rather than a cosign signature, and
# publish.yml checks this checksum against the release's own signed-by-nothing
# osv-scanner_SHA256SUMS manifest -- that closes transcription error, not
# substitution. Verifying multiple.intoto.jsonl is the outstanding gap; it is
# NOT the equivalent of the Syft/Grype cosign step, and this comment used to
# claim it was.
ARG OSV_SCANNER_VERSION=v2.5.1
ARG OSV_SCANNER_CHECKSUM=f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

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

# ── osv-scanner — SHA256-verified static binary ───────────────────────────────
RUN curl -fL \
        "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
        -o /tmp/osv-scanner \
    && echo "${OSV_SCANNER_CHECKSUM}  /tmp/osv-scanner" | sha256sum -c - \
    && chmod 0755 /tmp/osv-scanner

# ── govulncheck build (reachability variant only) ─────────────────────────────
# govulncheck ships no release binary, only `go install`, whose integrity is the
# Go module checksum database (sum.golang.org — a signed transparency log), the
# same guarantee backing every dependency of the KICS source build above. Pinned
# version, static output, `-mod=readonly` so the build cannot silently pull an
# unpinned module. This binary lands ONLY in the opt-in reachability image.
FROM golang:${GO_VERSION}@${GO_DIGEST} AS govulnbuild
ARG GOVULNCHECK_VERSION=v1.1.4
ENV GOBIN=/out GOFLAGS=-mod=readonly
RUN go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" \
    && /out/govulncheck -version

# ── Final stage: minimal runtime image (no curl, no dpkg, no compiler) ────────
FROM cgr.dev/chainguard/wolfi-base@${WOLFI_DIGEST} AS base-min

# python-3.13 provides /usr/bin/python3 directly; no symlink needed. Wolfi's
# git pulls no perl, which is where 44 of the old image's critical/high CVEs
# came from.
RUN apk add --no-cache ca-certificates git python-3.13

# ── Non-root runtime user ──────────────────────────────────────────────────────
# This image clones and scans untrusted pull-request content (scanner.py's
# clone_branch()) and runs five third-party binaries -- kics, syft, grype,
# betterleaks, osv-scanner -- directly over attacker-authored input
# (Terraform/YAML, lockfiles, arbitrary repo blobs). A parser bug in any of
# them must degrade to an unprivileged crash, not root-in-container. See
# SUP-06.
# busybox addgroup/adduser, not shadow's groupadd/useradd: they are already in
# the base, so the image needs no extra package to create the account.
RUN addgroup -g 1000 zagware \
    && adduser -D -u 1000 -G zagware -s /sbin/nologin -h /home/zagware zagware
ENV HOME=/home/zagware

# Scope git safe.directory to /tmp (where scanner clones repos) instead of '*'
# to preserve the CVE-2022-24765 ownership check for other paths. --system (not
# --global) so the setting applies to whichever user runs git -- the non-root
# USER below must not depend on root's own $HOME/.gitconfig.
RUN git config --system safe.directory '/tmp/*' \
    && git config --system advice.detachedHead false

# ── Copy verified binaries (--chmod=755 makes them world-readable/executable
# so the non-root USER below can run them) ────────────────────────────────────
COPY --from=kicsbuild --chmod=755 /out/kics        /usr/local/bin/kics
COPY --from=kicsbuild --chmod=755 /out/iac-rules   /opt/iac-rules
COPY --from=builder   --chmod=755 /usr/bin/syft    /usr/bin/syft
COPY --from=builder   --chmod=755 /usr/bin/grype   /usr/bin/grype
COPY --from=builder   --chmod=755 /tmp/betterleaks /usr/local/bin/betterleaks
# osv-scanner ships in BOTH images (advisory matching in core; call analysis in
# the reachability variant, where a Go toolchain is present).
COPY --from=builder   --chmod=755 /tmp/osv-scanner /usr/local/bin/osv-scanner

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

# Syft and Grype resolve their cache from $XDG_CACHE_HOME, falling back to
# $HOME/.cache. HOME is set above, but a caller can override it -- the GitHub
# Actions docker-action runtime does exactly that, passing `-e HOME` and
# bind-mounting its own /github/home, which is owned by the runner user (uid
# 1001) and therefore NOT writable by this image's uid 1000. Grype then could
# not create its vulnerability DB and exited 1 within a second:
#
#   error updating db: unable to create db root dir /github/home/.cache/grype/db
#   ERROR failed to load vulnerability db: database does not exist
#
# This was invisible before SUP-06 introduced the non-root USER, because root
# could write the overridden HOME. Pinning the cache to a path that is always
# writable makes SCA independent of whatever HOME the caller injects.
ENV XDG_CACHE_HOME=/tmp/.cache
RUN mkdir -p /tmp/.cache && chown zagware:zagware /tmp/.cache && chmod 700 /tmp/.cache

USER zagware
ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"]

# ── Reachability variant (opt-in) — + Go/Node toolchains + govulncheck ────────
# The SAME attested core plus the toolchains that govulncheck and osv-scanner's
# call analysis need at SCAN time to build a call graph, plus npm for
# dependency-scope enrichment. Larger trusted surface, so it is a SEPARATE tag
# consumers opt into — the default core image never carries a compiler or Node.
# Still cosign-signed + SLSA-attested by publish.yml. go/nodejs/npm come from
# Wolfi's apk repos, which apk verifies against Chainguard's signing keys.
FROM base-min AS reachability
USER root
RUN apk add --no-cache go nodejs npm
COPY --from=govulnbuild --chmod=755 /out/govulncheck /usr/local/bin/govulncheck
USER zagware

# ── Core (DEFAULT target) — the minimal, fully-attested image ─────────────────
# Declared last so a bare `docker build` (and CI's build step) produces the
# minimal core, never the heavier reachability variant. publish.yml builds
# `--target core` for :latest and `--target reachability` for :reachability.
FROM base-min AS core
