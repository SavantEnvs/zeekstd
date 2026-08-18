# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — RUST target (cargo / cargo-fuzz). Builds ON TOP of the org base
# (ghcr.io/savantenvs/base), adding a pinned Rust nightly + cargo-fuzz under
# /opt/toolchains/rust, then runs mayhem/build.sh.
#
# zeekstd implements the Zstandard Seekable Format in pure Rust over the `zstd-safe` binding.
# `zstd-safe`'s `zstd-sys` dependency VENDORS the libzstd C sources inside the crate itself and
# compiles them via the `cc` crate at build time (confirmed locally: `cargo build` pulls no
# libzstd from apt/pkg-config, and needs no network beyond the ordinary crates.io fetch that
# every dependency gets). That vendored C source is fetched into $CARGO_HOME/registry by THIS
# (online) build, same as any other crate, so the air-gapped PATCH re-run resolves it from the
# same on-disk cache — no separate step needed. We still install libzstd1/-dev via apt defensively
# (harmless, and covers the pkg-config fallback path some zstd-sys versions support), but the
# actual link is the crate's own vendored static build, not the system .so.
#
# WHY a Rust-specific template (SPEC §6.2 items 8/9, §6.5): see mayhem-repo-integration-rust/.
#
# DWARF<4 (SPEC §6.2 item 10): cargo-fuzz links Rust nightly's ASan runtime archive
# (librustc-nightly_rt.asan.a) via --whole-archive; those precompiled objects carry DWARF5 and
# land FIRST in .debug_info, so the `-Z dwarf-version=3` RUSTFLAG (which only affects rustc's OWN
# compilation units) can't lower them. Fix: prepend a hand-compiled `clang -gdwarf-3` anchor.o as
# the FIRST object in every link via a `-Clinker=<cc-wrapper>` RUSTFLAG — .debug_info CUs appear
# in linker-argument order, so the anchor's DWARF3 CU lands at offset 0, which is what
# verify-repo's `-m1` (first-CU) check reads.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] -t zeekstd-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (never an ENV — an empty ENV breaks clang). build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Undefaulted (no '=') so the base ENV default flows through unless --build-arg overrides it.
ARG SANITIZER_FLAGS

# ── Rust toolchain @ a FIXED, lockable, $HOME-independent prefix ───────────────────────────
# Nightly is required for -Zsanitizer=address (the OSS-Fuzz Rust ASan path) and for the
# -Z dwarf-version=3 flag. Dated channel for a reproducible build; recent enough for zeekstd's
# edition = "2024" workspace.
ARG RUST_CHANNEL=nightly-2025-09-05
ARG CARGO_FUZZ_VERSION=0.12.0

ENV RUSTUP_HOME=/opt/toolchains/rust/rustup \
    CARGO_HOME=/opt/toolchains/rust/cargo \
    PATH=/opt/toolchains/rust/cargo/bin:${PATH}

USER root

# Defensive apt install of libzstd (headers + runtime): NOT required for the default vendored
# zstd-sys build (see header comment), but cheap insurance if a future zstd-sys version prefers
# pkg-config, and it's a small, pinned apt package rather than an extra network fetch at build time.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libzstd-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

RUN install -d /opt/toolchains/rust \
 && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_CHANNEL}" \
 && rustup component add rust-src --toolchain "${RUST_CHANNEL}" \
 && cargo install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked \
 && rm -f /tmp/rustup-init.sh \
 # The commit build AND the air-gapped PATCH re-run run as `mayhem` (2000): it must read the
 # toolchain and read/refresh the cargo registry cache, so hand the whole prefix to 2000.
 && chown -R 2000:2000 /opt/toolchains/rust

# DWARF3 anchor object + cc-wrapper (see header). Lives under /opt/toolchains/rust alongside the
# rest of the Rust build tooling (it's a link-time helper for the Rust build, not a language
# toolchain cache, so it doesn't need the chown-2000 write access the registry needs).
RUN set -eux; \
    mkdir -p /opt/toolchains/rust/dwarf3-anchor; \
    printf 'void __mayhem_dwarf3_anchor(void) __attribute__((visibility("hidden"),used));\nvoid __mayhem_dwarf3_anchor(void) {}\n' \
      > /opt/toolchains/rust/dwarf3-anchor/anchor.c; \
    clang -g -gdwarf-3 -c /opt/toolchains/rust/dwarf3-anchor/anchor.c \
      -o /opt/toolchains/rust/dwarf3-anchor/anchor.o; \
    printf '#!/bin/bash\nexec cc /opt/toolchains/rust/dwarf3-anchor/anchor.o "$@"\n' \
      > /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    chmod +x /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    chmod a+rX /opt/toolchains/rust/dwarf3-anchor /opt/toolchains/rust/dwarf3-anchor/anchor.o \
               /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    echo "DWARF3 anchor ready: $(readelf --debug-dump=info /opt/toolchains/rust/dwarf3-anchor/anchor.o | grep -m1 Version:)"

USER mayhem

# Source enters from the build CONTEXT (CI checkout): the FULL repo (incl. .git history) → /mayhem.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates $CARGO_HOME (online, this first build) and builds the sanitized fuzz target(s) + KAT probe.
RUN bash mayhem/build.sh

# Run the project's functional suite + the KAT probe at build time (a failing suite fails the build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
