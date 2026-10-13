# syntax=docker/dockerfile:1.7
#
# IntelliPilot API container — distroless, nonroot, statically reproducible.
#
# Build: docker build -f docker/Dockerfile -t intellipilot:dev .
# Run:   docker run --rm -p 8080:8080 --read-only --tmpfs /tmp intellipilot:dev

# ---------- Stage 1: planner (cargo-chef) --------------------------------
# Base image must match (or exceed) the rust-toolchain.toml pin so cargo-chef
# is built against the same cargo that will compile our workspace.
FROM rust:1.88-bookworm AS chef
# cmake + perl are required to build the vendored libgit2 / OpenSSL that the
# `git2` crate compiles from source (in-memory SSH credentials).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-chef@0.1.71
WORKDIR /work

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------- Stage 2: build cached dependencies ---------------------------
FROM chef AS builder
COPY --from=planner /work/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# Stamp the build with the release version. Pass at build time, e.g.
#   docker build --build-arg IP_BUILD_VERSION="$(git describe --tags --always)" ...
# When unset, build.rs falls back to `git describe` (the .git dir is in the
# build context) and finally to the Cargo version.
ARG IP_BUILD_VERSION=""
ENV IP_BUILD_VERSION=$IP_BUILD_VERSION
RUN cargo build --release --locked --bin intellipilot \
    && strip target/release/intellipilot
# Empty storage dir for the runtime stage (distroless has no shell to mkdir).
RUN mkdir -p /work/storage/attachments

# ---------- Stage 3: runtime (distroless) --------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
USER nonroot:nonroot
WORKDIR /app
COPY --from=builder /work/target/release/intellipilot /app/intellipilot
# Owned by nonroot so a fresh named volume mounted here inherits a writable
# root; otherwise Docker creates it root:root and every upload fails (EACCES).
COPY --from=builder --chown=nonroot:nonroot /work/storage /var/lib/intellipilot

EXPOSE 8080
ENV INTELLIPILOT_BIND=0.0.0.0:8080 \
    INTELLIPILOT_ENV=production \
    RUST_LOG=info

ENTRYPOINT ["/app/intellipilot"]
