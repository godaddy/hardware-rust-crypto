# Pinned toolchain for the F* / hax extraction proof, baked into one image so the
# release gate (publish.yml -> fstar.yml) never builds from source or hits the
# network at release time. Rebuilt only when a pin below is advanced on purpose.
#
# Pins mirror .github/workflows/README.md "Pinned tool versions". Bump the ARG,
# rebuild via .github/workflows/proof-image.yml, and bump the image tag in
# fstar.yml to match.
FROM ubuntu:24.04

ARG HAX_REV=a914ac7
ARG HAX_NIGHTLY=nightly-2025-11-08
ARG FSTAR_VERSION=v2026.03.24
ARG OCAML_VERSION=5.2.1

ENV DEBIAN_FRONTEND=noninteractive
# Toolchains live at fixed absolute paths (not under $HOME) because GitHub
# container jobs override HOME; everything is selected via these ENV vars.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    OPAMROOT=/opt/opam \
    OPAMROOTISOK=1 \
    HAX=/opt/hax-src \
    PATH=/opt/cargo/bin:/opt/hax-tools/bin:/opt/fstar/bin:/usr/bin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip xz-utils \
      build-essential pkg-config m4 \
      opam nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- Rust nightly that hax links against (rustc internals) -------------------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --default-toolchain "${HAX_NIGHTLY}" \
        -c rustc-dev -c llvm-tools-preview -c rust-src -c rustfmt

# --- Prebuilt F* (bundles its own z3) ----------------------------------------
RUN curl -fSL --retry 3 -o /tmp/fstar.tgz \
      "https://github.com/FStarLang/FStar/releases/download/${FSTAR_VERSION}/fstar-${FSTAR_VERSION}-Linux-x86_64.tar.gz" \
    && tar xzf /tmp/fstar.tgz -C /opt && rm /tmp/fstar.tgz \
    && fstar.exe --version

# --- hax Rust binaries + a stable symlink to its source checkout --------------
RUN cargo install --git https://github.com/hacspec/hax --rev "${HAX_REV}" cargo-hax --root /opt/hax-tools \
    && src="$(ls -d /opt/cargo/git/checkouts/hax-*/*/ | head -1)" \
    && ln -s "$src" /opt/hax-src \
    && cargo "+${HAX_NIGHTLY}" install --path "$HAX/cli/driver"           --root /opt/hax-tools \
    && cargo "+${HAX_NIGHTLY}" install --path "$HAX/rust-engine"          --root /opt/hax-tools \
    && cargo "+${HAX_NIGHTLY}" install --path "$HAX/engine/names/extract" --root /opt/hax-tools

# --- OCaml + the hax OCaml engine (the Rust engine delegates some phases) -----
# opam installs system depexts itself (root + unsafe-yes), so the engine's native
# deps are present without a separate apt list to maintain.
RUN opam init -y --bare --disable-sandboxing \
    && opam switch create default "${OCAML_VERSION}" \
    && eval "$(opam env)" \
    && opam install "$HAX/engine" -y --confirm-level=unsafe-yes \
    && opam clean -y

# Smoke-check that the runtime entrypoints resolve in the baked environment.
RUN eval "$(opam env)" \
    && cargo-hax --version >/dev/null \
    && test -d "$HAX/hax-lib/proof-libs/fstar/core"
