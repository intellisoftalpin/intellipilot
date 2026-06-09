//! Capture build-time version metadata into the binary.
//!
//! Precedence for the human-facing "git" string:
//!   1. `IP_BUILD_VERSION` env (set by CI / `docker build --build-arg`) —
//!      authoritative for release images.
//!   2. `git describe --tags --always --dirty` — local/dev builds and any
//!      build where the `.git` directory is present.
//!   3. empty — the API falls back to `CARGO_PKG_VERSION` (always present and,
//!      for releases, equal to the tag thanks to the verify-tag CI gate).
//!
//! All three `rustc-env` values are always emitted (possibly empty) so the
//! `env!()` reads in the crate compile unconditionally.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=IP_BUILD_VERSION");
    if std::path::Path::new("../../.git/HEAD").exists() {
        println!("cargo:rerun-if-changed=../../.git/HEAD");
    }

    let describe = std::env::var("IP_BUILD_VERSION")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_default();
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();

    println!("cargo:rustc-env=IP_GIT_DESCRIBE={describe}");
    println!("cargo:rustc-env=IP_GIT_SHA={sha}");
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}
