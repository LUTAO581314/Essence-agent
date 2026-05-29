# Releasing

Essence Agent releases are driven by Git tags named `v*`.

## Local Preflight

Run the same gates used by CI:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Create A Release

1. Update the workspace version in `Cargo.toml` when the release changes public
   behavior or API surface.
2. Commit the version and release notes updates.
3. Create and push a tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The `Release` workflow first runs the Rust CI gate on Linux, Windows, and
macOS. When those checks pass, it publishes a GitHub Release with a source
bundle and matching `.sha256` checksum.

## Install From A Release

Download the source bundle from GitHub Releases, verify the checksum, and use
the unpacked workspace as a pinned source snapshot. This repository currently
ships Rust library crates, not a CLI binary.
