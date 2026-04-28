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

1. Update the crate version in `crates/essence-core/Cargo.toml` when the
   release changes public behavior or API surface.
2. Commit the version and release notes updates.
3. Create and push a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow builds portable CLI archives for:

- Linux `x86_64-unknown-linux-gnu`
- Windows `x86_64-pc-windows-msvc`
- macOS `x86_64-apple-darwin`
- macOS `aarch64-apple-darwin`

Each uploaded asset includes the `essence` binary, README, LICENSE, and a
matching `.sha256` checksum file.

## Install From A Release

Download the archive for your platform from GitHub Releases, verify the
checksum, unpack it, and place the `essence` binary somewhere on `PATH`.

For local development, install directly from the workspace:

```bash
cargo install --path crates/essence-core --bin essence
```
