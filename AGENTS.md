# Repository guidelines

Rust 2024 workspace owning the WSUS protocol, client, server, and wsus CLI.
Preserve captured fixtures, evidence provenance, and existing working changes.
Use `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, and `cargo test --workspace --all-features --locked`.
Check fuzz harnesses with `cargo test --manifest-path fuzz/Cargo.toml --locked`.
Host checks do not establish Windows servicing correctness. Consult docs/wsus-validation.md
and the handler-specific validation documents before making native equivalence claims.
Keep cabinet, ms-compress, wim-rs, and windows-uup sibling checkouts available.

The root workspace contains only crates ready for crates.io publication.
The client/server/CLI form a separate unpublished workspace at `crates/Cargo.toml`.
Keep the pending workspace sources and feature sets intact; validate it separately when its sibling dependencies are ready.
