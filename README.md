# wsus-rs

Rust WSUS protocol codecs, client, server, and command-line tools, extracted
from windows-uup with tests, captured fixtures, documentation, scripts, and fuzz harnesses.

- `wsus-protocol`: SOAP, MS-WUSP/MS-WSUSSS, metadata, and applicability rules.
- `wsus-client`: synchronization, downloads, reporting, and optional install handlers.
- `wsus-server`: catalog storage, policy, content, and optional HTTP endpoints.
- `wsus-cli`: the `wsus` executable.

Keep sibling `cabinet`, `ms-compress`, `wim-rs`, and `windows-uup` checkouts.
The optional servicing handlers use windows-dism from windows-uup. Transitive
archive and image dependencies require their existing sibling checkouts as well.

```sh
nix develop
cargo run -p wsus-cli --locked -- --help
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --manifest-path fuzz/Cargo.toml --locked
```

See [CLI usage](docs/wsus-cli.md), [validation](docs/wsus-validation.md), and
[fuzzing](docs/wsus-fuzzing.md). Historical evidence paths are retained.
`migration/source-sha256.json` records every moved file before manifest adaptation.
Generated Windows executables and historical fuzz run artifacts remain at their
original locations in windows-uup. Source extraction does not rerun Windows lab gates.

## Publication

This first release publishes the portable `wsus-protocol` crate.
Client, server and CLI sources are preserved in the separate workspace
`crates/Cargo.toml`; their crates.io publication is pending the Windows servicing
dependencies. Validate them with `cargo test --manifest-path crates/Cargo.toml
--workspace --all-features --locked` once the sibling Windows dependencies are available.
Version tags validate and publish the protocol crate and create the GitHub Release.
