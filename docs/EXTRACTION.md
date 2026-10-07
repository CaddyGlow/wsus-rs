# WSUS extraction — 2026-10-07

Moved wsus-protocol, wsus-client, wsus-server, and wsus-cli from windows-uup
into this workspace, including their working-tree edits, tests, captured fixtures,
WSUS documents and scripts, nine honggfuzz targets, replay tool, seed generator,
smoke tests, and current corpora. All 1,801 files were verified against pre-move
SHA-256 values before adapting paths. The source hashes are retained in
migration/source-sha256.json; six moved text files were subsequently adapted.
No moved files were missing in the final audit.

The CLI is still named wsus. Optional servicing handlers retain a sibling dependency
on windows-uup/crates/windows-dism. Cabinet, compression and WIM dependencies
continue to use their existing sibling repositories. Existing windows-uup WSUS
cross-build Task commands now select this manifest and preserve their output paths.
Build outputs, private captures and historical fuzz-run artifacts were not moved.
Historical evidence paths have not been rewritten; active cross-repository Markdown
links and probe build instructions were adjusted.

Validation:

- All-feature workspace tests: 819 passed, 10 ignored, zero failures.
- Workspace Clippy, all targets and all features with warnings denied: passed.
- Workspace and fuzz formatting checks: passed.
- Fuzz regression tests: four passed; fuzz Clippy passed.
- windows-uup all-target/all-feature workspace compilation: passed.
- Both workspaces resolve with their own lockfiles; root and root-fuzz lockfiles
  no longer contain WSUS packages.

The shared windows-cbs dependency still emits existing dead-code warnings.
Ignored live-server/native tests, Windows cross-builds and Windows servicing gates
were not run for this source extraction. No new instrumented fuzz campaign was run.
