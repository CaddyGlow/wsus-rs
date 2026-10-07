//! The `wsus` command line as a library, so integration tests can drive the
//! same code paths as the binary.
//!
//! Evidence status: everything here is host-tested against this workspace's
//! own client and server. Nothing is validated against a real WSUS server or a
//! native Windows Update client.

pub mod admin;
pub mod app;
pub mod cli;
pub mod client_cmd;
pub mod config;
pub mod diagnostics;
pub mod export;
pub mod import;
pub mod install_cmd;
pub mod logging;
pub mod net;
pub mod output;
pub mod redact;
pub mod secure;
pub mod server_cmd;
pub mod sync_progress;
