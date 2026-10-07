//! Installing client built on the validated applicability evaluator.
//!
//! EVIDENCE STATUS: nothing in this module has been validated against a
//! Windows machine or a native Windows Update Agent. The evaluator it relies
//! on was compared with a native agent for the cases listed in
//! `docs/wsus-protocol-inventory.md` (12.7, 12.8); the plan builder, the
//! handlers, the signature gate and the executor are host-tested only, with
//! fakes. See `docs/wsus-install.md` for the safety model and the ledger rows
//! in `docs/wsus-validation.md`.
//!
//! * [`facts`]: fact recording (the facts hash of a plan) and a file-backed
//!   provider for host dry-runs;
//! * `facts_windows` (Windows only): `WindowsFacts`, the live provider that
//!   mirrors `scripts/wsus/collect-facts.ps1`;
//! * [`check`]: `facts-check`, a provider against a reference snapshot;
//! * [`defender`]: the Defender launcher-package family (ordering, terminal
//!   package, stub preconditions, exit-code descriptions);
//! * [`plan`]: decisions and install steps from the catalog and a provider;
//! * [`handlers`]: typed handler specifications (command line, MSI);
//! * [`signature`], [`runner`], [`safety`], [`store`]: the gates and the
//!   process runner behind traits so the executor is testable with fakes;
//! * [`executor`] and [`job`]: write-ahead evidence and step execution.
pub mod check;
pub mod defender;
pub mod executor;
pub mod facts;
#[cfg(windows)]
pub mod facts_windows;
pub mod handler_log;
pub mod handlers;
pub mod job;
pub mod plan;
pub mod runner;
pub mod safety;
pub mod servicing;
pub mod signature;
#[cfg(windows)]
pub mod signature_windows;
pub mod stdout_guard;
pub mod store;
#[doc(hidden)]
pub mod testkit;
#[cfg(windows)]
pub mod win_util;
#[cfg(windows)]
pub mod windows_acl;

pub use facts::{RecordingFacts, load_facts_file};
pub use plan::{InstallPlan, PlanOptions, PlanOutcome, build_plan, build_uninstall_plan};
