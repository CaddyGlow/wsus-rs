//! MS-WUSP client session: configuration discovery, authorization, cookie
//! lifecycle, registration and bounded fault recovery.
//!
//! Nothing in this module has been validated against a real WSUS server; the
//! behaviour follows the pinned MS-WUSP specification and is exercised only
//! against in-process fakes derived from it.

mod client;
mod clock;
mod config;
mod error;

pub use client::Service;
pub use client::{SessionStats, WuspSession};
pub use clock::{Clock, ManualClock, SystemClock, unix_to_xs, xs_to_unix};
pub use config::{DEFAULT_INSTALLED_NON_LEAF_LIMIT, SessionConfig};
pub use error::{FaultInfo, StorageError, WuspError};
