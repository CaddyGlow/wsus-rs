//! MS-WSUSSS (Windows Update Services: Server-Server Protocol) messages.
//!
//! The downstream server (DSS) encodes requests and decodes responses; the
//! upstream server (USS) decodes requests and encodes responses. Shapes come
//! from the MS-WSUSSS 17.0 WSDL appendices (6.1, 6.2).
//!
//! Not implemented in this milestone: driver operations
//! (`GetDriverIdList`, `GetDriverSetData`), `Ping`, and the reporting rollup
//! methods; the inventory lists them as unsupported.
pub mod messages;
pub mod types;

pub use messages::*;
pub use types::*;

/// Namespace of the Server Sync web service operations and types.
pub const SERVER_SYNC_NS: &str = "http://www.microsoft.com/SoftwareDistribution";
/// Namespace of the DSS Authorization web service.
pub const DSS_AUTH_NS: &str =
    "http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService";
