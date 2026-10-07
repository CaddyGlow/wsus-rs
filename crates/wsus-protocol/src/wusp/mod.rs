//! MS-WUSP (Windows Update Services: Client-Server Protocol) messages.
//!
//! Every message encodes and decodes in both directions: a client encodes
//! requests and decodes responses, a server decodes requests and encodes
//! responses. Shapes come from the MS-WUSP 38.0 WSDL appendices (6.1-6.3);
//! see each type's docs for implementation decisions where the specification
//! is ambiguous.
//!
//! `StartCategoryScan` (request, response) was added after the first native capture. Not
//! implemented: `SyncPrinterCatalog` (the prose and WSDL SOAPAction disagree, inventory
//! section 8 item 5), and the Reporting-service methods other than
//! `ReportEventBatch`.
pub mod messages;
pub mod types;

pub use messages::*;
pub use types::*;

/// Namespace of the Client web service (`/ClientWebService/Client.asmx`).
pub const CLIENT_NS: &str = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService";
/// Namespace of the SimpleAuth web service.
pub const SIMPLE_AUTH_NS: &str =
    "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService";
/// Namespace of the Reporting web service (also used by MS-WSUSSS server sync).
pub const REPORTING_NS: &str = "http://www.microsoft.com/SoftwareDistribution";
