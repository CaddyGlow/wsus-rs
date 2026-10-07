//! Types shared by MS-WUSP and MS-WSUSSS.
//!
//! The specifications define `Cookie`, `AuthorizationCookie` and
//! `UpdateIdentity` identically in both protocols; the namespace of the
//! enclosing message decides which namespace their children are encoded in
//! (see [`crate::soap::wire::WSUS_NAMESPACES`] for the decoding tolerance).
use uuid::Uuid;

use crate::error::{ProtocolError, Result};
use crate::identity::{Revision, UpdateId, UpdateRevision};
use crate::macros::wire_struct;
use crate::soap::wire::{Ctx, Fields, Presence, WireType, XsDateTime, put};
use crate::soap::xml::Element;

wire_struct! {
    /// Opaque server-issued session cookie. `EncryptedData` is meaningful
    /// only to the issuing server; clients store and return it verbatim.
    pub struct Cookie {
        /// Expiry as sent.
        req expiration: XsDateTime => "Expiration",
        /// Opaque encrypted state.
        opt encrypted_data: Vec<u8> => "EncryptedData",
    }
}

wire_struct! {
    /// Authorization cookie from the SimpleAuth / DssAuth service.
    pub struct AuthorizationCookie {
        /// Authorization plug-in identifier.
        opt plug_in_id: String => "PlugInId",
        /// Opaque cookie bytes.
        opt cookie_data: Vec<u8> => "CookieData",
    }
}

wire_struct! {
    /// One authorization plug-in advertised by the server.
    pub struct AuthPlugInInfo {
        /// Plug-in identifier.
        opt plug_in_id: String => "PlugInID",
        /// Service URL of the plug-in.
        opt service_url: String => "ServiceUrl",
        /// Plug-in specific parameter.
        opt parameter: String => "Parameter",
    }
}

/// `UpdateIdentity`: `UpdateID` GUID plus `RevisionNumber`.
impl WireType for UpdateRevision {
    fn to_xml(&self, ns: &str, name: &str) -> Element {
        let mut e = Element::new(ns, name);
        put(&mut e, "UpdateID", &self.id.0);
        put(&mut e, "RevisionNumber", &(self.revision.0 as i32));
        e
    }

    fn from_xml(el: &Element, ctx: &Ctx<'_>) -> Result<Self> {
        let f = Fields::new(el, ctx, &["UpdateID", "RevisionNumber"])?;
        let id: Uuid = f.req("UpdateID")?;
        let rev: i32 = f.req("RevisionNumber")?;
        let rev = u32::try_from(rev).map_err(|_| ProtocolError::InvalidValue {
            element: "RevisionNumber".into(),
            kind: "non-negative int",
            value: rev.to_string(),
        })?;
        Ok(UpdateRevision {
            id: UpdateId(id),
            revision: Revision(rev),
        })
    }
}

/// Convenience: an `Absent` presence.
pub fn absent<T>() -> Presence<T> {
    Presence::Absent
}
