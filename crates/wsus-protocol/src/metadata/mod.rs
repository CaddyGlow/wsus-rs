//! Update metadata: raw fragment preservation with provenance, and a parsed
//! index of identity, relationships and files.
//!
//! The raw fragment is the source of truth. The index is derived and never
//! replaces it; anything this crate does not understand stays reachable
//! through [`index::Extension`] values and the fragment bytes.
pub mod fragment;
pub mod index;

pub use fragment::{FragmentOrigin, FragmentSource, Provenance, RawFragment, Representation};
pub use index::{
    BundleClause, Extension, FileEntry, FragmentIndex, MSUS_UPDATE_NS, PrerequisiteClause,
    SLIMMED_DESCENDANTS_ATTR, UpdateIndex, UpdateProperties, UpdateType,
};
