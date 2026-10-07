//! Raw metadata fragments with origin and provenance.
use sha2::{Digest, Sha256};

use super::index::UpdateIndex;
use crate::error::{ProtocolError, Result};
use crate::identity::{ServerId, UpdateRevision, WireRevisionId};
use crate::soap::Limits;
use crate::wsusss::ServerSyncUpdateData;
use crate::wusp::{UpdateData, UpdateInfo, XmlUpdateFragmentType};

/// Protocol operation a fragment arrived through.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FragmentSource {
    /// `SyncUpdates` (`UpdateInfo.Xml`, the Core fragment).
    WuspSyncUpdates,
    /// `GetExtendedUpdateInfo` (`UpdateData.Xml`).
    WuspGetExtendedUpdateInfo,
    /// `GetExtendedUpdateInfo2`.
    WuspGetExtendedUpdateInfo2,
    /// MS-WSUSSS `GetUpdateData` (`XmlUpdateBlob[Compressed]`).
    WsusssGetUpdateData,
    /// Anything else (files, tests, imports), described by the caller.
    Other(String),
}

/// Where a fragment came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentOrigin {
    /// Operation that delivered it.
    pub source: FragmentSource,
    /// Issuing server; required before the revision id can be stored.
    pub server: Option<ServerId>,
    /// Server-local revision id, when the operation used one.
    pub wire_revision: Option<WireRevisionId>,
    /// Global identity, when the operation carried one.
    pub revision: Option<UpdateRevision>,
    /// Fragment kind, when requested explicitly.
    pub fragment_type: Option<XmlUpdateFragmentType>,
    /// Locale for localized fragments.
    pub locale: Option<String>,
}

impl FragmentOrigin {
    /// Origin with only a source set.
    pub fn new(source: FragmentSource) -> Self {
        Self {
            source,
            server: None,
            wire_revision: None,
            revision: None,
            fragment_type: None,
            locale: None,
        }
    }
}

/// How the fragment was represented when received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    /// XML text; the provenance hash covers its UTF-8 bytes.
    XmlText,
    /// Compressed blob; the provenance hash covers the compressed bytes.
    Compressed,
}

/// SHA-256 over the received representation.
///
/// Equal hashes of equal bytes say nothing about semantic identity and
/// different hashes do not imply semantic difference; they only identify what
/// was received.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    /// SHA-256 of the received bytes.
    pub sha256: [u8; 32],
    /// Number of received bytes hashed.
    pub received_len: u64,
}

impl Provenance {
    /// Hash `received`.
    pub fn of(received: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(received);
        Self {
            sha256: h.finalize().into(),
            received_len: received.len() as u64,
        }
    }

    /// Lower-case hex of the hash.
    pub fn hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A metadata fragment exactly as received, with origin and provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFragment {
    /// Origin.
    pub origin: FragmentOrigin,
    /// Representation received.
    pub representation: Representation,
    /// Hash of the received representation.
    pub provenance: Provenance,
    xml: Vec<u8>,
}

impl RawFragment {
    /// Wrap XML text received as an XML string value (the SOAP layer has
    /// already removed XML escaping). The provenance covers its UTF-8 bytes.
    pub fn from_xml_text(origin: FragmentOrigin, text: &str) -> Self {
        Self {
            origin,
            representation: Representation::XmlText,
            provenance: Provenance::of(text.as_bytes()),
            xml: text.as_bytes().to_vec(),
        }
    }

    /// Wrap a compressed blob. `compressed` is hashed; `xml` is the
    /// decompressed document supplied by the caller (decompression is not
    /// done in this I/O-free crate).
    pub fn from_compressed(origin: FragmentOrigin, compressed: &[u8], xml: Vec<u8>) -> Self {
        Self {
            origin,
            representation: Representation::Compressed,
            provenance: Provenance::of(compressed),
            xml,
        }
    }

    /// The fragment XML bytes (decompressed if it arrived compressed).
    pub fn xml(&self) -> &[u8] {
        &self.xml
    }

    /// Core fragment of a `SyncUpdates` result; `None` if `Xml` is absent or nil.
    pub fn from_update_info(server: Option<ServerId>, info: &UpdateInfo) -> Option<Self> {
        let text = info.xml.value()?;
        let mut origin = FragmentOrigin::new(FragmentSource::WuspSyncUpdates);
        origin.server = server;
        origin.wire_revision = Some(WireRevisionId(info.id));
        origin.fragment_type = Some(XmlUpdateFragmentType::Core);
        Some(Self::from_xml_text(origin, text))
    }

    /// Fragment of a `GetExtendedUpdateInfo[2]` result. `fragment_type` is
    /// unknown on the wire (the response does not label fragments), so the
    /// caller records what it asked for.
    pub fn from_update_data(
        server: Option<ServerId>,
        data: &UpdateData,
        source: FragmentSource,
        fragment_type: Option<XmlUpdateFragmentType>,
    ) -> Option<Self> {
        let text = data.xml.value()?;
        let mut origin = FragmentOrigin::new(source);
        origin.server = server;
        origin.wire_revision = Some(WireRevisionId(data.id));
        origin.fragment_type = fragment_type;
        Some(Self::from_xml_text(origin, text))
    }

    /// Metadata of a WSUSSS `GetUpdateData` item. A compressed blob is passed
    /// to `decompress`; `Ok(None)` is returned when neither blob is present.
    pub fn from_server_sync(
        server: Option<ServerId>,
        data: &ServerSyncUpdateData,
        decompress: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Option<Self>> {
        let mut origin = FragmentOrigin::new(FragmentSource::WsusssGetUpdateData);
        origin.server = server;
        origin.revision = data.id.value().copied();
        if let Some(text) = data.xml_update_blob.value() {
            return Ok(Some(Self::from_xml_text(origin, text)));
        }
        if let Some(c) = data.xml_update_blob_compressed.value() {
            let xml = decompress(c)?;
            return Ok(Some(Self::from_compressed(origin, c, xml)));
        }
        Ok(None)
    }

    /// Parse the fragment leniently (Core/Extended fragments are not
    /// well-formed XML, MS-WUSP 3.1.1.1). The stored bytes and provenance
    /// are not touched. Use [`UpdateIndex::from_fragments`] to combine
    /// fragments of one revision.
    pub fn fragment_index(&self, limits: &Limits) -> Result<super::index::FragmentIndex> {
        super::index::FragmentIndex::parse(&self.xml, limits)
    }

    /// Parse the derived index. Strict: requires a well-formed single
    /// `Update` document, which is what MS-WSUSSS `GetUpdateData` delivers.
    /// For `SyncUpdates`/`GetExtendedUpdateInfo` fragments use
    /// [`RawFragment::fragment_index`].
    pub fn index(&self, limits: &Limits) -> Result<UpdateIndex> {
        UpdateIndex::parse(&self.xml, limits)
    }

    /// Check that the stored hash matches `received` (for re-verification of
    /// persisted fragments).
    pub fn verify_provenance(&self, received: &[u8]) -> Result<()> {
        if Provenance::of(received) == self.provenance {
            Ok(())
        } else {
            Err(ProtocolError::Metadata("provenance hash mismatch".into()))
        }
    }
}
