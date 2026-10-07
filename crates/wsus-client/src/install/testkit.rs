//! Synthetic catalogs for tests (hidden from the documentation): a bundle
//! whose alternatives are command-line installers with rules and payloads.
//! Nothing here resembles evidence of real behavior.
use super::plan::PayloadRef;
use crate::sync::{RevisionRecord, RevisionStore, StoredFragment};
use base64::Engine as _;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};

/// One installer alternative.
#[derive(Clone)]
pub struct Child {
    pub id: u128,
    /// Body of the `IsInstalled` section (rule XML).
    pub installed: String,
    /// Body of the `IsInstallable` section; none means the section is absent.
    pub installable: Option<String>,
    pub file_name: String,
    pub payload: Vec<u8>,
    pub arguments: Option<String>,
    pub return_codes: Vec<(i32, &'static str, Option<bool>)>,
    pub handler_uri: String,
}

impl Child {
    pub fn new(id: u128, file_name: &str, payload: &[u8]) -> Self {
        Self {
            id,
            installed: r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" Value="Version" Comparison="GreaterThanOrEqualTo" Data="2" />"#.into(),
            installable: Some(r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" />"#.into()),
            file_name: file_name.into(),
            payload: payload.to_vec(),
            arguments: Some("WD /q".into()),
            return_codes: vec![(0, "Succeeded", None), (3010, "Succeeded", Some(true))],
            handler_uri: super::handlers::COMMAND_LINE_HANDLER_URI.into(),
        }
    }

    pub fn revision(&self) -> UpdateRevision {
        rev(self.id)
    }

    /// Payload descriptor as the planner derives it.
    pub fn payload_ref(&self) -> PayloadRef {
        use crate::download::hex_encode;
        PayloadRef {
            file_name: self.file_name.clone(),
            size: self.payload.len() as u64,
            digests: vec![
                super::plan::DigestRef {
                    algorithm: "sha1".into(),
                    hex: hex_encode(&Sha1::digest(&self.payload)),
                },
                super::plan::DigestRef {
                    algorithm: "sha256".into(),
                    hex: hex_encode(&Sha256::digest(&self.payload)),
                },
            ],
            patching: None,
        }
    }
}

pub fn rev(n: u128) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::from_u128(n)),
        revision: Revision(1),
    }
}

fn frag(kind: &str, xml: String) -> StoredFragment {
    StoredFragment {
        kind: kind.into(),
        locale: None,
        sha256: String::new(),
        xml,
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn put(store: &RevisionStore, id: UpdateRevision, leaf: bool, core: String, ext: Option<String>) {
    store
        .put(&RevisionRecord {
            identity: id,
            is_leaf: leaf,
            update_type: Some("Software".into()),
            deployment: None,
            core: frag("Core", core),
            fragments: ext.into_iter().map(|x| frag("Extended", x)).collect(),
        })
        .unwrap();
}

fn identity(id: UpdateRevision) -> String {
    format!(
        r#"<UpdateIdentity UpdateID="{}" RevisionNumber="{}" />"#,
        id.id, id.revision.0
    )
}

/// Writes a category `cat` (installed per `installed_rule`), the children and
/// a root bundle `root` with one clause per entry of `clauses` and the prerequisite
/// `cat`. Returns the root revision.
pub fn write_bundle(
    meta_dir: &Path,
    root: u128,
    cat: Option<(u128, &str)>,
    clauses: &[Vec<Child>],
) -> UpdateRevision {
    let store = RevisionStore::open(meta_dir).unwrap();
    let mut prereq = String::new();
    if let Some((c, rule)) = cat {
        put(
            &store,
            rev(c),
            false,
            format!(
                r#"{}<Properties UpdateType="Category" /><ApplicabilityRules><IsInstalled>{rule}</IsInstalled></ApplicabilityRules>"#,
                identity(rev(c))
            ),
            None,
        );
        prereq = format!(
            r#"<Prerequisites><AtLeastOne IsCategory="true"><UpdateIdentity UpdateID="{}" /></AtLeastOne></Prerequisites>"#,
            rev(c).id
        );
    }
    let mut bundled = String::new();
    for clause in clauses {
        bundled.push_str("<AtLeastOne>");
        for ch in clause {
            bundled.push_str(&identity(ch.revision()));
            let rules = format!(
                "<ApplicabilityRules><IsInstalled>{}</IsInstalled>{}</ApplicabilityRules>",
                ch.installed,
                ch.installable
                    .as_ref()
                    .map(|i| format!("<IsInstallable>{i}</IsInstallable>"))
                    .unwrap_or_default()
            );
            let core = format!(
                r#"{}<Properties UpdateType="Software" />{rules}"#,
                identity(ch.revision())
            );
            let codes: String = ch
                .return_codes
                .iter()
                .map(|(c, r, reboot)| {
                    format!(
                        r#"<ReturnCode Code="{c}" Result="{r}"{} />"#,
                        reboot
                            .map(|b| format!(r#" Reboot="{b}""#))
                            .unwrap_or_default()
                    )
                })
                .collect();
            let ext = format!(
                r#"<ExtendedProperties DefaultPropertiesLanguage="en" Handler="{}" MaxDownloadSize="{}"><InstallationBehavior /></ExtendedProperties><Files><File Digest="{}" DigestAlgorithm="SHA1" FileName="{}" Size="{}"><AdditionalDigest Algorithm="SHA256">{}</AdditionalDigest></File></Files><HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="{}"{}>{codes}</InstallCommand></HandlerSpecificData>"#,
                ch.handler_uri,
                ch.payload.len(),
                b64(&Sha1::digest(&ch.payload)),
                ch.file_name,
                ch.payload.len(),
                b64(&Sha256::digest(&ch.payload)),
                ch.file_name,
                ch.arguments
                    .as_ref()
                    .map(|a| format!(r#" Arguments="{a}""#))
                    .unwrap_or_default(),
            );
            put(&store, ch.revision(), true, core, Some(ext));
        }
        bundled.push_str("</AtLeastOne>");
    }
    let core = format!(
        r#"{}<Properties UpdateType="Software" /><Relationships>{prereq}<BundledUpdates>{bundled}</BundledUpdates></Relationships>"#,
        identity(rev(root))
    );
    put(
        &store,
        rev(root),
        true,
        core,
        Some("<ExtendedProperties DefaultPropertiesLanguage=\"en\" />".into()),
    );
    rev(root)
}
