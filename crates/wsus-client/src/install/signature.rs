//! Signature gate: Authenticode verification and a signer allowlist.
//!
//! The verifier is a trait. The Windows implementation
//! (`signature_windows::WinVerifyTrustVerifier`) calls `WinVerifyTrust` with
//! the generic Authenticode policy on the already open payload handle. The
//! `wintrust` crate of this workspace is NOT used: it verifies catalog
//! members under a portable policy and has no PE/MSI Authenticode path.
//!
//! The policy decides on the signer's organisation (`O`) and falls back to
//! the common name (`CN`) only when the certificate has no `O`. The default
//! allowlist is `Microsoft Corporation`. Matching is exact except for ASCII
//! case.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, path::Path};

/// Allowlist entry used when none is configured.
pub const DEFAULT_SIGNER: &str = "Microsoft Corporation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Subject common name of the signing certificate.
    pub subject_cn: Option<String>,
    /// Subject organisation.
    pub organization: Option<String>,
    pub issuer: Option<String>,
    /// SHA-1 thumbprint (hex) of the signing certificate.
    pub thumbprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("the file has no embedded Authenticode signature: {0}")]
    NotSigned(String),
    #[error("the signature does not verify: {0}")]
    Invalid(String),
    #[error("signature verification is not available here: {0}")]
    Unsupported(String),
    #[error("cannot read the signer: {0}")]
    Signer(String),
}

pub trait SignatureVerifier {
    /// Verifies the file open as `file` (the same handle the digest was
    /// computed over); `path` is for messages and for APIs that need a name.
    fn verify(&self, file: &File, path: &Path) -> Result<SignatureInfo, SignatureError>;
}

/// Allowlist of signer organisations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub allowed_signers: Vec<String>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            allowed_signers: vec![DEFAULT_SIGNER.to_owned()],
        }
    }
}

impl TrustPolicy {
    /// `Ok` when the signer is allowed.
    pub fn check(&self, info: &SignatureInfo) -> Result<(), String> {
        let who = info
            .organization
            .as_deref()
            .or(info.subject_cn.as_deref())
            .ok_or_else(|| {
                "the signing certificate has no organisation or common name".to_owned()
            })?;
        if self
            .allowed_signers
            .iter()
            .any(|a| a.eq_ignore_ascii_case(who))
        {
            Ok(())
        } else {
            Err(format!(
                "signer `{who}` is not in the allowlist ({})",
                self.allowed_signers.join(", ")
            ))
        }
    }
}

/// Verifier for platforms without Authenticode support: refuses everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedVerifier;

impl SignatureVerifier for UnsupportedVerifier {
    fn verify(&self, _file: &File, _path: &Path) -> Result<SignatureInfo, SignatureError> {
        Err(SignatureError::Unsupported(
            "Authenticode verification is implemented on Windows only".into(),
        ))
    }
}

/// Test double: answers by file name.
#[derive(Debug, Clone, Default)]
pub struct FakeVerifier {
    pub by_name: BTreeMap<String, Result<SignatureInfo, SignatureError>>,
    /// Answer for names not in the map.
    pub default: Option<Result<SignatureInfo, SignatureError>>,
}

impl FakeVerifier {
    /// Every file is signed by `organization`.
    pub fn signed_by(organization: &str) -> Self {
        Self {
            by_name: BTreeMap::new(),
            default: Some(Ok(SignatureInfo {
                subject_cn: Some(organization.to_owned()),
                organization: Some(organization.to_owned()),
                issuer: Some("Fake CA".into()),
                thumbprint: Some("00".repeat(20)),
            })),
        }
    }

    /// Nothing is signed.
    pub fn unsigned() -> Self {
        Self {
            by_name: BTreeMap::new(),
            default: Some(Err(SignatureError::NotSigned("fake".into()))),
        }
    }
}

impl SignatureVerifier for FakeVerifier {
    fn verify(&self, _file: &File, path: &Path) -> Result<SignatureInfo, SignatureError> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.by_name
            .get(&name)
            .or(self.default.as_ref())
            .cloned()
            .unwrap_or_else(|| Err(SignatureError::NotSigned("not configured".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(o: Option<&str>, cn: Option<&str>) -> SignatureInfo {
        SignatureInfo {
            subject_cn: cn.map(str::to_owned),
            organization: o.map(str::to_owned),
            issuer: None,
            thumbprint: None,
        }
    }

    #[test]
    fn default_policy_allows_microsoft_only() {
        let p = TrustPolicy::default();
        assert!(
            p.check(&info(
                Some("Microsoft Corporation"),
                Some("Microsoft Windows")
            ))
            .is_ok()
        );
        assert!(p.check(&info(Some("microsoft corporation"), None)).is_ok());
        assert!(
            p.check(&info(Some("Evil Corp"), Some("Microsoft Corporation")))
                .is_err()
        );
        assert!(p.check(&info(None, Some("Microsoft Corporation"))).is_ok());
        assert!(p.check(&info(None, None)).is_err());
        assert!(
            p.check(&info(Some("Microsoft Corporation Ltd"), None))
                .is_err()
        );
    }
}
