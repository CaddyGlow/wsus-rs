//! HTTP backend construction from the `[network]` settings.

use crate::config::NetworkSection;
use anyhow::{Context, Result};
use std::time::Duration;
use wsus_client::transport::reqwest_backend::ReqwestTransport;

/// Builds the reqwest backend with the configured proxy and extra roots.
/// Redirects are not followed: a signed request's meaning must not change
/// silently.
pub fn build_transport(
    network: &NetworkSection,
    connect_timeout: Duration,
) -> Result<ReqwestTransport> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout);
    if let Some(proxy) = &network.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy).context("invalid network.proxy")?);
    }
    for path in &network.trust_roots {
        let pem = std::fs::read(path)
            .with_context(|| format!("cannot read trust root {}", path.display()))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .with_context(|| format!("trust root {} is not a PEM certificate", path.display()))?;
        builder = builder.add_root_certificate(cert);
    }
    Ok(ReqwestTransport::from_client(
        builder.build().context("cannot build the HTTP client")?,
    ))
}
