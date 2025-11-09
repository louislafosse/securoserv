use reqwest::ClientBuilder;
use securo::client::pin::create;
use securo::tls::TlsMode;

/// Create HTTP client with certificate pinning using a specific certificate
/// Uses the provided certificate's SPKI for pinning verification
/// Mode determines if client certificate should be sent (MutualTls) or not (ClassicalPinning)
pub fn create_pinned_client(cert: &[u8], key: Option<&[u8]>, mode: TlsMode) -> reqwest::Result<reqwest::Client> {
    let client_config = create::pinned_rustls_config(cert, key, mode);

    ClientBuilder::new()
        .use_preconfigured_tls((*client_config).clone())
        .gzip(true)
        .build()
}
