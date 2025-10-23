use reqwest::ClientBuilder;
use securo::client::pin::create_pinned_rustls_config;

/// Create HTTP client with certificate pinning
pub fn create_pinned_client(cert: Vec<u8>) -> reqwest::Result<reqwest::Client> {
    let client_config = create_pinned_rustls_config(cert);

    ClientBuilder::new()
        .use_preconfigured_tls((*client_config).clone())
        .gzip(true)
        .build()
}
