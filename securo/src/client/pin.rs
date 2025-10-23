
use rustls::ClientConfig;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use std::sync::Arc;

// Verifier that only accepts the pinned certificate
#[derive(Debug)]
struct PinningCertVerifier {
    pinned_cert: Vec<u8>,
}

impl ServerCertVerifier for PinningCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Compare the server certificate with the pinned certificate
        if end_entity.as_ref() == &self.pinned_cert[..] {
            tracing::info!("Certificate matches pinned certificate");
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::error!("Certificate does NOT match pinned certificate");
            Err(rustls::Error::General("error 501".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// Create TLS config with certificate pinning
pub fn create_pinned_rustls_config(cert: Vec<u8>) -> Arc<ClientConfig> {
    let mut file = std::io::Cursor::new(cert);
    let mut certs = rustls_pemfile::certs(&mut file);
    let pinned_cert = certs
        .next()
        .expect("error 405")
        .expect("error 409")
        .into_owned();

    tracing::info!("🔒 Certificate pinning enabled");
    tracing::info!("📌 Pinned cert length: {} bytes", pinned_cert.len());

    // Create the verifier
    let verifier = Arc::new(PinningCertVerifier {
        pinned_cert: pinned_cert.to_vec(),
    });

    // Configure rustls with empty RootCertStore
    let root_cert_store = RootCertStore::empty();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    tracing::info!("Setting SSL pinning");
    client_config
        .dangerous()
        .set_certificate_verifier(verifier);

    Arc::new(client_config)
}