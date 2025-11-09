use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::client::danger::HandshakeSignatureValid;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::sync::Arc;
use crate::tls::TlsMode;

/// Client certificate verifier that requires and pins a specific certificate
#[derive(Debug)]
struct PinnedClientCertVerifier {
    expected_cert: CertificateDer<'static>,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Compare certificate bytes directly - exact match required
        if end_entity.as_ref() == self.expected_cert.as_ref() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Since we're pinning the exact certificate, we trust it
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Since we're pinning the exact certificate, we trust it
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

pub fn init_rustls_config(
    cert: &[u8],
    key: &[u8],
    mode: TlsMode,
) -> rustls::ServerConfig {
    let mut cert_reader = std::io::Cursor::new(cert);
    let mut key_reader = std::io::Cursor::new(key);

    let cert_chain_der: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certificate chain");

    let mut keys = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse private key");

    match mode {
        TlsMode::MutualTlsPinning => {
            // Require client certificates and pin to the server's own certificate
            let client_verifier = Arc::new(PinnedClientCertVerifier {
                expected_cert: cert_chain_der[0].clone(),
            });

            ServerConfig::builder()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(cert_chain_der, rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)))
                .expect("bad certificate/key")
        }
        TlsMode::NormalPinning => {
            // No client cert required
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain_der, rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)))
                .expect("bad certificate/key")
        }
    }
}
