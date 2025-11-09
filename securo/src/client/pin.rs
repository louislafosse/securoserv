use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::tls::TlsMode;


/// SPKI-based certificate pinning verifier for single cert mode
/// Accepts only the specified certificate's SPKI
#[derive(Debug)]
struct SinglePinVerifier {
    expected_pin: String,
}

impl SinglePinVerifier {
    /// Create a new verifier with a single pin from a certificate
    // cert_pem is the PEM bytes of a certificate (or chain); we take the first cert
    fn new(cert_pem: &[u8]) -> Self {
        let mut cursor = std::io::Cursor::new(cert_pem);
        let mut certs = rustls_pemfile::certs(&mut cursor);
        let cert_der = certs
            .next()
            .expect("no certificate found in provided PEM")
            .expect("failed to parse certificate");

        let expected_pin = spki_pin_from_der(cert_der.as_ref());

        Self { expected_pin }
    }
}

impl ServerCertVerifier for SinglePinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = spki_pin_from_der(end_entity.as_ref());
        if pin == self.expected_pin {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::error!("Certificate pin does NOT match pinned certificate: {}", pin);
            Err(rustls::Error::General("Certificate pin mismatch".to_string()))
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

/// Extract SubjectPublicKeyInfo (SPKI) from an X.509 certificate DER
/// The SPKI is the public key information that should be hashed for pinning
fn extract_spki_from_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    // Parse the DER structure to find SPKI
    let mut offset = 0;
    
    // Parse outer SEQUENCE (Certificate)
    if offset >= cert_der.len() || cert_der[offset] != 0x30 {
        return None;
    }
    offset += 1;
    
    let (_cert_len, cert_len_bytes) = parse_der_length(&cert_der[offset..])?;
    offset += cert_len_bytes;
    
    // Parse TBSCertificate SEQUENCE
    if offset >= cert_der.len() || cert_der[offset] != 0x30 {
        return None;
    }
    offset += 1;
    
    let (tbs_len, tbs_len_bytes) = parse_der_length(&cert_der[offset..])?;
    offset += tbs_len_bytes;
    let tbs_end = offset + tbs_len;
    
    // Skip through TBSCertificate fields to get to field 6 (SPKI)
    // We need to skip: [0], INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE
    for _ in 0..6 {
        if offset >= tbs_end {
            return None;
        }
        
        let _tag = cert_der[offset];
        offset += 1;
        
        let (length, length_bytes) = parse_der_length(&cert_der[offset..])?;
        offset += length_bytes;
        offset += length;
    }
    
    // Now offset should be at the SPKI SEQUENCE
    if offset >= cert_der.len() || cert_der[offset] != 0x30 {
        return None;
    }
    
    let spki_tag_offset = offset;
    offset += 1;
    
    let (spki_len, spki_len_bytes) = parse_der_length(&cert_der[offset..])?;
    
    // Extract the complete SPKI including tag and length bytes
    let spki_total_len = 1 + spki_len_bytes + spki_len;
    if spki_tag_offset + spki_total_len > cert_der.len() {
        return None;
    }
    
    Some(cert_der[spki_tag_offset..spki_tag_offset + spki_total_len].to_vec())
}

/// Parse a DER length field (short or long form)
/// Returns (length_value, bytes_consumed) or None on error
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    
    let first = data[0];
    if first & 0x80 == 0 {
        // Short form (bits 6-0 are the length)
        Some((first as usize, 1))
    } else {
        // Long form (bits 6-0 indicate how many octets follow)
        let num_octets = (first & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || num_octets + 1 > data.len() {
            return None;
        }
        
        let mut length = 0usize;
        for i in 0..num_octets {
            length = (length << 8) | (data[1 + i] as usize);
        }
        
        Some((length, num_octets + 1))
    }
}

/// Compute base64(SHA256(SPKI)) from a certificate DER blob
fn spki_pin_from_der(cert_der: &[u8]) -> String {
    if let Some(spki) = extract_spki_from_der(cert_der) {
        let mut hasher = Sha256::new();
        hasher.update(&spki);
        let hash = hasher.finalize();
        BASE64.encode(hash)
    } else {
        // Fallback: hash the whole cert
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();
        BASE64.encode(hash)
    }
}

pub mod create {
    use rustls::ClientConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;
    use super::TlsMode;

    /// Create a TLS client configuration with SPKI-based certificate pinning
    /// Uses the provided certificate's SPKI for pinning verification
    /// Optionally sends client certificate based on TlsMode
    pub fn pinned_rustls_config(cert: &[u8], key: Option<&[u8]>, mode: TlsMode) -> Arc<ClientConfig> {
        // Parse provided PEM and create a SinglePinVerifier from it
        let verifier = Arc::new(super::SinglePinVerifier::new(cert));
        let mut cursor = std::io::Cursor::new(cert);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to parse certificates");

        // Configure rustls with custom certificate pinning verifier
        let root_cert_store = RootCertStore::empty();
        
        let mut client_config = match mode {
            TlsMode::MutualTlsPinning => {
                let mut cursor = std::io::Cursor::new(key.expect("Client key required for MutualTlsPinning mode"));
                let keys = rustls_pemfile::pkcs8_private_keys(&mut cursor)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse private keys");

                    // Send client certificate
                if !keys.is_empty() && !certs.is_empty() {
                    ClientConfig::builder()
                        .with_root_certificates(root_cert_store)
                        .with_client_auth_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(keys[0].clone_key()))
                        .expect("failed to set client certificate")
                } else {
                    panic!("MutualTls mode requires client certificate and key");
                }
            }
            TlsMode::NormalPinning => {
                // Don't send client certificate
                ClientConfig::builder()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth()
            }
        };

        client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        Arc::new(client_config)
    }
}
