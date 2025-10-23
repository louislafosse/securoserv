use std::io::BufReader;
use std::fs::File;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::{certs, pkcs8_private_keys};

pub fn init_rustls_config(cert_reader : &mut BufReader<File>, key_reader: &mut BufReader<File>) -> rustls::ServerConfig {

    let cert_chain_der: Vec<CertificateDer<'static>> = certs(cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certificate chain");

    let mut keys = pkcs8_private_keys(key_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse private key");

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain_der, rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)))
        .expect("bad certificate/key")
}