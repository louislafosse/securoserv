/// TLS configuration mode
#[derive(Debug, Clone, Copy)]
pub enum TlsMode {
    /// Normal pinning: server certificate validated, no client cert required
    NormalPinning,
    /// Mutual TLS: both server and client certificates required and validated
    MutualTlsPinning,
}
