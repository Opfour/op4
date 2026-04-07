use std::fmt;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    Crypto(CryptoError),
    Vault(VaultError),
    Network(NetworkError),
    Identity(IdentityError),
    Hardening(HardeningError),
    Io(std::io::Error),
    Postcard(postcard::Error),
}

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpand,
    AeadEncrypt,
    AeadDecrypt,
    Argon2Params,
    Argon2Hash,
    KeyParse,
    KemEncap,
    KemDecap,
    SigVerify,
    NoChainKey,
    NoDhrKey,
    TooManySkipped,
    /// Postcard serialization failure (distinct from AEAD errors).
    Serialize,
}

#[derive(Debug)]
pub enum VaultError {
    InvalidPassphrase,
    InvalidMagic,
    InvalidVersion,
    Corrupt,
    Io(std::io::Error),
    Crypto(CryptoError),
}

#[derive(Debug)]
pub enum NetworkError {
    NymInit(String),
    NymSend(String),
    NymRecv(String),
    TorUnavailable,
}

#[derive(Debug)]
pub enum IdentityError {
    InvalidBase58,
    InvalidFormat,
    SignatureVerification,
    KeyChangeTooFrequent,
}

#[derive(Debug)]
pub enum HardeningError {
    PrctlFailed(i32),
    SetrlimitFailed(i32),
    SeccompBuild(String),
    SeccompInstall(String),
    // Android-specific variants
    DebuggerDetected,
    InjectionDetected,
    IntegrityCheckFailed,
    ApkSignatureMismatch,
    EntropyUnavailable,
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Generic message — never reveal which specific check failed,
        // as that tells an attacker exactly what to bypass next.
        write!(f, "security check failed")
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Crypto(e) => write!(f, "crypto error: {e:?}"),
            AppError::Vault(e) => write!(f, "vault error: {e:?}"),
            AppError::Network(e) => write!(f, "network error: {e:?}"),
            AppError::Identity(e) => write!(f, "identity error: {e:?}"),
            AppError::Hardening(e) => write!(f, "hardening error: {e}"),
            AppError::Io(e) => write!(f, "I/O error: {e}"),
            AppError::Postcard(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<postcard::Error> for AppError {
    fn from(e: postcard::Error) -> Self {
        AppError::Postcard(e)
    }
}

impl From<CryptoError> for AppError {
    fn from(e: CryptoError) -> Self {
        AppError::Crypto(e)
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        AppError::Vault(e)
    }
}

impl From<NetworkError> for AppError {
    fn from(e: NetworkError) -> Self {
        AppError::Network(e)
    }
}

impl From<IdentityError> for AppError {
    fn from(e: IdentityError) -> Self {
        AppError::Identity(e)
    }
}

impl From<HardeningError> for AppError {
    fn from(e: HardeningError) -> Self {
        AppError::Hardening(e)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display impls ----

    #[test]
    fn hardening_error_display_is_generic() {
        // All variants must produce the same opaque message.
        let variants: Vec<HardeningError> = vec![
            HardeningError::PrctlFailed(1),
            HardeningError::SetrlimitFailed(2),
            HardeningError::SeccompBuild("x".into()),
            HardeningError::SeccompInstall("y".into()),
            HardeningError::DebuggerDetected,
            HardeningError::InjectionDetected,
            HardeningError::IntegrityCheckFailed,
            HardeningError::ApkSignatureMismatch,
            HardeningError::EntropyUnavailable,
        ];
        for v in variants {
            assert_eq!(v.to_string(), "security check failed");
        }
    }

    #[test]
    fn app_error_display_crypto() {
        let e = AppError::Crypto(CryptoError::AeadDecrypt);
        assert!(e.to_string().starts_with("crypto error:"));
    }

    #[test]
    fn app_error_display_vault() {
        let e = AppError::Vault(VaultError::InvalidPassphrase);
        assert!(e.to_string().starts_with("vault error:"));
    }

    #[test]
    fn app_error_display_network() {
        let e = AppError::Network(NetworkError::TorUnavailable);
        assert!(e.to_string().starts_with("network error:"));
    }

    #[test]
    fn app_error_display_identity() {
        let e = AppError::Identity(IdentityError::InvalidBase58);
        assert!(e.to_string().starts_with("identity error:"));
    }

    #[test]
    fn app_error_display_hardening() {
        let e = AppError::Hardening(HardeningError::DebuggerDetected);
        assert!(e.to_string().starts_with("hardening error:"));
    }

    #[test]
    fn app_error_display_io() {
        let e = AppError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(e.to_string().starts_with("I/O error:"));
    }

    #[test]
    fn app_error_display_postcard() {
        let e = AppError::Postcard(postcard::Error::SerializeBufferFull);
        assert!(e.to_string().starts_with("serialization error:"));
    }

    #[test]
    fn app_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(AppError::Crypto(CryptoError::HkdfExpand));
        assert!(!e.to_string().is_empty());
    }

    // ---- From impls ----

    #[test]
    fn from_io_error_for_app_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let app: AppError = io_err.into();
        assert!(matches!(app, AppError::Io(_)));
    }

    #[test]
    fn from_postcard_error_for_app_error() {
        let pc_err = postcard::Error::SerializeBufferFull;
        let app: AppError = pc_err.into();
        assert!(matches!(app, AppError::Postcard(_)));
    }

    #[test]
    fn from_crypto_error_for_app_error() {
        let app: AppError = CryptoError::AeadEncrypt.into();
        assert!(matches!(app, AppError::Crypto(_)));
    }

    #[test]
    fn from_vault_error_for_app_error() {
        let app: AppError = VaultError::InvalidMagic.into();
        assert!(matches!(app, AppError::Vault(_)));
    }

    #[test]
    fn from_network_error_for_app_error() {
        let app: AppError = NetworkError::TorUnavailable.into();
        assert!(matches!(app, AppError::Network(_)));
    }

    #[test]
    fn from_identity_error_for_app_error() {
        let app: AppError = IdentityError::InvalidFormat.into();
        assert!(matches!(app, AppError::Identity(_)));
    }

    #[test]
    fn from_hardening_error_for_app_error() {
        let app: AppError = HardeningError::EntropyUnavailable.into();
        assert!(matches!(app, AppError::Hardening(_)));
    }

    #[test]
    fn from_io_error_for_vault_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let ve: VaultError = io_err.into();
        assert!(matches!(ve, VaultError::Io(_)));
    }

    #[test]
    fn from_crypto_error_for_vault_error() {
        let ve: VaultError = CryptoError::KeyParse.into();
        assert!(matches!(ve, VaultError::Crypto(_)));
    }
}
