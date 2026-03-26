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
