use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSignErrorKind {
    /// IO Error.
    IoError,

    /// Invalid PE File.
    InvalidPeFile,

    /// Invalid Certificate ContentInfo.
    InvalidContentInfo,

    /// Invalid ContentType.
    InvalidContentType,

    /// Invalid SignedData.
    InvalidSignedData,

    /// Invalid Encapsulated ContentType.
    InvalidEncapsulatedContentType,

    /// Empty EncapsulatedContent.
    EmptyEncapsulatedContent,

    /// Invalid SpcIndirectDataContent.
    InvalidSpcIndirectDataContent,

    /// Empty Certificate.
    EmptyCertificate,

    /// Unsupported Certificate Format.
    UnsupportedCertificateFormat,

    /// Unsupported Algorithm.
    UnsupportedAlgorithm,

    /// Invalid Certificate Extension.
    InvalidCertificateExtension,

    /// Wrong Certificate Chain Build Param.
    WrongCertChainBuildParam,

    /// Invalid PEM Certificate.
    InvalidPEMCertificate,

    /// Invalid Public Key.
    InvalidPublicKey,

    /// No Found SignerInfo.
    NoFoundSignerInfo,

    /// Unknown Signer.
    UnknownSigner,

    /// No Found Message Digest.
    NoFoundMessageDigest,

    /// Invalid Counter Signature.
    InvalidCounterSignature,

    /// Invalid SigningTime.
    InvalidSigningTime,

    /// No Found SigningTime.
    NoFoundSigningTime,

    /// Invalid TSTInfo.
    InvalidTSTInfo,

    /// Export as DER Error.
    ExportDerError,

    /// Export as PEM Error.
    ExportPemError,

    /// Unknown Error.
    Unknown,
}

#[derive(Debug)]
pub struct PeSignError {
    pub kind: PeSignErrorKind,
    pub message: String,
}

impl fmt::Display for PeSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PeSignError {}

pub trait PeSignResult<T> {
    fn map_app_err(self: Self, kind: PeSignErrorKind) -> Result<T, PeSignError>;
    fn map_unknown_err(self: Self) -> Result<T, PeSignError>;
}

impl<T, E> PeSignResult<T> for std::result::Result<T, E>
where
    E: std::error::Error + 'static,
{
    fn map_app_err(self: Self, kind: PeSignErrorKind) -> Result<T, PeSignError> {
        self.map_err(|err| PeSignError {
            kind: kind,
            message: err.to_string(),
        })
    }

    fn map_unknown_err(self: Self) -> Result<T, PeSignError> {
        self.map_app_err(PeSignErrorKind::Unknown)
    }
}
