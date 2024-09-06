use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSignErrorKind {
    // IO 错误
    IoError,

    // 无效的 PE 文件
    InvalidPeFile,

    // 无效的证书内容
    InvalidContentInfo,

    // 无效的内容类型
    InvalidContentType,

    // 无效的 signedData
    InvalidSignedData,

    // 无效的签名封装内容类型
    InvalidEncapsulatedContentType,

    // 空的封装数据
    EmptyEncapsulatedContent,

    // 无效的签名封装内容
    InvalidSpcIndirectDataContent,

    // 空的证书
    EmptyCertificate,

    // 不支持的证书格式
    UnsupportedCertificateFormat,

    // 不支持的算法
    UnsupportedAlgorithm,

    // 无效的证书拓展
    InvalidCertificateExtension,

    // 错误的证书链构建参数
    WrongCertChainBuildParam,

    // 无效的 PEM 证书
    InvalidPEMCertificate,

    // 无效的公钥
    InvalidPublicKey,

    // 找不到签名者信息
    NoFoundSignerInfo,

    // 未知签名者
    UnknownSigner,

    // 不存在消息摘要
    NoFoundMessageDigest,

    // 无效的副署签名
    InvalidCounterSignature,

    // 无效的签名时间
    InvalidSigningTime,

    // 找不到签名时间
    NoFoundSigningTime,

    // 无效的TSTInfo
    InvalidTSTInfo,

    // 未知错误
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
