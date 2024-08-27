use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSignErrorKind {

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
    E : std::error::Error + 'static
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
