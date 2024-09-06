use std::path::Path;

use asn1_types::SpcIndirectDataContent;
use cert::Algorithm;
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
};
use der::{asn1::SetOfVec, Encode};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use exe::{Buffer, ImageDirectoryEntry, VecPE, PE};
use signed_data::SignedData;
use utils::{to_hex_str, TryVecInto};

pub mod asn1_types;
pub mod cert;
pub mod errors;
pub mod signed_data;
pub mod utils;
pub use der;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSign {
    pub signed_data: SignedData,
    pub authenticode: String,
    pub authenticode_digest: Algorithm,
    __inner: cms::content_info::ContentInfo,
}

impl der::Encode for PeSign {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.__inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.__inner.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for PeSign {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        Self::from_reader(decoder)
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl der::pem::PemLabel for PeSign {
    const PEM_LABEL: &'static str = "PKCS7";
}

impl<'a> PeSign {
    pub fn from_reader<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self, PeSignError> {
        let ci = ContentInfo::decode(decoder).map_app_err(PeSignErrorKind::InvalidContentInfo)?;

        let __inner = ci.clone();

        // signedData
        match ci.content_type {
            ID_SIGNED_DATA => {
                let signed_data: SignedData = ci
                    .content
                    .decode_as::<cms::signed_data::SignedData>()
                    .map_app_err(PeSignErrorKind::InvalidSignedData)?
                    .try_into()?;

                match &signed_data.encap_content_info.econtent_type[..] {
                    "1.3.6.1.4.1.311.2.1.4" => {
                        let spc_indirect_data_content = SpcIndirectDataContent::from_der(
                            &signed_data.encap_content_info.econtent,
                        )
                        .map_app_err(PeSignErrorKind::InvalidSpcIndirectDataContent)?;
                        let authenticode =
                            to_hex_str(spc_indirect_data_content.message_digest.digest.as_bytes());
                        let authenticode_digest =
                            spc_indirect_data_content.message_digest.algorithm.into();
                        Ok(Self {
                            signed_data,
                            authenticode,
                            authenticode_digest,
                            __inner,
                        })
                    }
                    _ => Err(PeSignError {
                        kind: PeSignErrorKind::InvalidEncapsulatedContentType,
                        message: signed_data.encap_content_info.econtent_type,
                    }),
                }
            }
            ct => Err(PeSignError {
                kind: PeSignErrorKind::InvalidContentType,
                message: ct.to_string(),
            }
            .into()),
        }
    }

    // 从导出的签名证书中提取签名信息
    pub fn from_certificate_table_buf(bin: &[u8]) -> Result<Self, PeSignError> {
        let mut reader = SliceReader::new(bin).map_unknown_err()?;
        Self::from_reader(&mut reader)
    }

    // 从 PE 文件中提取签名信息
    pub fn from_pe_path<P: AsRef<Path>>(filename: P) -> Result<Option<Self>, PeSignError> {
        let image = VecPE::from_disk_file(filename).map_app_err(PeSignErrorKind::IoError)?;

        Self::from_vecpe(&image)
    }

    // 从 PE 数据中提取签名信息
    pub fn from_pe_data(bin: &[u8]) -> Result<Option<Self>, PeSignError> {
        let image = VecPE::from_disk_data(bin);

        Self::from_vecpe(&image)
    }

    // 从 VecPE 提取签名信息
    pub fn from_vecpe(image: &VecPE) -> Result<Option<Self>, PeSignError> {
        // va = 0 表示无签名
        let security_directory = image
            .get_data_directory(ImageDirectoryEntry::Security)
            .map_app_err(PeSignErrorKind::InvalidPeFile)?;
        if security_directory.virtual_address.0 == 0x00 {
            return Ok(None);
        }

        let signature_data =
            Buffer::offset_to_ptr(image, security_directory.virtual_address.into())
                .map_app_err(PeSignErrorKind::InvalidPeFile)?; // security_data_directory rva is equivalent to file offset

        let win_certificate =
            unsafe { std::slice::from_raw_parts(signature_data, security_directory.size as usize) };
        let pkcs7 = &win_certificate[8..]; // _WIN_CERTIFICATE->bCertificate

        Ok(Some(Self::from_certificate_table_buf(&pkcs7)?))
    }

    // 验证证书是否有效
    pub fn verify(self: &Self) -> Result<PeSignStatus, PeSignError> {
        self.signed_data.verify()
    }
}

// 签名状态
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSignStatus {
    // 不受信任的证书链
    UntrustedCertificateChain,

    // 证书过期
    Expired,

    // 证书无效
    Invalid,

    // 证书有效
    Valid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attributes(pub Vec<Attribute>);

impl TryFrom<x509_cert::attr::Attributes> for Attributes {
    type Error = PeSignError;

    fn try_from(value: x509_cert::attr::Attributes) -> Result<Self, Self::Error> {
        Ok(Self(value.into_vec().try_vec_into().map_err(|err| {
            Self::Error {
                kind: PeSignErrorKind::Unknown,
                message: err.to_string(),
            }
        })?))
    }
}

impl Attributes {
    pub fn to_der(self: &Self) -> Result<Vec<u8>, PeSignError> {
        let mut result = SetOfVec::<x509_cert::attr::Attribute>::new();

        for vv in &self.0 {
            result.insert(vv.__inner.clone()).map_unknown_err()?;
        }

        Ok(result.to_der().map_unknown_err()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub oid: String,
    pub values: Vec<Vec<u8>>,
    __inner: x509_cert::attr::Attribute,
}

impl TryFrom<x509_cert::attr::Attribute> for Attribute {
    type Error = PeSignError;

    fn try_from(attr: x509_cert::attr::Attribute) -> Result<Self, Self::Error> {
        let mut values = vec![];

        for vv in attr.values.iter() {
            values.push(vv.to_der().map_unknown_err()?);
        }

        Ok(Self {
            oid: attr.oid.to_string(),
            values: values,
            __inner: attr,
        })
    }
}

#[cfg(test)]
mod tests {
    use cms::cert::x509::der::SliceReader;
    use der::{DecodePem, EncodePem};

    use super::*;

    #[test]
    fn test_parse_pkcs7_from_der() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        assert!(ContentInfo::from_der(bytes)
            .unwrap_err()
            .to_string()
            .starts_with("trailing data"));
    }

    #[test]
    fn test_parse_pkcs7_decode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let mut reader = SliceReader::new(bytes).unwrap();
        assert!(ContentInfo::decode(&mut reader).is_ok());
    }

    #[test]
    fn get_authenticode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.authenticode,
            "9253a6f72ee0e3970d5457e0f061fdb40b484f18"
        );
    }

    #[test]
    fn get_nested_authenticode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();
        let nested = pesign.signed_data.get_nested_signature().unwrap().unwrap();

        assert_eq!(
            nested.authenticode,
            "33a755311b428c2063f983058dbf9e1648d00d5fec4adf00e0a34ddee639f68b",
        );
    }

    #[test]
    fn get_cert_signature_data() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        let signature_value = &pesign.signed_data.signer_cert_chain[0].signature_value[..];
        let signature_bin = include_bytes!("./examples/signature.bin");

        assert_eq!(signature_value, signature_bin);
    }

    #[test]
    fn parse_signingtime_from_cs() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.signed_data.get_signature_time().unwrap().as_secs(),
            1459215302
        );
    }

    #[test]
    fn parse_signingtime_from_ms_tst_sign() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign
                .signed_data
                .get_nested_signature()
                .unwrap()
                .unwrap()
                .signed_data
                .get_signature_time()
                .unwrap()
                .as_secs(),
            1459215303
        );
    }

    #[test]
    fn parse_signingtime_from_attr() {
        let bytes = include_bytes!("./examples/pkcs7_with_signing_time.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.signed_data.get_signature_time().unwrap().as_secs(),
            1717347664
        );
    }

    #[test]
    fn export_pem() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.to_pem(Default::default()).unwrap(),
            include_str!("./examples/pkcs7.pem")
        );
    }

    #[test]
    fn from_pem() {
        let pem = include_str!("./examples/pkcs7.pem");
        let result = PeSign::from_pem(pem);

        assert!(result.is_ok());
    }

    #[test]
    fn from_pe() {
        let result = PeSign::from_pe_data(include_bytes!("./examples/ProcessHacker.exe"));

        assert!(result.is_ok());
    }
}
