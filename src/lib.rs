use asn1_types::SpcIndirectDataContent;
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
};
use der::{asn1::SetOfVec, Encode};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use signed_data::{SignedData, SignerInfo};
use utils::{to_hex_str, TryVecInto};

pub mod asn1_types;
pub mod cert;
pub mod errors;
pub mod signed_data;
pub mod utils;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSign {
    pub signed_data: SignedData,
    pub authenticode: String,
}

impl PeSign {
    // 从导出的签名证书中提取签名信息
    pub fn from_certificate_table_buf(bin: &[u8]) -> Result<Self, PeSignError> {
        let mut reader = SliceReader::new(bin).map_unknown_err()?;
        let ci =
            ContentInfo::decode(&mut reader).map_app_err(PeSignErrorKind::InvalidContentInfo)?;

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
                        Ok(Self {
                            signed_data,
                            authenticode,
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

    // 验证证书是否有效
    pub fn verify(self: &Self) -> Result<PeSignStatus, PeSignError> {
        self.signed_data.verify()
    }

    // 从签名属性中获取副署签名信息
    pub fn get_countersignature(self: &Self) -> Result<Option<SignerInfo>, PeSignError> {
        let signer_info = &self.signed_data.signer_info;
        match &signer_info.unsigned_attrs {
            Some(unsigned_attrs) => {
                match unsigned_attrs
                    .0
                    .iter()
                    .find(|v| v.oid == "1.2.840.113549.1.9.6")
                {
                    Some(countersignature_attr) => {
                        let attr_value = countersignature_attr.values.concat();
                        let cs_signer_info = cms::signed_data::SignerInfo::from_der(&attr_value)
                            .map_app_err(PeSignErrorKind::InvalidCounterSignature)?;

                        Ok(Some(cs_signer_info.try_into()?))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
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

impl Attribute {
    pub fn to_der(self: &Self) -> Result<Vec<u8>, PeSignError> {
        self.__inner.to_der().map_unknown_err()
    }
}

#[cfg(test)]
mod tests {
    use cms::cert::x509::der::SliceReader;

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
    fn test_parse_pkcs7() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.authenticode,
            "9253a6f72ee0e3970d5457e0f061fdb40b484f18"
        );
    }
}
