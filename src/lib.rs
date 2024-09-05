use asn1_types::SpcIndirectDataContent;
use cert::{
    ext::Extension, name::RdnSequence, Algorithm, Certificate, CertificateChain,
    CertificateChainBuilder,
};
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
    signed_data::SignerIdentifier,
};
use der::{
    asn1::{OctetStringRef, SetOfVec},
    oid::db::rfc5912::RSA_ENCRYPTION,
    Encode,
};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign};
use sha1::{Digest, Sha1};
use utils::{to_hex_str, TryVecInto};

pub mod asn1_types;
pub mod cert;
pub mod errors;
pub mod utils;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfo {
    pub signed_attrs: Option<Attributes>, // authenticatedAttributes
    pub unsigned_attrs: Option<Attributes>, // unauthenticatedAttributes
    pub signature: Vec<u8>,               // encryptedDigest
}

impl TryFrom<cms::signed_data::SignerInfo> for SignerInfo {
    type Error = PeSignError;

    fn try_from(signer_info: cms::signed_data::SignerInfo) -> Result<Self, Self::Error> {
        // signed attrs/auth attrs
        let signed_attrs = match signer_info.signed_attrs {
            Some(original_signed_attrs) => Some(original_signed_attrs.try_into()?),
            None => None,
        };
        // unsigned attrs/unauth attrs
        let unsigned_attrs = match signer_info.unsigned_attrs {
            Some(original_unsigned_attrs) => Some(original_unsigned_attrs.try_into()?),
            None => None,
        };
        // signature/encryptedDigest
        if signer_info.signature_algorithm.oid != RSA_ENCRYPTION {
            return Err(PeSignError {
                kind: PeSignErrorKind::UnsupportedAlgorithm,
                message: signer_info.signature_algorithm.oid.to_string(),
            });
        }
        let signature = signer_info.signature.as_bytes().to_vec();

        Ok(Self {
            signed_attrs,
            unsigned_attrs,
            signature,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: String,
    pub econtent: Vec<u8>,
    pub econtent_value: Vec<u8>,
}

impl TryFrom<cms::signed_data::EncapsulatedContentInfo> for EncapsulatedContentInfo {
    type Error = PeSignError;

    fn try_from(
        ecap_content_info: cms::signed_data::EncapsulatedContentInfo,
    ) -> Result<Self, Self::Error> {
        let econtent = ecap_content_info.econtent.ok_or(PeSignError {
            kind: PeSignErrorKind::EmptyEncapsulatedContent,
            message: "".to_owned(),
        })?;
        let econtent_value = econtent.value().to_vec();
        let econtent = econtent.to_der().map_unknown_err()?;
        let econtent_type = ecap_content_info.econtent_type.to_string();

        Ok(Self {
            econtent_type,
            econtent,
            econtent_value,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedData {
    pub encap_content_info: EncapsulatedContentInfo, // messageDigest
    pub signer_info: SignerInfo,                     // signerInfo
    pub signer_cert_chain: CertificateChain,         // signer_cert
    pub other_cert_chains: Vec<CertificateChain>,    // other cert
}

impl TryFrom<cms::signed_data::SignedData> for SignedData {
    type Error = PeSignError;

    fn try_from(signed_data: cms::signed_data::SignedData) -> Result<Self, Self::Error> {
        let encap_content_info = signed_data.encap_content_info.try_into()?;
        let signer_info = signed_data.signer_infos.0.get(0).ok_or(PeSignError {
            kind: PeSignErrorKind::NoFoundSignerInfo,
            message: "".to_owned(),
        })?;

        // certificates
        let certset = signed_data.certificates.ok_or(PeSignError {
            kind: PeSignErrorKind::EmptyCertificate,
            message: "".to_owned(),
        })?;

        let mut cert_list = vec![];
        for cert_choice in certset.0.iter() {
            match cert_choice {
                cms::cert::CertificateChoices::Certificate(cert) => {
                    cert_list.push(cert.to_owned().try_into()?)
                }
                cms::cert::CertificateChoices::Other(cert) => {
                    return Err(PeSignError {
                        kind: PeSignErrorKind::UnsupportedCertificateFormat,
                        message: cert.other_cert_format.to_string(),
                    }
                    .into())
                }
            }
        }

        // certificate chains
        let cert_chains = Self::build_certificate_chains(&cert_list)?;

        // signer certificate chain
        let mut signer_cert_chain = None;
        let mut other_cert_chains = vec![];
        match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(sid) => {
                let signer_issuer: RdnSequence = sid.issuer.clone().into();
                let signer_sn = sid.serial_number.as_bytes();
                for chain in &cert_chains {
                    if chain[0].issuer == signer_issuer && chain[0].serial_number == signer_sn {
                        signer_cert_chain = Some(chain.clone());
                        continue;
                    }

                    other_cert_chains.push(chain.clone());
                }

                if signer_cert_chain.is_none() {
                    return Err(PeSignError {
                        kind: PeSignErrorKind::UnknownSigner,
                        message: format!("RDN: {}, SN: {}", signer_issuer, to_hex_str(signer_sn)),
                    });
                }
            }
            SignerIdentifier::SubjectKeyIdentifier(sid) => {
                for chain in &cert_chains {
                    if signer_cert_chain.is_none() {
                        match &chain[0].extensions {
                            Some(exts) => {
                                for ext in &exts.0 {
                                    match ext {
                                        Extension::SubjectKeyIdentifier(cert_skid) => {
                                            if *cert_skid == sid.clone().into() {
                                                signer_cert_chain = Some(chain.clone());
                                                continue;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            None => {}
                        }
                    }

                    other_cert_chains.push(chain.clone());
                }

                if signer_cert_chain.is_none() {
                    return Err(PeSignError {
                        kind: PeSignErrorKind::UnknownSigner,
                        message: to_hex_str(sid.0.as_bytes()),
                    });
                }
            }
        }

        Ok(Self {
            encap_content_info,
            signer_info: signer_info.clone().try_into()?,
            signer_cert_chain: signer_cert_chain.unwrap(),
            other_cert_chains,
        })
    }
}

impl SignedData {
    // 获取证书链
    pub fn build_certificate_chains(
        cert_list: &[Certificate],
    ) -> Result<Vec<CertificateChain>, PeSignError> {
        // 加载 cacert.pem 中的 CA 证书
        let cacerts: Vec<Certificate> = Certificate::load_pem_chain(include_bytes!("cacert.pem"))?;

        // 构建证书建
        let cert_chains = CertificateChainBuilder::new()
            .set_trusted_ca_certs(&cacerts)
            .set_cert_list(cert_list)
            .build()?;

        Ok(cert_chains)
    }

    // 验证签名有效性
    pub fn verify(self: &Self) -> Result<PeSignStatus, PeSignError> {
        // 验证证书链是否可信
        if !self.signer_cert_chain.is_trusted()? {
            return Ok(PeSignStatus::UntrustedCertificateChain);
        }

        // 从签名者证书中获取到公钥
        let signer_cert = &self.signer_cert_chain[0];
        let publickey = &signer_cert.subject_public_key_info.subject_public_key;

        if signer_cert.subject_public_key_info.algorithm != Algorithm::RSA {
            return Err(PeSignError {
                kind: PeSignErrorKind::UnsupportedAlgorithm,
                message: signer_cert.subject_public_key_info.algorithm.to_string(),
            });
        }

        let rsa_publickey = rsa::RsaPublicKey::from_pkcs1_der(publickey)
            .map_app_err(PeSignErrorKind::InvalidPublicKey)?;
        let signature = &self.signer_info.signature;

        match &self.signer_info.signed_attrs {
            // 如果存在 signed_attrs，使用 signature 和 publickey 对 signed_attrs 验签
            Some(signed_attrs) => {
                let mut hasher = Sha1::new();
                hasher.update(&signed_attrs.to_der()?);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(Pkcs1v15Sign::new::<Sha1>(), &hashed, signature) {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(PeSignStatus::Invalid),
                }

                // message digest
                match signed_attrs
                    .0
                    .iter()
                    .find(|v| v.oid == "1.2.840.113549.1.9.4")
                {
                    Some(message_digest_attr) => match message_digest_attr.values.get(0) {
                        Some(message_digest_octet_string) => {
                            let octet_string =
                                OctetStringRef::from_der(&message_digest_octet_string)
                                    .map_unknown_err()?;
                            let message_digest = octet_string.as_bytes();

                            let mut hasher = Sha1::new();
                            hasher.update(&self.encap_content_info.econtent_value);
                            let hashed = hasher.finalize().to_vec();

                            if hashed != message_digest {
                                return Ok(PeSignStatus::Invalid);
                            }
                        }
                        None => {
                            return Err(PeSignError {
                                kind: PeSignErrorKind::NoFoundMessageDigest,
                                message: "".to_owned(),
                            });
                        }
                    },
                    None => {
                        return Err(PeSignError {
                            kind: PeSignErrorKind::NoFoundMessageDigest,
                            message: "".to_owned(),
                        });
                    }
                }
            }
            // 如果不存在 signed_attrs，使用 signature 和 publickey 对 content 验签
            None => {
                let mut hasher = Sha1::new();
                hasher.update(&self.encap_content_info.econtent_value);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(Pkcs1v15Sign::new::<Sha1>(), &hashed, signature) {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(PeSignStatus::Invalid),
                }
            }
        }

        Ok(PeSignStatus::Valid)
    }
}

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
