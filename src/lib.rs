use asn1_types::{SpcIndirectDataContent, ID_SPC_INDIRECT_DATA};
use cert::{
    ext::Extension, name::RdnSequence, Algorithm, Certificate, CertificateChain,
    CertificateChainBuilder,
};
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
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
pub struct PeSign {
    pub authenticode: String,
    pub indata: Vec<u8>,
    pub signed_attrs: Option<Attributes>, // authenticatedAttributes
    pub unsigned_attrs: Option<Attributes>, // unauthenticatedAttributes
    pub signature: Vec<u8>,               // encryptedDigest
    pub signer_cert_chain: CertificateChain, // signerinfo
    pub other_cert_chains: Vec<CertificateChain>, // timestamp ..
}

impl PeSign {
    // 从导出的签名证书中提取签名信息
    pub fn from_certificate_table_buf(bin: &[u8]) -> Result<Self, PeSignError> {
        let mut reader = SliceReader::new(bin).map_unknown_err()?;
        let ci =
            ContentInfo::decode(&mut reader).map_app_err(PeSignErrorKind::InvalidContentInfo)?;

        let indata;
        let authenticode;
        let mut cert_list: Vec<Certificate> = vec![];
        let mut signed_attrs: Option<Attributes> = None;
        let mut unsigned_attrs: Option<Attributes> = None;
        let mut signature = vec![];
        let mut signer_cert_chain: Option<CertificateChain> = None;
        let mut other_cert_chains: Vec<CertificateChain> = vec![];

        // signedData
        match ci.content_type {
            ID_SIGNED_DATA => {
                let signed_data = ci
                    .content
                    .decode_as::<SignedData>()
                    .map_app_err(PeSignErrorKind::InvalidSignedData)?;

                // SpcIndirectDataContent
                match signed_data.encap_content_info.econtent_type {
                    ID_SPC_INDIRECT_DATA => match signed_data.encap_content_info.econtent {
                        Some(econtent) => {
                            indata = econtent.value().to_vec();
                            let spc_indirect_data_content = econtent
                                .decode_as::<SpcIndirectDataContent>()
                                .map_app_err(PeSignErrorKind::InvalidSpcIndirectDataContent)?;
                            authenticode = to_hex_str(
                                spc_indirect_data_content.message_digest.digest.as_bytes(),
                            );
                        }
                        None => {
                            return Err(PeSignError {
                                kind: PeSignErrorKind::EmptyEncapsulatedContent,
                                message: "".to_owned(),
                            }
                            .into())
                        }
                    },
                    ect => {
                        return Err(PeSignError {
                            kind: PeSignErrorKind::InvalidEncapsulatedContentType,
                            message: ect.to_string(),
                        }
                        .into())
                    }
                }

                // certificates
                let certset = signed_data.certificates.ok_or(PeSignError {
                    kind: PeSignErrorKind::EmptyCertificate,
                    message: "".to_owned(),
                })?;

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

                // signer info
                for signer_info in signed_data.signer_infos.0.iter() {
                    // signed attrs/auth attrs
                    match signer_info.signed_attrs.clone() {
                        Some(orignal_signed_attrs) => {
                            signed_attrs = Some(orignal_signed_attrs.try_into()?);
                        }
                        None => {}
                    }

                    // unsigned_attrs/unauth attrs
                    match signer_info.unsigned_attrs.clone() {
                        Some(orignal_unsigned_attrs) => {
                            unsigned_attrs = Some(orignal_unsigned_attrs.try_into()?);
                        }
                        None => {}
                    }

                    // signature/encryptedDigest
                    if signer_info.signature_algorithm.oid != RSA_ENCRYPTION {
                        return Err(PeSignError {
                            kind: PeSignErrorKind::UnsupportedAlgorithm,
                            message: signer_info.signature_algorithm.oid.to_string(),
                        });
                    }
                    signature = signer_info.signature.as_bytes().to_vec();

                    // signer certificate chain
                    match &signer_info.sid {
                        SignerIdentifier::IssuerAndSerialNumber(sid) => {
                            let signer_issuer: RdnSequence = sid.issuer.clone().into();
                            let signer_sn = sid.serial_number.as_bytes();
                            for chain in &cert_chains {
                                if chain[0].issuer == signer_issuer
                                    && chain[0].serial_number == signer_sn
                                {
                                    signer_cert_chain = Some(chain.clone());
                                    continue;
                                }

                                other_cert_chains.push(chain.clone());
                            }

                            if signer_cert_chain.is_none() {
                                return Err(PeSignError {
                                    kind: PeSignErrorKind::UnknownSigner,
                                    message: format!(
                                        "RDN: {}, SN: {}",
                                        signer_issuer,
                                        to_hex_str(signer_sn)
                                    ),
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

                    // 只看第 1 个 SignerInfo
                    break;
                }
            }
            ct => {
                return Err(PeSignError {
                    kind: PeSignErrorKind::InvalidContentType,
                    message: ct.to_string(),
                }
                .into())
            }
        };

        let signer_cert_chain = signer_cert_chain.unwrap();

        Ok(Self {
            authenticode,
            indata,
            signed_attrs,
            unsigned_attrs,
            signature,
            signer_cert_chain,
            other_cert_chains,
        })
    }

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

    // 验证证书签名是否有效
    pub fn verify_signer(self: &Self) -> Result<PeSignStatus, PeSignError> {
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
        let signature = &self.signature;

        match &self.signed_attrs {
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
                            hasher.update(&self.indata);
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
            // 如果不存在 signed_attrs，使用 signature 和 publickey 对 indata 验签
            None => {
                let mut hasher = Sha1::new();
                hasher.update(&self.indata);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(Pkcs1v15Sign::new::<Sha1>(), &hashed, signature) {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(PeSignStatus::Invalid),
                }
            }
        }

        Ok(PeSignStatus::Valid)
    }

    // 验证其他证书是否有效
    pub fn verify_other(self: &Self) -> Result<PeSignStatus, PeSignError> {
        for chain in &self.other_cert_chains {
            if !chain.is_trusted()? {
                return Ok(PeSignStatus::UntrustedCertificateChain);
            }
        }

        Ok(PeSignStatus::Valid)
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
