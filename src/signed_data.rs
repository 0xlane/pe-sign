use std::time::Duration;

use cms::{attr::SigningTime, content_info::ContentInfo};
use der::{
    asn1::OctetStringRef,
    oid::db::{rfc5911::ID_SIGNED_DATA, rfc5912::RSA_ENCRYPTION},
    Decode, Encode, SliceReader,
};
use rsa::pkcs1::DecodeRsaPublicKey;

use super::asn1_types::TSTInfo;
use crate::{
    cert::{
        ext::SubjectKeyIdentifier, Algorithm, Certificate, CertificateChain,
        CertificateChainBuilder, IssuerAndSerialNumber,
    },
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    Attributes, PeSign, PeSignStatus, VerifyOption, DEFAULT_TRUSTED_CA_PEM,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl From<cms::signed_data::SignerIdentifier> for SignerIdentifier {
    fn from(value: cms::signed_data::SignerIdentifier) -> Self {
        match value {
            cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => {
                Self::IssuerAndSerialNumber(ias.into())
            }
            cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(skid) => {
                Self::SubjectKeyIdentifier(skid.into())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfo {
    pub sid: SignerIdentifier,
    pub signed_attrs: Option<Attributes>, // authenticatedAttributes
    pub unsigned_attrs: Option<Attributes>, // unauthenticatedAttributes
    pub signature: Vec<u8>,               // encryptedDigest
    pub digest_alg: Algorithm,            // digestAlgorithm
}

impl TryFrom<cms::signed_data::SignerInfo> for SignerInfo {
    type Error = PeSignError;

    fn try_from(signer_info: cms::signed_data::SignerInfo) -> Result<Self, Self::Error> {
        // sid
        let sid = signer_info.sid.into();
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
        let digest_alg = signer_info.digest_alg.into();

        Ok(Self {
            sid,
            signed_attrs,
            unsigned_attrs,
            signature,
            digest_alg,
        })
    }
}

impl SignerInfo {
    pub fn verify(
        self: &Self,
        cert_list: &[Certificate],
        indata: &[u8],
        option: &VerifyOption,
    ) -> Result<PeSignStatus, PeSignError> {
        // 构建证书链
        let cert_chain = CertificateChainBuilder::new()
            .set_trusted_ca_certs(&Certificate::load_pem_chain(
                match &option.trusted_ca_pem {
                    Some(ca_pem) => ca_pem.as_str(),
                    None => DEFAULT_TRUSTED_CA_PEM,
                },
            )?)
            .set_cert_list(cert_list)
            .set_sid(self.sid.clone())
            .build()?;

        // 验证证书链是否可信
        if !cert_chain.is_trusted()? {
            return Ok(PeSignStatus::UntrustedCertificateChain);
        }

        // 过期时间验证
        if option.check_time && cert_chain.is_expired()? {
            return Ok(PeSignStatus::Expired);
        }

        // 从签名者证书中获取到公钥
        let signer_cert = &cert_chain[0];
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
                let mut hasher = signer_cert.signature_algorithm.new_digest()?;
                hasher.update(&signed_attrs.to_der()?);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(
                    signer_cert.signature_algorithm.new_pkcs1v15sign()?,
                    &hashed,
                    signature,
                ) {
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

                            let mut hasher = self.digest_alg.new_digest()?;
                            hasher.update(indata);
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
                let mut hasher = self.digest_alg.new_digest()?;
                hasher.update(indata);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(
                    signer_cert.signature_algorithm.new_pkcs1v15sign()?,
                    &hashed,
                    signature,
                ) {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(PeSignStatus::Invalid),
                }
            }
        }

        Ok(PeSignStatus::Valid)
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
    pub cert_list: Vec<Certificate>,                 // cert list
    __inner: cms::signed_data::SignedData,
}

impl der::Encode for SignedData {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.__inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.__inner.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for SignedData {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let cert = cms::signed_data::SignedData::decode(decoder)?;

        cert.try_into()
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl TryFrom<cms::signed_data::SignedData> for SignedData {
    type Error = PeSignError;

    fn try_from(signed_data: cms::signed_data::SignedData) -> Result<Self, Self::Error> {
        let __inner = signed_data.clone();

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

        // signer info
        let signer_info: SignerInfo = signer_info.clone().try_into()?;

        Ok(Self {
            encap_content_info,
            signer_info,
            cert_list,
            __inner,
        })
    }
}

impl SignedData {
    // 获取证书链
    pub fn build_certificate_chain(
        self: &Self,
        ca_pem: Option<&str>,
    ) -> Result<CertificateChain, PeSignError> {
        // 构建证书建
        let cert_chain = CertificateChainBuilder::new()
            .set_trusted_ca_certs(&Certificate::load_pem_chain(match ca_pem {
                Some(ca_pem) => ca_pem,
                None => DEFAULT_TRUSTED_CA_PEM,
            })?)
            .set_cert_list(&self.cert_list)
            .set_sid(self.signer_info.sid.clone())
            .build()?;

        Ok(cert_chain)
    }

    // 从签名属性中获取副署签名信息
    pub fn get_countersignature(self: &Self) -> Result<Option<SignerInfo>, PeSignError> {
        let signer_info = &self.signer_info;
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

    // 构建副署签名证书链
    pub fn build_contersignature_cert_chain(
        self: &Self,
        ca_pem: Option<&str>,
    ) -> Result<Option<CertificateChain>, PeSignError> {
        if let Some(cs_signer_info) = self.get_countersignature()? {
            // 构建证书建
            let cert_chain = CertificateChainBuilder::new()
                .set_trusted_ca_certs(&Certificate::load_pem_chain(match ca_pem {
                    Some(ca_pem) => ca_pem,
                    None => DEFAULT_TRUSTED_CA_PEM,
                })?)
                .set_cert_list(&self.cert_list)
                .set_sid(cs_signer_info.sid.clone())
                .build()?;

            Ok(Some(cert_chain))
        } else {
            Ok(None)
        }
    }

    // 获取微软 TST 签名
    pub fn get_ms_tst_signature(self: &Self) -> Result<Option<SignedData>, PeSignError> {
        match &self.signer_info.unsigned_attrs {
            Some(unsigned_attrs) => {
                match unsigned_attrs
                    .0
                    .iter()
                    .find(|v| v.oid == "1.3.6.1.4.1.311.3.3.1")
                {
                    Some(ms_tst_sign_attr) => {
                        let attr_value = &ms_tst_sign_attr.values.concat()[..];
                        let tst_signed_data = {
                            let mut reader = SliceReader::new(attr_value).map_unknown_err()?;
                            let ci = ContentInfo::decode(&mut reader)
                                .map_app_err(PeSignErrorKind::InvalidContentInfo)?;

                            // signedData
                            match ci.content_type {
                                ID_SIGNED_DATA => ci
                                    .content
                                    .decode_as::<cms::signed_data::SignedData>()
                                    .map_app_err(PeSignErrorKind::InvalidSignedData)?
                                    .try_into()?,
                                ct => {
                                    return Err(PeSignError {
                                        kind: PeSignErrorKind::InvalidContentType,
                                        message: ct.to_string(),
                                    }
                                    .into());
                                }
                            }
                        };

                        Ok(Some(tst_signed_data))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    // 获取内嵌签名
    pub fn get_nested_signature(self: &Self) -> Result<Option<PeSign>, PeSignError> {
        match &self.signer_info.unsigned_attrs {
            Some(unsigned_attrs) => {
                match unsigned_attrs
                    .0
                    .iter()
                    .find(|v| v.oid == "1.3.6.1.4.1.311.2.4.1")
                {
                    Some(nested_sign_attr) => {
                        let attr_value = &nested_sign_attr.values.concat()[..];
                        let nested_sign = PeSign::from_certificate_table_buf(attr_value)?;

                        Ok(Some(nested_sign))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    // 得到签名时间
    pub fn get_signature_time(self: &Self) -> Result<Duration, PeSignError> {
        fn get_signing_time_from_attr(
            signed_attrs: &Option<Attributes>,
        ) -> Result<Option<Duration>, PeSignError> {
            if let Some(signing_time_attr) = match signed_attrs {
                Some(signed_attrs) => signed_attrs
                    .0
                    .iter()
                    .find(|v| v.oid == "1.2.840.113549.1.9.5"), // signingTime attr
                None => None,
            } {
                let attr_value = signing_time_attr.values.concat();
                match SigningTime::from_der(&attr_value)
                    .map_app_err(PeSignErrorKind::InvalidSigningTime)?
                {
                    x509_cert::time::Time::UtcTime(time) => Ok(Some(time.to_unix_duration())),
                    x509_cert::time::Time::GeneralTime(time) => Ok(Some(time.to_unix_duration())),
                }
            } else {
                Ok(None)
            }
        }

        let signing_time = match get_signing_time_from_attr(&self.signer_info.signed_attrs)? {
            Some(signing_time) => Some(signing_time),
            None => {
                match self.get_countersignature()? {
                    Some(cs_signer_info) => {
                        match get_signing_time_from_attr(&cs_signer_info.signed_attrs)? {
                            Some(signing_time) => Some(signing_time),
                            None => None,
                        }
                    }
                    None => {
                        match self.get_ms_tst_signature()? {
                            Some(ms_tst_signature) => match get_signing_time_from_attr(
                                &ms_tst_signature.signer_info.signed_attrs,
                            )? {
                                Some(signing_time) => Some(signing_time),
                                None => {
                                    match ms_tst_signature.encap_content_info.econtent_type.as_str()
                                    {
                                        "1.2.840.113549.1.9.16.1.4" => {
                                            // id-smime-ct-TSTInfo
                                            let x = TSTInfo::from_der(
                                                &ms_tst_signature.encap_content_info.econtent_value,
                                            )
                                            .map_app_err(PeSignErrorKind::InvalidTSTInfo)?;
                                            Some(x.gen_time.to_unix_duration())
                                        }
                                        _ => None,
                                    }
                                }
                            },
                            None => None,
                        }
                    }
                }
            }
        };

        Ok(signing_time.ok_or(PeSignError {
            kind: PeSignErrorKind::NoFoundSigningTime,
            message: "".to_owned(),
        })?)
    }

    // 验证签名有效性
    pub fn verify(self: &Self, option: &VerifyOption) -> Result<PeSignStatus, PeSignError> {
        self.signer_info.verify(
            &self.cert_list,
            &self.encap_content_info.econtent_value,
            option,
        )
    }
}
