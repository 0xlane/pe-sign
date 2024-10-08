use std::{
    fmt::{Debug, Display},
    time::SystemTime,
};

use cms::{attr::SigningTime, content_info::ContentInfo};
use der::{asn1::OctetStringRef, oid::db::rfc5911::ID_SIGNED_DATA, Decode, Encode, SliceReader};
use rsa::pkcs1::DecodeRsaPublicKey;

use super::asn1_types::TSTInfo;
use crate::{
    cert::{
        ext::SubjectKeyIdentifier, Algorithm, Certificate, CertificateChain,
        CertificateChainBuilder, IssuerAndSerialNumber,
    },
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    utils::{DisplayBytes, IndentString},
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

impl Display for SignerIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Signer Identifier:")?;
        let str = match self {
            SignerIdentifier::IssuerAndSerialNumber(vv) => vv.to_string(),
            SignerIdentifier::SubjectKeyIdentifier(vv) => vv.to_string(),
        };

        write!(f, "{}", str.indent(4))
    }
}

/// Parse SignerInfo.
///
/// This includes the signer information of a PE signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfo {
    /// Signer Identifier
    ///
    /// This ID refers to a certificate in the [`SignedData::cert_list`].
    pub sid: SignerIdentifier,
    /// Authenticated Attributes.
    ///
    /// It can be verified using a signature and [`SignerInfo::sid`]'s corresponding certificate chain.
    pub signed_attrs: Option<Attributes>, // authenticatedAttributes
    /// Unauthenticated Attributes.
    pub unsigned_attrs: Option<Attributes>, // unauthenticatedAttributes
    /// [`SignerInfo::signed_attrs`]'s signature.
    pub signature: Vec<u8>, // encryptedDigest
    /// Sigature Algorithm
    pub digest_alg: Algorithm, // digestAlgorithm
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

impl Display for SignerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Signer Info:")?;
        writeln!(f, "{}", self.sid.to_string().indent(4))?;
        if self.signed_attrs.is_some() {
            writeln!(f, "{}", "Authenticated Attributes:".indent(4))?;
            writeln!(
                f,
                "{}",
                self.signed_attrs.clone().unwrap().to_string().indent(8)
            )?;
        }
        if self.unsigned_attrs.is_some() {
            writeln!(f, "{}", "Unauthenticated Attributes:".indent(4))?;
            writeln!(
                f,
                "{}",
                self.unsigned_attrs.clone().unwrap().to_string().indent(8)
            )?;
        }
        if let Some(cs_info) = self.get_countersigner_info().map_err(|e| {
            eprintln!("{:?}", e);
            std::fmt::Error
        })? {
            writeln!(f, "{}", "Countersigner Info:".indent(4))?;
            writeln!(f, "{}", cs_info.to_string().indent(8))?;
        }
        writeln!(
            f,
            "{}",
            format!("Digest Algorithm: {}", self.digest_alg).indent(4)
        )?;
        writeln!(f, "{}", "Encrypted Digest:".indent(4))?;
        write!(f, "{}", self.signature.clone().to_bytes_string().indent(8))
    }
}

impl SignerInfo {
    /// Verifying the integrity of the `indata` using the [`SignerInfo`].
    ///
    /// `cert_list` is a list of certificates with sid and its parent certificates.
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
                let mut hasher = self.digest_alg.new_digest()?;
                hasher.update(&signed_attrs.to_der()?);
                let hashed = hasher.finalize();

                match rsa_publickey.verify(self.digest_alg.new_pkcs1v15sign()?, &hashed, signature)
                {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => {
                        return Ok(PeSignStatus::Invalid);
                    }
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

                match rsa_publickey.verify(self.digest_alg.new_pkcs1v15sign()?, &hashed, signature)
                {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(PeSignStatus::Invalid),
                }
            }
        }

        Ok(PeSignStatus::Valid)
    }

    /// Get countersignature.
    pub fn get_countersignature(self: &Self) -> Result<Option<Self>, PeSignError> {
        match &self.unsigned_attrs {
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

    /// Get microsoft TSTInfo signature.
    pub fn get_ms_tst_signature(self: &Self) -> Result<Option<SignedData>, PeSignError> {
        match &self.unsigned_attrs {
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
                                    .decode_as::<crate::asn1_types::SignedData>()
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

    /// Get nested signature in a [`SignedData`].
    pub fn get_nested_signature(self: &Self) -> Result<Option<PeSign>, PeSignError> {
        match &self.unsigned_attrs {
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

    /// Get countersigner infomation.
    pub fn get_countersigner_info(self: &Self) -> Result<Option<Self>, PeSignError> {
        match self.get_countersignature()? {
            Some(cs) => Ok(Some(cs)),
            None => match self.get_ms_tst_signature()? {
                Some(tst_sign) => Ok(Some(tst_sign.signer_info)),
                None => Ok(None),
            },
        }
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

/// Signed Data.
///
/// This includes the all signature information: message digest、signer info、cert list.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedData {
    pub encap_content_info: EncapsulatedContentInfo, // messageDigest
    pub signer_info: SignerInfo,                     // signerInfo
    pub cert_list: Vec<Certificate>,                 // cert list
    __inner: crate::asn1_types::SignedData,
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
        let cert = crate::asn1_types::SignedData::decode(decoder)?;

        cert.try_into()
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl TryFrom<crate::asn1_types::SignedData> for SignedData {
    type Error = PeSignError;

    fn try_from(signed_data: crate::asn1_types::SignedData) -> Result<Self, Self::Error> {
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
        for any_cert_choice in certset.0.iter() {
            match cms::cert::CertificateChoices::from_der(
                &any_cert_choice.to_der().map_unknown_err()?,
            ) {
                Ok(decoded_cert_choice) => match decoded_cert_choice {
                    cms::cert::CertificateChoices::Certificate(cert) => {
                        cert_list.push(cert.to_owned().try_into()?)
                    }
                    cms::cert::CertificateChoices::Other(_) => {
                        // PeSignErrorKind::UnsupportedCertificateFormat -> OtherCertificate
                    }
                },
                Err(_) => {
                    // PeSignErrorKind::UnsupportedCertificateFormat ->
                    //          ExtendedCertificate/AttributeCertificateV1/AttributeCertificateV2
                    // TODO: Parse Obsolete Certificate format
                    // Follow: https://github.com/RustCrypto/formats/issues/1452
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

impl Debug for SignedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedData")
            .field("encap_content_info", &self.encap_content_info)
            .field("signer_info", &self.signer_info)
            .field("cert_list", &self.cert_list)
            .field("__inner", &self.__inner)
            .finish()
    }
}

impl SignedData {
    /// Build signer certificate chain.
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

    /// Build countersigner certificate chain.
    pub fn build_contersignature_cert_chain(
        self: &Self,
        ca_pem: Option<&str>,
    ) -> Result<Option<CertificateChain>, PeSignError> {
        if let Some(cs_signer_info) = self.signer_info.get_countersignature()? {
            // 构建证书链
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
            match self.signer_info.get_ms_tst_signature()? {
                Some(tst_sign) => {
                    let cert_chain = CertificateChainBuilder::new()
                        .set_trusted_ca_certs(&Certificate::load_pem_chain(match ca_pem {
                            Some(ca_pem) => ca_pem,
                            None => DEFAULT_TRUSTED_CA_PEM,
                        })?)
                        .set_cert_list(&tst_sign.cert_list)
                        .set_sid(tst_sign.signer_info.sid.clone())
                        .build()?;

                    Ok(Some(cert_chain))
                }
                None => Ok(None),
            }
        }
    }

    /// Verify the validity of the signed data.
    pub fn verify(self: &Self, option: &VerifyOption) -> Result<PeSignStatus, PeSignError> {
        self.signer_info.verify(
            &self.cert_list,
            &self.encap_content_info.econtent_value,
            option,
        )
    }

    ///Get signing time.
    pub fn get_signing_time(self: &Self) -> Result<SystemTime, PeSignError> {
        fn get_signing_time_from_attr(
            signed_attrs: &Option<Attributes>,
        ) -> Result<Option<SystemTime>, PeSignError> {
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
                    x509_cert::time::Time::UtcTime(time) => Ok(Some(time.to_system_time())),
                    x509_cert::time::Time::GeneralTime(time) => Ok(Some(time.to_system_time())),
                }
            } else {
                Ok(None)
            }
        }

        let signing_time = match get_signing_time_from_attr(&self.signer_info.signed_attrs)? {
            Some(signing_time) => Some(signing_time),
            None => {
                match self.signer_info.get_countersignature()? {
                    Some(cs_signer_info) => {
                        match get_signing_time_from_attr(&cs_signer_info.signed_attrs)? {
                            Some(signing_time) => Some(signing_time),
                            None => None,
                        }
                    }
                    None => {
                        match self.encap_content_info.econtent_type.as_str() {
                            // self is ms_tst_signature
                            "1.2.840.113549.1.9.16.1.4" => {
                                // id-smime-ct-TSTInfo
                                let x = TSTInfo::from_der(&self.encap_content_info.econtent_value)
                                    .map_app_err(PeSignErrorKind::InvalidTSTInfo)?;
                                Some(
                                    x.get_gen_time()
                                        .map_app_err(PeSignErrorKind::InvalidTSTInfo)?
                                        .to_system_time(),
                                )
                            }
                            // countersignature
                            _ => match self.signer_info.get_ms_tst_signature()? {
                                Some(ms_tst_signature) => {
                                    Some(ms_tst_signature.get_signing_time()?)
                                }
                                None => None,
                            },
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
}
