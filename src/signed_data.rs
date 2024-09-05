use cms::signed_data::SignerIdentifier;
use der::{asn1::OctetStringRef, oid::db::rfc5912::RSA_ENCRYPTION, Decode, Encode};
use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign};
use sha1::{Digest, Sha1};

use crate::{
    cert::{
        ext::Extension, name::RdnSequence, Algorithm, Certificate, CertificateChain,
        CertificateChainBuilder,
    },
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    utils::to_hex_str,
    Attributes, PeSignStatus,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfo {
    pub signed_attrs: Option<Attributes>, // authenticatedAttributes
    pub unsigned_attrs: Option<Attributes>, // unauthenticatedAttributes
    pub signature: Vec<u8>,               // encryptedDigest
    pub digest_alg: Algorithm,            // digestAlgorithm
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
        let digest_alg = signer_info.digest_alg.into();

        Ok(Self {
            signed_attrs,
            unsigned_attrs,
            signature,
            digest_alg,
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
                let mut hasher = self.signer_info.digest_alg.new_digest()?;
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
