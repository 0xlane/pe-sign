use std::ops::Deref;

use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign};
use sha1::{Digest, Sha1};

use crate::{
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    signed_data::SignerIdentifier,
    utils::to_hex_str,
};

use super::{ext::Extension, name::RdnSequence, Algorithm, Certificate};

// 证书链构建器
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChainBuilder {
    // 受信任的 CA 证书
    trusted_ca_certs: Option<Vec<Certificate>>,

    // 用于构建证书链的证书列表
    cert_list: Option<Vec<Certificate>>,

    // 签名者ID
    sid: Option<SignerIdentifier>,
}

impl CertificateChainBuilder {
    pub fn new() -> Self {
        Self {
            trusted_ca_certs: None,
            cert_list: None,
            sid: None,
        }
    }

    pub fn set_trusted_ca_certs(self: &mut Self, ca_certs: &[Certificate]) -> &mut Self {
        self.trusted_ca_certs = Some(ca_certs.to_vec());
        self
    }

    pub fn set_cert_list(self: &mut Self, cert_list: &[Certificate]) -> &mut Self {
        self.cert_list = Some(cert_list.to_vec());
        self
    }

    pub fn set_sid(self: &mut Self, sid: SignerIdentifier) -> &mut Self {
        self.sid = Some(sid);
        self
    }

    pub fn build(self: &mut Self) -> Result<CertificateChain, PeSignError> {
        let trusted_ca_certs = self.trusted_ca_certs.take().ok_or(PeSignError {
            kind: crate::errors::PeSignErrorKind::WrongCertChainBuildParam,
            message: "ca cert list is none".to_owned(),
        })?;
        let cert_list = self.cert_list.take().ok_or(PeSignError {
            kind: crate::errors::PeSignErrorKind::WrongCertChainBuildParam,
            message: "cert list is none".to_owned(),
        })?;
        let sid = self.sid.take().ok_or(PeSignError {
            kind: crate::errors::PeSignErrorKind::WrongCertChainBuildParam,
            message: "sid is none".to_owned(),
        })?;

        let signer_cert = match sid {
            SignerIdentifier::IssuerAndSerialNumber(sid) => {
                let signer_issuer: RdnSequence = sid.issuer.clone().into();
                let signer_sn = &sid.serial_number[..];
                match cert_list
                    .iter()
                    .find(|v| v.issuer == signer_issuer && v.serial_number == signer_sn)
                {
                    Some(signer_cert) => signer_cert,
                    None => {
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
            }
            SignerIdentifier::SubjectKeyIdentifier(sid) => {
                match cert_list.iter().find(|v| match &v.extensions {
                    Some(exts) => {
                        match &exts.0.iter().find(|v| match v {
                            Extension::SubjectKeyIdentifier(cert_skid) => {
                                if *cert_skid == sid.clone().into() {
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        }) {
                            Some(_) => true,
                            None => false,
                        }
                    }
                    None => false,
                }) {
                    Some(signer_cert) => signer_cert,
                    None => {
                        return Err(PeSignError {
                            kind: PeSignErrorKind::UnknownSigner,
                            message: to_hex_str(sid.0.as_bytes()),
                        });
                    }
                }
            }
        };

        // 根据提供的证书列表构建证书链
        let mut cert_chain = Self::build_chain(&cert_list, signer_cert);
        cert_chain
            .extend(Self::build_chain(&trusted_ca_certs, cert_chain.last().unwrap())[1..].to_vec());

        Ok(CertificateChain {
            trusted_ca_certs,
            cert_chain,
        })
    }

    // 根据签名者证书从提供的证书列表中构建证书链
    fn build_chain(cert_list: &[Certificate], signer_cert: &Certificate) -> Vec<Certificate> {
        let mut cert_chain = vec![signer_cert.clone()];
        match signer_cert.is_selfsigned() {
            true => cert_chain,
            false => match cert_list.iter().find(|v| v.subject == signer_cert.issuer) {
                Some(issuer_cert) => {
                    cert_chain.extend(Self::build_chain(cert_list, issuer_cert));
                    cert_chain
                }
                None => cert_chain,
            },
        }
    }
}

/// 证书链结构
/// 用于验证证书链是否可信
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChain {
    // 受信任的 CA 证书
    trusted_ca_certs: Vec<Certificate>,

    // 证书链
    cert_chain: Vec<Certificate>,
}

impl CertificateChain {
    // 返回一个证书链的迭代器
    pub fn iter(self: &Self) -> std::slice::Iter<'_, Certificate> {
        self.cert_chain.iter()
    }

    // 返回证书链引用
    pub fn get_chain(self: &Self) -> &[Certificate] {
        &self
    }
}

impl AsRef<[Certificate]> for CertificateChain {
    fn as_ref(&self) -> &[Certificate] {
        &self.cert_chain[..]
    }
}

impl Deref for CertificateChain {
    type Target = [Certificate];

    fn deref(&self) -> &Self::Target {
        &self.cert_chain[..]
    }
}

impl CertificateChain {
    // 验证证书链是否可信
    pub fn is_trusted(self: &Self) -> Result<bool, PeSignError> {
        if self.cert_chain.len() < 2 {
            // 小于2个证书直接判定为不可信
            return Ok(false);
        }

        // 如果顶级证书不是来自于可信CA，直接判定为不可信
        let root_cert = self.cert_chain.last().unwrap();
        if self
            .trusted_ca_certs
            .iter()
            .find(|v| *v == root_cert)
            .is_none()
        {
            return Ok(false);
        }

        // 验证证书链
        for (index, subject_cert) in self.cert_chain.iter().enumerate() {
            if subject_cert.is_selfsigned() {
                break;
            }

            if let Some(issuer_cert) = self.cert_chain.get(index + 1) {
                if issuer_cert.subject_public_key_info.algorithm != Algorithm::RSA {
                    return Err(PeSignError {
                        kind: PeSignErrorKind::UnsupportedAlgorithm,
                        message: issuer_cert.subject_public_key_info.algorithm.to_string(),
                    });
                }

                // 使用颁发者的公钥验签
                let publickey = &issuer_cert.subject_public_key_info.subject_public_key[..];
                let signature = &subject_cert.signature_value[..];

                let rsa_publickey = rsa::RsaPublicKey::from_pkcs1_der(publickey)
                    .map_app_err(PeSignErrorKind::InvalidPublicKey)?;

                // 使用父证书的公钥验证签名，签名数据解密后里面有 tbs_certificate 内容的 hash，证书所有关键信息都在 tbs_certificate 里
                let mut hasher = Sha1::new();
                hasher.update(subject_cert.get_tbs_certificate_bytes());
                let hashed = hasher.finalize();

                match rsa_publickey.verify(Pkcs1v15Sign::new::<Sha1>(), &hashed, signature) {
                    Ok(()) => { /*Validated*/ }
                    Err(_) => return Ok(false),
                }
            } else {
                break;
            }
        }
        Ok(true)
    }
}
