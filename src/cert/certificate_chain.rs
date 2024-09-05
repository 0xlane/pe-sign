use std::ops::Deref;

use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign};
use sha1::{Digest, Sha1};

use crate::errors::{PeSignError, PeSignErrorKind, PeSignResult};

use super::{Algorithm, Certificate};

// 证书链构建器
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChainBuilder {
    // 受信任的 CA 证书
    trusted_ca_certs: Option<Vec<Certificate>>,

    // 用于构建证书链的证书列表
    cert_list: Option<Vec<Certificate>>,
}

impl CertificateChainBuilder {
    pub fn new() -> Self {
        Self {
            trusted_ca_certs: None,
            cert_list: None,
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

    pub fn build(self: &mut Self) -> Result<Vec<CertificateChain>, PeSignError> {
        let trusted_ca_certs = self.trusted_ca_certs.take().ok_or(PeSignError {
            kind: crate::errors::PeSignErrorKind::EmptyCACerts,
            message: "ca cert list is empty".to_owned(),
        })?;
        let mut cert_list = self.cert_list.take().ok_or(PeSignError {
            kind: crate::errors::PeSignErrorKind::EmptyCertList,
            message: "cert list is empty".to_owned(),
        })?;

        // 生成证书链
        let mut cert_chains = vec![];
        while !cert_list.is_empty() {
            let mut cert_chain = vec![];
            let cur_cert = cert_list.pop().unwrap();
            let is_self_sign = cur_cert.is_selfsigned();
            cert_chain.push(cur_cert);

            // 构建证书链
            if !is_self_sign {
                // 根据提供的证书列表构建证书链
                Self::build_chain(&mut cert_list, &mut cert_chain, -1);
                Self::build_chain(&mut cert_list, &mut cert_chain, 1);

                // 添加 CA 证书到证书链中
                loop {
                    let root_self = cert_chain.last().unwrap();
                    if let Some(ca) = trusted_ca_certs
                        .iter()
                        .find(|v| v.subject == root_self.issuer)
                    {
                        cert_chain.push(ca.clone());

                        if ca.is_selfsigned() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }

            cert_chains.push(CertificateChain {
                trusted_ca_certs: trusted_ca_certs.clone(),
                cert_chain,
            })
        }

        Ok(cert_chains)
    }

    /// 构建单条证书链
    /// `direction`: -1 表示反向（当前作为 issuer），1 表示正向（当前作为 subject）
    fn build_chain(
        cert_list: &mut Vec<Certificate>,
        cert_chain: &mut Vec<Certificate>,
        direction: i8,
    ) {
        if !cert_list.is_empty() && !cert_chain.is_empty() {
            // -1 表示反向（当前作为 issuer），1 表示正向（当前作为 subject）
            match direction {
                -1 => {
                    let issuer = cert_chain.first().unwrap().clone();
                    let mut son_index: isize = -1;
                    for (index, cert) in cert_list.into_iter().enumerate() {
                        if cert.issuer == issuer.subject {
                            son_index = index as isize;
                            break;
                        }
                    }

                    if son_index > -1 {
                        let son_cert = cert_list.remove(son_index as _);
                        cert_chain.insert(0, son_cert);
                        Self::build_chain(cert_list, cert_chain, direction);
                    }
                }
                1 => {
                    let subject = cert_chain.last().unwrap().clone();
                    let mut parent_index: isize = -1;
                    for (index, cert) in cert_list.into_iter().enumerate() {
                        if cert.subject == subject.issuer {
                            parent_index = index as isize;
                            break;
                        }
                    }

                    if parent_index > -1 {
                        let parent_index = cert_list.remove(parent_index as _);
                        cert_chain.push(parent_index);
                        Self::build_chain(cert_list, cert_chain, direction);
                    }
                }
                _ => unreachable!("only with -1 or 1"),
            }
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
        // 证书可信后，拿到证书的公钥，解密 SignerInfo->encryptedDigest，得到 authenticatedAttributes 内容的 hash，没有 authenticatedAttributes 则为 content 内容 hash
        Ok(true)
    }
}
