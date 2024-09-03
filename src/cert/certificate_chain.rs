use std::ops::Deref;

use crate::errors::PeSignError;

use super::Certificate;

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
