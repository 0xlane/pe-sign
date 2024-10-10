use std::{ops::Deref, time::Duration};

use chrono::Utc;
use der::Decode;
use rsa::pkcs1::DecodeRsaPublicKey;

use crate::{
    cert::ext::name::GeneralName,
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    signed_data::SignerIdentifier,
    utils::{to_hex_str, DisplayBytes},
};

use super::{ext::Extension, name::RdnSequence, Algorithm, Certificate};

/// Build a [`CertificateChain`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChainBuilder {
    trusted_ca_certs: Option<Vec<Certificate>>,
    cert_list: Option<Vec<Certificate>>,
    sid: Option<SignerIdentifier>,
}

impl CertificateChainBuilder {
    /// Create a [`CertificateChainBuilder`].
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
                    Some(signer_cert) => signer_cert.clone(),
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
                    Some(signer_cert) => signer_cert.clone(),
                    None => {
                        return Err(PeSignError {
                            kind: PeSignErrorKind::UnknownSigner,
                            message: sid.0.to_bytes_string(),
                        });
                    }
                }
            }
        };

        // Build a certificate chain based on the provided list of certificates.
        let mut new_cert_list = cert_list;
        new_cert_list.extend(trusted_ca_certs.clone());
        let mut cert_chain = Self::build_chain(&new_cert_list, &signer_cert);

        // Use trusted CA certificates to replace the certificates of the same subject in certificate list.
        for cert in cert_chain.as_mut_slice() {
            match trusted_ca_certs
                .iter()
                .find(|vv| vv.subject == cert.subject)
            {
                Some(trusted_cert) => {
                    *cert = trusted_cert.clone();
                }
                None => {}
            }
        }

        Ok(CertificateChain {
            trusted_ca_certs,
            cert_chain,
        })
    }

    /// Build a certificate chain from the provided certificate list using the signer certificate.
    fn build_chain(cert_list: &[Certificate], signer_cert: &Certificate) -> Vec<Certificate> {
        let mut cert_chain = vec![signer_cert.clone()];
        loop {
            let signer_cert = cert_chain.last().unwrap();
            match signer_cert.is_selfsigned() {
                true => break,
                false => {
                    match cert_list.iter().find(|v| v.subject == signer_cert.issuer) {
                        Some(issuer_cert) => cert_chain.push(issuer_cert.clone()),
                        None => {
                            // Download issuer cert from Authority Information Access
                            if let Ok(client) = reqwest::blocking::Client::builder()
                                .timeout(Duration::from_secs(5))
                                .build()
                            {
                                let mut dl_cert_url = None;
                                if let Some(exts) = &signer_cert.extensions {
                                    for ext in &exts.0 {
                                        if let Extension::AuthorityInfoAccess(aia) = ext {
                                            for aia_desc in &aia.0 {
                                                // CA Issuers
                                                if aia_desc.access_method == "1.3.6.1.5.5.7.48.2" {
                                                    dl_cert_url = match &aia_desc.access_location {
                                                        GeneralName::UniformResourceIdentifier(
                                                            uri,
                                                        ) => Some(uri),
                                                        _ => None,
                                                    }
                                                } else {
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(url) = dl_cert_url {
                                    if let Ok(body) = client.get(url).send().and_then(|v| v.bytes())
                                    {
                                        if let Ok(dl_cert) = Certificate::from_der(&body) {
                                            if dl_cert.subject == signer_cert.issuer {
                                                cert_chain.push(dl_cert);
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        cert_chain
    }
}

/// Certificate Chain.
/// It's used to verify the integrity of a certificate chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChain {
    trusted_ca_certs: Vec<Certificate>,
    cert_chain: Vec<Certificate>,
}

impl CertificateChain {
    /// Get a iterater of the certificate chain.
    pub fn iter(self: &Self) -> std::slice::Iter<'_, Certificate> {
        self.cert_chain.iter()
    }

    /// Get a ref of the certificate chain.
    pub fn get_chain(self: &Self) -> &[Certificate] {
        &self
    }

    /// Get the trusted ca certificate list.
    pub fn get_trusted_ca_list(self: &Self) -> &[Certificate] {
        &self.trusted_ca_certs
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
    /// Check if it's expired.
    pub fn is_expired(self: &Self) -> Result<bool, PeSignError> {
        for cert in &self.cert_chain {
            let start_time = cert.validity.not_before;
            let end_time = cert.validity.not_after;

            let cur_time = Utc::now();

            if cur_time < start_time || cur_time > end_time {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if it's trusted. (No check timestamp)
    pub fn is_trusted(self: &Self) -> Result<bool, PeSignError> {
        if self.cert_chain.len() < 2 {
            // 小于2个证书直接判定为不可信
            return Ok(false);
        }

        // Check chain if include trusted ca certificate.
        if !self.cert_chain.iter().any(|vv| {
            self.trusted_ca_certs
                .iter()
                .find(|vvv| *vvv == vv)
                .is_some()
        }) {
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
                let mut hasher = subject_cert.signature_algorithm.new_digest()?;
                hasher.update(&subject_cert.get_tbs_certificate_bytes());
                let hashed = hasher.finalize();

                match rsa_publickey.verify(
                    subject_cert.signature_algorithm.new_pkcs1v15sign()?,
                    &hashed,
                    signature,
                ) {
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
