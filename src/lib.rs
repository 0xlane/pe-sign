use asn1_types::{SpcIndirectDataContent, ID_SPC_INDIRECT_DATA};
use cert::{Certificate, CertificateChain, CertificateChainBuilder};
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
    signed_data::SignedData,
};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use utils::to_hex_str;

pub mod asn1_types;
pub mod cert;
pub mod errors;
pub mod utils;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSign {
    pub cert_list: Vec<Certificate>,
    pub authenticode: String,
    pub indata: Vec<u8>,
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
            }
            ct => {
                return Err(PeSignError {
                    kind: PeSignErrorKind::InvalidContentType,
                    message: ct.to_string(),
                }
                .into())
            }
        };

        Ok(Self {
            cert_list,
            authenticode,
            indata,
        })
    }

    // 获取证书链
    pub fn get_certificate_chains(self: &Self) -> Result<Vec<CertificateChain>, PeSignError> {
        // 加载 cacert.pem 中的 CA 证书
        let cacerts: Vec<Certificate> = Certificate::load_pem_chain(include_bytes!("cacert.pem"))?;

        // 构建证书建
        let cert_chains = CertificateChainBuilder::new()
            .set_trusted_ca_certs(&cacerts)
            .set_cert_list(&self.cert_list)
            .build()?;

        Ok(cert_chains)
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
