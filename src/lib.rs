use std::error::Error;

use asn1_types::{SpcIndirectDataContent, ID_SPC_INDIRECT_DATA};
use cms::{cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader}, content_info::ContentInfo, signed_data::SignedData};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use utils::to_hex_str;

pub mod asn1_types;
pub mod errors;
mod utils;

pub fn parse_pkcs7(bin: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut reader = SliceReader::new(bin).map_unknown_err()?;
    let ci = ContentInfo::decode(&mut reader).map_app_err(PeSignErrorKind::InvalidContentInfo)?;

    let indata;
    let authenticode;

    // signedData
    match ci.content_type {
        ID_SIGNED_DATA => {
            let signed_data = ci.content.decode_as::<SignedData>().map_app_err(PeSignErrorKind::InvalidSignedData)?;

            // SpcIndirectDataContent
            match signed_data.encap_content_info.econtent_type {
                ID_SPC_INDIRECT_DATA => {
                    match signed_data.encap_content_info.econtent {
                        Some(econtent) => {
                            indata= econtent.value().to_vec();
                            let spc_indirect_data_content = econtent.decode_as::<SpcIndirectDataContent>().map_app_err(PeSignErrorKind::InvalidSpcIndirectDataContent)?;
                            authenticode = to_hex_str(spc_indirect_data_content.message_digest.digest.as_bytes());
                        },
                        None => return Err(PeSignError {
                            kind: PeSignErrorKind::EmptyEncapsulatedContent,
                            message: "".to_owned(),
                        }.into()),
                    }
                },
                ect => return Err(PeSignError {
                    kind: PeSignErrorKind::InvalidEncapsulatedContentType,
                    message: ect.to_string(),
                }.into()),
            }
        },
        ct => return Err(PeSignError {
            kind: PeSignErrorKind::InvalidContentType,
            message: ct.to_string(),
        }.into()),
    };

    println!("authenticode: {}", authenticode);
    println!("indata: {:?}", indata);

    Ok(())
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
        assert!(ContentInfo::decode(&mut reader)
            .is_ok());
    }

    #[test]
    fn test_parse_pkcs7() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        assert!(parse_pkcs7(bytes).is_ok());
    }
}
