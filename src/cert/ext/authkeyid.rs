use der::oid::{db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER, AssociatedOid, ObjectIdentifier};

use crate::utils::{to_hex_str, OptionVecInto};

use super::name::GeneralNames;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<String>,
    pub authority_cert_issuer: Option<GeneralNames>,
    pub authority_cert_serial_number: Option<Vec<u8>>,
}

impl AssociatedOid for AuthorityKeyIdentifier {
    const OID: ObjectIdentifier = ID_CE_AUTHORITY_KEY_IDENTIFIER;
}

impl From<x509_cert::ext::pkix::AuthorityKeyIdentifier> for AuthorityKeyIdentifier {
    fn from(value: x509_cert::ext::pkix::AuthorityKeyIdentifier) -> Self {
        Self {
            key_identifier: value
                .key_identifier
                .and_then(|v| Some(to_hex_str(v.as_bytes()))),
            authority_cert_issuer: value.authority_cert_issuer.opt_vec_into(),
            authority_cert_serial_number: value
                .authority_cert_serial_number
                .and_then(|v| Some(v.as_bytes().to_vec())),
        }
    }
}
