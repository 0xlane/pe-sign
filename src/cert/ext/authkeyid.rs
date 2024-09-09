use std::fmt::Display;

use der::oid::{db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER, AssociatedOid, ObjectIdentifier};

use crate::utils::{DisplayBytes, IndentString, OptionInto};

use super::name::GeneralNames;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<Vec<u8>>,
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
                .and_then(|v| Some(v.as_bytes().to_vec())),
            authority_cert_issuer: value.authority_cert_issuer.opt_into(),
            authority_cert_serial_number: value
                .authority_cert_serial_number
                .and_then(|v| Some(v.as_bytes().to_vec())),
        }
    }
}

impl Display for AuthorityKeyIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let skid = match &self.key_identifier {
            Some(kid) => kid.to_bytes_string(),
            None => match &self.authority_cert_issuer {
                Some(aci) => aci.to_string(),
                None => match &self.authority_cert_serial_number {
                    Some(sn) => sn.to_bytes_string(),
                    None => "None".to_owned(),
                },
            },
        };

        writeln!(f, "Authority Key Identifier:")?;
        write!(f, "{}", skid.indent(4))
    }
}
