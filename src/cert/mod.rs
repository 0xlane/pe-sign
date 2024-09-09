pub mod ext;
pub mod name;

mod certificate;
mod certificate_chain;

use std::fmt::Display;

pub use certificate::{Algorithm, Certificate, SubjectPublicKeyInfo, Validity};
pub use certificate_chain::{CertificateChain, CertificateChainBuilder};
use name::Name;

use crate::utils::{DisplayBytes, IndentString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: Vec<u8>,
}

impl From<cms::cert::IssuerAndSerialNumber> for IssuerAndSerialNumber {
    fn from(value: cms::cert::IssuerAndSerialNumber) -> Self {
        let issuer = value.issuer.into();
        let serial_number = value.serial_number.as_bytes().to_vec();

        Self {
            issuer,
            serial_number,
        }
    }
}

impl Display for IssuerAndSerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Issuer And Serial Number:")?;
        writeln!(f, "{}", format!("Issuer: {}", self.issuer).indent(4))?;
        writeln!(f, "{}", "Serial Number:".indent(4))?;
        write!(f, "{}", self.serial_number.clone().to_bytes_string().indent(8))
    }
}
