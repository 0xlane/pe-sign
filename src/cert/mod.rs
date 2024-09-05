pub mod ext;
pub mod name;

mod certificate;
mod certificate_chain;

pub use certificate::{Algorithm, Certificate, SubjectPublicKeyInfo, Validity};
pub use certificate_chain::{CertificateChain, CertificateChainBuilder};
use name::Name;

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
