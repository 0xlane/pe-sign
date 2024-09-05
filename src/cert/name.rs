use std::fmt::Display;

use crate::utils::VecInto;

pub type Name = RdnSequence;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdnSequence(pub Vec<RelativeDistinguishedName>);

impl Display for RdnSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rdn = self.0.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
        write!(f, "{}", rdn)
    }
}

impl From<x509_cert::name::RdnSequence> for RdnSequence {
    fn from(value: x509_cert::name::RdnSequence) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeDistinguishedName(pub Vec<String>);

impl Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(", "))
    }
}

impl From<x509_cert::name::RelativeDistinguishedName> for RelativeDistinguishedName {
    fn from(value: x509_cert::name::RelativeDistinguishedName) -> Self {
        Self(value.0.iter().map(|v| v.to_string()).collect())
    }
}
