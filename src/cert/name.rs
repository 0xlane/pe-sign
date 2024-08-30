use crate::utils::VecInto;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdnSequence(pub Vec<RelativeDistinguishedName>);

impl From<x509_cert::name::RdnSequence> for RdnSequence {
    fn from(value: x509_cert::name::RdnSequence) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeDistinguishedName(pub Vec<String>);

impl From<x509_cert::name::RelativeDistinguishedName> for RelativeDistinguishedName {
    fn from(value: x509_cert::name::RelativeDistinguishedName) -> Self {
        Self(value.0.iter().map(|v| v.to_string()).collect())
    }
}
