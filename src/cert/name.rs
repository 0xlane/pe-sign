use std::fmt::Display;

use crate::utils::VecInto;

pub type Name = RdnSequence;

#[derive(Clone, Debug, Default)]
pub struct RdnSequence(pub Vec<RelativeDistinguishedName>);

impl PartialEq for RdnSequence {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }

        for rdn in &self.0 {
            if !other.0.iter().any(|vv| vv == rdn) {
                return false;
            }
        }

        true
    }
}

impl Eq for RdnSequence {}

impl Display for RdnSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rdn = self
            .0
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", rdn)
    }
}

impl From<x509_cert::name::RdnSequence> for RdnSequence {
    fn from(value: x509_cert::name::RdnSequence) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug)]
pub struct RelativeDistinguishedName(pub Vec<String>);

impl PartialEq for RelativeDistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }

        for rdn in &self.0 {
            if !other.0.iter().any(|vv| vv == rdn) {
                return false;
            }
        }

        true
    }
}

impl Eq for RelativeDistinguishedName {}

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

#[cfg(test)]
mod tests {
    use super::{RdnSequence, RelativeDistinguishedName};

    #[test]
    fn test_rdns_eq() {
        let a = RdnSequence(vec![RelativeDistinguishedName(vec![
            "O=test".to_owned(),
            "CN=test".to_owned(),
        ])]);
        let b = RdnSequence(vec![RelativeDistinguishedName(vec![
            "CN=test".to_owned(),
            "O=test".to_owned(),
        ])]);
        let c = RdnSequence(vec![RelativeDistinguishedName(vec!["CN=test".to_owned()])]);

        assert_eq!(a, b);
        assert_ne!(b, c);
    }
}
