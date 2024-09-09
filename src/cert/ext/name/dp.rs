use std::fmt::Display;

use crate::{cert::name::RelativeDistinguishedName, utils::IndentString};

use super::GeneralNames;

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum DistributionPointName {
    FullName(GeneralNames),
    NameRelativeToCRLIssuer(RelativeDistinguishedName),
}

impl From<x509_cert::ext::pkix::name::DistributionPointName> for DistributionPointName {
    fn from(value: x509_cert::ext::pkix::name::DistributionPointName) -> Self {
        match value {
            x509_cert::ext::pkix::name::DistributionPointName::FullName(vv) => {
                Self::FullName(vv.into())
            }
            x509_cert::ext::pkix::name::DistributionPointName::NameRelativeToCRLIssuer(vv) => {
                Self::NameRelativeToCRLIssuer(vv.into())
            }
        }
    }
}

impl Display for DistributionPointName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DistributionPointName::FullName(vv) => {
                writeln!(f, "Full Name:")?;
                write!(f, "{}", vv.to_string().indent(4))?;
            }
            DistributionPointName::NameRelativeToCRLIssuer(vv) => {
                writeln!(f, "Name Relative To CRL Issuer:")?;
                write!(f, "{}", vv.to_string().indent(4))?;
            }
        }

        Ok(())
    }
}
