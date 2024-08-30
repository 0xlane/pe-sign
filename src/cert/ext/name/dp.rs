use crate::{cert::name::RelativeDistinguishedName, utils::VecInto};

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
            x509_cert::ext::pkix::name::DistributionPointName::FullName(vv) => Self::FullName(vv.vec_into()),
            x509_cert::ext::pkix::name::DistributionPointName::NameRelativeToCRLIssuer(vv) => Self::NameRelativeToCRLIssuer(vv.into()),
        }
    }
}
