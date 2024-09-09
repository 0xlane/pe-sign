use std::fmt::Display;

pub use x509_cert::ext::pkix::crl::dp::ReasonFlags;

use crate::{
    cert::ext::name::{DistributionPointName, GeneralNames},
    utils::OptionInto,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributionPoint {
    pub distribution_point: Option<DistributionPointName>,
    pub reasons: Option<crate::cert::ext::crl::dp::ReasonFlags>,
    pub crl_issuer: Option<GeneralNames>,
}

impl From<x509_cert::ext::pkix::crl::dp::DistributionPoint> for DistributionPoint {
    fn from(value: x509_cert::ext::pkix::crl::dp::DistributionPoint) -> Self {
        Self {
            distribution_point: value.distribution_point.opt_into(),
            reasons: value.reasons,
            crl_issuer: value.crl_issuer.opt_into(),
        }
    }
}

impl Display for DistributionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.distribution_point {
            Some(vv) => write!(f, "{}", vv),
            None => match &self.crl_issuer {
                Some(vv) => write!(f, "{}", vv),
                None => write!(f, "None"),
            },
        }
    }
}
