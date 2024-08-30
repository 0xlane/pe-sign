pub use x509_cert::ext::pkix::crl::dp::ReasonFlags;

use crate::{
    cert::ext::name::{DistributionPointName, GeneralNames},
    utils::{OptionInto, OptionVecInto},
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
            crl_issuer: value.crl_issuer.opt_vec_into(),
        }
    }
}
