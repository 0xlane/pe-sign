use crate::utils::VecInto;
use der::oid::{
    db::rfc5280::{
        ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_CRL_NUMBER, ID_CE_DELTA_CRL_INDICATOR,
        ID_CE_FRESHEST_CRL,
    },
    AssociatedOid, ObjectIdentifier,
};

pub mod dp;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrlNumber(pub Vec<u8>);

impl AssociatedOid for CrlNumber {
    const OID: ObjectIdentifier = ID_CE_CRL_NUMBER;
}

impl From<x509_cert::ext::pkix::CrlNumber> for CrlNumber {
    fn from(value: x509_cert::ext::pkix::CrlNumber) -> Self {
        Self(value.0.as_bytes().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseCrlNumber(pub Vec<u8>);

impl AssociatedOid for BaseCrlNumber {
    const OID: ObjectIdentifier = ID_CE_DELTA_CRL_INDICATOR;
}

impl From<x509_cert::ext::pkix::BaseCrlNumber> for BaseCrlNumber {
    fn from(value: x509_cert::ext::pkix::BaseCrlNumber) -> Self {
        Self(value.0.as_bytes().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrlDistributionPoints(pub Vec<dp::DistributionPoint>);

impl AssociatedOid for CrlDistributionPoints {
    const OID: ObjectIdentifier = ID_CE_CRL_DISTRIBUTION_POINTS;
}

impl From<x509_cert::ext::pkix::CrlDistributionPoints> for CrlDistributionPoints {
    fn from(value: x509_cert::ext::pkix::CrlDistributionPoints) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshestCrl(pub Vec<dp::DistributionPoint>);

impl AssociatedOid for FreshestCrl {
    const OID: ObjectIdentifier = ID_CE_FRESHEST_CRL;
}

impl From<x509_cert::ext::pkix::FreshestCrl> for FreshestCrl {
    fn from(value: x509_cert::ext::pkix::FreshestCrl) -> Self {
        Self(value.0.vec_into())
    }
}

pub use x509_cert::ext::pkix::crl::CrlReason;
