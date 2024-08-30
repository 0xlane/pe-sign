use std::time::Duration;

use der::oid::{
    db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_CE_PRIVATE_KEY_USAGE_PERIOD},
    AssociatedOid, ObjectIdentifier,
};

pub use x509_cert::ext::pkix::KeyUsage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedKeyUsage(pub Vec<String>);

impl AssociatedOid for ExtendedKeyUsage {
    const OID: ObjectIdentifier = ID_CE_EXT_KEY_USAGE;
}

impl From<x509_cert::ext::pkix::ExtendedKeyUsage> for ExtendedKeyUsage {
    fn from(value: x509_cert::ext::pkix::ExtendedKeyUsage) -> Self {
        Self(value.0.iter().map(|v| v.to_string()).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyUsagePeriod {
    pub not_before: Option<Duration>,
    pub not_after: Option<Duration>,
}

impl AssociatedOid for PrivateKeyUsagePeriod {
    const OID: ObjectIdentifier = ID_CE_PRIVATE_KEY_USAGE_PERIOD;
}

impl From<x509_cert::ext::pkix::PrivateKeyUsagePeriod> for PrivateKeyUsagePeriod {
    fn from(value: x509_cert::ext::pkix::PrivateKeyUsagePeriod) -> Self {
        Self {
            not_before: value.not_before.and_then(|v| Some(v.to_unix_duration())),
            not_after: value.not_after.and_then(|v| Some(v.to_unix_duration())),
        }
    }
}
