use std::fmt::Display;

use chrono::{DateTime, Local, Utc};
use der::oid::{
    db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_CE_PRIVATE_KEY_USAGE_PERIOD},
    AssociatedOid, ObjectIdentifier,
};

pub use x509_cert::ext::pkix::KeyUsage;

use crate::utils::IndentString;

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

impl Display for ExtendedKeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Extended Key Usage:")?;
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|v| match v.as_str() {
                    "1.3.6.1.5.5.7.3.1" => "Server Authentication",
                    "1.3.6.1.5.5.7.3.2" => "Client Authentication",
                    "1.3.6.1.5.5.7.3.3" => "Code Signing",
                    "1.3.6.1.5.5.7.3.4" => "Email Protection",
                    "1.3.6.1.5.5.7.3.8" => "Time Stamping",
                    "1.3.6.1.5.5.7.3.9" => "OCSP Signing",
                    "1.3.6.1.5.5.7.3.5" => "IPSec End System",
                    "1.3.6.1.5.5.7.3.6" => "IPSec Tunnel",
                    "1.3.6.1.5.5.7.3.7" => "IPSec User",
                    "1.3.6.1.4.1.311.10.3.3" => "Microsoft Server Gated Crypto",
                    "2.16.840.1.113730.4.1" => "Netscape Server Gated Crypto",
                    vv => vv,
                })
                .collect::<Vec<&str>>()
                .join(", ")
                .indent(4)
        ) /* TODO */
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyUsagePeriod {
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
}

impl AssociatedOid for PrivateKeyUsagePeriod {
    const OID: ObjectIdentifier = ID_CE_PRIVATE_KEY_USAGE_PERIOD;
}

impl From<x509_cert::ext::pkix::PrivateKeyUsagePeriod> for PrivateKeyUsagePeriod {
    fn from(value: x509_cert::ext::pkix::PrivateKeyUsagePeriod) -> Self {
        Self {
            not_before: value
                .not_before
                .and_then(|v| Some(v.to_system_time().into())),
            not_after: value
                .not_after
                .and_then(|v| Some(v.to_system_time().into())),
        }
    }
}

impl Display for PrivateKeyUsagePeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Private Key Usage Period:")?;
        if self.not_before.is_some() {
            write!(
                f,
                "{}",
                format!(
                    "Not Before: {}",
                    self.not_before.unwrap().with_timezone(&Local)
                )
                .indent(4)
            )?;
        }
        if self.not_after.is_some() {
            write!(
                f,
                "{}",
                format!(
                    "Not After : {}",
                    self.not_after.unwrap().with_timezone(&Local)
                )
                .indent(4)
            )?;
        }
        Ok(())
    }
}
