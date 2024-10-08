pub mod constraints;
pub mod crl;
pub mod name;

mod access;
mod authkeyid;
mod extension;
mod keyusage;
mod policymap;

use std::fmt::Display;

pub use access::{AccessDescription, AuthorityInfoAccess, SubjectInfoAccess};
pub use authkeyid::AuthorityKeyIdentifier;
use der::oid::{
    db::rfc5912::{
        ID_CE_INHIBIT_ANY_POLICY, ID_CE_ISSUER_ALT_NAME, ID_CE_SUBJECT_ALT_NAME,
        ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES,
    },
    ObjectIdentifier,
};
pub use extension::{
    CertificatePolicies, Extension, Extensions, SignedCertificateTimestampList,
    SubjectKeyIdentifier,
};
pub use keyusage::{ExtendedKeyUsage, KeyUsage, PrivateKeyUsagePeriod};
pub use policymap::{PolicyMapping, PolicyMappings};

use name::GeneralNames;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAltName(pub GeneralNames);

impl AssociatedOid for SubjectAltName {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_ALT_NAME;
}

impl From<x509_cert::ext::pkix::SubjectAltName> for SubjectAltName {
    fn from(value: x509_cert::ext::pkix::SubjectAltName) -> Self {
        Self(value.0.into())
    }
}

impl Display for SubjectAltName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subject Alternative Name:")?;
        write!(f, "{}", self.0.to_string().indent(4))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAltName(pub GeneralNames);

impl AssociatedOid for IssuerAltName {
    const OID: ObjectIdentifier = ID_CE_ISSUER_ALT_NAME;
}

impl From<x509_cert::ext::pkix::IssuerAltName> for IssuerAltName {
    fn from(value: x509_cert::ext::pkix::IssuerAltName) -> Self {
        Self(value.0.into())
    }
}

impl Display for IssuerAltName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Issuer Alternative Name:")?;
        write!(f, "{}", self.0.to_string().indent(4))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectDirectoryAttributes(pub Vec<String>);

impl AssociatedOid for SubjectDirectoryAttributes {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES;
}

impl From<x509_cert::ext::pkix::SubjectDirectoryAttributes> for SubjectDirectoryAttributes {
    fn from(value: x509_cert::ext::pkix::SubjectDirectoryAttributes) -> Self {
        Self(value.0.iter().map(|v| v.to_string()).collect())
    }
}

impl Display for SubjectDirectoryAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Subject Directory Attributes: <Unsupported>")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InhibitAnyPolicy(pub u32);

impl AssociatedOid for InhibitAnyPolicy {
    const OID: ObjectIdentifier = ID_CE_INHIBIT_ANY_POLICY;
}

impl From<x509_cert::ext::pkix::InhibitAnyPolicy> for InhibitAnyPolicy {
    fn from(value: x509_cert::ext::pkix::InhibitAnyPolicy) -> Self {
        Self(value.0)
    }
}

impl Display for InhibitAnyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inhibit Any Policy: {}", self.0)
    }
}

pub use der::oid::AssociatedOid;

use crate::utils::IndentString;
