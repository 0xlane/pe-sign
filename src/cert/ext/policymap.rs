use der::oid::{db::rfc5280::ID_CE_POLICY_MAPPINGS, AssociatedOid, ObjectIdentifier};

use crate::utils::VecInto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMappings(pub Vec<PolicyMapping>);

impl AssociatedOid for PolicyMappings {
    const OID: ObjectIdentifier = ID_CE_POLICY_MAPPINGS;
}

impl From<x509_cert::ext::pkix::PolicyMappings> for PolicyMappings {
    fn from(value: x509_cert::ext::pkix::PolicyMappings) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMapping {
    pub issuer_domain_policy: String,
    pub subject_domain_policy: String,
}

impl From<x509_cert::ext::pkix::PolicyMapping> for PolicyMapping {
    fn from(value: x509_cert::ext::pkix::PolicyMapping) -> Self {
        Self {
            issuer_domain_policy: value.issuer_domain_policy.to_string(),
            subject_domain_policy: value.subject_domain_policy.to_string(),
        }
    }
}
