use der::{oid::{db::rfc5280::{ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS}, AssociatedOid, ObjectIdentifier}, Decode};

use crate::{errors::{PeSignError, PeSignErrorKind, PeSignResult}, utils::VecInto};

use super::name::GeneralName;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityInfoAccess(pub Vec<AccessDescription>);

impl AssociatedOid for AuthorityInfoAccess {
    const OID: ObjectIdentifier = ID_PE_AUTHORITY_INFO_ACCESS;
}

impl From<x509_cert::ext::pkix::AuthorityInfoAccessSyntax> for AuthorityInfoAccess {
    fn from(value: x509_cert::ext::pkix::AuthorityInfoAccessSyntax) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectInfoAccess(pub Vec<AccessDescription>);

impl AssociatedOid for SubjectInfoAccess {
    const OID: ObjectIdentifier = ID_PE_SUBJECT_INFO_ACCESS;
}

impl From<x509_cert::ext::pkix::SubjectInfoAccessSyntax> for SubjectInfoAccess {
    fn from(value: x509_cert::ext::pkix::SubjectInfoAccessSyntax) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessDescription {
    pub access_method: String,
    pub access_location: GeneralName,
}

impl From<x509_cert::ext::pkix::AccessDescription> for AccessDescription {
    fn from(value: x509_cert::ext::pkix::AccessDescription) -> Self {
        Self {
            access_method: value.access_method.to_string(),
            access_location: value.access_location.into(),
        }
    }
}

impl AccessDescription {
    pub fn from_der(bin: &[u8]) -> Result<Self, PeSignError> {
        type Type = x509_cert::ext::pkix::AccessDescription;

        let tt = Type::from_der(bin).map_app_err(PeSignErrorKind::InvalidCertificateExtension)?;

        Ok(Self {
            access_method: tt.access_method.to_string(),
            access_location: GeneralName::from(tt.access_location),
        })
    }
}
