use der::{
    oid::{
        db::{
            rfc5280::ID_CE_CERTIFICATE_POLICIES, rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER,
            rfc6962::CT_PRECERT_SCTS,
        },
        AssociatedOid, ObjectIdentifier,
    },
    Decode, Encode,
};
use x509_cert::ext::pkix::{CrlReason, KeyUsage};

use crate::{
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    utils::{to_hex_str, TryVecInto},
};

use super::{
    constraints::{BasicConstraints, NameConstraints, PolicyConstraints},
    crl::{BaseCrlNumber, CrlDistributionPoints, CrlNumber, FreshestCrl},
    AuthorityInfoAccess, AuthorityKeyIdentifier, ExtendedKeyUsage, InhibitAnyPolicy, IssuerAltName,
    PolicyMappings, PrivateKeyUsagePeriod, SubjectAltName, SubjectDirectoryAttributes,
    SubjectInfoAccess,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extensions(pub Vec<Extension>);

impl TryFrom<x509_cert::ext::Extensions> for Extensions {
    type Error = PeSignError;

    fn try_from(value: x509_cert::ext::Extensions) -> Result<Self, Self::Error> {
        Ok(Self(value.try_vec_into().map_err(|err| Self::Error {
            kind: PeSignErrorKind::InvalidCertificateExtension,
            message: err.to_string(),
        })?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Extension {
    AuthorityInfoAccess(AuthorityInfoAccess),
    SubjectInfoAccess(SubjectInfoAccess),
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    CertificatePolicies(CertificatePolicies),
    BasicConstraints(BasicConstraints),
    NameConstraints(NameConstraints),
    PolicyConstraints(PolicyConstraints),
    CrlNumber(CrlNumber),
    BaseCRLNumber(BaseCrlNumber),
    CrlDistributionPoints(CrlDistributionPoints),
    FreshestCrl(FreshestCrl),
    CRLReason(crate::cert::ext::crl::CrlReason),
    KeyUsage(crate::cert::ext::KeyUsage),
    ExtendedKeyUsage(ExtendedKeyUsage),
    PrivateKeyUsagePeriod(PrivateKeyUsagePeriod),
    PolicyMappings(PolicyMappings),
    SignedCertificateTimestampList(SignedCertificateTimestampList),
    SubjectAltName(SubjectAltName),
    IssuerAltName(IssuerAltName),
    SubjectDirectoryAttributes(SubjectDirectoryAttributes),
    InhibitAnyPolicy(InhibitAnyPolicy),
    Unknown(Vec<u8>),
}

impl TryFrom<x509_cert::ext::Extension> for Extension {
    type Error = PeSignError;

    fn try_from(value: x509_cert::ext::Extension) -> Result<Self, Self::Error> {
        match value.extn_id {
            AuthorityInfoAccess::OID => Ok(Self::AuthorityInfoAccess(
                x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(
                    value.extn_value.as_bytes(),
                )
                .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                .into(),
            )),
            SubjectInfoAccess::OID => Ok(Self::SubjectInfoAccess(
                x509_cert::ext::pkix::SubjectInfoAccessSyntax::from_der(
                    value.extn_value.as_bytes(),
                )
                .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                .into(),
            )),
            AuthorityKeyIdentifier::OID => Ok(Self::AuthorityKeyIdentifier(
                x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            SubjectKeyIdentifier::OID => Ok(Self::SubjectKeyIdentifier(
                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            CertificatePolicies::OID => Ok(Self::CertificatePolicies(
                x509_cert::ext::pkix::CertificatePolicies::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            BasicConstraints::OID => Ok(Self::BasicConstraints(
                x509_cert::ext::pkix::BasicConstraints::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            NameConstraints::OID => Ok(Self::NameConstraints(
                x509_cert::ext::pkix::NameConstraints::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            PolicyConstraints::OID => Ok(Self::PolicyConstraints(
                x509_cert::ext::pkix::PolicyConstraints::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            CrlNumber::OID => Ok(Self::CrlNumber(
                x509_cert::ext::pkix::CrlNumber::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            BaseCrlNumber::OID => Ok(Self::BaseCRLNumber(
                x509_cert::ext::pkix::BaseCrlNumber::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            CrlDistributionPoints::OID => Ok(Self::CrlDistributionPoints(
                x509_cert::ext::pkix::CrlDistributionPoints::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            FreshestCrl::OID => Ok(Self::FreshestCrl(
                x509_cert::ext::pkix::FreshestCrl::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            CrlReason::OID => Ok(Self::CRLReason(
                CrlReason::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            KeyUsage::OID => Ok(Self::KeyUsage(
                KeyUsage::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            ExtendedKeyUsage::OID => Ok(Self::ExtendedKeyUsage(
                x509_cert::ext::pkix::ExtendedKeyUsage::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            PrivateKeyUsagePeriod::OID => Ok(Self::PrivateKeyUsagePeriod(
                x509_cert::ext::pkix::PrivateKeyUsagePeriod::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            PolicyMappings::OID => Ok(Self::PolicyMappings(
                x509_cert::ext::pkix::PolicyMappings::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            SignedCertificateTimestampList::OID => Ok(Self::SignedCertificateTimestampList(
                x509_cert::ext::pkix::SignedCertificateTimestampList::from_der(
                    value.extn_value.as_bytes(),
                )
                .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                .into(),
            )),
            SubjectAltName::OID => Ok(Self::SubjectAltName(
                x509_cert::ext::pkix::SubjectAltName::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            IssuerAltName::OID => Ok(Self::IssuerAltName(
                x509_cert::ext::pkix::IssuerAltName::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            SubjectDirectoryAttributes::OID => Ok(Self::SubjectDirectoryAttributes(
                x509_cert::ext::pkix::SubjectDirectoryAttributes::from_der(
                    value.extn_value.as_bytes(),
                )
                .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                .into(),
            )),
            InhibitAnyPolicy::OID => Ok(Self::InhibitAnyPolicy(
                x509_cert::ext::pkix::InhibitAnyPolicy::from_der(value.extn_value.as_bytes())
                    .map_app_err(PeSignErrorKind::InvalidCertificateExtension)?
                    .into(),
            )),
            _ => Ok(Self::Unknown(value.extn_value.into_bytes())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyIdentifier(pub String);

impl AssociatedOid for SubjectKeyIdentifier {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_KEY_IDENTIFIER;
}

impl From<x509_cert::ext::pkix::SubjectKeyIdentifier> for SubjectKeyIdentifier {
    fn from(value: x509_cert::ext::pkix::SubjectKeyIdentifier) -> Self {
        Self(to_hex_str(value.0.as_bytes()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificatePolicies(pub Vec<u8>);

impl AssociatedOid for CertificatePolicies {
    const OID: ObjectIdentifier = ID_CE_CERTIFICATE_POLICIES;
}

impl From<x509_cert::ext::pkix::CertificatePolicies> for CertificatePolicies {
    fn from(value: x509_cert::ext::pkix::CertificatePolicies) -> Self {
        let mut buf = vec![];
        value.encode_to_vec(&mut buf).unwrap();

        Self(buf)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCertificateTimestampList(pub Vec<u8>);

impl AssociatedOid for SignedCertificateTimestampList {
    const OID: ObjectIdentifier = CT_PRECERT_SCTS;
}

impl From<x509_cert::ext::pkix::SignedCertificateTimestampList> for SignedCertificateTimestampList {
    fn from(value: x509_cert::ext::pkix::SignedCertificateTimestampList) -> Self {
        let mut buf = vec![];
        value.encode_to_vec(&mut buf).unwrap();
        Self(buf)
    }
}
