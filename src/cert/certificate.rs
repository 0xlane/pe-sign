use std::time::Duration;

use der::oid::db::rfc5912::{
    ID_SHA_1, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION,
    SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};

use crate::{
    errors::{PeSignError, PeSignErrorKind},
    utils::TryVecInto,
};

use super::{ext::Extensions, name::RdnSequence};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub version: u8,
    pub serial_number: Vec<u8>,
    pub issuer: RdnSequence,
    pub validity: Validity,
    pub subject: RdnSequence,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Option<Extensions>,
    pub signature_algorithm: Algorithm,
    pub signature_value: Vec<u8>,
}

impl TryFrom<x509_cert::Certificate> for Certificate {
    type Error = PeSignError;

    fn try_from(value: x509_cert::Certificate) -> Result<Self, Self::Error> {
        let version = value.tbs_certificate.version as u8;
        let serial_number = value.tbs_certificate.serial_number.as_bytes().to_vec();
        let issuer = value.tbs_certificate.issuer.into();
        let validity = value.tbs_certificate.validity.into();
        let subject = value.tbs_certificate.subject.into();
        let subject_public_key_info = value.tbs_certificate.subject_public_key_info.try_into()?;
        let extensions = match value.tbs_certificate.extensions {
            Some(exs) => Some(Extensions(exs.try_vec_into().map_err(|err| {
                Self::Error {
                    kind: PeSignErrorKind::InvalidCertificateExtension,
                    message: err.to_string(),
                }
            })?)),
            None => None,
        };
        let signature_algorithm = value.signature_algorithm.try_into()?;
        let signature_value = value.signature.raw_bytes().to_vec();

        Ok(Self {
            version,
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
            signature_algorithm,
            signature_value,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Md5,
    RSA,
    Sha1WithRSA,
    Sha224WithRSA,
    Sha256WithRSA,
    Sha384WithRSA,
    Sha512WithRSA,
}

impl TryFrom<x509_cert::spki::AlgorithmIdentifierOwned> for Algorithm {
    type Error = PeSignError;

    fn try_from(value: x509_cert::spki::AlgorithmIdentifierOwned) -> Result<Self, Self::Error> {
        // let params = match value.parameters {
        //     Some(p) => match p.is_null() {
        //         true => None,
        //         false => Some(p.value().to_vec()),
        //     },
        //     None => None,
        // };

        match value.oid {
            ID_SHA_1 => Ok(Self::Sha1),
            ID_SHA_224 => Ok(Self::Sha224),
            ID_SHA_256 => Ok(Self::Sha256),
            ID_SHA_384 => Ok(Self::Sha384),
            ID_SHA_512 => Ok(Self::Sha512),
            RSA_ENCRYPTION => Ok(Self::RSA),
            SHA_1_WITH_RSA_ENCRYPTION => Ok(Self::Sha1WithRSA),
            SHA_224_WITH_RSA_ENCRYPTION => Ok(Self::Sha224WithRSA),
            SHA_256_WITH_RSA_ENCRYPTION => Ok(Self::Sha256WithRSA),
            SHA_384_WITH_RSA_ENCRYPTION => Ok(Self::Sha384WithRSA),
            SHA_512_WITH_RSA_ENCRYPTION => Ok(Self::Sha512WithRSA),
            oid => Err(PeSignError {
                kind: crate::errors::PeSignErrorKind::UnsupportedAlgorithm,
                message: oid.to_string(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    pub not_before: Duration,
    pub not_after: Duration,
}

impl From<x509_cert::time::Validity> for Validity {
    fn from(value: x509_cert::time::Validity) -> Self {
        Self {
            not_before: value.not_before.to_unix_duration(),
            not_after: value.not_after.to_unix_duration(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    algorithm: Algorithm,
    subject_public_key: Vec<u8>,
}

impl TryFrom<x509_cert::spki::SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
    type Error = PeSignError;

    fn try_from(value: x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        Ok(Self {
            algorithm: value.algorithm.try_into()?,
            subject_public_key: value.subject_public_key.raw_bytes().to_vec(),
        })
    }
}
