use std::{fmt::Display, io::Read, time::Duration};

use der::{
    oid::db::rfc5912::{
        ID_SHA_1, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION,
        SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    },
    Decode, Encode,
};
use digest::{Digest, DynDigest};
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::{
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    utils::{DisplayBytes, IndentString, TryVecInto},
};

use super::{
    ext::{Extension, Extensions},
    name::RdnSequence,
};

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
    __inner: x509_cert::Certificate,
}

impl der::Encode for Certificate {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.__inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.__inner.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for Certificate {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let cert = x509_cert::Certificate::decode(decoder)?;

        cert.try_into()
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl der::pem::PemLabel for Certificate {
    const PEM_LABEL: &'static str = "CERTIFICATE";
}

impl Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Certificate {
    // 从 PEM 文件导入证书
    pub fn load_pem_chain(input: &str) -> Result<Vec<Self>, PeSignError> {
        fn find_boundary<T>(haystack: &[T], needle: &[T]) -> Option<usize>
        where
            for<'a> &'a [T]: PartialEq,
        {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        }

        let mut certs = Vec::new();
        let mut position: usize = 0;

        let start_boundary = &b"-----BEGIN CERTIFICATE-----"[..];
        let end_boundary = &b"-----END CERTIFICATE-----"[..];

        let mut input = input.as_bytes();

        // Strip the trailing whitespaces
        loop {
            if input.is_empty() {
                break;
            }
            let last_pos = input.len() - 1;

            match input.get(last_pos) {
                Some(b'\r') | Some(b'\n') => {
                    input = &input[..last_pos];
                }
                _ => break,
            }
        }

        while position < input.len() - 1 {
            let rest = &input[position..];
            let start_pos = find_boundary(rest, start_boundary).ok_or(PeSignError {
                kind: PeSignErrorKind::InvalidPEMCertificate,
                message: "".to_owned(),
            })?;
            let end_pos = find_boundary(rest, end_boundary).ok_or(PeSignError {
                kind: PeSignErrorKind::InvalidPEMCertificate,
                message: "".to_owned(),
            })? + end_boundary.len();

            let cert_buf = &rest[start_pos..end_pos];
            // println!("{}", String::from_utf8_lossy(cert_buf));

            // from_pem 会报  PEM Base64 error，PEM 库使用的默认的 64，并不是动态动态判断的
            let mut decoder = pem_rfc7468::Decoder::new_detect_wrap(cert_buf)
                .map_app_err(PeSignErrorKind::InvalidPEMCertificate)?;
            let mut buf = vec![];
            decoder
                .read_to_end(&mut buf)
                .map_app_err(PeSignErrorKind::InvalidPEMCertificate)?;
            let cert = x509_cert::Certificate::from_der(&buf)
                .map_app_err(PeSignErrorKind::InvalidPEMCertificate)?
                .try_into()?;

            certs.push(cert);

            position += end_pos;
        }

        Ok(certs)
    }

    // 是否是 CA 证书
    pub fn is_ca(self: &Self) -> bool {
        match &self.extensions {
            Some(extensions) => {
                match extensions.0.iter().find(|&ext| match ext {
                    Extension::BasicConstraints(_) => true,
                    _ => false,
                }) {
                    Some(Extension::BasicConstraints(basic_constraints)) => basic_constraints.ca,
                    _ => false,
                }
            }
            None => false,
        }
    }

    // 是否是自签名证书
    pub fn is_selfsigned(self: &Self) -> bool {
        if self.issuer == self.subject {
            true
        } else {
            false
        }
    }

    // 返回 tbs_certificate，用于验证证书是否可信，signature 解密后为 tbs_certificate 的 hash
    pub fn get_tbs_certificate_bytes(self: &Self) -> Vec<u8> {
        self.__inner.tbs_certificate.to_der().unwrap()
    }
}

impl TryFrom<x509_cert::Certificate> for Certificate {
    type Error = PeSignError;

    fn try_from(value: x509_cert::Certificate) -> Result<Self, Self::Error> {
        let __inner_orginal_cert = value.clone();
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
        let signature_algorithm = value.signature_algorithm.into();
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
            __inner: __inner_orginal_cert,
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
    Unsupported(String),
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<x509_cert::spki::AlgorithmIdentifierOwned> for Algorithm {
    fn from(value: x509_cert::spki::AlgorithmIdentifierOwned) -> Self {
        // let params = match value.parameters {
        //     Some(p) => match p.is_null() {
        //         true => None,
        //         false => Some(p.value().to_vec()),
        //     },
        //     None => None,
        // };

        match value.oid {
            ID_SHA_1 => Self::Sha1,
            ID_SHA_224 => Self::Sha224,
            ID_SHA_256 => Self::Sha256,
            ID_SHA_384 => Self::Sha384,
            ID_SHA_512 => Self::Sha512,
            RSA_ENCRYPTION => Self::RSA,
            SHA_1_WITH_RSA_ENCRYPTION => Self::Sha1WithRSA,
            SHA_224_WITH_RSA_ENCRYPTION => Self::Sha224WithRSA,
            SHA_256_WITH_RSA_ENCRYPTION => Self::Sha256WithRSA,
            SHA_384_WITH_RSA_ENCRYPTION => Self::Sha384WithRSA,
            SHA_512_WITH_RSA_ENCRYPTION => Self::Sha512WithRSA,
            oid => Self::Unsupported(oid.to_string()),
        }
    }
}

impl Algorithm {
    pub fn new_digest(self: &Self) -> Result<Box<dyn DynDigest>, PeSignError> {
        match self {
            Algorithm::Sha1 | Algorithm::Sha1WithRSA => Ok(Sha1::new().box_clone()),
            Algorithm::Sha224 | Algorithm::Sha224WithRSA => Ok(Sha224::new().box_clone()),
            Algorithm::Sha256 | Algorithm::Sha256WithRSA => Ok(Sha256::new().box_clone()),
            Algorithm::Sha384 | Algorithm::Sha384WithRSA => Ok(Sha384::new().box_clone()),
            Algorithm::Sha512 | Algorithm::Sha512WithRSA => Ok(Sha512::new().box_clone()),
            _ => Err(PeSignError {
                kind: PeSignErrorKind::UnsupportedAlgorithm,
                message: format!("digest: {}", self),
            }),
        }
    }

    pub fn new_pkcs1v15sign(self: &Self) -> Result<Pkcs1v15Sign, PeSignError> {
        match self {
            Algorithm::Sha1 | Algorithm::Sha1WithRSA => Ok(Pkcs1v15Sign::new::<Sha1>()),
            Algorithm::Sha224 | Algorithm::Sha224WithRSA => Ok(Pkcs1v15Sign::new::<Sha224>()),
            Algorithm::Sha256 | Algorithm::Sha256WithRSA => Ok(Pkcs1v15Sign::new::<Sha256>()),
            Algorithm::Sha384 | Algorithm::Sha384WithRSA => Ok(Pkcs1v15Sign::new::<Sha384>()),
            Algorithm::Sha512 | Algorithm::Sha512WithRSA => Ok(Pkcs1v15Sign::new::<Sha512>()),
            _ => Err(PeSignError {
                kind: PeSignErrorKind::UnsupportedAlgorithm,
                message: format!("pkcs1v15sign: {}", self),
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
    pub algorithm: Algorithm,
    pub subject_public_key: Vec<u8>,
    __inner: x509_cert::spki::SubjectPublicKeyInfoOwned,
    __inner_public_key: Option<RsaPublicKey>,
}

impl der::Encode for SubjectPublicKeyInfo {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.__inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.__inner.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for SubjectPublicKeyInfo {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let cert = x509_cert::spki::SubjectPublicKeyInfoOwned::decode(decoder)?;

        cert.try_into()
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl der::pem::PemLabel for SubjectPublicKeyInfo {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}

impl TryFrom<x509_cert::spki::SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
    type Error = PeSignError;

    fn try_from(value: x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        let __inner = value.clone();
        let algorithm = value.algorithm.into();
        let mut rsa_publickey = None;

        if algorithm == Algorithm::RSA {
            rsa_publickey = Some(
                RsaPublicKey::from_pkcs1_der(value.subject_public_key.raw_bytes())
                    .map_app_err(PeSignErrorKind::InvalidPublicKey)?,
            );
        }

        Ok(Self {
            algorithm,
            subject_public_key: value.subject_public_key.raw_bytes().to_vec(),
            __inner,
            __inner_public_key: rsa_publickey,
        })
    }
}

impl Display for SubjectPublicKeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subject Public Key Info:")?;
        writeln!(
            f,
            "{}",
            format!("Algorithm: {:?}", self.algorithm).indent(4)
        )?;
        writeln!(
            f,
            "{}",
            format!(
                "Public-Key: ({} bit)\nModules:",
                (self.get_public_key_modules().len() - 1) * 8
            )
            .indent(4)
        )?;
        writeln!(f, "{}", self.get_public_key_modules().to_string().indent(8))
    }
}

impl SubjectPublicKeyInfo {
    pub fn get_public_key_modules(self: &Self) -> Vec<u8> {
        match &self.__inner_public_key {
            Some(rsa_public_key) => {
                let mut tmp = rsa_public_key.n().to_bytes_be();
                tmp.insert(0, 0);
                tmp
            }
            None => self.subject_public_key.clone(),
        }
    }
}
