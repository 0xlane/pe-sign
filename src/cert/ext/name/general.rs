use der::asn1::Utf8StringRef;

use crate::utils::to_hex_str;

pub type GeneralNames = Vec<GeneralName>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralName {
    OtherName(String),
    Rfc822Name(String),
    DnsName(String),
    DirectoryName(String),
    EdiPartyName(String),
    UniformResourceIdentifier(String),
    IpAddress(String),
    RegisteredId(String),
}

impl From<x509_cert::ext::pkix::name::GeneralName> for GeneralName {
    fn from(value: x509_cert::ext::pkix::name::GeneralName) -> Self {
        match value {
            x509_cert::ext::pkix::name::GeneralName::OtherName(name) => Self::OtherName(format!(
                "{} = UTF8String:{}",
                name.type_id.to_string(),
                Utf8StringRef::try_from(&name.value)
                    .map(|v| v.as_str())
                    .unwrap_or("<parse error>")
            )),
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(name) => {
                Self::Rfc822Name(name.to_string())
            }
            x509_cert::ext::pkix::name::GeneralName::DnsName(name) => {
                Self::DnsName(name.to_string())
            }
            x509_cert::ext::pkix::name::GeneralName::DirectoryName(name) => {
                Self::DirectoryName(name.to_string())
            }
            x509_cert::ext::pkix::name::GeneralName::EdiPartyName(name) => Self::EdiPartyName(
                match name.name_assigner {
                    Some(na) => match na {
                        x509_cert::ext::pkix::name::DirectoryString::PrintableString(ss) => {
                            ss.to_string()
                        }
                        x509_cert::ext::pkix::name::DirectoryString::TeletexString(ss) => {
                            ss.to_string()
                        }
                        x509_cert::ext::pkix::name::DirectoryString::Utf8String(ss) => {
                            ss.to_string()
                        }
                    },
                    None => "".to_owned(),
                } + &format!(
                    "partyName={}",
                    match name.party_name {
                        x509_cert::ext::pkix::name::DirectoryString::PrintableString(ss) =>
                            ss.to_string(),
                        x509_cert::ext::pkix::name::DirectoryString::TeletexString(ss) =>
                            ss.to_string(),
                        x509_cert::ext::pkix::name::DirectoryString::Utf8String(ss) =>
                            ss.to_string(),
                    }
                ),
            ),
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(name) => {
                Self::UniformResourceIdentifier(name.to_string())
            }
            x509_cert::ext::pkix::name::GeneralName::IpAddress(name) => {
                Self::IpAddress(to_hex_str(name.as_bytes()))
            }
            x509_cert::ext::pkix::name::GeneralName::RegisteredId(name) => {
                Self::RegisteredId(name.to_string())
            }
        }
    }
}
