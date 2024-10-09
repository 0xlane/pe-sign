use der::{
    asn1::{BmpString, Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef},
    oid::db::DB,
    Decode, Encode, Tag, Tagged,
};
use std::fmt::Display;

use crate::utils::VecInto;

pub type Name = RdnSequence;

#[derive(Clone, Debug, Default)]
pub struct RdnSequence(pub Vec<RelativeDistinguishedName>);

impl PartialEq for RdnSequence {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }

        for rdn in &self.0 {
            if !other.0.iter().any(|vv| vv == rdn) {
                return false;
            }
        }

        true
    }
}

impl Eq for RdnSequence {}

impl Display for RdnSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rdn = self
            .0
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", rdn)
    }
}

impl From<x509_cert::name::RdnSequence> for RdnSequence {
    fn from(value: x509_cert::name::RdnSequence) -> Self {
        Self(value.0.vec_into())
    }
}

#[derive(Clone, Debug)]
pub struct RelativeDistinguishedName(pub Vec<String>);

impl PartialEq for RelativeDistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }

        for rdn in &self.0 {
            if !other.0.iter().any(|vv| vv == rdn) {
                return false;
            }
        }

        true
    }
}

impl Eq for RelativeDistinguishedName {}

impl Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(", "))
    }
}

impl From<x509_cert::name::RelativeDistinguishedName> for RelativeDistinguishedName {
    fn from(value: x509_cert::name::RelativeDistinguishedName) -> Self {
        Self(
            value
                .0
                .iter()
                .map(|tv| {
                    let mut ss;
                    let val = match tv.value.tag() {
                        Tag::PrintableString => PrintableStringRef::try_from(&tv.value)
                            .ok()
                            .map(|s| s.to_string()),
                        Tag::Utf8String => Utf8StringRef::try_from(&tv.value)
                            .ok()
                            .map(|s| s.to_string()),
                        Tag::Ia5String => Ia5StringRef::try_from(&tv.value)
                            .ok()
                            .map(|s| s.to_string()),
                        Tag::TeletexString => TeletexStringRef::try_from(&tv.value)
                            .ok()
                            .map(|s| s.to_string()),
                        // UTF-16
                        Tag::BmpString => BmpString::from_der(&tv.value.to_der().unwrap())
                            .ok()
                            .map(|s| s.to_string()),
                        _ => None,
                    };

                    let key = {
                        let mut best_match: Option<&str> = None;

                        for m in DB.find_names_for_oid(tv.oid) {
                            if let Some(previous) = best_match {
                                if m.len() < previous.len() {
                                    best_match = Some(m);
                                }
                            } else {
                                best_match = Some(m);
                            }
                        }

                        best_match
                    };

                    if let (Some(key), Some(val)) = (key, val) {
                        ss = format!("{}=", key.to_ascii_uppercase());

                        let mut iter = val.char_indices().peekable();
                        while let Some((i, c)) = iter.next() {
                            match c {
                                '#' if i == 0 => ss.push_str("\\#"),
                                ' ' if i == 0 || iter.peek().is_none() => ss.push_str("\\ "),
                                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                                    ss = format!("{}\\{}", ss, c)
                                }
                                '\x00'..='\x1f' | '\x7f' => ss = format!("{}\\{:02x}", ss, c as u8),
                                _ => ss.push(c),
                            }
                        }
                    } else {
                        let value = tv.value.to_der().unwrap();

                        ss = format!("{}=#", tv.oid);
                        for c in value {
                            ss = format!("{}{:02x}", ss, c);
                        }
                    }

                    ss
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use der::Decode;

    use super::{RdnSequence, RelativeDistinguishedName};

    #[test]
    fn test_rdns_eq() {
        let a = RdnSequence(vec![RelativeDistinguishedName(vec![
            "O=test".to_owned(),
            "CN=test".to_owned(),
        ])]);
        let b = RdnSequence(vec![RelativeDistinguishedName(vec![
            "CN=test".to_owned(),
            "O=test".to_owned(),
        ])]);
        let c = RdnSequence(vec![RelativeDistinguishedName(vec!["CN=test".to_owned()])]);

        assert_eq!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn test_utf16_rdn() {
        let der_rdn = x509_cert::name::RelativeDistinguishedName::from_der(
            b"\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x1e\x04\x66\x53\x7f\xbd",
        )
        .unwrap();

        let rdn = RelativeDistinguishedName::from(der_rdn);

        assert_eq!(rdn.to_string(), "CN=晓羽");
    }
}
