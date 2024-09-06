use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use der::{
    asn1::{GeneralizedTime, OctetString},
    oid::ObjectIdentifier,
    Any, Enumerated, Sequence, ValueOrd,
};
use x509_cert::{ext::Extensions, serial_number::SerialNumber};

pub const ID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// ```text
/// DigestInfo ::= SEQUENCE {
/// digestAlgorithm DigestAlgorithmIdentifier,
/// digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct DigestInfo {
    pub algorithm: AlgorithmIdentifierOwned,
    pub digest: OctetString,
}

/// ```text
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
/// type ObjectID,
/// value [0] EXPLICIT ANY OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    pub type_: ObjectIdentifier,
    pub value: Option<Any>,
}

/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
/// data SpcAttributeTypeAndOptionalValue,
/// messageDigest DigestInfo }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    pub data: SpcAttributeTypeAndOptionalValue,
    pub message_digest: DigestInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TSTInfo {
    pub version: TSTVersion,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: SerialNumber,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Any>,
    #[asn1(optional = "true")]
    pub ordering: Option<bool>,
    #[asn1(optional = "true")]
    pub nonce: Option<u8>,
    #[asn1(context_specific = "0", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum TSTVersion {
    V1 = 1,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}
