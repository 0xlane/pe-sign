use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use der::{asn1::OctetString, oid::ObjectIdentifier, Any, Sequence, ValueOrd};

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
