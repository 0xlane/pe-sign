use cms::{
    content_info::CmsVersion,
    signed_data::{DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerInfos},
};
use der::{
    asn1::{GeneralizedTime, OctetString, SetOfVec},
    oid::ObjectIdentifier,
    Any, Decode, Enumerated, Sequence, ValueOrd,
};
use x509_cert::{
    ext::Extensions, impl_newtype, serial_number::SerialNumber, spki::AlgorithmIdentifierOwned,
};

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

/// Timestamps on TrustedTpm.cab feature mis-encoded GeneralizedTime values, as shown in this dump
/// generated using dumpasn1:
///
/// ```text
///  4477    19:                               GeneralizedTime '20240614203756.847Z'
///            :                   Error: Time is encoded incorrectly.
///```
///
/// This structure treats the time field as an Any, which at least allows the message digest to be
/// compared.
///
/// References from `<https://github.com/carl-wallace/tpm_cab_verify/blob/main/src/asn1.rs#L39C1-L48C14>`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TSTInfo {
    pub version: TSTVersion,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: SerialNumber,
    pub gen_time: Any,
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

impl TSTInfo {
    pub fn get_gen_time(self: &Self) -> Result<GeneralizedTime, der::Error> {
        let value = self.gen_time.value();
        if value.len() > 15 {
            let mut fix_value = vec![0x18, 0x0F];
            fix_value.extend(&value[..14]);
            fix_value.extend(&[b'Z']);

            Ok(GeneralizedTime::from_der(&fix_value)?)
        } else {
            Ok(GeneralizedTime::from_der(&value)?)
        }
    }
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

/// Alternative SignedData decoder that tolerates v1 attribute certificates.
///
/// For some bizarre reason, the SignedData used for the timestamp includes v1 attribute certs (!!!),
/// which are marked as obsolete in CMS and are not supported in the cms crate.
///
/// References from `<https://github.com/carl-wallace/tpm_cab_verify/blob/main/src/asn1.rs#L23>`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub(crate) struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    //todo consider defer decoding certs and CRLs
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<AnySet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<AnySet>,
    pub signer_infos: SignerInfos,
}

/// Used in lieu of full support for all certificate and CRL types
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct AnySet(pub SetOfVec<Any>);
impl_newtype!(AnySet, SetOfVec<Any>);

#[cfg(test)]
mod test {
    use der::Decode;

    use super::TSTInfo;

    #[test]
    fn test_tstinfo_with_malformed_generalizedtime() {
        let tstinfo = TSTInfo::from_der(include_bytes!(
            "./examples/tstinfo_with_malformed_generalizedtime.bin"
        ))
        .unwrap();

        assert!(tstinfo.get_gen_time().is_ok());
    }
}
