use std::{ops::Range, path::Path};

use asn1_types::SpcIndirectDataContent;
use cert::Algorithm;
use cms::{
    cert::x509::der::{oid::db::rfc5911::ID_SIGNED_DATA, Decode, SliceReader},
    content_info::ContentInfo,
};
use der::{asn1::SetOfVec, Encode, EncodePem};
use errors::{PeSignError, PeSignErrorKind, PeSignResult};
use exe::{Buffer, ImageDataDirectory, ImageDirectoryEntry, NTHeaders, VecPE, PE};
use signed_data::SignedData;
use utils::{to_hex_str, TryVecInto};

pub mod asn1_types;
pub mod cert;
pub mod errors;
pub mod signed_data;
pub mod utils;
pub use der;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSign {
    pub signed_data: SignedData,
    pub authenticode_digest: String,
    pub authenticode_digest_algorithm: Algorithm,
    __inner: cms::content_info::ContentInfo,
}

impl der::Encode for PeSign {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.__inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.__inner.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for PeSign {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        Self::from_reader(decoder)
            .map_err(|_| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

impl der::pem::PemLabel for PeSign {
    const PEM_LABEL: &'static str = "PKCS7";
}

impl<'a> PeSign {
    pub fn from_reader<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self, PeSignError> {
        let ci = ContentInfo::decode(decoder).map_app_err(PeSignErrorKind::InvalidContentInfo)?;

        let __inner = ci.clone();

        // signedData
        match ci.content_type {
            ID_SIGNED_DATA => {
                let signed_data: SignedData = ci
                    .content
                    .decode_as::<cms::signed_data::SignedData>()
                    .map_app_err(PeSignErrorKind::InvalidSignedData)?
                    .try_into()?;

                match &signed_data.encap_content_info.econtent_type[..] {
                    "1.3.6.1.4.1.311.2.1.4" => {
                        let spc_indirect_data_content = SpcIndirectDataContent::from_der(
                            &signed_data.encap_content_info.econtent,
                        )
                        .map_app_err(PeSignErrorKind::InvalidSpcIndirectDataContent)?;
                        let authenticode =
                            to_hex_str(spc_indirect_data_content.message_digest.digest.as_bytes());
                        let authenticode_digest =
                            spc_indirect_data_content.message_digest.algorithm.into();
                        Ok(Self {
                            signed_data,
                            authenticode_digest: authenticode,
                            authenticode_digest_algorithm: authenticode_digest,
                            __inner,
                        })
                    }
                    _ => Err(PeSignError {
                        kind: PeSignErrorKind::InvalidEncapsulatedContentType,
                        message: signed_data.encap_content_info.econtent_type,
                    }),
                }
            }
            ct => Err(PeSignError {
                kind: PeSignErrorKind::InvalidContentType,
                message: ct.to_string(),
            }
            .into()),
        }
    }

    // 从导出的签名证书中提取签名信息
    pub fn from_certificate_table_buf(bin: &[u8]) -> Result<Self, PeSignError> {
        let mut reader = SliceReader::new(bin).map_unknown_err()?;
        Self::from_reader(&mut reader)
    }

    // 从 PE 文件中提取签名信息
    pub fn from_pe_path<P: AsRef<Path>>(filename: P) -> Result<Option<Self>, PeSignError> {
        let image = VecPE::from_disk_file(filename).map_app_err(PeSignErrorKind::IoError)?;

        Self::from_vecpe(&image)
    }

    // 从 PE 数据中提取签名信息
    pub fn from_pe_data(bin: &[u8]) -> Result<Option<Self>, PeSignError> {
        let image = VecPE::from_disk_data(bin);

        Self::from_vecpe(&image)
    }

    // 从 VecPE 提取签名信息
    pub fn from_vecpe(image: &VecPE) -> Result<Option<Self>, PeSignError> {
        // va = 0 表示无签名
        let security_directory = image
            .get_data_directory(ImageDirectoryEntry::Security)
            .map_app_err(PeSignErrorKind::InvalidPeFile)?;
        if security_directory.virtual_address.0 == 0x00 {
            return Ok(None);
        }

        let signature_data =
            Buffer::offset_to_ptr(image, security_directory.virtual_address.into())
                .map_app_err(PeSignErrorKind::InvalidPeFile)?; // security_data_directory rva is equivalent to file offset

        let win_certificate =
            unsafe { std::slice::from_raw_parts(signature_data, security_directory.size as usize) };
        let pkcs7 = &win_certificate[8..]; // _WIN_CERTIFICATE->bCertificate

        Ok(Some(Self::from_certificate_table_buf(&pkcs7)?))
    }

    // 计算 PE 文件 authenticode
    pub fn calc_authenticode_from_pe_path<P: AsRef<Path>>(
        filename: P,
        algorithm: &Algorithm,
    ) -> Result<String, PeSignError> {
        let image = VecPE::from_disk_file(filename).map_app_err(PeSignErrorKind::IoError)?;

        Self::calc_authenticode_from_vecpe(&image, algorithm)
    }

    // 计算 PE 文件 authenticode
    pub fn calc_authenticode_from_pe_data(
        bin: &[u8],
        algorithm: &Algorithm,
    ) -> Result<String, PeSignError> {
        let image = VecPE::from_disk_data(bin);

        Self::calc_authenticode_from_vecpe(&image, algorithm)
    }

    // 计算 PE 文件 authenticode
    pub fn calc_authenticode_from_vecpe(
        image: &VecPE,
        algorithm: &Algorithm,
    ) -> Result<String, PeSignError> {
        let mut hasher = algorithm.new_digest()?;

        // SizeOfHeaders > dosHeader + ntHeader + dataDirectory + sectionTable
        let (checknum_ref, size_of_headers) = match image
            .get_valid_nt_headers()
            .map_app_err(PeSignErrorKind::InvalidPeFile)?
        {
            NTHeaders::NTHeaders32(h32) => (
                &h32.optional_header.checksum,
                h32.optional_header.size_of_headers as usize,
            ),
            NTHeaders::NTHeaders64(h64) => (
                &h64.optional_header.checksum,
                h64.optional_header.size_of_headers as usize,
            ),
        };
        let checknum_offset = image
            .ref_to_offset(checknum_ref)
            .map_app_err(PeSignErrorKind::InvalidPeFile)?;
        let before_checknum_offset = checknum_offset;
        let after_checknum_offset = checknum_offset
            .checked_add(std::mem::size_of::<u32>())
            .ok_or(PeSignError {
                kind: PeSignErrorKind::InvalidPeFile,
                message: "overflow".to_owned(),
            })?;
        let sec_directory_ref = image
            .get_data_directory(ImageDirectoryEntry::Security)
            .map_app_err(PeSignErrorKind::InvalidPeFile)?;
        let sec_directory_offset = image
            .ref_to_offset(sec_directory_ref)
            .map_app_err(PeSignErrorKind::InvalidPeFile)?;
        let before_sec_directory_offset = sec_directory_offset;
        let after_sec_directory_offset = sec_directory_offset
            .checked_add(std::mem::size_of::<ImageDataDirectory>())
            .ok_or(PeSignError {
                kind: PeSignErrorKind::InvalidPeFile,
                message: "overflow".to_owned(),
            })?;
        let header_end_offset = size_of_headers;
        let file_size = image.len();
        let mut num_of_bytes_hashed: usize;

        hasher.update(&image[..before_checknum_offset]);
        hasher.update(&image[after_checknum_offset..before_sec_directory_offset]);
        hasher.update(&image[after_sec_directory_offset..header_end_offset]);
        num_of_bytes_hashed = header_end_offset;

        // 排序 section 后 hash
        let mut section_ranges = image
            .get_section_table()
            .map_app_err(PeSignErrorKind::InvalidPeFile)?
            .iter()
            .map(|v| {
                v.pointer_to_raw_data.0 as usize
                    ..v.pointer_to_raw_data.0 as usize + v.size_of_raw_data as usize
            })
            .collect::<Vec<Range<usize>>>();
        section_ranges.sort_unstable_by_key(|v| v.start);

        for section_range in section_ranges {
            let section_data = &image[section_range];
            hasher.update(section_data);
            num_of_bytes_hashed += section_data.len();
        }

        // Security data size
        let num_of_security_data = sec_directory_ref.size as usize;

        // hash 额外内容
        let extra_start = num_of_bytes_hashed;
        let extra_size = file_size - num_of_security_data - num_of_bytes_hashed;
        let extra_end = extra_start + extra_size;
        hasher.update(&image[extra_start..extra_end]);

        let result = hasher.finalize();

        Ok(to_hex_str(&result))
    }

    // 验证证书是否有效
    pub fn verify(self: &Self, option: &VerifyOption) -> Result<PeSignStatus, PeSignError> {
        self.signed_data.verify(option)
    }

    // 验证 PE 是否被篡改
    pub fn verify_pe_path<P: AsRef<Path>>(
        self: &Self,
        filename: P,
        option: &VerifyOption,
    ) -> Result<PeSignStatus, PeSignError> {
        let image = VecPE::from_disk_file(filename).map_app_err(PeSignErrorKind::IoError)?;

        self.verify_vecpe(&image, option)
    }

    // 验证 PE 是否被篡改
    pub fn verify_pe_data(
        self: &Self,
        bin: &[u8],
        option: &VerifyOption,
    ) -> Result<PeSignStatus, PeSignError> {
        let image = VecPE::from_disk_data(bin);

        self.verify_vecpe(&image, option)
    }

    // 验证 PE 是否被篡改
    pub fn verify_vecpe(
        self: &Self,
        image: &VecPE,
        option: &VerifyOption,
    ) -> Result<PeSignStatus, PeSignError> {
        let authenticode =
            Self::calc_authenticode_from_vecpe(image, &self.authenticode_digest_algorithm)?;

        if authenticode != self.authenticode_digest {
            Ok(PeSignStatus::Invalid)
        } else {
            self.verify(option)
        }
    }

    // 导出为 DER
    pub fn export_der(self: &Self) -> Result<Vec<u8>, PeSignError> {
        self.to_der().map_app_err(PeSignErrorKind::ExportDerError)
    }

    // 导出为 PEM
    pub fn export_pem(self: &Self) -> Result<String, PeSignError> {
        self.to_pem(Default::default())
            .map_app_err(PeSignErrorKind::ExportPemError)
    }
}

// 签名状态
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSignStatus {
    // 不受信任的证书链
    UntrustedCertificateChain,

    // 证书过期
    Expired,

    // 证书无效
    Invalid,

    // 证书有效
    Valid,
}

const DEFAULT_TRUSTED_CA_PEM: &str = include_str!("./cacert.pem");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyOption {
    pub check_time: bool,
    pub trusted_ca_pem: Option<String>,
}

impl Default for VerifyOption {
    fn default() -> Self {
        Self {
            check_time: true,
            trusted_ca_pem: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attributes(pub Vec<Attribute>);

impl TryFrom<x509_cert::attr::Attributes> for Attributes {
    type Error = PeSignError;

    fn try_from(value: x509_cert::attr::Attributes) -> Result<Self, Self::Error> {
        Ok(Self(value.into_vec().try_vec_into().map_err(|err| {
            Self::Error {
                kind: PeSignErrorKind::Unknown,
                message: err.to_string(),
            }
        })?))
    }
}

impl Attributes {
    pub fn to_der(self: &Self) -> Result<Vec<u8>, PeSignError> {
        let mut result = SetOfVec::<x509_cert::attr::Attribute>::new();

        for vv in &self.0 {
            result.insert(vv.__inner.clone()).map_unknown_err()?;
        }

        Ok(result.to_der().map_unknown_err()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub oid: String,
    pub values: Vec<Vec<u8>>,
    __inner: x509_cert::attr::Attribute,
}

impl TryFrom<x509_cert::attr::Attribute> for Attribute {
    type Error = PeSignError;

    fn try_from(attr: x509_cert::attr::Attribute) -> Result<Self, Self::Error> {
        let mut values = vec![];

        for vv in attr.values.iter() {
            values.push(vv.to_der().map_unknown_err()?);
        }

        Ok(Self {
            oid: attr.oid.to_string(),
            values: values,
            __inner: attr,
        })
    }
}

#[cfg(test)]
mod tests {
    use cms::cert::x509::der::SliceReader;
    use der::{DecodePem, EncodePem};

    use super::*;

    #[test]
    fn test_parse_pkcs7_from_der() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        assert!(ContentInfo::from_der(bytes)
            .unwrap_err()
            .to_string()
            .starts_with("trailing data"));
    }

    #[test]
    fn test_parse_pkcs7_decode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let mut reader = SliceReader::new(bytes).unwrap();
        assert!(ContentInfo::decode(&mut reader).is_ok());
    }

    #[test]
    fn get_authenticode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.authenticode_digest,
            "9253a6f72ee0e3970d5457e0f061fdb40b484f18"
        );
    }

    #[test]
    fn get_nested_authenticode() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();
        let nested = pesign.signed_data.get_nested_signature().unwrap().unwrap();

        assert_eq!(
            nested.authenticode_digest,
            "33a755311b428c2063f983058dbf9e1648d00d5fec4adf00e0a34ddee639f68b",
        );
    }

    #[test]
    fn get_cert_signature_data() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        let signer_cert_chain = pesign.signed_data.build_certificate_chain(None).unwrap();

        let signature_value = &signer_cert_chain[0].signature_value[..];
        let signature_bin = include_bytes!("./examples/signature.bin");

        assert_eq!(signature_value, signature_bin);
    }

    #[test]
    fn parse_signingtime_from_cs() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.signed_data.get_signature_time().unwrap().as_secs(),
            1459215302
        );
    }

    #[test]
    fn parse_signingtime_from_ms_tst_sign() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign
                .signed_data
                .get_nested_signature()
                .unwrap()
                .unwrap()
                .signed_data
                .get_signature_time()
                .unwrap()
                .as_secs(),
            1459215303
        );
    }

    #[test]
    fn parse_signingtime_from_attr() {
        let bytes = include_bytes!("./examples/pkcs7_with_signing_time.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.signed_data.get_signature_time().unwrap().as_secs(),
            1717347664
        );
    }

    #[test]
    fn export_pem() {
        let bytes = include_bytes!("./examples/pkcs7.cer");
        let pesign = PeSign::from_certificate_table_buf(bytes).unwrap();

        assert_eq!(
            pesign.to_pem(Default::default()).unwrap(),
            include_str!("./examples/pkcs7.pem")
        );
    }

    #[test]
    fn from_pem() {
        let pem = include_str!("./examples/pkcs7.pem");
        let result = PeSign::from_pem(pem);

        assert!(result.is_ok());
    }

    #[test]
    fn from_pe() {
        let result = PeSign::from_pe_data(include_bytes!("./examples/ProcessHacker.exe"));

        assert!(result.is_ok());
    }

    #[test]
    fn verify_pe() {
        let pedata = include_bytes!("./examples/ProcessHacker.exe");

        let status = PeSign::from_pe_data(pedata)
            .unwrap()
            .unwrap()
            .verify_pe_data(pedata, &Default::default())
            .unwrap();

        assert_eq!(status, PeSignStatus::Valid);
    }
}
