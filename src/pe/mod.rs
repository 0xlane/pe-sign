pub mod structs;

use std::{
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    ops::Range,
    path::Path,
};

use digest::DynDigest;
use structs::*;

use crate::{
    cert::Algorithm,
    errors::{PeSignError, PeSignErrorKind, PeSignResult},
    utils::to_hex_str,
};

pub trait ReadAndSeek: Read + Seek {}
impl<T> ReadAndSeek for T where T: Read + Seek {}

/// PE struct.
pub struct PE<'a> {
    _buf_reader: BufReader<Box<dyn ReadAndSeek + 'a>>,
}

impl<'a> PE<'a> {
    /// Parse PE struct from disk path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pesign::{PE, structs::{ImageNtHeaders, HDR64_MAGIC}};
    ///
    /// let mut image = PE::from_path("test/normal64.exe").unwrap();
    /// let headers = image.get_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    pub fn from_path<P: AsRef<Path>>(filename: P) -> Result<Self, PeSignError> {
        Ok(Self::from_reader(Box::new(Box::new(
            File::open(filename).map_app_err(PeSignErrorKind::IoError)?,
        )))?)
    }

    /// Parse PE struct from memory bytes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pesign::{PE, structs::{ImageNtHeaders, HDR64_MAGIC}};
    ///
    /// let bytes = std::fs::read("test/normal64.exe").unwrap();
    ///
    /// let mut image = PE::from_bytes(&bytes).unwrap();
    /// let headers = image.get_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, PeSignError> {
        Ok(Self::from_reader(Box::new(Cursor::new(bytes)))?)
    }

    /// Parse PE struct from reader.
    ///
    /// The reader must implement both the [`Read`](std::io::Read) and [`Seek`](std::io::Seek) traits.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pesign::{PE, structs::{ImageNtHeaders, HDR64_MAGIC}};
    ///
    /// let file = Box::new(std::fs::File::open("test/normal64.exe").unwrap());
    ///
    /// let mut image = PE::from_reader(file).unwrap();
    /// let headers = image.get_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    pub fn from_reader(reader: Box<dyn ReadAndSeek + 'a>) -> Result<Self, PeSignError> {
        let buf_reader = BufReader::new(reader);

        Ok(Self {
            _buf_reader: buf_reader,
        })
    }

    /// Get the DOS header of the PE file.
    pub fn get_dos_header(self: &mut Self) -> Result<ImageDOSHeader, PeSignError> {
        Ok(unsafe { self.cast_c_struct(0)? })
    }

    /// Get the offset of NTHeaders within the PE file.
    pub fn e_lfanew(self: &mut Self) -> Result<u32, PeSignError> {
        let dos_header = self.get_dos_header()?;

        Ok(dos_header.e_lfanew)
    }

    /// Get the architecture of the PE file.
    pub fn get_arch(self: &mut Self) -> Result<Arch, PeSignError> {
        let magic = self.get_nt_magic()?;

        match magic {
            HDR32_MAGIC => Ok(Arch::X86),
            HDR64_MAGIC => Ok(Arch::X64),
            _ => Err(PeSignError {
                kind: PeSignErrorKind::InvalidPeFile,
                message: "The PE magic is invalid.".to_owned(),
            }),
        }
    }

    /// Get the NT headers of this PE file, inferring from the content of the file which architecture it is.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pesign::{PE, structs::{ImageNtHeaders, HDR64_MAGIC}};
    ///
    /// let mut image = PE::from_path("test/normal64.exe").unwrap();
    /// let headers = image.get_nt_headers().unwrap();
    ///
    /// let magic = match headers {
    ///    ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.magic,
    ///    ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.magic,
    /// };
    ///
    /// assert_eq!(magic, HDR64_MAGIC);
    /// ```
    pub fn get_nt_headers(self: &mut Self) -> Result<ImageNtHeaders, PeSignError> {
        match self.get_arch()? {
            Arch::X86 => Ok(ImageNtHeaders::ImageNTHeaders32(self.get_nt_headers_32()?)),
            Arch::X64 => Ok(ImageNtHeaders::ImageNTHeaders64(self.get_nt_headers_64()?)),
        }
    }

    /// Get 32-bit NT Headers
    pub fn get_nt_headers_32(self: &mut Self) -> Result<ImageNTHeaders32, PeSignError> {
        let e_lfanew = self.e_lfanew()?;

        Ok(unsafe { self.cast_c_struct(e_lfanew as _)? })
    }

    /// Get 64-bit NT Headers
    pub fn get_nt_headers_64(self: &mut Self) -> Result<ImageNTHeaders64, PeSignError> {
        let e_lfanew = self.e_lfanew()?;

        Ok(unsafe { self.cast_c_struct(e_lfanew as _)? })
    }

    /// Get the NT magic from the optional header of the NT headers.
    pub fn get_nt_magic(self: &mut Self) -> Result<u16, PeSignError> {
        // the difference in size doesn't affect the magic header, so we
        // simply blindly cast it to a 32-bit header to get the value

        Ok(self.get_nt_headers_32()?.optional_header.magic)
    }

    /// Get the offset to the data directory within the PE file.
    pub fn get_data_directory_offset(self: &mut Self) -> Result<u64, PeSignError> {
        let e_lfanew = self.e_lfanew()?;
        let nt_header = self.get_nt_headers()?;
        let header_size = match nt_header {
            ImageNtHeaders::ImageNTHeaders32(_) => std::mem::size_of::<ImageNTHeaders32>(),
            ImageNtHeaders::ImageNTHeaders64(_) => std::mem::size_of::<ImageNTHeaders64>(),
        };

        let offset = e_lfanew as u64 + header_size as u64;

        if !self.validate_offset(offset)? {
            return Err(PeSignError {
                kind: PeSignErrorKind::InvalidPeFile,
                message: "Bad data directory offset.".to_owned(),
            });
        }

        Ok(offset)
    }

    /// Get the size of the data directory.
    ///
    /// Rounds down [`number_of_rva_and_sizes`](crate::structs::ImageOptionalHeader32::number_of_rva_and_sizes) to 16, which is what
    /// the Windows loader does.
    pub fn get_data_directory_size(self: &mut Self) -> Result<u64, PeSignError> {
        let nt_headers = self.get_nt_headers()?;
        let size = match nt_headers {
            ImageNtHeaders::ImageNTHeaders32(hdr32) => {
                hdr32.optional_header.number_of_rva_and_sizes
            }
            ImageNtHeaders::ImageNTHeaders64(hdr64) => {
                hdr64.optional_header.number_of_rva_and_sizes
            }
        };

        // data directory gets rounded down if greater than 16
        if size > 16 {
            Ok(16)
        } else {
            Ok(size as _)
        }
    }

    /// Get the data directory table.
    ///
    /// Normally one would expect this to be a part of [`ImageOptionalHeader`](ImageOptionalHeader32), but
    /// [`ImageOptionalHeader::number_of_rva_and_sizes`](ImageOptionalHeader32::number_of_rva_and_sizes) controls
    /// the size of the array. Therefore, we can't stick it in the optional header, because that would
    /// produce a variable-sized structure, which Rust doesn't support.
    pub fn get_data_directory_table(
        self: &mut Self,
    ) -> Result<Vec<ImageDataDirectory>, PeSignError> {
        let offset = self.get_data_directory_offset()?;
        let size = self.get_data_directory_size()?;

        Ok(unsafe { self.cast_c_array(offset, size)? })
    }

    /// Get the data directory reference represented by the [`ImageDirectoryEntry`](crate::structs::ImageDirectoryEntry) enum.
    /// Returns [`PeSignError`](crate::errors::PeSignError) if the given directory is inaccessible due to the directory
    /// size.
    pub fn get_data_directory(
        self: &mut Self,
        idx: ImageDirectoryEntry,
    ) -> Result<ImageDataDirectory, PeSignError> {
        let offset = self.get_data_directory_offset()?;
        let t_size = std::mem::size_of::<ImageDataDirectory>() as u64;

        Ok(unsafe { self.cast_c_struct(offset + idx as u64 * t_size)? })
    }

    /// Get the offset to the section table within the PE file.
    pub fn get_section_table_offset(self: &mut Self) -> Result<u64, PeSignError> {
        let e_lfanew = self.e_lfanew()? as u64;
        let size_of_opt_hdr = match self.get_nt_headers()? {
            ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.file_header.size_of_optional_header,
            ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.file_header.size_of_optional_header,
        } as u64;

        Ok(e_lfanew
            + std::mem::size_of::<u32>() as u64
            + std::mem::size_of::<ImageFileHeader>() as u64
            + size_of_opt_hdr)
    }

    /// Get the size of the section table within the PE file.
    pub fn get_section_table_size(self: &mut Self) -> Result<u64, PeSignError> {
        let size_of_st = match self.get_nt_headers()? {
            ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.file_header.number_of_sections,
            ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.file_header.number_of_sections,
        };

        Ok(size_of_st as u64)
    }

    /// Get the section table of the PE file.
    pub fn get_section_table(self: &mut Self) -> Result<Vec<ImageSectionHeader>, PeSignError> {
        let offset = self.get_section_table_offset()?;
        let size = self.get_section_table_size()?;

        Ok(unsafe { self.cast_c_array(offset, size)? })
    }

    /// Get the size of the header within the PE file.
    ///
    /// SizeOfHeaders > dosHeader + ntHeader + dataDirectory + sectionTable.
    pub fn get_header_size(self: &mut Self) -> Result<u64, PeSignError> {
        let size_of_header = match self.get_nt_headers()? {
            ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.size_of_headers,
            ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.size_of_headers,
        };

        Ok(size_of_header as u64)
    }

    /// Get the PE file size.
    pub fn get_size(self: &mut Self) -> Result<u64, PeSignError> {
        let old_pos = self
            ._buf_reader
            .stream_position()
            .map_app_err(PeSignErrorKind::IoError)?;
        let len = self
            ._buf_reader
            .seek(SeekFrom::End(0))
            .map_app_err(PeSignErrorKind::IoError)?;

        // Avoid seeking a third time when we were already at the end of the
        // stream. The branch is usually way cheaper than a seek operation.
        if old_pos != len {
            self._buf_reader
                .seek(SeekFrom::Start(old_pos))
                .map_app_err(PeSignErrorKind::IoError)?;
        }

        Ok(len)
    }

    /// Get security data within the PE file.
    pub fn get_security_data(self: &mut Self) -> Result<Option<Vec<u8>>, PeSignError> {
        let security_directory = self.get_data_directory(ImageDirectoryEntry::Security)?;
        let offset_of_security_data_start = security_directory.virtual_address as u64; // security_data_directory rva is equivalent to file offset
        let size_of_security_data = security_directory.size as u64;
        let offset_of_security_data_end = offset_of_security_data_start + size_of_security_data;

        // No signature.
        if offset_of_security_data_start <= 0 || size_of_security_data <= 8 {
            return Ok(None);
        }

        if !self.validate_offset(offset_of_security_data_end)? {
            return Err(PeSignError { kind: PeSignErrorKind::InvalidPeFile, message: "The offset for the end of the security data is out of bounds relative to the file size.".to_owned() });
        }

        let mut buf = vec![0; size_of_security_data as _];
        self.read_exact_at(offset_of_security_data_start, &mut buf)?;

        Ok(Some(buf[8..].to_vec())) // _WIN_CERTIFICATE->bCertificate
    }

    /// Calculate authenticode of the PE file.
    pub fn calc_authenticode(self: &mut Self, algorithm: Algorithm) -> Result<String, PeSignError> {
        const CHUNK_SIZE: u64 = 1024 * 128;

        // Offsets relative to e_lfanew(the start of NtHeaders).
        const X64_R_OFFSET_CHECKNUM_START: u64 = 0x58;
        const X64_R_OFFSET_CHECKNUM_END: u64 = 0x58 + 0x4;
        const X64_R_OFFSET_SECURITY_DIRECTORY_START: u64 = 0xA8;
        const X64_R_OFFSET_SECURITY_DIRECTORY_END: u64 = 0xA8 + 0x4 * 2;
        const X86_R_OFFSET_CHECKNUM_START: u64 = 0x58;
        const X86_R_OFFSET_CHECKNUM_END: u64 = 0x58 + 0x4;
        const X86_R_OFFSET_SECURITY_DIRECTORY_START: u64 = 0x98;
        const X86_R_OFFSET_SECURITY_DIRECTORY_END: u64 = 0x98 + 0x4 * 2;

        let mut hasher = algorithm.new_digest()?;

        fn read_and_update(
            pe: &mut PE,
            hasher: &mut dyn DynDigest,
            mut start: u64,
            end: u64,
        ) -> Result<(), PeSignError> {
            loop {
                if start >= end {
                    break;
                }

                let mut buf = vec![0; CHUNK_SIZE.min(end - start) as _];

                pe._buf_reader
                    .seek(SeekFrom::Start(start))
                    .map_app_err(PeSignErrorKind::IoError)?;
                pe._buf_reader
                    .read(buf.as_mut_slice())
                    .map_app_err(PeSignErrorKind::IoError)?;

                hasher.update(&buf);

                start += CHUNK_SIZE;
            }

            Ok(())
        }

        let offset_of_nt_header_start = self.e_lfanew()? as u64;
        let offset_of_header_end = self.get_header_size()?;
        let (
            offset_of_checknum_start,
            offset_of_checknum_end,
            offset_of_security_directory_start,
            offset_of_security_directory_end,
        ) = match self.get_arch()? {
            Arch::X86 => (
                offset_of_nt_header_start + X86_R_OFFSET_CHECKNUM_START,
                offset_of_nt_header_start + X86_R_OFFSET_CHECKNUM_END,
                offset_of_nt_header_start + X86_R_OFFSET_SECURITY_DIRECTORY_START,
                offset_of_nt_header_start + X86_R_OFFSET_SECURITY_DIRECTORY_END,
            ),
            Arch::X64 => (
                offset_of_nt_header_start + X64_R_OFFSET_CHECKNUM_START,
                offset_of_nt_header_start + X64_R_OFFSET_CHECKNUM_END,
                offset_of_nt_header_start + X64_R_OFFSET_SECURITY_DIRECTORY_START,
                offset_of_nt_header_start + X64_R_OFFSET_SECURITY_DIRECTORY_END,
            ),
        };
        let offset_of_section_data_start = self
            .get_data_directory(ImageDirectoryEntry::Security)?
            .virtual_address as u64;

        // Hash headers.
        read_and_update(self, hasher.as_mut(), 0, offset_of_checknum_start)?;
        read_and_update(
            self,
            hasher.as_mut(),
            offset_of_checknum_end,
            offset_of_security_directory_start,
        )?;
        read_and_update(
            self,
            hasher.as_mut(),
            offset_of_security_directory_end,
            offset_of_header_end,
        )?;
        let mut num_of_bytes_hashed = offset_of_header_end;

        // Get section table.
        let section_table = self.get_section_table()?;
        // Sort section.
        let mut section_ranges = section_table
            .iter()
            .map(|v| {
                v.pointer_to_raw_data as u64
                    ..v.pointer_to_raw_data as u64 + v.size_of_raw_data as u64
            })
            .collect::<Vec<Range<u64>>>();
        section_ranges.sort_unstable_by_key(|v| v.start);
        // Hash section data.
        for section_range in section_ranges {
            // Passing through the overlap.
            let start = section_range.start.max(num_of_bytes_hashed);
            let end = section_range.end.max(num_of_bytes_hashed);

            read_and_update(self, hasher.as_mut(), start, end)?;

            num_of_bytes_hashed += end - start;
        }

        // Hash extra content after section data.
        let file_size = self.get_size()?;
        let extra_start = num_of_bytes_hashed;
        let extra_end = if offset_of_section_data_start != 0 {
            offset_of_section_data_start.min(file_size)
        } else {
            file_size
        };
        read_and_update(self, hasher.as_mut(), extra_start, extra_end)?;

        // Finish.
        let result = hasher.finalize();

        Ok(to_hex_str(&result))
    }

    fn validate_offset(self: &mut Self, offset: u64) -> Result<bool, PeSignError> {
        Ok(offset <= self.get_size()?)
    }

    /// Cast c struct bytes to rust struct.
    pub unsafe fn cast_c_struct<T: Castable>(
        self: &mut Self,
        offset: u64,
    ) -> Result<T, PeSignError> {
        let t_size = std::mem::size_of::<T>();
        let mut buf = vec![0; t_size];

        self.read_exact_at(offset, &mut buf)?;

        Ok(std::ptr::read(buf.as_ptr() as *const T))
    }

    /// Cast c array bytes to rust struct.
    pub unsafe fn cast_c_array<T: Castable>(
        self: &mut Self,
        offset: u64,
        size: u64,
    ) -> Result<Vec<T>, PeSignError> {
        self._buf_reader
            .seek(SeekFrom::Start(offset))
            .map_app_err(PeSignErrorKind::IoError)?;

        let t_size = std::mem::size_of::<T>();

        let mut t_array: Vec<T> = vec![];

        for _ in 0..size {
            let mut buf = vec![0; t_size];
            self._buf_reader
                .read_exact(&mut buf)
                .map_app_err(PeSignErrorKind::IoError)?;

            t_array.push(std::ptr::read(buf.as_ptr() as *const T));
        }

        Ok(t_array)
    }

    /// Read bytes into a fixed-size buffer.
    ///
    /// If the end is reached and there is not enough data to fill the buffer, it will return an Err.
    pub fn read_exact_at(self: &mut Self, offset: u64, buf: &mut [u8]) -> Result<(), PeSignError> {
        self._buf_reader
            .seek(SeekFrom::Start(offset))
            .map_app_err(PeSignErrorKind::IoError)?;

        self._buf_reader
            .read_exact(buf)
            .map_app_err(PeSignErrorKind::IoError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header() {
        let mut pe = PE::from_path("src\\examples\\ProcessHacker.exe").unwrap();
        let dos_header = pe.get_dos_header().unwrap();

        assert!(dos_header.e_lfanew == 0x118)
    }

    #[test]
    fn test_nt_headers() {
        let mut pe = PE::from_path("src\\examples\\ProcessHacker.exe").unwrap();
        let magic = match pe.get_nt_headers().unwrap() {
            ImageNtHeaders::ImageNTHeaders32(hdr32) => hdr32.optional_header.magic,
            ImageNtHeaders::ImageNTHeaders64(hdr64) => hdr64.optional_header.magic,
        };

        assert_eq!(magic, HDR64_MAGIC)
    }

    #[test]
    fn test_data_directory() {
        let mut pe = PE::from_path("src\\examples\\ProcessHacker.exe").unwrap();
        let security_ddt = pe
            .get_data_directory(ImageDirectoryEntry::Security)
            .unwrap();

        assert_eq!(security_ddt.virtual_address, 0x1a0400)
    }

    #[test]
    fn test_section_table() {
        let mut pe = PE::from_path("src\\examples\\ProcessHacker.exe").unwrap();
        let st = pe.get_section_table().unwrap();

        assert_eq!(st[0].name().unwrap(), ".text")
    }

    #[test]
    fn test_calc_authenticode() {
        let mut pe = PE::from_path("src\\examples\\ProcessHacker.exe").unwrap();

        assert_eq!(
            pe.calc_authenticode(Algorithm::Sha1).unwrap(),
            "9253a6f72ee0e3970d5457e0f061fdb40b484f18"
        )
    }
}
