//! MediaTek MT79xx Bluetooth firmware images (`BT_RAM_CODE_MT79xx_*_hdr.bin`).
//!
//! Layout:
//! - `0x00` header (32 bytes): build time (16), platform (4), hw ver, sw ver, magic
//! - `0x20` global descriptor (64 bytes): patch ver, subsystem, feature options,
//!   section count, ...
//! - `0x60` section maps, 64 bytes each: type, file offset, size, then a
//!   52-byte "bin info" block that is sent verbatim with the section query
//!   (load address, download size, key index, alignment, type, mode/CRC type,
//!   CRC, reserved).

use core::fmt;

pub const HEADER_SIZE: usize = 32;
pub const GLOBAL_DESC_SIZE: usize = 64;
pub const SECTION_MAP_SIZE: usize = 64;
pub const SECTION_COMMON_SIZE: usize = 12;
pub const BIN_INFO_SIZE: usize = 52;
pub const MAX_SECTIONS: usize = 16;
/// Largest WMT payload: the 255-byte HCI parameter limit minus the 5-byte WMT header.
pub const CHUNK_SIZE: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareError {
    TooSmall,
    NoSections,
    TooManySections(u32),
    MapsTruncated,
    SectionOutOfBounds { index: usize },
}

impl fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "image too small"),
            Self::NoSections => write!(f, "image declares no sections"),
            Self::TooManySections(n) => write!(f, "{n} sections, at most {MAX_SECTIONS} supported"),
            Self::MapsTruncated => write!(f, "section maps truncated"),
            Self::SectionOutOfBounds { index } => write!(f, "section {index} lies outside the file"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Section<'a> {
    pub sec_type: u32,
    pub offset: u32,
    pub size: u32,
    pub dl_addr: u32,
    pub dl_size: u32,
    pub bin_type: u32,
    pub dl_mode_crc_type: u32,
    pub crc: u32,
    /// The 52-byte block sent with the section query.
    pub bin_info: &'a [u8; BIN_INFO_SIZE],
    /// `dl_size` bytes of payload (empty when the section is not sent).
    pub data: &'a [u8],
}

impl Section<'_> {
    pub fn chunks(&self) -> usize {
        (self.dl_size as usize).div_ceil(CHUNK_SIZE)
    }
}

#[derive(Debug, Clone)]
pub struct FirmwareImage<'a> {
    pub build_time: &'a str,
    pub platform: &'a str,
    pub hw_ver: u16,
    pub sw_ver: u16,
    pub magic: u32,
    sections: [Option<Section<'a>>; MAX_SECTIONS],
    section_count: usize,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Printable ASCII prefix of a fixed-width field.
fn ascii_field(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| !(0x20..=0x7e).contains(&c)).unwrap_or(b.len());
    // Printable ASCII is valid UTF-8.
    core::str::from_utf8(&b[..end]).unwrap_or("")
}

impl<'a> FirmwareImage<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self, FirmwareError> {
        if image.len() < HEADER_SIZE + GLOBAL_DESC_SIZE {
            return Err(FirmwareError::TooSmall);
        }

        let count = le32(image, HEADER_SIZE + 12);
        if count == 0 {
            return Err(FirmwareError::NoSections);
        }
        if count as usize > MAX_SECTIONS {
            return Err(FirmwareError::TooManySections(count));
        }
        let count = count as usize;
        if HEADER_SIZE + GLOBAL_DESC_SIZE + count * SECTION_MAP_SIZE > image.len() {
            return Err(FirmwareError::MapsTruncated);
        }

        let mut sections = [None; MAX_SECTIONS];
        for (index, slot) in sections.iter_mut().enumerate().take(count) {
            let map = &image[HEADER_SIZE + GLOBAL_DESC_SIZE + index * SECTION_MAP_SIZE..][..SECTION_MAP_SIZE];
            let bin_info: &[u8; BIN_INFO_SIZE] = map[SECTION_COMMON_SIZE..SECTION_COMMON_SIZE + BIN_INFO_SIZE]
                .try_into()
                .expect("52-byte slice");
            let offset = le32(map, 4);
            let dl_size = le32(bin_info, 4);
            let data = if dl_size == 0 {
                &image[..0]
            } else {
                let start = offset as usize;
                let end = start
                    .checked_add(dl_size as usize)
                    .filter(|&end| end <= image.len())
                    .ok_or(FirmwareError::SectionOutOfBounds { index })?;
                &image[start..end]
            };
            *slot = Some(Section {
                sec_type: le32(map, 0),
                offset,
                size: le32(map, 8),
                dl_addr: le32(bin_info, 0),
                dl_size,
                bin_type: le32(bin_info, 16),
                dl_mode_crc_type: le32(bin_info, 20),
                crc: le32(bin_info, 24),
                bin_info,
                data,
            });
        }

        Ok(Self {
            build_time: ascii_field(&image[0..16]),
            platform: ascii_field(&image[16..20]),
            hw_ver: le16(image, 20),
            sw_ver: le16(image, 22),
            magic: le32(image, 24),
            sections,
            section_count: count,
        })
    }

    pub fn sections(&self) -> impl Iterator<Item = &Section<'a>> {
        self.sections[..self.section_count].iter().flatten()
    }

    pub fn section_count(&self) -> usize {
        self.section_count
    }

    /// Bytes a full upload sends.
    pub fn download_bytes(&self) -> u32 {
        self.sections().map(|s| s.dl_size).sum()
    }

    /// WMT chunk commands a full upload needs.
    pub fn download_chunks(&self) -> usize {
        self.sections().map(Section::chunks).sum()
    }
}

/// File name Linux requests for a chip, e.g. `BT_RAM_CODE_MT7922_1_1_hdr.bin`.
/// Only the MT7922 / MT7961 / MT7902 naming scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareName {
    chip_id: u16,
    flavor_a: bool,
    variant: u32,
}

impl FirmwareName {
    pub fn for_chip(chip_id: u32, fw_version: u32, fw_flavor: u32) -> Option<Self> {
        match chip_id {
            0x7922 | 0x7961 | 0x7902 => Some(Self {
                chip_id: chip_id as u16,
                flavor_a: chip_id == 0x7961 && fw_flavor != 0,
                variant: (fw_version & 0xff) + 1,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for FirmwareName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BT_RAM_CODE_MT{:04x}_1{}_{:x}_hdr.bin",
            self.chip_id,
            if self.flavor_a { "a" } else { "" },
            self.variant
        )
    }
}
