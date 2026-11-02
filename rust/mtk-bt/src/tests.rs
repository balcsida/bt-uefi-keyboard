//! Tests against the simulated MT7922, including a full upload of the real
//! linux-firmware image when it is available (`MTK_FW_PATH`, or the copy the
//! scripts unpack into `qemu/fw/`).

use std::vec::Vec;

use crate::firmware::*;
use crate::sim::{Sim, SimSection};
use crate::wmt::*;

/// Three downloadable sections that exercise the chunk-flag rules (several
/// chunks; one chunk plus one byte; a single chunk) and one info section that
/// is never sent.
const SYN_SIZES: [u32; 4] = [1000, 251, 100, 16];
const SYN_DL_SIZES: [u32; 4] = [1000, 251, 100, 0];
const SYN_DL_ADDRS: [u32; 4] = [0x0090_0000, 0x0091_C000, 0x00A0_0000, 0];

struct Synthetic {
    image: Vec<u8>,
    offsets: [usize; 4],
}

fn synthetic() -> Synthetic {
    let maps_end = HEADER_SIZE + GLOBAL_DESC_SIZE + 4 * SECTION_MAP_SIZE;
    let mut image = std::vec![0u8; maps_end + SYN_SIZES.iter().sum::<u32>() as usize];
    image[..14].copy_from_slice(b"20260101120000");
    image[16..20].copy_from_slice(b"ALPS");
    image[20] = 0x8a;
    image[22] = 0x8a;
    image[24..28].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    image[HEADER_SIZE + 12..HEADER_SIZE + 16].copy_from_slice(&4u32.to_le_bytes());

    let mut offsets = [0; 4];
    let mut offset = maps_end;
    for i in 0..4 {
        offsets[i] = offset;
        let map = HEADER_SIZE + GLOBAL_DESC_SIZE + i * SECTION_MAP_SIZE;
        let sec_type: u32 = if i == 3 { 1 } else { 0x0001_0002 + i as u32 * 0x0002_0000 };
        image[map..map + 4].copy_from_slice(&sec_type.to_le_bytes());
        image[map + 4..map + 8].copy_from_slice(&(offset as u32).to_le_bytes());
        image[map + 8..map + 12].copy_from_slice(&SYN_SIZES[i].to_le_bytes());
        image[map + 12..map + 16].copy_from_slice(&SYN_DL_ADDRS[i].to_le_bytes());
        image[map + 16..map + 20].copy_from_slice(&SYN_DL_SIZES[i].to_le_bytes());
        image[map + 36..map + 40].copy_from_slice(&(0x1234_0000 + i as u32).to_le_bytes());
        for b in 0..SYN_SIZES[i] as usize {
            image[offset + b] = (b * 7 + i * 31 + 1) as u8;
        }
        offset += SYN_SIZES[i] as usize;
    }
    Synthetic { image, offsets }
}

fn sim_for(syn: &Synthetic, loaded: bool) -> Sim {
    Sim::with_sections(
        (0..3)
            .map(|i| SimSection {
                dl_addr: SYN_DL_ADDRS[i],
                dl_size: SYN_DL_SIZES[i],
                expected: syn.image[syn.offsets[i]..syn.offsets[i] + SYN_DL_SIZES[i] as usize].to_vec(),
                loaded,
            })
            .collect(),
    )
}

#[test]
fn parses_synthetic_image() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    assert_eq!(fw.build_time, "20260101120000");
    assert_eq!(fw.platform, "ALPS");
    assert_eq!(fw.hw_ver, 0x8a);
    assert_eq!(fw.section_count(), 4);
    let sections: Vec<_> = fw.sections().collect();
    assert_eq!(sections[0].offset as usize, syn.offsets[0]);
    assert_eq!(sections[1].dl_addr, 0x0091_C000);
    assert_eq!(sections[1].crc, 0x1234_0001);
    assert_eq!(sections[2].dl_size, 100);
    assert_eq!(sections[2].data.as_ptr(), syn.image[syn.offsets[2]..].as_ptr());
    assert!(sections[3].data.is_empty());
    assert_eq!(fw.download_bytes(), 1351);
    assert_eq!(fw.download_chunks(), 4 + 2 + 1);
}

#[test]
fn rejects_bad_images() {
    let syn = synthetic();
    let maps_end = HEADER_SIZE + GLOBAL_DESC_SIZE + 4 * SECTION_MAP_SIZE;
    assert_eq!(FirmwareImage::parse(&syn.image[..50]).unwrap_err(), FirmwareError::TooSmall);
    assert_eq!(FirmwareImage::parse(&syn.image[..maps_end - 1]).unwrap_err(), FirmwareError::MapsTruncated);
    assert_eq!(
        FirmwareImage::parse(&syn.image[..syn.image.len() - 17]).unwrap_err(),
        FirmwareError::SectionOutOfBounds { index: 2 }
    );

    let mut copy = syn.image.clone();
    copy[HEADER_SIZE + 12..HEADER_SIZE + 16].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(FirmwareImage::parse(&copy).unwrap_err(), FirmwareError::NoSections);
    copy[HEADER_SIZE + 12..HEADER_SIZE + 16].copy_from_slice(&17u32.to_le_bytes());
    assert_eq!(FirmwareImage::parse(&copy).unwrap_err(), FirmwareError::TooManySections(17));

    let mut copy = syn.image.clone();
    let map = HEADER_SIZE + GLOBAL_DESC_SIZE + SECTION_MAP_SIZE;
    copy[map + 4..map + 8].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(FirmwareImage::parse(&copy).unwrap_err(), FirmwareError::SectionOutOfBounds { index: 1 });
}

#[test]
fn firmware_names_follow_linux() {
    let name = |chip, ver, flavor| FirmwareName::for_chip(chip, ver, flavor).map(|n| std::format!("{n}"));
    assert_eq!(name(0x7922, 0x0000_8A00, 0).as_deref(), Some("BT_RAM_CODE_MT7922_1_1_hdr.bin"));
    assert_eq!(name(0x7961, 0x8A00_0001, 1).as_deref(), Some("BT_RAM_CODE_MT7961_1a_2_hdr.bin"));
    assert_eq!(name(0x7922, 0x0000_000F, 1).as_deref(), Some("BT_RAM_CODE_MT7922_1_10_hdr.bin"));
    assert_eq!(name(0x7925, 0, 0), None);
}

#[test]
fn chip_info_enable_disable() {
    let mut mtk = Mtk::new(Sim { empty_polls: 2, ..Sim::new() });
    let info = mtk.chip_info().unwrap();
    assert_eq!(info, ChipInfo { chip_id: 0x7922, fw_version: 0, fw_flavor: 0 });

    let event = mtk.enable().unwrap();
    assert_eq!(mtk.transport.reg_ep_rst_opt, UHW_EP_RST_IN_OUT);
    assert!(mtk.transport.function_on);
    assert_eq!(event.op, OP_FUNC_CTRL);
    assert_eq!(event.status, Some(0x0404));
    assert_eq!(mtk.transport.polls, 3); // two empty polls, then the event
    assert_eq!(mtk.stats.short_polls, 3);
    assert_eq!(mtk.transport.elapsed_us, 2 * 500);

    let event = mtk.disable().unwrap();
    assert!(!mtk.transport.function_on);
    assert_eq!(event.status, None);
    assert_eq!(mtk.transport.func_ctrls, 2);
    assert_eq!(mtk.transport.error, None);
}

#[test]
fn loaded_sections_are_only_queried() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    let mut mtk = Mtk::new(sim_for(&syn, true));
    let result = mtk.load_firmware(&fw, false).unwrap();
    assert_eq!(result.sections_checked, 3);
    assert_eq!(result.sections_already_loaded, 3);
    assert_eq!(result.chunks_sent, 0);
    assert_eq!(mtk.transport.queries, 3);
    assert_eq!(mtk.transport.chunks, 0);
    assert_eq!(mtk.transport.elapsed_us, 100_000); // activation wait only
    assert_eq!(mtk.transport.error, None);
}

#[test]
fn missing_section_is_not_uploaded_without_permission() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    let mut sim = sim_for(&syn, true);
    sim.sections[1].loaded = false;
    let mut mtk = Mtk::new(sim);
    assert_eq!(mtk.load_firmware(&fw, false).unwrap_err(), Error::NotLoaded { section: 1 });
    assert_eq!(mtk.transport.chunks, 0);
    assert_eq!(mtk.transport.queries, 2);
    assert!(!mtk.transport.sections[1].loaded);
    assert_eq!(mtk.transport.error, None);
}

#[test]
fn upload_survives_busy_replies_and_slow_events() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    let mut mtk = Mtk::new(Sim { busy_replies: 2, empty_polls: 3, ..sim_for(&syn, false) });
    let result = mtk.load_firmware(&fw, true).unwrap();
    assert_eq!(mtk.transport.error, None);
    assert!(mtk.transport.sections.iter().all(|s| s.loaded));
    assert_eq!(result.sections_downloaded, 3);
    assert_eq!(result.busy_retries, 2);
    assert_eq!(result.chunks_sent as usize, fw.download_chunks());
    assert_eq!(mtk.transport.queries, 3 + 2);
    assert_eq!(mtk.stats.wmt_commands as usize, 3 + 2 + fw.download_chunks());
    assert_eq!(mtk.transport.polls, 4 * mtk.stats.wmt_commands);
}

#[test]
fn works_when_short_replies_are_not_flagged() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    let mut mtk = Mtk::new(Sim { report_short: false, empty_polls: 2, ..sim_for(&syn, false) });
    let result = mtk.load_firmware(&fw, true).unwrap();
    assert_eq!(mtk.transport.error, None);
    assert_eq!(result.chunks_sent as usize, fw.download_chunks());
    assert_eq!(mtk.stats.short_polls, 0);
    assert_eq!(mtk.stats.event_polls, 3 * mtk.stats.wmt_commands);
}

#[test]
fn short_register_read_is_an_error() {
    let mut mtk = Mtk::new(Sim { short_register_reads: true, ..Sim::new() });
    assert_eq!(mtk.read_chip_reg(REG_CHIP_ID).unwrap_err(), Error::Protocol("short register read"));
}

#[test]
fn chip_that_stays_busy_gives_up_after_20_queries() {
    let syn = synthetic();
    let fw = FirmwareImage::parse(&syn.image).unwrap();
    let mut mtk = Mtk::new(Sim { busy_replies: 1000, ..sim_for(&syn, false) });
    assert_eq!(mtk.load_firmware(&fw, true).unwrap_err(), Error::Busy { section: 0 });
    assert_eq!(mtk.transport.queries, 20);
    assert_eq!(mtk.transport.chunks, 0);
}

#[test]
fn silent_chip_times_out() {
    let mut mtk = Mtk::new(Sim { never_reply: true, ..Sim::new() });
    mtk.event_timeout_ms = 20;
    assert_eq!(mtk.enable().unwrap_err(), Error::Timeout { op: OP_FUNC_CTRL });
    assert_eq!(mtk.transport.polls, 41); // 20 ms / 500 us, plus the first poll
}

#[test]
fn subsys_reset_drops_firmware() {
    let syn = synthetic();
    let mut mtk = Mtk::new(Sim { function_on: true, reset_done_polls: 3, ..sim_for(&syn, true) });
    mtk.subsys_reset_7922().unwrap();
    assert!(!mtk.transport.sections[0].loaded);
    assert!(!mtk.transport.function_on);
    assert_eq!(mtk.transport.reg_subsys_rst & 0x2020, 0x2020);
    assert_eq!(mtk.transport.reg_udma_int_sta, 0xFF);
    assert_eq!(mtk.transport.error, None);
}

fn real_image() -> Option<Vec<u8>> {
    let path = std::env::var("MTK_FW_PATH").unwrap_or_else(|_| {
        std::string::String::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../qemu/fw/BT_RAM_CODE_MT7922_1_1_hdr.bin"))
    });
    std::fs::read(path).ok()
}

#[test]
fn real_mt7922_image_uploads_chunk_for_chunk() {
    let Some(image) = real_image() else {
        std::eprintln!("real firmware image not found; set MTK_FW_PATH or run scripts/test.sh once");
        return;
    };
    let fw = FirmwareImage::parse(&image).unwrap();

    // Cross-checked with an independent Python parser of the same file.
    assert_eq!(image.len(), 517_398);
    assert_eq!(fw.build_time, "20260724143815");
    assert_eq!(fw.platform, "ALPS");
    assert_eq!(fw.section_count(), 3);
    let sections: Vec<_> = fw.sections().collect();
    assert_eq!((sections[0].offset, sections[0].dl_size, sections[0].dl_addr), (0x120, 80_128, 0x0090_0000));
    assert_eq!((sections[1].offset, sections[1].dl_size, sections[1].dl_addr), (0x13A20, 436_864, 0x0091_C000));
    assert_eq!(sections[2].dl_size, 0);
    assert_eq!(fw.download_bytes(), 516_992);
    assert_eq!(fw.download_chunks(), 2069);

    // Expected bytes straight from the file offsets, independent of the parser.
    let sim = Sim {
        empty_polls: 1,
        ..Sim::with_sections(std::vec![
            SimSection { dl_addr: 0x0090_0000, dl_size: 80_128, expected: image[0x120..0x120 + 80_128].to_vec(), loaded: false },
            SimSection { dl_addr: 0x0091_C000, dl_size: 436_864, expected: image[0x13A20..0x13A20 + 436_864].to_vec(), loaded: false },
        ])
    };
    let mut mtk = Mtk::new(sim);
    let result = mtk.load_firmware(&fw, true).unwrap();
    assert_eq!(mtk.transport.error, None);
    assert!(mtk.transport.sections.iter().all(|s| s.loaded));
    assert_eq!(result.chunks_sent, 2069);
    assert_eq!(mtk.stats.wmt_commands, 2 + 2069);
    std::eprintln!(
        "upload: {} WMT commands, {} polls, {} ms of stalls with one empty poll per event",
        mtk.stats.wmt_commands,
        mtk.transport.polls,
        mtk.transport.elapsed_us / 1000
    );
}

#[test]
fn borrowed_transport_drives_the_chip() {
    let mut sim = Sim::new();
    {
        let mut mtk = Mtk::new(&mut sim);
        mtk.enable().unwrap();
        mtk.disable().unwrap();
    }
    assert_eq!(sim.func_ctrls, 2);
    assert!(!sim.function_on);
    assert_eq!(sim.error, None);
}
