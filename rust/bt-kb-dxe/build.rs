// A UEFI boot service driver, not an application: it stays resident after
// its entry point returns, and its memory is boot services memory.
//
// The MT7922 firmware image is pinned here: BT_KB_FIRMWARE names the image
// (scripts/build-rust.sh passes the linux-firmware copy), and its SHA-256
// becomes FIRMWARE_SHA256. Secure Boot covers the driver but not files next
// to it, so the driver checks the image on the ESP against this before it
// parses it. Without BT_KB_FIRMWARE the build accepts no image at all.
//
// So are the bonds: BT_KB_BOND_DIGESTS lists the digests (hex, separated by
// commas or spaces; scripts/bond-digest.py) of the only bonds the driver
// trusts. Anyone who can write the ESP can drop a bond file there, but
// only a driver signed with the db key can trust it. Without
// BT_KB_BOND_DIGESTS the build trusts no bond.
use std::{env, fs, path::Path};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rustc-link-arg-bins=/subsystem:efi_boot_service_driver");
    println!("cargo:rerun-if-env-changed=BT_KB_FIRMWARE");
    println!("cargo:rerun-if-env-changed=BT_KB_BOND_DIGESTS");
    let bonds: Vec<[u8; 32]> = env::var("BT_KB_BOND_DIGESTS")
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|hex| {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("x"), 16))
                .collect::<Result<_, _>>()
                .unwrap_or_else(|_| panic!("BT_KB_BOND_DIGESTS: not hex: {hex}"));
            bytes.try_into().unwrap_or_else(|_| panic!("BT_KB_BOND_DIGESTS: not a SHA-256: {hex}"))
        })
        .collect();
    let pin = match env::var("BT_KB_FIRMWARE") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            let data = fs::read(&path).unwrap_or_else(|e| panic!("BT_KB_FIRMWARE={path}: {e}"));
            let hash: [u8; 32] = Sha256::digest(&data).into();
            format!("Some({hash:?})")
        }
        _ => String::from("None"),
    };
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("pins.rs");
    fs::write(
        out,
        format!(
            "/// SHA-256 of the only MT7922 firmware image this build accepts\n\
             /// (`BT_KB_FIRMWARE` at build time; `None`: none).\n\
             pub const FIRMWARE_SHA256: Option<[u8; 32]> = {pin};\n\
             /// Digests of the only bonds this build trusts (`BT_KB_BOND_DIGESTS`).\n\
             pub const TRUSTED_BONDS: &[[u8; 32]] = &{bonds:?};\n"
        ),
    )
    .expect("writing pins.rs");
}
