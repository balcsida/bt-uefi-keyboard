// A UEFI boot service driver, not an application: it stays resident after
// its entry point returns, and its memory is boot services memory.
//
// The MT7922 firmware image is pinned here: BT_KB_FIRMWARE names the image
// (scripts/build-rust.sh passes the linux-firmware copy), and its SHA-256
// becomes FIRMWARE_SHA256. Secure Boot covers the driver but not files next
// to it, so the driver checks the image on the ESP against this before it
// parses it. Without BT_KB_FIRMWARE the build accepts no image at all.
use std::{env, fs, path::Path};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rustc-link-arg-bins=/subsystem:efi_boot_service_driver");
    println!("cargo:rerun-if-env-changed=BT_KB_FIRMWARE");
    let pin = match env::var("BT_KB_FIRMWARE") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            let data = fs::read(&path).unwrap_or_else(|e| panic!("BT_KB_FIRMWARE={path}: {e}"));
            let hash: [u8; 32] = Sha256::digest(&data).into();
            format!("Some({hash:?})")
        }
        _ => String::from("None"),
    };
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("firmware_pin.rs");
    fs::write(
        out,
        format!(
            "/// SHA-256 of the only MT7922 firmware image this build accepts\n\
             /// (`BT_KB_FIRMWARE` at build time; `None`: none).\n\
             pub const FIRMWARE_SHA256: Option<[u8; 32]> = {pin};\n"
        ),
    )
    .expect("writing firmware_pin.rs");
}
