// A UEFI boot service driver, not an application: it stays resident after
// its entry point returns, and its memory is boot services memory.
fn main() {
    println!("cargo:rustc-link-arg-bins=/subsystem:efi_boot_service_driver");
}
