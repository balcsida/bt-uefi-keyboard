//! Unsealing against a real TPM implementation: libtpms in swtpm, over
//! swtpm's TCP command port (raw TPM commands, as the swtpm TCTI sends
//! them). `scripts/tpm-host-test.sh` starts swtpm, seals a test bond with
//! `scripts/tpm-seal.sh`, and runs this with:
//!
//! - `BTKB_SWTPM`: host:port of the command port;
//! - `BTKB_SEALED`: the sealed bond file;
//! - `BTKB_EXPECT`: `ok:DIGEST` (the bond's digest, `bond-digest.py`) or
//!   `fail:TEXT` (a part of the reason unsealing must fail with).
//!
//! Without `BTKB_SWTPM` it does nothing.

use std::io::{Read, Write};
use std::net::TcpStream;

use uefi_bt::bond::ExportedBond;
use uefi_bt::rng::Rng;
use uefi_bt::seal::{self, Sealed};
use uefi_bt::tpm2::{Error, Tpm};

struct Swtpm(TcpStream);

impl Tpm for Swtpm {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        self.0.write_all(command).map_err(|_| Error::Transport)?;
        let mut header = [0u8; 10];
        self.0.read_exact(&mut header).map_err(|_| Error::Transport)?;
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if !(10..=response.len()).contains(&size) {
            return Err(Error::Transport);
        }
        response[..10].copy_from_slice(&header);
        self.0.read_exact(&mut response[10..size]).map_err(|_| Error::Transport)?;
        Ok(size)
    }
}

#[test]
fn unseal_with_swtpm() {
    let Ok(address) = std::env::var("BTKB_SWTPM") else {
        eprintln!("BTKB_SWTPM isn't set: skipped (scripts/tpm-host-test.sh runs this)");
        return;
    };
    let path = std::env::var("BTKB_SEALED").expect("BTKB_SEALED");
    let expect = std::env::var("BTKB_EXPECT").expect("BTKB_EXPECT");
    let sealed = Sealed::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut tpm = Swtpm(TcpStream::connect(&address).unwrap());
    let mut rng = Rng::new(&[]);
    let result = seal::unseal(&mut tpm, &sealed, &mut rng);
    match expect.split_once(':') {
        Some(("ok", digest)) => {
            let unsealed = result.unwrap_or_else(|e| panic!("unsealing failed: {} ({e:?})", e.reason()));
            let bond = ExportedBond::from_record(&unsealed.record).expect("the unsealed data is a bond record");
            assert_eq!(seal::hex(&bond.digest()), digest);
            assert!(unsealed.hmac_checked, "the TPM's answer had no HMAC");
            println!("unsealed: the bond's digest matches, the answer's HMAC checked");
        }
        Some(("fail", what)) => {
            let e = result.err().expect("unsealing must fail");
            assert!(e.reason().contains(what), "failed with {e:?}: {}; expected {what:?}", e.reason());
            println!("refused as expected: {} ({e:?})", e.reason());
        }
        _ => panic!("BTKB_EXPECT must be ok:DIGEST or fail:TEXT"),
    }
    // Nothing left loaded in the TPM: the object and the session were
    // flushed (TPM2_GetCapability, transient handles and policy sessions).
    for (first, what) in [(0x8000_0000u32, "transient objects"), (0x0300_0000u32, "policy sessions")] {
        let mut cmd = vec![0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A, 0, 0, 0, 1];
        cmd.extend_from_slice(&first.to_be_bytes());
        cmd.extend_from_slice(&16u32.to_be_bytes());
        let mut response = [0u8; 256];
        let n = tpm.submit(&cmd, &mut response).unwrap();
        let count = u32::from_be_bytes(response[15..19].try_into().unwrap());
        assert_eq!(count, 0, "{what} left in the TPM ({n}-byte answer)");
    }
}
