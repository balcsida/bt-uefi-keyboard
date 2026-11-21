//! A bond made in firmware, handed to the OS.
//!
//! The keyboard holds one key per host, so the OS has to use the very bond
//! the driver made, and can't be allowed to pair again. The driver keeps
//! that bond where the OS can't read it; what the OS gets is this: the
//! bond record encrypted to a public key the driver was built with, in a
//! variable anyone may read. Only the holder of the private key (root, on
//! the installed system) can open it.
//!
//! ECIES from standard parts, one message per boot:
//! - an ephemeral P-256 key pair; the shared secret is the x coordinate of
//!   ephemeral private key x recipient's public key;
//! - HKDF-SHA256 (RFC 5869) of it, salted with both public keys, gives a
//!   key stream as long as the record and a MAC key;
//! - the record XOR the key stream, then HMAC-SHA256 over everything.
//!
//! The format, 147 bytes: `"BTKBHO1\0"`, the ephemeral public key (65
//! bytes, uncompressed), the encrypted record (42), the MAC (32).
//! `scripts/bond-handoff.py` opens it, and has the same known answer in
//! its self-test.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::bond::RECORD_LEN;
use crate::rng::Rng;

pub const MAGIC: &[u8; 8] = b"BTKBHO1\0";
const INFO: &[u8] = b"bt-kb-dxe hand-off v1";
/// An uncompressed P-256 point: 0x04, x, y.
pub const POINT_LEN: usize = 65;
pub const BLOB_LEN: usize = MAGIC.len() + POINT_LEN + RECORD_LEN + 32;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869): extract, then expand into `out`.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let mut prk = hmac(salt, &[ikm]);
    let mut block = [0u8; 32];
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let previous: &[u8] = if i == 0 { &[] } else { &block };
        let next = hmac(&prk, &[previous, info, &[i as u8 + 1]]);
        block = next;
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    prk.zeroize();
    block.zeroize();
}

/// The hand-off for a given shared secret (`z`, the x coordinate, most
/// significant byte first) and the two public keys it came from.
pub fn seal_with(z: &[u8; 32], ephemeral: &[u8; POINT_LEN], recipient: &[u8; POINT_LEN], record: &[u8; RECORD_LEN]) -> [u8; BLOB_LEN] {
    let mut salt = [0u8; 2 * POINT_LEN];
    salt[..POINT_LEN].copy_from_slice(ephemeral);
    salt[POINT_LEN..].copy_from_slice(recipient);
    let mut keys = [0u8; RECORD_LEN + 32];
    hkdf(z, &salt, INFO, &mut keys);
    let mut blob = [0u8; BLOB_LEN];
    let (body, tag) = blob.split_at_mut(BLOB_LEN - 32);
    body[..MAGIC.len()].copy_from_slice(MAGIC);
    body[MAGIC.len()..MAGIC.len() + POINT_LEN].copy_from_slice(ephemeral);
    for ((out, byte), key) in body[MAGIC.len() + POINT_LEN..].iter_mut().zip(record).zip(&keys[..RECORD_LEN]) {
        *out = byte ^ key;
    }
    tag.copy_from_slice(&hmac(&keys[RECORD_LEN..], &[body]));
    keys.zeroize();
    blob
}

/// A recipient's public key, if these 65 bytes are a point on the curve.
fn public_key(point: &[u8; POINT_LEN]) -> Option<PublicKey> {
    let point = EncodedPoint::from_bytes(point).ok()?;
    Option::from(PublicKey::from_encoded_point(&point))
}

/// Whether a hand-off can be made for this key: an uncompressed point on
/// P-256.
pub fn valid_recipient(point: &[u8; POINT_LEN]) -> bool {
    point[0] == 0x04 && public_key(point).is_some()
}

/// The hand-off of `record` to the holder of `recipient`'s private key.
/// `None` if `recipient` isn't a point on the curve.
pub fn seal(record: &[u8; RECORD_LEN], recipient: &[u8; POINT_LEN], rng: &mut Rng) -> Option<[u8; BLOB_LEN]> {
    if recipient[0] != 0x04 {
        return None;
    }
    let theirs = public_key(recipient)?;
    let ours = loop {
        let mut bytes = rng.array::<32>();
        let key = SecretKey::from_slice(&bytes);
        bytes.zeroize();
        if let Ok(key) = key {
            break key;
        }
    };
    let shared = (theirs.to_projective() * *ours.to_nonzero_scalar()).to_affine().to_encoded_point(false);
    let mut z: [u8; 32] = shared.x()?.as_slice().try_into().ok()?;
    let ephemeral: [u8; POINT_LEN] = ours.public_key().to_encoded_point(false).as_bytes().try_into().ok()?;
    let blob = seal_with(&z, &ephemeral, recipient, record);
    z.zeroize();
    Some(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use sha2::Digest;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(text.len(), 2 * N);
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    // The P-256 sample data of the Bluetooth Core Specification (Vol 3,
    // Part H, Appendix D): two key pairs and their shared secret.
    const PRIVATE_B: &str = "55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd";
    const PUBLIC_A: &str = "04 20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6
                               dc809c49 652aeb6d 63329abf 5a52155c 766345c2 8fed3024 741c8ed0 1589d28b";
    const PUBLIC_B: &str = "04 1ea1f0f0 1faf1d96 09592284 f19e4c00 47b58afd 8615a69f 559077b2 2faaa190
                               4c55f33e 429dad37 7356703a 9ab85160 472d1130 e28e3676 5f89aff9 15b1214a";
    const DHKEY: &str = "ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698";

    #[test]
    fn hkdf_matches_rfc_5869() {
        // Test case 1.
        let mut okm = [0u8; 42];
        hkdf(&[0x0b; 22], &hex::<13>("000102030405060708090a0b0c"), &hex::<10>("f0f1f2f3f4f5f6f7f8f9"), &mut okm);
        assert_eq!(okm, hex::<42>("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
        // More than two blocks, as the hand-off needs.
        let mut long = [0u8; 74];
        hkdf(&[0x0b; 22], &hex::<13>("000102030405060708090a0b0c"), &hex::<10>("f0f1f2f3f4f5f6f7f8f9"), &mut long);
        assert_eq!(long[..42], okm);
    }

    /// The same values as the self-test of scripts/bond-handoff.py, which
    /// prints the SHA-256 of the result.
    #[test]
    fn the_format_has_a_known_answer() {
        let record: [u8; RECORD_LEN] = core::array::from_fn(|i| i as u8 + 1);
        let blob = seal_with(&hex(DHKEY), &hex(PUBLIC_A), &hex(PUBLIC_B), &record);
        assert_eq!(&blob[..8], MAGIC);
        assert_eq!(blob[8..73], hex::<65>(PUBLIC_A));
        let digest: [u8; 32] = Sha256::digest(blob).into();
        assert_eq!(digest, hex::<32>("bf6b4e520b534255ee915cb6399e63f21226e20ddfed4e65e712e3debc0e73c2"));
    }

    /// What the recipient does: the shared secret from its private key
    /// and the ephemeral public key, the MAC, the record.
    fn open(blob: &[u8; BLOB_LEN], private: &[u8; 32], recipient: &[u8; POINT_LEN]) -> Option<[u8; RECORD_LEN]> {
        let ephemeral: [u8; POINT_LEN] = blob[8..73].try_into().unwrap();
        let secret = SecretKey::from_slice(private).unwrap();
        let shared = (public_key(&ephemeral)?.to_projective() * *secret.to_nonzero_scalar()).to_affine().to_encoded_point(false);
        let z: [u8; 32] = shared.x()?.as_slice().try_into().ok()?;
        let mut salt = [0u8; 2 * POINT_LEN];
        salt[..POINT_LEN].copy_from_slice(&ephemeral);
        salt[POINT_LEN..].copy_from_slice(recipient);
        let mut keys = [0u8; RECORD_LEN + 32];
        hkdf(&z, &salt, INFO, &mut keys);
        if hmac(&keys[RECORD_LEN..], &[&blob[..BLOB_LEN - 32]]) != blob[BLOB_LEN - 32..] {
            return None;
        }
        Some(core::array::from_fn(|i| blob[73 + i] ^ keys[i]))
    }

    #[test]
    fn only_the_recipient_opens_it() {
        let record: [u8; RECORD_LEN] = core::array::from_fn(|i| 0xA0 ^ i as u8);
        let mut rng = Rng::from_seed([7; 32]);
        let blob = seal(&record, &hex(PUBLIC_B), &mut rng).unwrap();
        assert_eq!(open(&blob, &hex(PRIVATE_B), &hex(PUBLIC_B)), Some(record));
        // The record isn't in it as it is, and two hand-offs differ.
        assert!(!blob.windows(8).any(|w| w == &record[..8]));
        let again = seal(&record, &hex(PUBLIC_B), &mut rng).unwrap();
        assert_ne!(blob[8..], again[8..]);
        assert_eq!(open(&again, &hex(PRIVATE_B), &hex(PUBLIC_B)), Some(record));
        // Another private key, or a changed byte anywhere: nothing.
        assert_eq!(open(&blob, &[0x11; 32], &hex(PUBLIC_B)), None);
        for i in [0, 8, 40, 73, 100, BLOB_LEN - 1] {
            let mut bad = blob;
            bad[i] ^= 1;
            assert_eq!(open(&bad, &hex(PRIVATE_B), &hex(PUBLIC_B)), None, "byte {i}");
        }
    }

    #[test]
    fn a_recipient_has_to_be_a_point_on_the_curve() {
        let mut rng = Rng::from_seed([7; 32]);
        let record = [0u8; RECORD_LEN];
        assert!(valid_recipient(&hex(PUBLIC_B)));
        let mut off = hex::<65>(PUBLIC_B);
        off[64] ^= 1;
        assert!(!valid_recipient(&off));
        assert!(seal(&record, &off, &mut rng).is_none());
        // A compressed point, or zeros.
        let mut compressed = hex::<65>(PUBLIC_B);
        compressed[0] = 0x02;
        assert!(!valid_recipient(&compressed));
        assert!(seal(&record, &compressed, &mut rng).is_none());
        assert!(seal(&record, &[0; 65], &mut rng).is_none());
    }
}
