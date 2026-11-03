//! Random bytes for the TPM session (nonces, the ephemeral ECDH key of the
//! salt). Not only from the TPM: whoever sits on the TPM bus would then
//! choose them. The seed mixes the CPU's RDSEED and RDRAND, the time
//! stamp counter and what the caller adds (the TPM's GetRandom, the
//! firmware's EFI_RNG_PROTOCOL) through SHA-256; output is HMAC-SHA256 of
//! a counter under that seed.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub struct Rng {
    key: [u8; 32],
    counter: u64,
    /// Whether the CPU contributed (RDSEED or RDRAND worked).
    pub cpu: bool,
}

#[cfg(target_arch = "x86_64")]
mod cpu {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step};

    #[target_feature(enable = "rdseed")]
    fn rdseed() -> Option<u64> {
        let mut v = 0;
        // A few tries: RDSEED may run dry for a moment.
        for _ in 0..32 {
            if _rdseed64_step(&mut v) == 1 {
                return Some(v);
            }
        }
        None
    }

    #[target_feature(enable = "rdrand")]
    fn rdrand() -> Option<u64> {
        let mut v = 0;
        for _ in 0..32 {
            if _rdrand64_step(&mut v) == 1 {
                return Some(v);
            }
        }
        None
    }

    /// 64 bits from RDSEED, or RDRAND, if the CPU has them.
    pub fn random() -> Option<u64> {
        // SAFETY: CPUID is always there on x86_64; each instruction only
        // after CPUID says the CPU has it.
        unsafe {
            if __cpuid_count(7, 0).ebx & (1 << 18) != 0
                && let Some(v) = rdseed()
            {
                return Some(v);
            }
            if __cpuid(1).ecx & (1 << 30) != 0 { rdrand() } else { None }
        }
    }

    pub fn tsc() -> u64 {
        // SAFETY: RDTSC has no preconditions.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod cpu {
    pub fn random() -> Option<u64> {
        None
    }
    pub fn tsc() -> u64 {
        0
    }
}

impl Rng {
    /// Seeded from the CPU and `extra` (other sources; any may be empty).
    pub fn new(extra: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update(b"bt-kb-dxe rng v1");
        let mut cpu = false;
        for _ in 0..8 {
            if let Some(v) = cpu::random() {
                h.update(v.to_le_bytes());
                cpu = true;
            }
            h.update(cpu::tsc().to_le_bytes());
        }
        for part in extra {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        Self { key: h.finalize().into(), counter: 0, cpu }
    }

    /// Deterministic, for tests.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: seed, counter: 0, cpu: false }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.counter += 1;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC takes any key size");
            mac.update(&self.counter.to_be_bytes());
            let block = mac.finalize().into_bytes();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_output_is_stable_and_never_repeats() {
        let mut a = Rng::from_seed([7; 32]);
        let mut b = Rng::from_seed([7; 32]);
        let (x, y): ([u8; 40], [u8; 40]) = (a.array(), a.array());
        assert_eq!(x, b.array::<40>());
        assert_ne!(x, y);
        assert_ne!(x[..32], x[32..]);
    }

    #[test]
    fn new_mixes_its_sources() {
        let (mut a, mut b) = (Rng::new(&[b"one"]), Rng::new(&[b"two"]));
        assert_ne!(a.array::<32>(), b.array::<32>());
    }
}
