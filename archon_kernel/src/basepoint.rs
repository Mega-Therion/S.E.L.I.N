//! Sovereign Identity basepoint seal.
//!
//! The seal binds an identity to a set of governing values with tamper-evidence.
//! It is an HMAC — this gives **integrity/authenticity, not confidentiality**.
//!
//! Hardening over v1: entropy now comes from the OS CSPRNG (`getrandom`), not
//! `hostname:timestamp` (which was brute-forceable by anyone who knew the host
//! and approximate init time). The HMAC key is derived from that entropy via
//! HKDF-SHA256 rather than used raw, and the random salt is stored alongside the
//! seal so it can be re-verified without leaking the governing values.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HKDF `info` label — versions the derivation so future changes stay distinct.
const SEAL_INFO: &[u8] = b"selin-basepoint-seal-v2";

/// Draw 32 bytes from the OS CSPRNG. Returns `Err` if the platform RNG is
/// unavailable rather than silently falling back to something predictable.
pub fn generate_entropy() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| format!("CSPRNG unavailable: {e}"))?;
    Ok(buf)
}

/// Derive the 32-byte seal key from random `salt` and the governing `user_values`
/// via HKDF-SHA256. This is the proper KDF step the v1 seal lacked.
fn derive_seal_key(salt: &[u8], user_values: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), user_values.as_bytes());
    let mut okm = [0u8; 32];
    // expand only fails for absurd output lengths; 32 bytes never does.
    hk.expand(SEAL_INFO, &mut okm)
        .expect("HKDF expand of 32 bytes cannot fail");
    okm
}

/// Produce the hex seal for `user_values` bound to random `salt` entropy.
pub fn generate_basepoint_seal(user_values: &str, salt: &[u8]) -> String {
    let key = derive_seal_key(salt, user_values);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts a 32-byte key");
    mac.update(user_values.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Recompute the seal and compare in constant time. `salt_hex` is the stored
/// hex-encoded salt from `basepoint.json`.
pub fn verify_basepoint_seal(user_values: &str, salt_hex: &str, seal_hex: &str) -> bool {
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    let key = derive_seal_key(&salt, user_values);
    let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
        return false;
    };
    mac.update(user_values.as_bytes());
    let Ok(expected) = hex::decode(seal_hex) else {
        return false;
    };
    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_64_hex_chars() {
        let salt = generate_entropy().unwrap();
        let seal = generate_basepoint_seal("sovereignty,truth", &salt);
        assert_eq!(seal.len(), 64);
        assert!(seal.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn entropy_is_not_constant() {
        // Two draws must differ — proves we're not on a fixed seed.
        assert_ne!(generate_entropy().unwrap(), generate_entropy().unwrap());
    }

    #[test]
    fn verify_roundtrips() {
        let salt = generate_entropy().unwrap();
        let salt_hex = hex::encode(salt);
        let seal = generate_basepoint_seal("a,b,c", &salt);
        assert!(verify_basepoint_seal("a,b,c", &salt_hex, &seal));
    }

    #[test]
    fn verify_rejects_wrong_values() {
        let salt = generate_entropy().unwrap();
        let salt_hex = hex::encode(salt);
        let seal = generate_basepoint_seal("a,b,c", &salt);
        assert!(!verify_basepoint_seal("a,b,X", &salt_hex, &seal));
    }

    #[test]
    fn test_randomness_distribution() {
        // Collect multiple CSPRNG draws and ensure uniqueness and non-zero distribution
        let mut draws = std::collections::HashSet::new();
        for _ in 0..100 {
            let entropy = generate_entropy().expect("entropy generation must succeed");
            assert!(!entropy.iter().all(|&b| b == 0), "entropy cannot be all zeroes");
            assert!(draws.insert(entropy), "entropy draws must be strictly unique");
        }
    }

    #[test]
    fn test_tamper_detection() {
        let salt = generate_entropy().unwrap();
        let salt_hex = hex::encode(salt);
        let seal = generate_basepoint_seal("sovereignty,truth", &salt);

        // 1. Valid seal passes
        assert!(verify_basepoint_seal("sovereignty,truth", &salt_hex, &seal));

        // 2. Tampered values fails
        assert!(!verify_basepoint_seal("sovereignty,falsehood", &salt_hex, &seal));

        // 3. Tampered salt fails
        let mut tampered_salt_bytes = hex::decode(&salt_hex).unwrap();
        tampered_salt_bytes[0] ^= 0xFF;
        let tampered_salt_hex = hex::encode(tampered_salt_bytes);
        assert!(!verify_basepoint_seal("sovereignty,truth", &tampered_salt_hex, &seal));

        // 4. Tampered seal bytes fails
        let mut tampered_seal_bytes = hex::decode(&seal).unwrap();
        let last_idx = tampered_seal_bytes.len() - 1;
        tampered_seal_bytes[last_idx] ^= 0xAA;
        let tampered_seal_hex = hex::encode(tampered_seal_bytes);
        assert!(!verify_basepoint_seal("sovereignty,truth", &salt_hex, &tampered_seal_hex));
    }
}
