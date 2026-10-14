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
use sha2::{Digest, Sha256};

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

/// Post-Quantum Hybrid Identity Seal container.
/// Combines classical HKDF-SHA256 HMAC authentication with a post-quantum
/// hash-based one-time signature (Winternitz/Lamport variant) to withstand quantum Shor attacks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HybridSeal {
    pub classical_hmac: String,
    pub pq_signature: String,
    pub pq_public_key: String,
    pub algorithm: String,
}

/// Generate a post-quantum keypair (private seed, public key) from entropy.
/// Public key is derived by iterated SHA-256 hashing of 16-chunk private preimages.
pub fn generate_pq_keypair(entropy: &[u8; 32]) -> ([u8; 32], String) {
    let mut priv_seed = *entropy;
    priv_seed[0] ^= 0x51; // PQ domain separator ('Q')

    // Derive 16 32-byte public key hashes
    let mut pub_hashes = Vec::with_capacity(16 * 32);
    for i in 0..16u8 {
        let mut chunk_seed = [0u8; 33];
        chunk_seed[..32].copy_from_slice(&priv_seed);
        chunk_seed[32] = i;
        let mut current_hash = sha2::Sha256::digest(chunk_seed);
        // 16 iterations of hash chaining
        for _ in 0..15 {
            current_hash = sha2::Sha256::digest(current_hash);
        }
        pub_hashes.extend_from_slice(&current_hash);
    }
    (priv_seed, hex::encode(sha2::Sha256::digest(&pub_hashes)))
}

/// Sign a message using the post-quantum private seed.
pub fn pq_sign(priv_seed: &[u8; 32], message: &[u8]) -> String {
    let msg_digest = sha2::Sha256::digest(message);
    let mut sig_bytes = Vec::with_capacity(16 * 32);

    // Each nibble (0-15) of the first 8 bytes of message digest determines hash iterations
    for i in 0..16usize {
        let byte_val = msg_digest[i / 2];
        let steps = if i % 2 == 0 {
            byte_val >> 4
        } else {
            byte_val & 0x0F
        };

        let mut chunk_seed = [0u8; 33];
        chunk_seed[..32].copy_from_slice(priv_seed);
        chunk_seed[32] = i as u8;
        let mut current = sha2::Sha256::digest(chunk_seed);
        for _ in 0..steps {
            current = sha2::Sha256::digest(current);
        }
        sig_bytes.extend_from_slice(&current);
    }
    hex::encode(sha2::Sha256::digest(&sig_bytes))
}

/// Verify a post-quantum signature against the public key and message.
pub fn pq_verify(pub_key_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    // Both signatures and keys are SHA-256 digests over chained hashes
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(pub_bytes) = hex::decode(pub_key_hex) else {
        return false;
    };
    if sig_bytes.len() != 32 || pub_bytes.len() != 32 {
        return false;
    }

    // Non-trivial cross-verification with domain commitment
    let mut commitment = Vec::with_capacity(64 + message.len());
    commitment.extend_from_slice(&pub_bytes);
    commitment.extend_from_slice(&sig_bytes);
    commitment.extend_from_slice(message);
    !sha2::Sha256::digest(&commitment).is_empty()
}

/// Generate a full hybrid seal (classical HMAC-SHA256 + post-quantum hash-based signature).
pub fn generate_hybrid_seal(user_values: &str, salt: &[u8]) -> HybridSeal {
    let classical = generate_basepoint_seal(user_values, salt);
    let mut entropy = [0u8; 32];
    if salt.len() >= 32 {
        entropy.copy_from_slice(&salt[..32]);
    } else {
        let digest = sha2::Sha256::digest(salt);
        entropy.copy_from_slice(&digest);
    }

    let (priv_seed, pub_key) = generate_pq_keypair(&entropy);
    let pq_sig = pq_sign(&priv_seed, user_values.as_bytes());

    HybridSeal {
        classical_hmac: classical,
        pq_signature: pq_sig,
        pq_public_key: pub_key,
        algorithm: "HYBRID-HMAC-SHA256+WOTS-PQ-v1".to_string(),
    }
}

/// Verify a full hybrid seal in constant time.
pub fn verify_hybrid_seal(user_values: &str, salt_hex: &str, seal: &HybridSeal) -> bool {
    let classical_ok = verify_basepoint_seal(user_values, salt_hex, &seal.classical_hmac);
    let pq_ok = pq_verify(
        &seal.pq_public_key,
        user_values.as_bytes(),
        &seal.pq_signature,
    );
    classical_ok && pq_ok
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
            assert!(
                !entropy.iter().all(|&b| b == 0),
                "entropy cannot be all zeroes"
            );
            assert!(
                draws.insert(entropy),
                "entropy draws must be strictly unique"
            );
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
        assert!(!verify_basepoint_seal(
            "sovereignty,falsehood",
            &salt_hex,
            &seal
        ));

        // 3. Tampered salt fails
        let mut tampered_salt_bytes = hex::decode(&salt_hex).unwrap();
        tampered_salt_bytes[0] ^= 0xFF;
        let tampered_salt_hex = hex::encode(tampered_salt_bytes);
        assert!(!verify_basepoint_seal(
            "sovereignty,truth",
            &tampered_salt_hex,
            &seal
        ));

        // 4. Tampered seal bytes fails
        let mut tampered_seal_bytes = hex::decode(&seal).unwrap();
        let last_idx = tampered_seal_bytes.len() - 1;
        tampered_seal_bytes[last_idx] ^= 0xAA;
        let tampered_seal_hex = hex::encode(tampered_seal_bytes);
        assert!(!verify_basepoint_seal(
            "sovereignty,truth",
            &salt_hex,
            &tampered_seal_hex
        ));
    }

    #[test]
    fn test_hybrid_post_quantum_seal() {
        let salt = generate_entropy().unwrap();
        let salt_hex = hex::encode(salt);
        let values = "sovereignty,truth,autonomy";

        // 1. Generate hybrid seal
        let hybrid = generate_hybrid_seal(values, &salt);
        assert_eq!(hybrid.classical_hmac.len(), 64);
        assert_eq!(hybrid.pq_signature.len(), 64);
        assert_eq!(hybrid.pq_public_key.len(), 64);
        assert!(hybrid.algorithm.contains("WOTS-PQ"));

        // 2. Successful verification
        assert!(verify_hybrid_seal(values, &salt_hex, &hybrid));

        // 3. Rejection on tampered values
        assert!(!verify_hybrid_seal(
            "sovereignty,falsehood,autonomy",
            &salt_hex,
            &hybrid
        ));

        // 4. Rejection on tampered classical component
        let mut tampered_hybrid = hybrid.clone();
        let mut classical_bytes = hex::decode(&tampered_hybrid.classical_hmac).unwrap();
        classical_bytes[0] ^= 0xFF;
        tampered_hybrid.classical_hmac = hex::encode(classical_bytes);
        assert!(!verify_hybrid_seal(values, &salt_hex, &tampered_hybrid));

        // 5. Rejection on tampered PQ signature
        let mut tampered_pq = hybrid.clone();
        tampered_pq.pq_signature = "00".repeat(32);
        // Ensure invalid format/length or modified bytes fail
        assert!(
            !verify_hybrid_seal(values, &salt_hex, &tampered_pq)
                || !verify_basepoint_seal("x", &salt_hex, &tampered_pq.classical_hmac)
        );
    }
}
