//! SAMO epistemic envelopes (spec §3.2, §6.4).
//!
//! Every claim exchanged over the mesh travels in a typed epistemic container:
//! a [`Claim`] carrying its content address, its position on the certainty
//! lattice (`open < conjectured < axiomatic < derived < proven`), its §3.1
//! memory tier, its provenance, and — when a deterministic verifier has run —
//! the hash of the verifier's witness receipt.
//!
//! - **Monadic bind law (§3.2):** composing claims yields at most the *minimum*
//!   certainty and the *most restrictive* memory tier among the inputs, and
//!   clears the witness. The only way back up is [`Claim::promote_with_witness`]:
//!   an independent deterministic verifier executes and emits a new receipt.
//! - **Falsification certificates (§6.4):** a peer that falsifies a claim issues
//!   a signed [`FalsificationCertificate`] — artifact hash, minimal failing
//!   input, reproducible witness hash, zero private operator data. Subscribers
//!   index verified certificates into Tier 3 (Quarantine) memory.
//!
//! Claims and certificates travel on the existing RYTT canonical envelope
//! surface (`rytt_seal::seal_verdict` / `open_verdict`): JCS-canonical bytes,
//! Ed25519-signed, vocabulary allow-listed. Opening an envelope re-derives the
//! content address from the payload, so a re-signed forgery with a stale hash
//! is still rejected.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::memory_tiers::MemoryTier;
use crate::rytt_seal::{self, SealError, WireVerdict};

const CLAIM_DOMAIN: &[u8] = b"selin-samo-claim-v1";
const CERT_DOMAIN: &[u8] = b"selin-samo-xcert-v1";

/// Certainty lattice (spec §3.2, after `4leibniz/Leibniz/Epistemic.lean`).
/// Declaration order *is* the lattice order: `Open` is the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    Open,
    Conjectured,
    Axiomatic,
    Derived,
    Proven,
}

#[derive(Debug)]
pub enum SamoError {
    Seal(SealError),
    Json(String),
    BadSignature,
    BadKey,
    HashMismatch,
    WitnessMismatch,
    EmptyComposition,
    UntrustedIssuer,
}

impl std::fmt::Display for SamoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seal(e) => write!(f, "{e}"),
            Self::Json(m) => write!(f, "JSON: {m}"),
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::BadKey => write!(f, "malformed public key"),
            Self::HashMismatch => {
                write!(f, "artifact hash does not match the payload content")
            }
            Self::WitnessMismatch => {
                write!(f, "witness hash does not match the certificate body")
            }
            Self::EmptyComposition => write!(f, "cannot compose zero claims"),
            Self::UntrustedIssuer => {
                write!(f, "certificate issuer is not in the trusted issuer set")
            }
        }
    }
}
impl std::error::Error for SamoError {}
impl From<SealError> for SamoError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

/// Content address of a payload: hex SHA-256 over its JCS-canonical bytes,
/// domain-separated. This is the index key used by content-addressed
/// deduplication (§3.2) and by the memory partition (§3.1).
pub fn content_hash(payload: &Value) -> Result<String, SamoError> {
    let c = rytt_seal::canonical(payload)?;
    let mut h = Sha256::new();
    h.update(CLAIM_DOMAIN);
    h.update(c.as_bytes());
    Ok(hex::encode(h.finalize()))
}

fn key_from_hex(h: &str) -> Result<VerifyingKey, SamoError> {
    let b: [u8; 32] = hex::decode(h)
        .map_err(|_| SamoError::BadKey)?
        .try_into()
        .map_err(|_| SamoError::BadKey)?;
    VerifyingKey::from_bytes(&b).map_err(|_| SamoError::BadKey)
}

/// An epistemic-tiered claim: the mesh's unit of exchange (spec §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// Content address of `payload` (see [`content_hash`]).
    pub artifact_hash: String,
    pub payload: Value,
    pub certainty: Certainty,
    pub memory_tier: MemoryTier,
    /// Issuer fingerprint (hex of the issuer's Ed25519 public key hash; see
    /// `rytt_seal::fingerprint` for the canonical 128-bit form).
    pub provenance: String,
    /// Hash of the deterministic verifier's witness receipt, if one has run.
    pub witness_hash: Option<String>,
    /// True when some checks could not run; such claims are fenced as
    /// Conditional and can never be presented as fully verified (§2, §3.1).
    pub checks_unavailable: bool,
}

impl Claim {
    /// Wrap a payload as a claim issued by `provenance`. A fresh claim has no
    /// witness: nothing has verified it yet.
    pub fn new(
        payload: Value,
        certainty: Certainty,
        memory_tier: MemoryTier,
        provenance: &str,
    ) -> Result<Self, SamoError> {
        let artifact_hash = content_hash(&payload)?;
        Ok(Self {
            artifact_hash,
            payload,
            certainty,
            memory_tier,
            provenance: provenance.to_string(),
            witness_hash: None,
            checks_unavailable: false,
        })
    }

    /// The monadic bind (§3.2): compose `inputs` into a new claim over
    /// `payload`. The result takes the minimum certainty and the most
    /// restrictive memory tier among the inputs, inherits any
    /// `checks_unavailable` fencing, and clears the witness — aggregation is
    /// not verification.
    pub fn combine(inputs: &[&Claim], payload: Value, provenance: &str) -> Result<Self, SamoError> {
        let first = inputs.first().ok_or(SamoError::EmptyComposition)?;
        let certainty = inputs
            .iter()
            .map(|c| c.certainty)
            .min()
            .unwrap_or(first.certainty);
        let memory_tier = inputs
            .iter()
            .map(|c| c.memory_tier)
            .fold(MemoryTier::Canon, MemoryTier::most_restrictive);
        let checks_unavailable = inputs.iter().any(|c| c.checks_unavailable);
        let mut out = Self::new(payload, certainty, memory_tier, provenance)?;
        out.checks_unavailable = checks_unavailable;
        Ok(out)
    }

    /// Raise certainty after an independent deterministic verifier has run and
    /// emitted a witness receipt (§3.2). Never lowers certainty; the witness
    /// hash is recorded so the promotion is auditable.
    pub fn promote_with_witness(mut self, target: Certainty, witness_hash: &str) -> Self {
        if target > self.certainty {
            self.certainty = target;
        }
        self.witness_hash = Some(witness_hash.to_string());
        self
    }

    /// Check the content address still matches the payload.
    pub fn verify_content_hash(&self) -> Result<(), SamoError> {
        if content_hash(&self.payload)? != self.artifact_hash {
            return Err(SamoError::HashMismatch);
        }
        Ok(())
    }
}

/// A signed `[X]` falsification / counterexample certificate (spec §6.4).
/// Compact and free of private operator data: artifact hash, the minimal
/// failing input or condition, and a reproducible witness hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsificationCertificate {
    /// Content address of the falsified claim.
    pub artifact_hash: String,
    /// Minimal failing input / condition that reproduces the falsification.
    pub failing_input: Value,
    /// Hex SHA-256 over the canonical certificate body (see [`Self::verify`]).
    pub witness_hash: String,
    /// Hex Ed25519 public key of the issuing peer.
    pub issuer: String,
    /// Hex Ed25519 signature over the canonical certificate body.
    pub signature: String,
}

impl FalsificationCertificate {
    /// The unsigned body whose canonical bytes are hashed and signed.
    fn body(&self) -> Value {
        json!({
            "artifact_hash": self.artifact_hash,
            "failing_input": self.failing_input,
            "issuer": self.issuer,
        })
    }

    fn witness_for(body: &Value) -> Result<String, SamoError> {
        let c = rytt_seal::canonical(body)?;
        let mut h = Sha256::new();
        h.update(CERT_DOMAIN);
        h.update(c.as_bytes());
        Ok(hex::encode(h.finalize()))
    }

    /// Issue a certificate: hash the body into the witness, then sign the same
    /// canonical bytes with the issuer's key.
    pub fn issue(
        key: &SigningKey,
        artifact_hash: &str,
        failing_input: Value,
    ) -> Result<Self, SamoError> {
        let mut cert = Self {
            artifact_hash: artifact_hash.to_string(),
            failing_input,
            witness_hash: String::new(),
            issuer: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let body = cert.body();
        cert.witness_hash = Self::witness_for(&body)?;
        let c = rytt_seal::canonical(&body)?;
        let mut msg = CERT_DOMAIN.to_vec();
        msg.extend_from_slice(c.as_bytes());
        cert.signature = hex::encode(key.sign(&msg).to_bytes());
        Ok(cert)
    }

    /// Verify the witness hash recomputes from the body and the issuer's
    /// signature covers it. Any mismatch rejects the certificate.
    pub fn verify(&self) -> Result<(), SamoError> {
        let body = self.body();
        if Self::witness_for(&body)? != self.witness_hash {
            return Err(SamoError::WitnessMismatch);
        }
        let pk = key_from_hex(&self.issuer)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| SamoError::BadSignature)?
            .try_into()
            .map_err(|_| SamoError::BadSignature)?;
        let c = rytt_seal::canonical(&body)?;
        let mut msg = CERT_DOMAIN.to_vec();
        msg.extend_from_slice(c.as_bytes());
        pk.verify(&msg, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| SamoError::BadSignature)?;
        Ok(())
    }

    /// Issue a certificate from a raw 32-byte seed. Convenience for callers
    /// (like the `selin` CLI) that hold seeds rather than `ed25519_dalek` keys.
    pub fn issue_from_seed(
        seed: [u8; 32],
        artifact_hash: &str,
        failing_input: Value,
    ) -> Result<Self, SamoError> {
        Self::issue(&SigningKey::from_bytes(&seed), artifact_hash, failing_input)
    }

    /// Verify the certificate *and* require its issuer to be in the
    /// evaluator's configured trusted-issuer set (hex public keys).
    ///
    /// [`Self::verify`] alone only proves the certificate is self-consistent:
    /// anyone can mint a key, choose an artifact hash and failing input, and
    /// sign — `issue` takes all of them from the caller. A self-signed
    /// certificate from an unconfigured key must never, by itself, demote a
    /// record, so every trust decision (e.g. demotion into Quarantine) goes
    /// through this check. Fail-closed: an empty trusted set trusts nobody.
    pub fn verify_with_trusted_issuers(&self, trusted_issuers: &[String]) -> Result<(), SamoError> {
        self.verify()?;
        if !trusted_issuers.iter().any(|k| k == &self.issuer) {
            return Err(SamoError::UntrustedIssuer);
        }
        Ok(())
    }
}

/// Seal a claim into a RYTT wire envelope (signed, canonical, allow-listed).
pub fn seal_claim(key: &SigningKey, claim: &Claim) -> Result<WireVerdict, SamoError> {
    claim.verify_content_hash()?;
    let v = serde_json::to_value(claim).map_err(|e| SamoError::Json(e.to_string()))?;
    Ok(rytt_seal::seal_verdict(key, &v)?)
}

/// Open a RYTT wire envelope back into a claim. Beyond the envelope's own
/// checks, the content address is re-derived from the payload.
pub fn open_claim(wire: &WireVerdict, allow: &[String]) -> Result<Claim, SamoError> {
    let v = rytt_seal::open_verdict(wire, allow)?;
    let claim: Claim = serde_json::from_value(v).map_err(|e| SamoError::Json(e.to_string()))?;
    claim.verify_content_hash()?;
    Ok(claim)
}

/// Seal a falsification certificate into a RYTT wire envelope. The certificate
/// is verified first: an invalid certificate is never put on the wire.
pub fn seal_certificate(
    key: &SigningKey,
    cert: &FalsificationCertificate,
) -> Result<WireVerdict, SamoError> {
    cert.verify()?;
    let v = serde_json::to_value(cert).map_err(|e| SamoError::Json(e.to_string()))?;
    Ok(rytt_seal::seal_verdict(key, &v)?)
}

/// Open a RYTT wire envelope back into a falsification certificate and verify
/// the certificate itself (witness hash + issuer signature).
pub fn open_certificate(
    wire: &WireVerdict,
    allow: &[String],
) -> Result<FalsificationCertificate, SamoError> {
    let v = rytt_seal::open_verdict(wire, allow)?;
    let cert: FalsificationCertificate =
        serde_json::from_value(v).map_err(|e| SamoError::Json(e.to_string()))?;
    cert.verify()?;
    Ok(cert)
}

/// Open a wire envelope into a falsification certificate and verify it
/// against a configured trusted-issuer set (see
/// [`FalsificationCertificate::verify_with_trusted_issuers`]). This is the
/// open path for certificates that will be *acted on* (e.g. demotions).
pub fn open_certificate_with_trusted_issuers(
    wire: &WireVerdict,
    allow: &[String],
    trusted_issuers: &[String],
) -> Result<FalsificationCertificate, SamoError> {
    let cert = open_certificate(wire, allow)?;
    cert.verify_with_trusted_issuers(trusted_issuers)?;
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rytt_seal::{default_allow_list, NodeIdentity};

    fn claim(payload: Value, certainty: Certainty, tier: MemoryTier) -> Claim {
        Claim::new(payload, certainty, tier, "issuer-fp").unwrap()
    }

    #[test]
    fn certainty_lattice_orders_as_the_spec_requires() {
        assert!(Certainty::Open < Certainty::Conjectured);
        assert!(Certainty::Conjectured < Certainty::Axiomatic);
        assert!(Certainty::Axiomatic < Certainty::Derived);
        assert!(Certainty::Derived < Certainty::Proven);
    }

    #[test]
    fn bind_takes_the_minimum_certainty_and_clears_the_witness() {
        let proven = claim(json!({"a": 1}), Certainty::Proven, MemoryTier::Canon)
            .promote_with_witness(Certainty::Proven, "witness-1");
        let guess = claim(json!({"b": 2}), Certainty::Conjectured, MemoryTier::Sandbox);
        let out = Claim::combine(&[&proven, &guess], json!({"c": 3}), "combiner").unwrap();
        assert_eq!(out.certainty, Certainty::Conjectured);
        assert_eq!(out.memory_tier, MemoryTier::Sandbox);
        assert_eq!(out.witness_hash, None, "aggregation is not verification");
    }

    #[test]
    fn bind_with_a_quarantined_input_stays_quarantined() {
        let ok = claim(json!({"a": 1}), Certainty::Derived, MemoryTier::Conditional);
        let bad = claim(json!({"b": 2}), Certainty::Derived, MemoryTier::Quarantine);
        let out = Claim::combine(&[&ok, &bad], json!({"c": 3}), "combiner").unwrap();
        assert_eq!(out.memory_tier, MemoryTier::Quarantine);
    }

    #[test]
    fn bind_inherits_checks_unavailable_fencing() {
        let mut fenced = claim(json!({"a": 1}), Certainty::Derived, MemoryTier::Conditional);
        fenced.checks_unavailable = true;
        let plain = claim(json!({"b": 2}), Certainty::Derived, MemoryTier::Conditional);
        let out = Claim::combine(&[&fenced, &plain], json!({"c": 3}), "combiner").unwrap();
        assert!(out.checks_unavailable);
    }

    #[test]
    fn promotion_requires_a_witness_and_never_lowers() {
        let c = claim(json!({"a": 1}), Certainty::Conjectured, MemoryTier::Sandbox);
        let raised = c.clone().promote_with_witness(Certainty::Derived, "w-9");
        assert_eq!(raised.certainty, Certainty::Derived);
        assert_eq!(raised.witness_hash.as_deref(), Some("w-9"));
        let not_lowered = raised.promote_with_witness(Certainty::Open, "w-10");
        assert_eq!(not_lowered.certainty, Certainty::Derived);
    }

    #[test]
    fn a_certificate_verifies_and_tampering_breaks_it() {
        let id = NodeIdentity::generate().unwrap();
        let target = claim(json!({"x": 1}), Certainty::Derived, MemoryTier::Conditional);
        let cert =
            FalsificationCertificate::issue(&id.signing, &target.artifact_hash, json!({"x": 0}))
                .unwrap();
        cert.verify().unwrap();

        let mut forged = cert.clone();
        forged.failing_input = json!({"x": 999});
        assert!(matches!(forged.verify(), Err(SamoError::WitnessMismatch)));

        let mut resigned = cert.clone();
        let other = NodeIdentity::generate().unwrap();
        resigned.issuer = hex::encode(other.signing.verifying_key().to_bytes());
        assert!(resigned.verify().is_err());
    }

    #[test]
    fn regression_self_signed_certificate_from_untrusted_issuer_is_rejected() {
        // Regression (finding 3): anyone can call `issue` with a key they
        // minted, an artifact hash they chose, and a failing input they
        // invented, and the result passes plain `verify()` — it is
        // self-consistent. Trust decisions must additionally require the
        // issuer to be in the configured trusted set.
        let attacker = NodeIdentity::generate().unwrap();
        let cert =
            FalsificationCertificate::issue(&attacker.signing, "victim-artifact", json!({"x": 0}))
                .unwrap();
        cert.verify().unwrap(); // self-consistent — that alone proves nothing
        let trusted = vec![hex::encode(
            NodeIdentity::generate()
                .unwrap()
                .signing
                .verifying_key()
                .to_bytes(),
        )];
        assert!(matches!(
            cert.verify_with_trusted_issuers(&trusted),
            Err(SamoError::UntrustedIssuer)
        ));
        // An empty trusted set trusts nobody (fail closed).
        assert!(matches!(
            cert.verify_with_trusted_issuers(&[]),
            Err(SamoError::UntrustedIssuer)
        ));

        // Positive path: the same check passes for a configured issuer, and
        // the trusted open path round-trips its certificate.
        let authority = NodeIdentity::generate().unwrap();
        let authority_key = hex::encode(authority.signing.verifying_key().to_bytes());
        let good =
            FalsificationCertificate::issue(&authority.signing, "ab12", json!({"input": "0"}))
                .unwrap();
        good.verify_with_trusted_issuers(&[authority_key]).unwrap();
        let allow = default_allow_list().unwrap();
        let wire = seal_certificate(&authority.signing, &good).unwrap();
        let trusted = vec![hex::encode(authority.signing.verifying_key().to_bytes())];
        let back = open_certificate_with_trusted_issuers(&wire, &allow, &trusted).unwrap();
        assert_eq!(back.artifact_hash, "ab12");
        assert!(matches!(
            open_certificate_with_trusted_issuers(&wire, &allow, &[]),
            Err(SamoError::UntrustedIssuer)
        ));
    }

    #[test]
    fn sealed_claims_round_trip_through_the_rytt_envelope() {
        let id = NodeIdentity::generate().unwrap();
        let allow = default_allow_list().unwrap();
        let c = claim(
            json!({"theorem": "t"}),
            Certainty::Proven,
            MemoryTier::Canon,
        );
        let wire = seal_claim(&id.signing, &c).unwrap();
        let back = open_claim(&wire, &allow).unwrap();
        assert_eq!(back.artifact_hash, c.artifact_hash);
        assert_eq!(back.certainty, Certainty::Proven);
        assert_eq!(back.memory_tier, MemoryTier::Canon);
    }

    #[test]
    fn a_resigned_claim_with_a_stale_hash_is_rejected() {
        // The envelope signature is honestly made by the key holder — but over
        // a payload whose content address was not recomputed. Opening must
        // still reject: the hash is the identity of the claim.
        let id = NodeIdentity::generate().unwrap();
        let allow = default_allow_list().unwrap();
        let mut c = claim(json!({"v": 1}), Certainty::Derived, MemoryTier::Conditional);
        c.payload = json!({"v": 2}); // payload changed, artifact_hash now stale
        let v = serde_json::to_value(&c).unwrap();
        let wire = rytt_seal::seal_verdict(&id.signing, &v).unwrap();
        assert!(matches!(
            open_claim(&wire, &allow),
            Err(SamoError::HashMismatch)
        ));
    }

    #[test]
    fn sealed_certificates_round_trip_and_verify_on_open() {
        let id = NodeIdentity::generate().unwrap();
        let allow = default_allow_list().unwrap();
        let cert =
            FalsificationCertificate::issue(&id.signing, "ab12", json!({"input": "0"})).unwrap();
        let wire = seal_certificate(&id.signing, &cert).unwrap();
        let back = open_certificate(&wire, &allow).unwrap();
        assert_eq!(back.artifact_hash, "ab12");
        assert_eq!(back.witness_hash, cert.witness_hash);
    }

    #[test]
    fn combining_zero_claims_is_an_error() {
        assert!(matches!(
            Claim::combine(&[], json!({}), "nobody"),
            Err(SamoError::EmptyComposition)
        ));
    }
}
