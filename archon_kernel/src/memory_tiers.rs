//! Four-tier monotonic memory partition (SAMO spec §3.1).
//!
//! Every local memory record is tagged with exactly one provenance tier:
//!
//! - **Canon** — mechanically verified artifacts backed by reproducible receipts.
//!   A monotonic ratchet: a record enters Canon only via independent deterministic
//!   verification plus a multi-substrate quorum ([`CANON_QUORUM`]) of *signed*
//!   attestations (see [`CanonAttestation`]), and leaves it only when a
//!   falsification certificate from a *trusted* issuer demotes it.
//! - **Conditional** — partially verified artifacts, explicitly fenced with
//!   coverage bounds; `checks_unavailable` is a first-class flag and blocks Canon.
//! - **Sandbox** — unverified outputs and cold-start proposals. Ephemeral working
//!   context; strictly barred from promoting directly into Canon.
//! - **Quarantine** — refuted claims and reproducible counterexamples. An
//!   append-only negative-knowledge cache: records are never silently deleted,
//!   and are co-retrieved as explicit regression warnings.
//!
//! [`MEMORY_ARTIFACTS_DDL`] is the SQL form of the same partition, applied to the
//! node's local Myelin store by the `selin` CLI (`cli/src/memory.rs`) so the
//! on-disk layout and this in-memory layout cannot drift apart.
//!
//! Evidence discipline: nothing in this module accepts a bare caller-supplied
//! witness string or quorum count. Canon admission requires
//! [`CanonAttestation`]s — Ed25519 signatures over the record's own hash —
//! the quorum is the count of *distinct verified* attesters, and the stored
//! witness hash is recomputed here from the record hash and the verified
//! attester set.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::samo_envelope::{FalsificationCertificate, SamoError};

/// Independent substrates that must attest before a record may enter Canon.
pub const CANON_QUORUM: usize = 2;

const CANON_ATTESTATION_DOMAIN: &[u8] = b"selin-canon-attestation-v1";
const CANON_WITNESS_DOMAIN: &[u8] = b"selin-canon-witness-v1";

/// SQL schema for the four-tier partition in the local Myelin (SQLCipher) store.
pub const MEMORY_ARTIFACTS_DDL: &str = "\
CREATE TABLE IF NOT EXISTS memory_artifacts (
    artifact_hash TEXT PRIMARY KEY,
    tier TEXT NOT NULL CHECK (tier IN ('canon', 'conditional', 'sandbox', 'quarantine')),
    payload TEXT NOT NULL,
    witness_hash TEXT,
    checks_unavailable INTEGER NOT NULL DEFAULT 0,
    coverage TEXT,
    created_at TEXT NOT NULL
);";

/// One of the four disjoint provenance tiers of SAMO spec §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    Canon,
    Conditional,
    Sandbox,
    Quarantine,
}

impl MemoryTier {
    /// Stable storage name (matches the SQL `CHECK` constraint above).
    pub fn name(self) -> &'static str {
        match self {
            Self::Canon => "canon",
            Self::Conditional => "conditional",
            Self::Sandbox => "sandbox",
            Self::Quarantine => "quarantine",
        }
    }

    /// Parse a storage name back into a tier.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "canon" => Some(Self::Canon),
            "conditional" => Some(Self::Conditional),
            "sandbox" => Some(Self::Sandbox),
            "quarantine" => Some(Self::Quarantine),
            _ => None,
        }
    }

    /// Restrictiveness for the monadic bind law (§3.2): a composition lands in
    /// the most restrictive tier among its inputs, so unverified or refuted
    /// inputs can never be laundered into Canon by aggregation.
    pub fn restrictiveness(self) -> u8 {
        match self {
            Self::Canon => 0,
            Self::Conditional => 1,
            Self::Sandbox => 2,
            Self::Quarantine => 3,
        }
    }

    /// The more restrictive of two tiers.
    pub fn most_restrictive(a: Self, b: Self) -> Self {
        if a.restrictiveness() >= b.restrictiveness() {
            a
        } else {
            b
        }
    }
}

/// A signed attestation that one independent substrate verified the record
/// with this `artifact_hash`. The signature covers the artifact hash under a
/// domain separator; an attestation for one record proves nothing about any
/// other, and the same attester signing twice still counts once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonAttestation {
    /// Hex Ed25519 public key of the attesting substrate.
    pub attester: String,
    /// Hex Ed25519 signature over the attested record's artifact hash.
    pub signature: String,
}

/// The exact message an attester signs for a record.
pub fn canon_attestation_message(artifact_hash: &str) -> Vec<u8> {
    let mut msg = CANON_ATTESTATION_DOMAIN.to_vec();
    msg.push(0x1f);
    msg.extend_from_slice(artifact_hash.as_bytes());
    msg
}

/// Produce an attestation as a verifying substrate would.
pub fn sign_canon_attestation(key: &SigningKey, artifact_hash: &str) -> CanonAttestation {
    CanonAttestation {
        attester: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(key.sign(&canon_attestation_message(artifact_hash)).to_bytes()),
    }
}

/// Produce an attestation from a raw 32-byte seed. Convenience for callers
/// (like the `selin` CLI) that hold seeds rather than `ed25519_dalek` keys.
pub fn attestation_from_seed(seed: [u8; 32], artifact_hash: &str) -> CanonAttestation {
    sign_canon_attestation(&SigningKey::from_bytes(&seed), artifact_hash)
}

/// The witness hash stored on a Canon record: recomputed from the record's
/// own hash and the *sorted set of verified attesters* — never supplied by
/// the caller.
pub fn canon_witness_hash(artifact_hash: &str, attesters: &BTreeSet<String>) -> String {
    let mut h = Sha256::new();
    h.update(CANON_WITNESS_DOMAIN);
    h.update(artifact_hash.as_bytes());
    for a in attesters {
        h.update([0x1f]);
        h.update(a.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Verify every attestation against the record hash and return the set of
/// distinct attesters whose signatures actually verify. Any malformed or
/// non-verifying attestation is an error (fail closed), not a skipped vote.
fn verified_attesters(
    artifact_hash: &str,
    attestations: &[CanonAttestation],
) -> Result<BTreeSet<String>, MemoryError> {
    let mut out = BTreeSet::new();
    for att in attestations {
        let key_bytes: [u8; 32] = hex::decode(&att.attester)
            .map_err(|_| MemoryError::InvalidAttestation("attester is not hex".into()))?
            .try_into()
            .map_err(|_| MemoryError::InvalidAttestation("attester key is not 32 bytes".into()))?;
        let pk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| MemoryError::InvalidAttestation("attester key is invalid".into()))?;
        let sig_bytes: [u8; 64] = hex::decode(&att.signature)
            .map_err(|_| MemoryError::InvalidAttestation("signature is not hex".into()))?
            .try_into()
            .map_err(|_| MemoryError::InvalidAttestation("signature is not 64 bytes".into()))?;
        pk.verify(
            &canon_attestation_message(artifact_hash),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| {
            MemoryError::InvalidAttestation(
                "attestation signature does not verify for this record".into(),
            )
        })?;
        out.insert(att.attester.clone());
    }
    Ok(out)
}

/// Check the Canon evidence rule for a record and derive its witness hash:
/// at least one verified attestation for any verified admission, fully
/// available checks plus [`CANON_QUORUM`] distinct verified attesters for
/// Canon itself.
fn canon_evidence(
    record: &MemoryRecord,
    attestations: &[CanonAttestation],
) -> Result<String, MemoryError> {
    let attesters = verified_attesters(&record.artifact_hash, attestations)?;
    if attesters.is_empty() {
        return Err(MemoryError::CanonNeedsWitness);
    }
    if record.tier == MemoryTier::Canon {
        if record.checks_unavailable {
            return Err(MemoryError::ChecksUnavailable);
        }
        if attesters.len() < CANON_QUORUM {
            return Err(MemoryError::CanonNeedsQuorum {
                got: attesters.len(),
            });
        }
    }
    Ok(canon_witness_hash(&record.artifact_hash, &attesters))
}

/// One artifact held in the local memory partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// Content address: hex SHA-256 of the canonical payload (see `samo_envelope`).
    pub artifact_hash: String,
    pub tier: MemoryTier,
    pub payload: Value,
    /// Hash of the deterministic verification receipt that supports this tier.
    pub witness_hash: Option<String>,
    /// First-class "some checks could not run" flag (§2 Tier A rule 3). A record
    /// with unavailable checks can never enter Canon.
    pub checks_unavailable: bool,
    /// Coverage bound for Conditional records (what was *not* checked).
    pub coverage: Option<String>,
}

#[derive(Debug)]
pub enum MemoryError {
    NotFound(String),
    Duplicate(String),
    CanonNeedsWitness,
    CanonNeedsQuorum { got: usize },
    ChecksUnavailable,
    SandboxCannotJumpToCanon,
    QuarantineAppendOnly,
    RemovalRefused(MemoryTier),
    CertificateInvalid(String),
    CertificateForOtherArtifact { expected: String, got: String },
    InvalidAttestation(String),
    UntrustedCertificateIssuer,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(h) => write!(f, "no memory record for artifact {h}"),
            Self::Duplicate(h) => write!(f, "artifact {h} is already in memory"),
            Self::CanonNeedsWitness => {
                write!(f, "Canon requires a deterministic verification witness")
            }
            Self::CanonNeedsQuorum { got } => write!(
                f,
                "Canon requires a quorum of {CANON_QUORUM} independent substrates, got {got}"
            ),
            Self::ChecksUnavailable => {
                write!(f, "record has unavailable checks and cannot enter Canon")
            }
            Self::SandboxCannotJumpToCanon => {
                write!(
                    f,
                    "Sandbox records must pass through Conditional before Canon"
                )
            }
            Self::QuarantineAppendOnly => {
                write!(f, "Quarantine is append-only; records are never deleted")
            }
            Self::RemovalRefused(t) => {
                write!(f, "records in tier {} cannot be removed", t.name())
            }
            Self::CertificateInvalid(m) => write!(f, "falsification certificate invalid: {m}"),
            Self::CertificateForOtherArtifact { expected, got } => {
                write!(f, "certificate is for artifact {got}, not {expected}")
            }
            Self::InvalidAttestation(m) => write!(f, "canon attestation invalid: {m}"),
            Self::UntrustedCertificateIssuer => {
                write!(f, "falsification certificate issuer is not trusted")
            }
        }
    }
}
impl std::error::Error for MemoryError {}

/// The local four-tier memory store. In-memory here; the `selin` CLI persists
/// the identical partition to the Myelin SQLCipher store via
/// [`MEMORY_ARTIFACTS_DDL`].
#[derive(Debug, Default)]
pub struct MemoryStore {
    records: HashMap<String, MemoryRecord>,
    /// Artifact hashes in the order they entered Quarantine. Append-only.
    quarantine_log: Vec<String>,
    /// Configured hex public keys whose falsification certificates may demote
    /// records. Empty by default: an unconfigured store trusts no issuer
    /// (fail closed).
    trusted_falsification_issuers: HashSet<String>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a falsification-certificate issuer as trusted for demotions
    /// (hex Ed25519 public key). Certificates from any other issuer — however
    /// self-consistent — demote nothing in this store.
    pub fn trust_falsification_issuer(&mut self, issuer_hex: &str) {
        self.trusted_falsification_issuers
            .insert(issuer_hex.to_string());
    }

    /// Insert an unverified or partially verified record (Sandbox, Conditional,
    /// or Quarantine). Canon is refused here: use [`MemoryStore::insert_verified`].
    pub fn insert(&mut self, record: MemoryRecord) -> Result<(), MemoryError> {
        if record.tier == MemoryTier::Canon {
            return Err(MemoryError::CanonNeedsWitness);
        }
        self.insert_inner(record)
    }

    /// Insert a record backed by signed verification attestations. The
    /// witness hash is recomputed from the record and the verified attester
    /// set; Canon additionally requires a quorum of [`CANON_QUORUM`] distinct
    /// verified attesters and fully available checks.
    pub fn insert_verified(
        &mut self,
        mut record: MemoryRecord,
        attestations: &[CanonAttestation],
    ) -> Result<(), MemoryError> {
        let witness = canon_evidence(&record, attestations)?;
        record.witness_hash = Some(witness);
        self.insert_inner(record)
    }

    fn insert_inner(&mut self, record: MemoryRecord) -> Result<(), MemoryError> {
        if self.records.contains_key(&record.artifact_hash) {
            return Err(MemoryError::Duplicate(record.artifact_hash.clone()));
        }
        if record.tier == MemoryTier::Quarantine {
            self.quarantine_log.push(record.artifact_hash.clone());
        }
        self.records.insert(record.artifact_hash.clone(), record);
        Ok(())
    }

    /// Promote one step: Sandbox → Conditional → Canon. Each step requires
    /// fresh signed attestations; the step into Canon additionally requires
    /// the quorum of distinct verified attesters and fully available checks.
    /// Canon and Quarantine never promote.
    pub fn promote(
        &mut self,
        artifact_hash: &str,
        attestations: &[CanonAttestation],
    ) -> Result<MemoryTier, MemoryError> {
        let current = self
            .tier_of(artifact_hash)
            .ok_or_else(|| MemoryError::NotFound(artifact_hash.to_string()))?;
        match current {
            MemoryTier::Canon => return Ok(MemoryTier::Canon),
            MemoryTier::Quarantine => return Err(MemoryError::QuarantineAppendOnly),
            _ => {}
        }
        // Evaluate the evidence against the *target* tier's rule.
        let target = match current {
            MemoryTier::Sandbox => MemoryTier::Conditional,
            _ => MemoryTier::Canon,
        };
        let record = self.records.get(artifact_hash).expect("tier checked above");
        let mut probe = record.clone();
        probe.tier = target;
        let witness = canon_evidence(&probe, attestations)?;
        let record = self
            .records
            .get_mut(artifact_hash)
            .expect("tier checked above");
        record.tier = target;
        record.witness_hash = Some(witness);
        Ok(target)
    }

    /// Guard rail for callers that ask for Canon directly: Sandbox → Canon is
    /// the one promotion the spec forbids outright (§3.1), so it gets its own
    /// error instead of silently stepping. Conditional → Canon is a single
    /// lawful step and is delegated to [`MemoryStore::promote`].
    pub fn promote_direct_to_canon(
        &mut self,
        artifact_hash: &str,
        attestations: &[CanonAttestation],
    ) -> Result<MemoryTier, MemoryError> {
        match self.tier_of(artifact_hash) {
            Some(MemoryTier::Sandbox) => Err(MemoryError::SandboxCannotJumpToCanon),
            Some(MemoryTier::Conditional) => self.promote(artifact_hash, attestations),
            Some(MemoryTier::Canon) => Ok(MemoryTier::Canon),
            Some(MemoryTier::Quarantine) => Err(MemoryError::QuarantineAppendOnly),
            None => Err(MemoryError::NotFound(artifact_hash.to_string())),
        }
    }

    /// Demote a record into Quarantine. The *only* way out of Canon (§3.1):
    /// a falsification certificate for this exact artifact, issued by one of
    /// this store's configured trusted issuers (see
    /// [`MemoryStore::trust_falsification_issuer`]).
    pub fn demote_to_quarantine(
        &mut self,
        artifact_hash: &str,
        certificate: &FalsificationCertificate,
    ) -> Result<(), MemoryError> {
        certificate
            .verify_with_trusted_issuers(
                &self
                    .trusted_falsification_issuers
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| match e {
                SamoError::UntrustedIssuer => MemoryError::UntrustedCertificateIssuer,
                other => MemoryError::CertificateInvalid(other.to_string()),
            })?;
        if certificate.artifact_hash != artifact_hash {
            return Err(MemoryError::CertificateForOtherArtifact {
                expected: artifact_hash.to_string(),
                got: certificate.artifact_hash.clone(),
            });
        }
        let record = self
            .records
            .get_mut(artifact_hash)
            .ok_or_else(|| MemoryError::NotFound(artifact_hash.to_string()))?;
        if record.tier != MemoryTier::Quarantine {
            record.tier = MemoryTier::Quarantine;
            self.quarantine_log.push(artifact_hash.to_string());
        }
        Ok(())
    }

    /// Remove a record. Only Sandbox working context may be dropped; Quarantine
    /// is append-only and Canon/Conditional leave only via demotion.
    pub fn remove(&mut self, artifact_hash: &str) -> Result<(), MemoryError> {
        match self.tier_of(artifact_hash) {
            None => Err(MemoryError::NotFound(artifact_hash.to_string())),
            Some(MemoryTier::Sandbox) => {
                self.records.remove(artifact_hash);
                Ok(())
            }
            Some(MemoryTier::Quarantine) => Err(MemoryError::QuarantineAppendOnly),
            Some(t) => Err(MemoryError::RemovalRefused(t)),
        }
    }

    pub fn get(&self, artifact_hash: &str) -> Option<&MemoryRecord> {
        self.records.get(artifact_hash)
    }

    pub fn tier_of(&self, artifact_hash: &str) -> Option<MemoryTier> {
        self.records.get(artifact_hash).map(|r| r.tier)
    }

    /// Quarantine records for an artifact, co-retrieved strictly as explicit
    /// regression warnings (§3.1 Tier 3, §6.4) alongside any live record.
    pub fn regression_warnings(&self, artifact_hash: &str) -> Vec<&MemoryRecord> {
        self.records
            .values()
            .filter(|r| r.tier == MemoryTier::Quarantine && r.artifact_hash == artifact_hash)
            .collect()
    }

    /// Artifact hashes in the order they entered Quarantine (append-only proof).
    pub fn quarantine_log(&self) -> &[String] {
        &self.quarantine_log
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::samo_envelope::content_hash;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn record(payload: Value, tier: MemoryTier) -> MemoryRecord {
        MemoryRecord {
            artifact_hash: content_hash(&payload).unwrap(),
            tier,
            payload,
            witness_hash: None,
            checks_unavailable: false,
            coverage: None,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Valid attestations for `hash` from the attesters identified by seed.
    fn atts(hash: &str, seeds: &[u8]) -> Vec<CanonAttestation> {
        seeds
            .iter()
            .map(|s| attestation_from_seed([*s; 32], hash))
            .collect()
    }

    #[test]
    fn canon_refuses_a_plain_insert() {
        let mut s = MemoryStore::new();
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        assert!(matches!(s.insert(r), Err(MemoryError::CanonNeedsWitness)));
    }

    #[test]
    fn canon_needs_witness_quorum_and_available_checks() {
        let mut s = MemoryStore::new();
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        let h = r.artifact_hash.clone();
        // No attestations at all: no witness.
        assert!(matches!(
            s.insert_verified(r.clone(), &[]),
            Err(MemoryError::CanonNeedsWitness)
        ));
        // One valid attestation is below the quorum of distinct attesters.
        assert!(matches!(
            s.insert_verified(r.clone(), &atts(&h, &[31])),
            Err(MemoryError::CanonNeedsQuorum { got: 1 })
        ));
        let mut unchecked = r.clone();
        unchecked.checks_unavailable = true;
        assert!(matches!(
            s.insert_verified(unchecked, &atts(&h, &[31, 32])),
            Err(MemoryError::ChecksUnavailable)
        ));
        s.insert_verified(r, &atts(&h, &[31, 32])).unwrap();
        assert_eq!(s.tier_of(&h), Some(MemoryTier::Canon));
    }

    #[test]
    fn regression_bare_witness_and_count_no_longer_admit_canon() {
        // Regression (finding 4): the old `insert_verified` accepted any
        // nonempty witness string plus the integer 2 as a "quorum". The
        // replacement evidence must be signatures that verify against the
        // record being admitted, from distinct attesters.
        let mut s = MemoryStore::new();
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        let h = r.artifact_hash.clone();

        // Forged signature: attester field names one key, another key signed.
        let mut forged = attestation_from_seed([41u8; 32], &h);
        forged.signature = sign_canon_attestation(&SigningKey::from_bytes(&[42u8; 32]), &h).signature;
        let second = attestation_from_seed([43u8; 32], &h);
        assert!(matches!(
            s.insert_verified(r.clone(), &[forged, second]),
            Err(MemoryError::InvalidAttestation(_))
        ));
        assert_eq!(s.tier_of(&h), None, "forgery must not admit the record");

        // The same attester twice is one vote, not a quorum.
        let dup = atts(&h, &[41, 41]);
        assert!(matches!(
            s.insert_verified(r.clone(), &dup),
            Err(MemoryError::CanonNeedsQuorum { got: 1 })
        ));

        // Attestations over a *different* record prove nothing about this one.
        let other = atts("some-other-hash", &[41, 42]);
        assert!(matches!(
            s.insert_verified(r.clone(), &other),
            Err(MemoryError::InvalidAttestation(_))
        ));

        // Positive path: two distinct valid attesters admit the record, and
        // the stored witness is the recomputed hash of the attester set.
        s.insert_verified(r, &atts(&h, &[41, 42])).unwrap();
        let stored = s.get(&h).unwrap();
        let expected = canon_witness_hash(
            &h,
            &atts(&h, &[41, 42])
                .iter()
                .map(|a| a.attester.clone())
                .collect::<BTreeSet<_>>(),
        );
        assert_eq!(stored.witness_hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn sandbox_cannot_jump_straight_to_canon() {
        let mut s = MemoryStore::new();
        let r = record(json!({"draft": 1}), MemoryTier::Sandbox);
        let h = r.artifact_hash.clone();
        s.insert(r).unwrap();
        assert!(matches!(
            s.promote_direct_to_canon(&h, &atts(&h, &[31, 32])),
            Err(MemoryError::SandboxCannotJumpToCanon)
        ));
        // The lawful path is step by step, each with its own attestations.
        assert_eq!(
            s.promote(&h, &atts(&h, &[31])).unwrap(),
            MemoryTier::Conditional
        );
        assert_eq!(
            s.promote(&h, &atts(&h, &[31, 32])).unwrap(),
            MemoryTier::Canon
        );
    }

    #[test]
    fn only_a_verified_certificate_demotes_canon() {
        let mut s = MemoryStore::new();
        s.trust_falsification_issuer(&hex::encode(key().verifying_key().to_bytes()));
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        let h = r.artifact_hash.clone();
        s.insert_verified(r, &atts(&h, &[31, 32])).unwrap();

        let cert = FalsificationCertificate::issue(&key(), &h, json!({"input": "x=0"})).unwrap();
        s.demote_to_quarantine(&h, &cert).unwrap();
        assert_eq!(s.tier_of(&h), Some(MemoryTier::Quarantine));
        assert_eq!(s.quarantine_log(), [h].as_slice());

        // A certificate for a different artifact demotes nothing.
        let mut s2 = MemoryStore::new();
        s2.trust_falsification_issuer(&hex::encode(key().verifying_key().to_bytes()));
        let r2 = record(json!({"claim": "b"}), MemoryTier::Canon);
        let h2 = r2.artifact_hash.clone();
        s2.insert_verified(r2, &atts(&h2, &[31, 32])).unwrap();
        assert!(matches!(
            s2.demote_to_quarantine(&h2, &cert),
            Err(MemoryError::CertificateForOtherArtifact { .. })
        ));
        assert_eq!(s2.tier_of(&h2), Some(MemoryTier::Canon));
    }

    #[test]
    fn regression_self_signed_certificate_cannot_demote_canon() {
        // Regression (finding 3): an attacker mints its own key, chooses the
        // victim's artifact hash and a failing input, and self-signs a
        // certificate. The store has not configured that issuer as trusted,
        // so the demotion must be refused and Canon must stand.
        let mut s = MemoryStore::new();
        s.trust_falsification_issuer(&hex::encode(key().verifying_key().to_bytes()));
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        let h = r.artifact_hash.clone();
        s.insert_verified(r, &atts(&h, &[31, 32])).unwrap();

        let attacker = SigningKey::from_bytes(&[77u8; 32]);
        let forged =
            FalsificationCertificate::issue(&attacker, &h, json!({"input": "x=0"})).unwrap();
        forged.verify().unwrap(); // self-consistent — and still worthless here
        assert!(matches!(
            s.demote_to_quarantine(&h, &forged),
            Err(MemoryError::UntrustedCertificateIssuer)
        ));
        assert_eq!(s.tier_of(&h), Some(MemoryTier::Canon));
    }

    #[test]
    fn quarantine_is_append_only_and_co_retrieved_as_a_warning() {
        let mut s = MemoryStore::new();
        let r = record(json!({"bad": true}), MemoryTier::Quarantine);
        let h = r.artifact_hash.clone();
        s.insert(r).unwrap();
        assert!(matches!(
            s.remove(&h),
            Err(MemoryError::QuarantineAppendOnly)
        ));
        let warnings = s.regression_warnings(&h);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].tier, MemoryTier::Quarantine);
    }

    #[test]
    fn sandbox_records_can_be_dropped_canon_cannot() {
        let mut s = MemoryStore::new();
        let draft = record(json!({"draft": 1}), MemoryTier::Sandbox);
        let dh = draft.artifact_hash.clone();
        s.insert(draft).unwrap();
        s.remove(&dh).unwrap();
        assert!(s.get(&dh).is_none());

        let canon = record(json!({"claim": "a"}), MemoryTier::Canon);
        let ch = canon.artifact_hash.clone();
        s.insert_verified(canon, &atts(&ch, &[31, 32])).unwrap();
        assert!(matches!(
            s.remove(&ch),
            Err(MemoryError::RemovalRefused(MemoryTier::Canon))
        ));
    }

    #[test]
    fn tier_names_round_trip_through_storage_names() {
        for t in [
            MemoryTier::Canon,
            MemoryTier::Conditional,
            MemoryTier::Sandbox,
            MemoryTier::Quarantine,
        ] {
            assert_eq!(MemoryTier::from_name(t.name()), Some(t));
        }
        assert_eq!(MemoryTier::from_name("vault"), None);
    }
}
