//! Four-tier monotonic memory partition (SAMO spec §3.1).
//!
//! Every local memory record is tagged with exactly one provenance tier:
//!
//! - **Canon** — mechanically verified artifacts backed by reproducible receipts.
//!   A monotonic ratchet: a record enters Canon only via independent deterministic
//!   verification plus a multi-substrate quorum ([`CANON_QUORUM`]), and leaves it
//!   only when a verified `[X]` falsification certificate demotes it.
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

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::samo_envelope::FalsificationCertificate;

/// Independent substrates that must attest before a record may enter Canon.
pub const CANON_QUORUM: usize = 2;

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
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an unverified or partially verified record (Sandbox, Conditional,
    /// or Quarantine). Canon is refused here: use [`MemoryStore::insert_verified`].
    pub fn insert(&mut self, record: MemoryRecord) -> Result<(), MemoryError> {
        if record.tier == MemoryTier::Canon {
            return Err(MemoryError::CanonNeedsWitness);
        }
        self.insert_inner(record)
    }

    /// Insert a record backed by a deterministic verification witness. Canon
    /// additionally requires a multi-substrate quorum and fully available checks.
    pub fn insert_verified(
        &mut self,
        mut record: MemoryRecord,
        witness_hash: &str,
        quorum: usize,
    ) -> Result<(), MemoryError> {
        if witness_hash.is_empty() {
            return Err(MemoryError::CanonNeedsWitness);
        }
        if record.tier == MemoryTier::Canon {
            if record.checks_unavailable {
                return Err(MemoryError::ChecksUnavailable);
            }
            if quorum < CANON_QUORUM {
                return Err(MemoryError::CanonNeedsQuorum { got: quorum });
            }
        }
        record.witness_hash = Some(witness_hash.to_string());
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

    /// Promote one step: Sandbox → Conditional → Canon. Each step requires a
    /// fresh witness; the step into Canon additionally requires the quorum and
    /// fully available checks. Canon and Quarantine never promote.
    pub fn promote(
        &mut self,
        artifact_hash: &str,
        witness_hash: &str,
        quorum: usize,
    ) -> Result<MemoryTier, MemoryError> {
        let record = self
            .records
            .get_mut(artifact_hash)
            .ok_or_else(|| MemoryError::NotFound(artifact_hash.to_string()))?;
        if witness_hash.is_empty() {
            return Err(MemoryError::CanonNeedsWitness);
        }
        let next = match record.tier {
            MemoryTier::Sandbox => MemoryTier::Conditional,
            MemoryTier::Conditional => {
                if record.checks_unavailable {
                    return Err(MemoryError::ChecksUnavailable);
                }
                if quorum < CANON_QUORUM {
                    return Err(MemoryError::CanonNeedsQuorum { got: quorum });
                }
                MemoryTier::Canon
            }
            MemoryTier::Canon => return Ok(MemoryTier::Canon),
            MemoryTier::Quarantine => return Err(MemoryError::QuarantineAppendOnly),
        };
        record.tier = next;
        record.witness_hash = Some(witness_hash.to_string());
        Ok(next)
    }

    /// Guard rail for callers that ask for Canon directly: Sandbox → Canon is
    /// the one promotion the spec forbids outright (§3.1), so it gets its own
    /// error instead of silently stepping. Conditional → Canon is a single
    /// lawful step and is delegated to [`MemoryStore::promote`].
    pub fn promote_direct_to_canon(
        &mut self,
        artifact_hash: &str,
        witness_hash: &str,
        quorum: usize,
    ) -> Result<MemoryTier, MemoryError> {
        match self.tier_of(artifact_hash) {
            Some(MemoryTier::Sandbox) => Err(MemoryError::SandboxCannotJumpToCanon),
            Some(MemoryTier::Conditional) => self.promote(artifact_hash, witness_hash, quorum),
            Some(MemoryTier::Canon) => Ok(MemoryTier::Canon),
            Some(MemoryTier::Quarantine) => Err(MemoryError::QuarantineAppendOnly),
            None => Err(MemoryError::NotFound(artifact_hash.to_string())),
        }
    }

    /// Demote a record into Quarantine. The *only* way out of Canon (§3.1):
    /// a verified `[X]` falsification certificate for this exact artifact.
    pub fn demote_to_quarantine(
        &mut self,
        artifact_hash: &str,
        certificate: &FalsificationCertificate,
    ) -> Result<(), MemoryError> {
        certificate
            .verify()
            .map_err(|e| MemoryError::CertificateInvalid(e.to_string()))?;
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
        assert!(matches!(
            s.insert_verified(r.clone(), "", CANON_QUORUM),
            Err(MemoryError::CanonNeedsWitness)
        ));
        assert!(matches!(
            s.insert_verified(r.clone(), "witness", 1),
            Err(MemoryError::CanonNeedsQuorum { got: 1 })
        ));
        let mut unchecked = r.clone();
        unchecked.checks_unavailable = true;
        assert!(matches!(
            s.insert_verified(unchecked, "witness", CANON_QUORUM),
            Err(MemoryError::ChecksUnavailable)
        ));
        s.insert_verified(r, "witness", CANON_QUORUM).unwrap();
        assert_eq!(s.tier_of(&h), Some(MemoryTier::Canon));
    }

    #[test]
    fn sandbox_cannot_jump_straight_to_canon() {
        let mut s = MemoryStore::new();
        let r = record(json!({"draft": 1}), MemoryTier::Sandbox);
        let h = r.artifact_hash.clone();
        s.insert(r).unwrap();
        assert!(matches!(
            s.promote_direct_to_canon(&h, "w", CANON_QUORUM),
            Err(MemoryError::SandboxCannotJumpToCanon)
        ));
        // The lawful path is step by step, each with its own witness.
        assert_eq!(s.promote(&h, "w1", 0).unwrap(), MemoryTier::Conditional);
        assert_eq!(
            s.promote(&h, "w2", CANON_QUORUM).unwrap(),
            MemoryTier::Canon
        );
    }

    #[test]
    fn only_a_verified_certificate_demotes_canon() {
        let mut s = MemoryStore::new();
        let r = record(json!({"claim": "a"}), MemoryTier::Canon);
        let h = r.artifact_hash.clone();
        s.insert_verified(r, "witness", CANON_QUORUM).unwrap();

        let cert = FalsificationCertificate::issue(&key(), &h, json!({"input": "x=0"})).unwrap();
        s.demote_to_quarantine(&h, &cert).unwrap();
        assert_eq!(s.tier_of(&h), Some(MemoryTier::Quarantine));
        assert_eq!(s.quarantine_log(), [h].as_slice());

        // A certificate for a different artifact demotes nothing.
        let mut s2 = MemoryStore::new();
        let r2 = record(json!({"claim": "b"}), MemoryTier::Canon);
        let h2 = r2.artifact_hash.clone();
        s2.insert_verified(r2, "witness", CANON_QUORUM).unwrap();
        assert!(matches!(
            s2.demote_to_quarantine(&h2, &cert),
            Err(MemoryError::CertificateForOtherArtifact { .. })
        ));
        assert_eq!(s2.tier_of(&h2), Some(MemoryTier::Canon));
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
        s.insert_verified(canon, "w", CANON_QUORUM).unwrap();
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
