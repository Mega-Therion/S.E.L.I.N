//! Four-tier memory parity in the local Myelin store (SAMO spec §3.1).
//!
//! The node's persistent memory lives in the SQLCipher database opened by
//! [`crate::init::open_myelin`]. This module applies the archon_kernel
//! four-tier partition (`archon_kernel::memory_tiers`) to that store: the
//! `memory_artifacts` table is created from the kernel's own DDL
//! ([`MEMORY_ARTIFACTS_DDL`]) so the on-disk layout and the in-memory
//! [`MemoryStore`](archon_kernel::MemoryStore) semantics cannot drift apart.
//!
//! Tier transition *rules* are enforced here, at the persistence boundary,
//! with the same discipline as the kernel store — this helper is not a raw
//! row writer. [`store_memory_record`] validates the requested write against
//! the currently stored record before persisting anything:
//!
//! - **Legal transitions** (existing tier → new tier): same-tier refresh for
//!   Sandbox/Conditional; Sandbox → Conditional; Conditional → Canon;
//!   anything → Quarantine *only* with a verified falsification certificate
//!   ([`StoreEvidence::demotion_certificate`]). Everything else is rejected.
//! - **Quarantine is append-only**: an existing Quarantine record's tier and
//!   payload can never be rewritten — in particular it can never be promoted
//!   out by re-storing it as Sandbox/Canon. (The verified-admission path is
//!   the kernel [`MemoryStore`], not this helper.)
//! - **Canon writes require the Canon evidence rule**: signed
//!   [`CanonAttestation`]s from at least [`CANON_QUORUM`] distinct verified
//!   attesters over the record's hash, with fully available checks. The
//!   stored witness hash is the recomputed Canon witness, never a
//!   caller-supplied string.
//! - **Canon payloads are immutable here**: re-storing a Canon record with a
//!   different payload is rejected (its verification was over the old one).

use archon_kernel::memory_tiers::{
    CanonAttestation, MemoryRecord, MemoryTier, CANON_QUORUM, MEMORY_ARTIFACTS_DDL,
};
use archon_kernel::samo_envelope::FalsificationCertificate;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;

/// Evidence accompanying a [`store_memory_record`] call. The default
/// ([`StoreEvidence::none`]) authorizes only writes that need no evidence:
/// first inserts into Sandbox/Conditional/Quarantine and same-tier refreshes
/// of Sandbox/Conditional records.
#[derive(Default)]
pub struct StoreEvidence<'a> {
    /// Signed attestations backing a verified admission/promotion
    /// (required for any Canon write, and for step promotions).
    pub canon_attestations: &'a [CanonAttestation],
    /// Verified falsification certificate backing a demotion into
    /// Quarantine of an existing record.
    pub demotion_certificate: Option<&'a FalsificationCertificate>,
}

impl<'a> StoreEvidence<'a> {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn canon(attestations: &'a [CanonAttestation]) -> Self {
        Self {
            canon_attestations: attestations,
            demotion_certificate: None,
        }
    }

    pub fn demotion(certificate: &'a FalsificationCertificate) -> Self {
        Self {
            canon_attestations: &[],
            demotion_certificate: Some(certificate),
        }
    }
}

/// Create the `memory_artifacts` table if it does not exist yet.
pub fn ensure_memory_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(MEMORY_ARTIFACTS_DDL)
        .map_err(|e| format!("could not create memory_artifacts table: {e}"))
}

/// Verify the Canon evidence rule for `record` from signed attestations and
/// return the recomputed witness hash. Mirrors
/// `archon_kernel::memory_tiers` Canon admission: every attestation must
/// verify against the record hash, and at least [`CANON_QUORUM`] *distinct*
/// attesters must have signed. (The kernel exposes the same rule through
/// `MemoryStore::insert_verified`; it is re-checked here because this helper
/// persists records that never pass through an in-memory store.)
fn verified_canon_witness(
    record: &MemoryRecord,
    attestations: &[CanonAttestation],
) -> Result<String, String> {
    if record.checks_unavailable {
        return Err("record has unavailable checks and cannot enter Canon".into());
    }
    // Reuse the kernel's verification by probing a throwaway store: a Canon
    // insert succeeds only under the full evidence rule, and yields exactly
    // the witness hash the kernel would store.
    let mut probe = archon_kernel::MemoryStore::new();
    let mut candidate = record.clone();
    candidate.witness_hash = None;
    probe
        .insert_verified(candidate, attestations)
        .map_err(|e| format!("Canon evidence rejected: {e}"))?;
    let witness = probe
        .get(&record.artifact_hash)
        .and_then(|r| r.witness_hash.clone())
        .ok_or_else(|| "Canon evidence rejected: no witness derived".to_string())?;
    Ok(witness)
}

/// Count distinct attesters in a slice (used only for clearer errors).
fn distinct_attesters(attestations: &[CanonAttestation]) -> usize {
    attestations
        .iter()
        .map(|a| a.attester.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Validate a write of `record` against the existing stored record (if any)
/// and the supplied evidence. Returns the witness hash to persist.
fn validate_transition(
    existing: Option<&MemoryRecord>,
    record: &MemoryRecord,
    evidence: &StoreEvidence,
) -> Result<Option<String>, String> {
    let canon_witness = |rec: &MemoryRecord| verified_canon_witness(rec, evidence.canon_attestations);
    match existing {
        None => {
            // First insert: Canon still requires the full evidence rule;
            // the other tiers are unverified/negative by definition.
            if record.tier == MemoryTier::Canon {
                return canon_witness(record).map(Some);
            }
            Ok(record.witness_hash.clone())
        }
        Some(old) => {
            // Quarantine is append-only: no rewrite of tier or payload, ever.
            if old.tier == MemoryTier::Quarantine {
                return Err(
                    "Quarantine is append-only; an existing Quarantine record cannot be \
                     rewritten or promoted out through the persistence helper"
                        .into(),
                );
            }
            match (old.tier, record.tier) {
                (t, u) if t == u => {
                    if t == MemoryTier::Canon {
                        // Canon content is what was verified; changing the
                        // payload under the same hash voids the verification.
                        if old.payload != record.payload {
                            return Err(
                                "Canon records are immutable in the persistence store; \
                                 a changed payload must be re-verified as a new record"
                                    .into(),
                            );
                        }
                        return canon_witness(record).map(Some);
                    }
                    Ok(record.witness_hash.clone())
                }
                (MemoryTier::Sandbox, MemoryTier::Conditional) => {
                    // Step promotion requires at least one attestation whose
                    // signature verifies against this record — checked by
                    // running the kernel's own verified-insert rule on a
                    // throwaway store with the record at the target tier.
                    if evidence.canon_attestations.is_empty() {
                        return Err(
                            "promotion Sandbox -> Conditional requires signed verification \
                             attestations"
                                .into(),
                        );
                    }
                    let mut probe = archon_kernel::MemoryStore::new();
                    let mut candidate = record.clone();
                    candidate.tier = MemoryTier::Conditional;
                    candidate.witness_hash = None;
                    probe
                        .insert_verified(candidate, evidence.canon_attestations)
                        .map_err(|e| format!("promotion evidence rejected: {e}"))?;
                    Ok(probe
                        .get(&record.artifact_hash)
                        .and_then(|r| r.witness_hash.clone()))
                }
                (MemoryTier::Conditional, MemoryTier::Canon) => {
                    if distinct_attesters(evidence.canon_attestations) < CANON_QUORUM {
                        return Err(format!(
                            "Canon requires a quorum of {CANON_QUORUM} independent substrates"
                        ));
                    }
                    canon_witness(record).map(Some)
                }
                (_, MemoryTier::Quarantine) => {
                    // Demotion of an existing record requires a verified
                    // falsification certificate for this exact artifact.
                    let cert = evidence.demotion_certificate.ok_or_else(|| {
                        "demotion to Quarantine requires a falsification certificate".to_string()
                    })?;
                    cert.verify()
                        .map_err(|e| format!("falsification certificate invalid: {e}"))?;
                    if cert.artifact_hash != record.artifact_hash {
                        return Err(format!(
                            "falsification certificate is for artifact {}, not {}",
                            cert.artifact_hash, record.artifact_hash
                        ));
                    }
                    Ok(record.witness_hash.clone())
                }
                (from, to) => Err(format!(
                    "illegal memory tier transition {} -> {}",
                    from.name(),
                    to.name()
                )),
            }
        }
    }
}

/// Insert or replace the stored record for an artifact, after validating the
/// tier transition and its evidence (see the module docs for the legal set).
/// `created_at` is an RFC 3339 timestamp supplied by the caller (this module
/// never invents one). A rejected transition persists nothing.
pub fn store_memory_record(
    conn: &Connection,
    record: &MemoryRecord,
    created_at: &str,
    evidence: &StoreEvidence,
) -> Result<(), String> {
    let existing = load_memory_record(conn, &record.artifact_hash)?;
    let witness_hash = validate_transition(existing.as_ref(), record, evidence)?;
    let mut to_store = record.clone();
    to_store.witness_hash = witness_hash;

    let payload = serde_json::to_string(&to_store.payload)
        .map_err(|e| format!("could not serialize memory payload: {e}"))?;
    conn.execute(
        "INSERT INTO memory_artifacts
            (artifact_hash, tier, payload, witness_hash, checks_unavailable, coverage, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(artifact_hash) DO UPDATE SET
            tier = excluded.tier,
            payload = excluded.payload,
            witness_hash = excluded.witness_hash,
            checks_unavailable = excluded.checks_unavailable,
            coverage = excluded.coverage,
            created_at = excluded.created_at",
        params![
            to_store.artifact_hash,
            to_store.tier.name(),
            payload,
            to_store.witness_hash,
            to_store.checks_unavailable as i64,
            to_store.coverage,
            created_at,
        ],
    )
    .map_err(|e| format!("could not store memory record: {e}"))?;
    Ok(())
}

/// The tier currently stored for an artifact, if any.
pub fn load_memory_tier(
    conn: &Connection,
    artifact_hash: &str,
) -> Result<Option<MemoryTier>, String> {
    let name: Option<String> = conn
        .query_row(
            "SELECT tier FROM memory_artifacts WHERE artifact_hash = ?1",
            params![artifact_hash],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("could not read memory tier: {e}"))?;
    match name {
        None => Ok(None),
        Some(n) => MemoryTier::from_name(&n)
            .map(Some)
            .ok_or_else(|| format!("memory_artifacts holds unknown tier {n:?}")),
    }
}

/// The full stored record for an artifact, if any.
pub fn load_memory_record(
    conn: &Connection,
    artifact_hash: &str,
) -> Result<Option<MemoryRecord>, String> {
    let row = conn
        .query_row(
            "SELECT tier, payload, witness_hash, checks_unavailable, coverage
             FROM memory_artifacts WHERE artifact_hash = ?1",
            params![artifact_hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("could not read memory record: {e}"))?;
    match row {
        None => Ok(None),
        Some((tier_name, payload_json, witness_hash, checks_unavailable, coverage)) => {
            let tier = MemoryTier::from_name(&tier_name)
                .ok_or_else(|| format!("memory_artifacts holds unknown tier {tier_name:?}"))?;
            let payload = serde_json::from_str(&payload_json)
                .map_err(|e| format!("stored memory payload is not valid JSON: {e}"))?;
            Ok(Some(MemoryRecord {
                artifact_hash: artifact_hash.to_string(),
                tier,
                payload,
                witness_hash,
                checks_unavailable: checks_unavailable != 0,
                coverage,
            }))
        }
    }
}

/// How many artifacts the store currently holds in a tier.
pub fn count_by_tier(conn: &Connection, tier: MemoryTier) -> Result<usize, String> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_artifacts WHERE tier = ?1",
            params![tier.name()],
            |r| r.get(0),
        )
        .map_err(|e| format!("could not count memory records: {e}"))?;
    Ok(n as usize)
}

/// Artifact hashes currently held in Quarantine, in insertion order — the
/// persistent form of the append-only negative-knowledge cache (§3.1, §6.4).
pub fn quarantine_index(conn: &Connection) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT artifact_hash FROM memory_artifacts WHERE tier = 'quarantine' ORDER BY rowid",
        )
        .map_err(|e| format!("could not read quarantine index: {e}"))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| format!("could not read quarantine index: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("could not read quarantine index: {e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archon_kernel::memory_tiers::{attestation_from_seed, canon_witness_hash};
    use serde_json::json;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_memory_schema(&c).unwrap();
        c
    }

    fn record(hash: &str, tier: MemoryTier) -> MemoryRecord {
        MemoryRecord {
            artifact_hash: hash.to_string(),
            tier,
            payload: json!({"hash": hash}),
            witness_hash: None,
            checks_unavailable: false,
            coverage: None,
        }
    }

    fn atts(hash: &str, seeds: &[u8]) -> Vec<CanonAttestation> {
        seeds
            .iter()
            .map(|s| attestation_from_seed([*s; 32], hash))
            .collect()
    }

    const TS: &str = "2026-11-25T00:00:00Z";

    #[test]
    fn schema_is_idempotent() {
        let c = Connection::open_in_memory().unwrap();
        ensure_memory_schema(&c).unwrap();
        ensure_memory_schema(&c).unwrap();
    }

    #[test]
    fn records_round_trip_through_the_store() {
        let c = conn();
        let mut r = record("aa11", MemoryTier::Conditional);
        r.witness_hash = Some("w-1".into());
        r.checks_unavailable = true;
        r.coverage = Some("no lean kernel on this node".into());
        store_memory_record(&c, &r, TS, &StoreEvidence::none()).unwrap();

        assert_eq!(
            load_memory_tier(&c, "aa11").unwrap(),
            Some(MemoryTier::Conditional)
        );
        let back = load_memory_record(&c, "aa11").unwrap().unwrap();
        assert_eq!(back.payload, json!({"hash": "aa11"}));
        assert_eq!(back.witness_hash.as_deref(), Some("w-1"));
        assert!(back.checks_unavailable);
        assert_eq!(
            back.coverage.as_deref(),
            Some("no lean kernel on this node")
        );
        assert_eq!(load_memory_tier(&c, "missing").unwrap(), None);
    }

    #[test]
    fn tier_transitions_update_in_place_and_count() {
        let c = conn();
        store_memory_record(&c, &record("bb22", MemoryTier::Sandbox), TS, &StoreEvidence::none())
            .unwrap();
        store_memory_record(&c, &record("cc33", MemoryTier::Sandbox), TS, &StoreEvidence::none())
            .unwrap();
        assert_eq!(count_by_tier(&c, MemoryTier::Sandbox).unwrap(), 2);

        // The lawful path persists step by step: Sandbox -> Conditional with
        // a signed attestation, then Conditional -> Canon with a quorum.
        // The row is updated in place, not duplicated.
        store_memory_record(
            &c,
            &record("bb22", MemoryTier::Conditional),
            "2026-11-25T01:00:00Z",
            &StoreEvidence::canon(&atts("bb22", &[31])),
        )
        .unwrap();
        store_memory_record(
            &c,
            &record("bb22", MemoryTier::Canon),
            "2026-11-25T02:00:00Z",
            &StoreEvidence::canon(&atts("bb22", &[31, 32])),
        )
        .unwrap();
        assert_eq!(count_by_tier(&c, MemoryTier::Sandbox).unwrap(), 1);
        assert_eq!(count_by_tier(&c, MemoryTier::Canon).unwrap(), 1);
        assert_eq!(
            load_memory_tier(&c, "bb22").unwrap(),
            Some(MemoryTier::Canon)
        );
        // The stored witness is the recomputed Canon witness, not caller text.
        let stored = load_memory_record(&c, "bb22").unwrap().unwrap();
        let expected = canon_witness_hash(
            "bb22",
            &atts("bb22", &[31, 32])
                .iter()
                .map(|a| a.attester.clone())
                .collect::<BTreeSet<_>>(),
        );
        assert_eq!(stored.witness_hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn regression_quarantine_cannot_be_rewritten_as_sandbox() {
        // Regression (finding 5): the old helper let any caller rewrite a
        // Quarantine row as Sandbox, silently vanishing it from the
        // quarantine index. Now the rewrite is rejected and the row stands.
        let c = conn();
        store_memory_record(
            &c,
            &record("q1", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::none(),
        )
        .unwrap();
        let err = store_memory_record(
            &c,
            &record("q1", MemoryTier::Sandbox),
            TS,
            &StoreEvidence::none(),
        )
        .unwrap_err();
        assert!(err.contains("append-only"), "unexpected error: {err}");
        assert_eq!(quarantine_index(&c).unwrap(), ["q1"]);
        assert_eq!(
            load_memory_tier(&c, "q1").unwrap(),
            Some(MemoryTier::Quarantine)
        );
    }

    #[test]
    fn regression_sandbox_cannot_be_rewritten_as_canon_without_evidence() {
        // Regression (finding 5): the old helper persisted a Sandbox row as
        // Canon with no witness or quorum at all. Both the direct jump and
        // an evidence-free (or single-attester) Canon write are rejected.
        let c = conn();
        store_memory_record(&c, &record("s1", MemoryTier::Sandbox), TS, &StoreEvidence::none())
            .unwrap();
        assert!(store_memory_record(
            &c,
            &record("s1", MemoryTier::Canon),
            TS,
            &StoreEvidence::none()
        )
        .is_err());
        assert!(store_memory_record(
            &c,
            &record("s1", MemoryTier::Canon),
            TS,
            &StoreEvidence::canon(&atts("s1", &[31]))
        )
        .is_err());
        assert_eq!(
            load_memory_tier(&c, "s1").unwrap(),
            Some(MemoryTier::Sandbox)
        );

        // A *first* insert straight into Canon is likewise evidence-gated.
        assert!(store_memory_record(
            &c,
            &record("c1", MemoryTier::Canon),
            TS,
            &StoreEvidence::none()
        )
        .is_err());
        store_memory_record(
            &c,
            &record("c1", MemoryTier::Canon),
            TS,
            &StoreEvidence::canon(&atts("c1", &[31, 32])),
        )
        .unwrap();
        assert_eq!(
            load_memory_tier(&c, "c1").unwrap(),
            Some(MemoryTier::Canon)
        );
    }

    #[test]
    fn regression_demotion_requires_a_certificate_for_this_artifact() {
        // Regression (finding 5): moving an existing record into Quarantine
        // through the persistence helper requires a verified falsification
        // certificate for that artifact — not a bare re-store.
        use archon_kernel::samo_envelope::FalsificationCertificate;

        fn cert_for(hash: &str) -> FalsificationCertificate {
            FalsificationCertificate::issue_from_seed([7u8; 32], hash, json!({"input": "x=0"}))
                .unwrap()
        }

        let c = conn();
        store_memory_record(
            &c,
            &record("d1", MemoryTier::Conditional),
            TS,
            &StoreEvidence::none(),
        )
        .unwrap();
        // No certificate: rejected.
        assert!(store_memory_record(
            &c,
            &record("d1", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::none()
        )
        .is_err());
        // Certificate for a different artifact: rejected.
        let wrong = cert_for("other");
        assert!(store_memory_record(
            &c,
            &record("d1", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::demotion(&wrong)
        )
        .is_err());
        assert_eq!(
            load_memory_tier(&c, "d1").unwrap(),
            Some(MemoryTier::Conditional)
        );
        // The right certificate: demotion persists and is indexed.
        let right = cert_for("d1");
        store_memory_record(
            &c,
            &record("d1", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::demotion(&right),
        )
        .unwrap();
        assert_eq!(quarantine_index(&c).unwrap(), ["d1"]);
    }

    #[test]
    fn quarantine_index_lists_refuted_artifacts_in_order() {
        let c = conn();
        store_memory_record(
            &c,
            &record("q1", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::none(),
        )
        .unwrap();
        store_memory_record(&c, &record("s1", MemoryTier::Sandbox), TS, &StoreEvidence::none())
            .unwrap();
        store_memory_record(
            &c,
            &record("q2", MemoryTier::Quarantine),
            TS,
            &StoreEvidence::none(),
        )
        .unwrap();
        assert_eq!(quarantine_index(&c).unwrap(), ["q1", "q2"]);
    }
}
