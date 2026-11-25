//! Four-tier memory parity in the local Myelin store (SAMO spec §3.1).
//!
//! The node's persistent memory lives in the SQLCipher database opened by
//! [`crate::init::open_myelin`]. This module applies the archon_kernel
//! four-tier partition (`archon_kernel::memory_tiers`) to that store: the
//! `memory_artifacts` table is created from the kernel's own DDL
//! ([`MEMORY_ARTIFACTS_DDL`]) so the on-disk layout and the in-memory
//! [`MemoryStore`](archon_kernel::MemoryStore) semantics cannot drift apart.
//! Tier transition *rules* (Canon ratchet, Sandbox step-promotion, Quarantine
//! append-only) are enforced by the kernel store; this module is the durable
//! record of which tier each artifact currently occupies.

use archon_kernel::memory_tiers::{MemoryRecord, MemoryTier, MEMORY_ARTIFACTS_DDL};
use rusqlite::{params, Connection, OptionalExtension};

/// Create the `memory_artifacts` table if it does not exist yet.
pub fn ensure_memory_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(MEMORY_ARTIFACTS_DDL)
        .map_err(|e| format!("could not create memory_artifacts table: {e}"))
}

/// Insert or replace the stored record for an artifact. `created_at` is an
/// RFC 3339 timestamp supplied by the caller (this module never invents one).
pub fn store_memory_record(
    conn: &Connection,
    record: &MemoryRecord,
    created_at: &str,
) -> Result<(), String> {
    let payload = serde_json::to_string(&record.payload)
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
            record.artifact_hash,
            record.tier.name(),
            payload,
            record.witness_hash,
            record.checks_unavailable as i64,
            record.coverage,
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
        store_memory_record(&c, &r, "2026-11-25T00:00:00Z").unwrap();

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
        store_memory_record(
            &c,
            &record("bb22", MemoryTier::Sandbox),
            "2026-11-25T00:00:00Z",
        )
        .unwrap();
        store_memory_record(
            &c,
            &record("cc33", MemoryTier::Sandbox),
            "2026-11-25T00:00:00Z",
        )
        .unwrap();
        assert_eq!(count_by_tier(&c, MemoryTier::Sandbox).unwrap(), 2);

        // A promotion recorded by the kernel store is persisted by re-storing
        // the record at its new tier; the row is updated, not duplicated.
        store_memory_record(
            &c,
            &record("bb22", MemoryTier::Canon),
            "2026-11-25T01:00:00Z",
        )
        .unwrap();
        assert_eq!(count_by_tier(&c, MemoryTier::Sandbox).unwrap(), 1);
        assert_eq!(count_by_tier(&c, MemoryTier::Canon).unwrap(), 1);
        assert_eq!(
            load_memory_tier(&c, "bb22").unwrap(),
            Some(MemoryTier::Canon)
        );
    }

    #[test]
    fn quarantine_index_lists_refuted_artifacts_in_order() {
        let c = conn();
        store_memory_record(
            &c,
            &record("q1", MemoryTier::Quarantine),
            "2026-11-25T00:00:00Z",
        )
        .unwrap();
        store_memory_record(
            &c,
            &record("s1", MemoryTier::Sandbox),
            "2026-11-25T00:00:00Z",
        )
        .unwrap();
        store_memory_record(
            &c,
            &record("q2", MemoryTier::Quarantine),
            "2026-11-25T00:00:00Z",
        )
        .unwrap();
        assert_eq!(quarantine_index(&c).unwrap(), ["q1", "q2"]);
    }
}
