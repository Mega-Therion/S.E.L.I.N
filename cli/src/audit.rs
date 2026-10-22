use crate::init::{myelin_db_path, open_myelin};

/// Render the proof trace for an ADCCL run from the myelin store.
/// This is the public transparency mechanism — every number shown here
/// is exactly what was computed at runtime, sourced from the audit log.
pub fn execute_audit(run_id: &str) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     SELIN AUDIT — ADCCL Proof Trace                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  Run ID: {}\n", run_id);

    let db_path = myelin_db_path();
    if !db_path.exists() {
        eprintln!("  [error] Myelin store not found at {}.", db_path.display());
        eprintln!("  Run `selin init` first.");
        std::process::exit(1);
    }

    let conn = match open_myelin() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  [error] Failed to open myelin store: {}", e);
            std::process::exit(1);
        }
    };

    let result = conn.query_row(
        "SELECT run_id, created_at, prompt_hash, v_score, j_penalty, chi_invariant, passed, rejection_reason, model_endpoint, raw_output_snippet
         FROM adccl_runs
         WHERE run_id = ?1",
        rusqlite::params![run_id],
        |row| {
            Ok(AuditRecord {
                run_id: row.get(0)?,
                created_at: row.get(1)?,
                prompt_hash: row.get(2)?,
                v_score: row.get(3)?,
                j_penalty: row.get(4)?,
                chi_invariant: row.get(5)?,
                passed: row.get::<_, i64>(6)? != 0,
                rejection_reason: row.get(7)?,
                model_endpoint: row.get(8)?,
                raw_output_snippet: row.get(9)?,
            })
        },
    );

    match result {
        Ok(record) => render_trace(&record),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            eprintln!("  [error] Run ID '{}' not found in myelin store.", run_id);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  [error] Database query failed: {}", e);
            std::process::exit(1);
        }
    }
}

struct AuditRecord {
    run_id: String,
    created_at: String,
    prompt_hash: String,
    v_score: f64,
    j_penalty: f64,
    chi_invariant: f64,
    passed: bool,
    rejection_reason: Option<String>,
    model_endpoint: String,
    raw_output_snippet: Option<String>,
}

fn render_trace(r: &AuditRecord) {
    // Re-compute χ from V and J to verify the stored value (transparency check)
    let recomputed_chi = ((r.v_score.powi(2) + (1.0 - r.j_penalty).powi(2)) / 2.0).sqrt();
    let chi_matches = (recomputed_chi - r.chi_invariant).abs() < 1e-10;

    println!("  ┌─ PROOF TRACE ───────────────────────────────────────────────┐");
    println!("  │  Timestamp:   {}", r.created_at);
    println!("  │  Run ID:      {}", r.run_id);
    println!("  │  Prompt Hash: {}", r.prompt_hash);
    println!("  │  Model:       {}", r.model_endpoint);
    println!("  ├─ ADCCL COMPUTATION ──────────────────────────────────────────");
    println!("  │  Formula: χ = √[(V² + (1-J)²) / 2]");
    println!("  │  V_score:    {:.10}", r.v_score);
    println!("  │  J_penalty:  {:.10}", r.j_penalty);
    println!("  │  χ_stored:   {:.10}", r.chi_invariant);
    println!(
        "  │  χ_recomputed: {:.10}  [{}]",
        recomputed_chi,
        if chi_matches {
            "✓ verified"
        } else {
            "✗ MISMATCH — store may be corrupted"
        }
    );
    println!("  │  Threshold:  0.7071067811865476 (1/√2)");
    println!("  ├─ VERDICT ────────────────────────────────────────────────────");
    if r.passed {
        println!(
            "  │  ✓ PASSED — χ={:.4} >= 0.7071 — output released to caller.",
            r.chi_invariant
        );
    } else {
        println!("  │  ✗ REJECTED — ChiralViolation");
        if let Some(reason) = &r.rejection_reason {
            println!("  │  Reason: {}", reason);
        }
        println!(
            "  │  χ={:.4} < 0.7071 — output suppressed, not returned to caller.",
            r.chi_invariant
        );
    }
    println!("  ├─ OUTPUT SNIPPET ─────────────────────────────────────────────");
    match &r.raw_output_snippet {
        Some(snippet) if !snippet.is_empty() => println!("  │  {}", snippet),
        _ => println!("  │  (no output — gate rejected or empty response)"),
    }
    println!("  └──────────────────────────────────────────────────────────────┘");
}

/// One stored receipt row, as needed to recompute its chain hash.
pub struct ChainRow {
    pub fields: Vec<String>,
    pub prev_hash: String,
    pub row_hash: String,
}

/// Check a sequence of rows (in insertion order). Returns Ok(n) or Err(index, reason).
pub fn check_chain(rows: &[ChainRow]) -> Result<usize, (usize, String)> {
    let mut prev = String::new();
    for (i, r) in rows.iter().enumerate() {
        if r.prev_hash != prev {
            return Err((
                i,
                "prev_hash does not match the previous row (row deleted or reordered)".into(),
            ));
        }
        let refs: Vec<&str> = r.fields.iter().map(String::as_str).collect();
        let h = crate::governance::row_hash(&prev, &refs);
        if h != r.row_hash {
            return Err((i, "row_hash mismatch (row edited)".into()));
        }
        prev = r.row_hash.clone();
    }
    Ok(rows.len())
}

/// `selin audit --verify-chain`: recompute the receipt chain. Exit code 0 = intact.
pub fn execute_verify_chain() -> i32 {
    let conn = match open_myelin() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  [error] {e}");
            return 1;
        }
    };
    let mut stmt = match conn.prepare(
        "SELECT run_id, created_at, prompt_hash, v_score, j_penalty, chi_invariant, passed,
                COALESCE(rejection_reason, ''), model_endpoint, COALESCE(raw_output_snippet, ''),
                COALESCE(prev_hash, ''), COALESCE(row_hash, '')
         FROM adccl_runs WHERE row_hash IS NOT NULL ORDER BY rowid",
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [error] query failed: {e}");
            return 1;
        }
    };
    let rows: Vec<ChainRow> = match stmt.query_map([], |r| {
        let v: f64 = r.get(3)?;
        let j: f64 = r.get(4)?;
        let c: f64 = r.get(5)?;
        let passed: i64 = r.get(6)?;
        Ok(ChainRow {
            fields: vec![
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                format!("{v:.17e}"),
                format!("{j:.17e}"),
                format!("{c:.17e}"),
                if passed != 0 { "1".into() } else { "0".into() },
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
            ],
            prev_hash: r.get(10)?,
            row_hash: r.get(11)?,
        })
    }) {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(e) => {
            eprintln!("  [error] query failed: {e}");
            return 1;
        }
    };
    match check_chain(&rows) {
        Ok(n) => {
            println!("  Receipt chain intact: {n} rows verified.");
            0
        }
        Err((i, why)) => {
            eprintln!("  [BROKEN] receipt chain fails at row {i}: {why}");
            1
        }
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::governance::row_hash;

    fn chain(n: usize) -> Vec<ChainRow> {
        let mut prev = String::new();
        (0..n)
            .map(|i| {
                let fields = vec![format!("run-{i}"), "t".into(), "p".into(), "x".into()];
                let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
                let h = row_hash(&prev, &refs);
                let row = ChainRow {
                    fields,
                    prev_hash: prev.clone(),
                    row_hash: h.clone(),
                };
                prev = h;
                row
            })
            .collect()
    }

    #[test]
    fn intact_chain_verifies() {
        assert_eq!(check_chain(&chain(5)), Ok(5));
    }

    #[test]
    fn edited_row_is_caught() {
        let mut c = chain(5);
        c[2].fields[3] = "tampered".into();
        assert!(matches!(check_chain(&c), Err((2, _))));
    }

    #[test]
    fn deleted_row_is_caught() {
        let mut c = chain(5);
        c.remove(2);
        assert!(matches!(check_chain(&c), Err((2, _))));
    }
}
