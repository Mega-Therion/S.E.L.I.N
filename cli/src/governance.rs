//! Shared governance pipeline — the single implementation of "govern a prompt"
//! used by both the `selin run` CLI command and the HTTP `/v1/govern` endpoint.
//!
//! Async (tokio + reqwest) so the server can handle concurrent requests. The
//! pipeline is: risk-classify → three-tier action gate → generate answer →
//! independent verification → chiral-invariant verdict → persist to the myelin
//! store. It never self-scores and fails closed (see `archon_kernel::verifier`).

use archon_kernel::{
    build_verifier_prompt, classify_prompt, extract_scores, parse_verifier_strict, AdcclGate,
    SignOffLedger, ThreeTierGate, FAIL_CLOSED,
};
use chrono::Utc;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::init::open_myelin;

/// Per-request configuration resolved before governance runs.
#[derive(Clone)]
pub struct GovernConfig {
    pub endpoint: String,
    pub model: String,
    /// Optional sign-off TOKEN for a high-risk prompt: hex HMAC-SHA256 of the prompt hash under the
    /// operator key (SELIN_SIGNOFF_KEY). A phrase or word is never accepted (work order item 1).
    pub signoff_token: Option<String>,
}

impl GovernConfig {
    /// Resolve the verifier (work order item 2). The verifier must be independent of the
    /// generator: a different endpoint or a different model. If VERIFIER_ENDPOINT and
    /// VERIFIER_MODEL leave it identical to the generator, governance refuses, unless the
    /// operator sets SELIN_ALLOW_SELF_VERIFY=1, in which case the receipt says "self-verified".
    /// Returns (endpoint, model, self_verified) or an error string.
    pub fn verifier(&self) -> Result<(String, String, bool), String> {
        let ep = std::env::var("VERIFIER_ENDPOINT").unwrap_or_else(|_| self.endpoint.clone());
        let model = std::env::var("VERIFIER_MODEL").unwrap_or_else(|_| self.model.clone());
        let same =
            ep.trim_end_matches('/') == self.endpoint.trim_end_matches('/') && model == self.model;
        if !same {
            return Ok((ep, model, false));
        }
        if std::env::var("SELIN_ALLOW_SELF_VERIFY")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return Ok((ep, model, true));
        }
        Err("verifier is the generator (set VERIFIER_ENDPOINT or VERIFIER_MODEL to an independent model, \
             or SELIN_ALLOW_SELF_VERIFY=1 to accept a self-verified receipt)"
            .to_string())
    }
}

/// The ADCCL gate, honoring ADCCL_THRESHOLD but never below the chiral floor 1/√2.
fn gate_from_env() -> AdcclGate {
    let floor = std::f64::consts::FRAC_1_SQRT_2;
    match std::env::var("ADCCL_THRESHOLD")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
    {
        Some(t) if t.is_finite() && t <= 1.0 => AdcclGate::new(t.max(floor)),
        _ => AdcclGate::default(),
    }
}

/// The structured result of governing one prompt. Serializes directly as the
/// HTTP response body; the CLI renders its own view from the same struct.
#[derive(Serialize, Clone)]
pub struct GovernOutcome {
    pub run_id: String,
    pub passed: bool,
    pub chi: f64,
    pub v_score: f64,
    pub j_penalty: f64,
    pub tier: String,
    pub verdict_source: String,
    pub rejection_reason: Option<String>,
    /// Present only when the output cleared the gate.
    pub output: Option<String>,
}

/// Run the full governance pipeline for `prompt`.
/// Spent sign-off tokens for this process (single use).
static SIGNOFF_LEDGER: std::sync::LazyLock<std::sync::Mutex<SignOffLedger>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(SignOffLedger::default()));

/// The operator sign-off key, hex in SELIN_SIGNOFF_KEY. Absent or invalid means no sign-off can validate.
fn signoff_key() -> Option<Vec<u8>> {
    let k = hex::decode(std::env::var("SELIN_SIGNOFF_KEY").ok()?.trim()).ok()?;
    (k.len() >= 32).then_some(k)
}

pub async fn govern(client: &Client, cfg: &GovernConfig, prompt: &str) -> GovernOutcome {
    let run_id = Uuid::new_v4().to_string();
    let prompt_hash = hex::encode(Sha256::digest(prompt.as_bytes()));
    let gate = gate_from_env();

    // 1. Three-tier action gate — before any model call.
    let (risk_score, illegal_threat) = classify_prompt(prompt);
    let signoff_valid = match (&cfg.signoff_token, signoff_key()) {
        (Some(tok), Some(key)) => SIGNOFF_LEDGER
            .lock()
            .map(|mut l| l.redeem(&key, &prompt_hash, tok))
            .unwrap_or(false),
        _ => false,
    };
    let action = ThreeTierGate::evaluate_action(risk_score, illegal_threat, signoff_valid);
    let tier = format!("{:?}", action.level);
    if !action.permitted {
        let reason = format!("Action blocked at {:?}", action.level);
        let report = gate.evaluate(FAIL_CLOSED.0, FAIL_CLOSED.1);
        let src = match persist(&run_id, &prompt_hash, &report, &cfg.endpoint, &reason).await {
            Ok(()) => "three-tier-gate".to_string(),
            Err(e) => format!("three-tier-gate; receipt not stored: {e}"),
        };
        return outcome(run_id, &report, tier, src, None);
    }

    // 2. Generate the answer (clean prompt — no self-scoring).
    let answer = match call_model(client, &cfg.endpoint, &cfg.model, prompt).await {
        Ok(a) if !a.trim().is_empty() => a,
        Ok(_) => {
            return fail_closed(
                &run_id,
                &prompt_hash,
                &gate,
                cfg,
                tier,
                "empty model response",
            )
            .await
        }
        Err(e) => {
            let note = format!("model call failed: {e}");
            return fail_closed(&run_id, &prompt_hash, &gate, cfg, tier, &note).await;
        }
    };

    // 3. Independent verification (separate, injection-resistant call).
    let verifier_prompt = build_verifier_prompt(prompt, &answer);
    let (v_endpoint, v_model, self_verified) = match cfg.verifier() {
        Ok(x) => x,
        Err(note) => return fail_closed(&run_id, &prompt_hash, &gate, cfg, tier, &note).await,
    };
    let label = if self_verified {
        "self-verified"
    } else {
        "verifier-scored"
    };
    let (v, j, source, verifier_unavail) =
        match call_model(client, &v_endpoint, &v_model, &verifier_prompt).await {
            Ok(vraw) => match parse_verifier_strict(&vraw).and_then(|json| extract_scores(&json)) {
                Some((v, j)) => (v, j, format!("{label} ({v_model})"), false),
                None => (
                    FAIL_CLOSED.0,
                    FAIL_CLOSED.1,
                    "fail-closed: verifier returned no usable score".to_string(),
                    false,
                ),
            },
            Err(e) => (
                FAIL_CLOSED.0,
                FAIL_CLOSED.1,
                format!("fail-closed: verifier call failed: {e}"),
                true,
            ),
        };

    // 4. Chiral verdict + persist.
    let mut report = gate.evaluate(v, j);
    if verifier_unavail {
        report.passed = false;
        report.rejection_reason = Some("verifier_unavailable".to_string());
    }
    let source = match persist(&run_id, &prompt_hash, &report, &cfg.endpoint, &answer).await {
        Ok(()) => source,
        Err(e) => {
            // No receipt, no release.
            if report.passed {
                report.passed = false;
                report.rejection_reason = Some("receipt_not_stored".to_string());
            }
            format!("{source}; receipt not stored: {e}")
        }
    };
    let output = report.passed.then(|| answer.trim().to_string());
    outcome(run_id, &report, tier, source, output)
}

async fn fail_closed(
    run_id: &str,
    prompt_hash: &str,
    gate: &AdcclGate,
    cfg: &GovernConfig,
    tier: String,
    note: &str,
) -> GovernOutcome {
    let report = gate.evaluate(FAIL_CLOSED.0, FAIL_CLOSED.1);
    let src = match persist(run_id, prompt_hash, &report, &cfg.endpoint, note).await {
        Ok(()) => format!("fail-closed: {note}"),
        Err(e) => format!("fail-closed: {note}; receipt not stored: {e}"),
    };
    outcome(run_id.to_string(), &report, tier, src, None)
}

fn outcome(
    run_id: String,
    report: &archon_kernel::VerificationReport,
    tier: String,
    verdict_source: String,
    output: Option<String>,
) -> GovernOutcome {
    GovernOutcome {
        run_id,
        passed: report.passed,
        chi: report.chiral_invariant,
        v_score: report.v_gate_score,
        j_penalty: report.drift_penalty_j,
        tier,
        verdict_source,
        rejection_reason: report.rejection_reason.clone(),
        output,
    }
}

/// One model call with bounded retry + exponential backoff on transient errors.
pub async fn call_model(
    client: &Client,
    endpoint: &str,
    model: &str,
    prompt: &str,
) -> Result<String, String> {
    let is_ollama = endpoint.contains("11434");
    let api_url = if is_ollama {
        format!("{}/api/generate", endpoint.trim_end_matches('/'))
    } else {
        format!("{}/v1/chat/completions", endpoint.trim_end_matches('/'))
    };
    let body = if is_ollama {
        json!({ "model": model, "prompt": prompt, "stream": false })
    } else {
        json!({ "model": model, "messages": [{"role": "user", "content": prompt}] })
    };

    let mut last_err = String::new();
    for attempt in 0..3u32 {
        if attempt > 0 {
            let backoff = 200u64 * (1u64 << (attempt - 1)); // 200ms, 400ms
            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
        }
        match client.post(&api_url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                let v: Value = resp.json().await.map_err(|e| e.to_string())?;
                let text = v
                    .get("response")
                    .and_then(|x| x.as_str())
                    .or_else(|| {
                        v.pointer("/choices/0/message/content")
                            .and_then(|x| x.as_str())
                    })
                    .unwrap_or("")
                    .to_string();
                return Ok(text);
            }
            Ok(resp) => last_err = format!("HTTP {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(format!("after 3 attempts: {last_err}"))
}

/// Persist a run to the myelin store (2000-char output). Runs on a blocking
/// thread so the sync SQLite driver doesn't stall the async runtime.
/// The chain hash of one receipt row: SHA-256 over the previous row's hash and every field.
pub fn row_hash(prev: &str, fields: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(b"selin-receipt-v1");
    h.update(prev.as_bytes());
    for f in fields {
        h.update([0x1f]);
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Store the receipt for a run, hash-chained to the previous row. Returns an error if the
/// receipt could not be stored; callers MUST NOT release output in that case (work order item 3).
async fn persist(
    run_id: &str,
    prompt_hash: &str,
    report: &archon_kernel::VerificationReport,
    endpoint: &str,
    output: &str,
) -> Result<(), String> {
    let (run_id, prompt_hash, endpoint) = (
        run_id.to_string(),
        prompt_hash.to_string(),
        endpoint.to_string(),
    );
    let snippet: String = output.chars().take(2000).collect();
    let (v, j, chi, passed, reason) = (
        report.v_gate_score,
        report.drift_penalty_j,
        report.chiral_invariant,
        report.passed,
        report.rejection_reason.clone(),
    );
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut conn = open_myelin().map_err(|e| format!("open_myelin failed: {e}"))?;
        let tx = conn.transaction().map_err(|e| format!("begin failed: {e}"))?;
        let prev: String = tx
            .query_row(
                "SELECT COALESCE(row_hash, '') FROM adccl_runs ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let created = Utc::now().to_rfc3339();
        let passed_s = if passed { "1" } else { "0" };
        let (vs, js, cs) = (format!("{v:.17e}"), format!("{j:.17e}"), format!("{chi:.17e}"));
        let reason_s = reason.clone().unwrap_or_default();
        let h = row_hash(
            &prev,
            &[&run_id, &created, &prompt_hash, &vs, &js, &cs, passed_s, &reason_s, &endpoint, &snippet],
        );
        tx.execute(
            "INSERT INTO adccl_runs (run_id, created_at, prompt_hash, v_score, j_penalty, chi_invariant, passed, rejection_reason, model_endpoint, raw_output_snippet, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                run_id, created, prompt_hash, v, j, chi,
                if passed { 1 } else { 0 }, reason, endpoint, snippet, prev, h,
            ],
        )
        .map_err(|e| format!("insert adccl_runs failed: {e}"))?;
        tx.commit().map_err(|e| format!("commit failed: {e}"))
    })
    .await
    .map_err(|e| format!("persist task failed: {e}"))?
}
