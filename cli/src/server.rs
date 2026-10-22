//! ARCHON HTTP server.
//!
//! Long-running local service. Endpoints:
//!   GET  /health            → liveness probe
//!   POST /v1/govern         → govern a prompt, returns the ADCCL verdict
//!   GET  /v1/audit/:run_id  → the stored proof trace for a run
//!
//! Default bind is 127.0.0.1 (local-first). Docker should pass --bind 0.0.0.0.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::governance::{govern, GovernConfig};
use crate::init::open_myelin;

struct AppState {
    client: Client,
    endpoint: String,
    model: String,
    limiter: Semaphore,
    api_key: Option<String>,
}

const MAX_CONCURRENT: usize = 8;
const GOVERN_TIMEOUT_SECS: u64 = 120;
pub const MAX_PROMPT_BYTES: usize = 32 * 1024; // 32KB

/// Sanitize input prompt: validates non-empty, checks byte length <= 32KB,
/// strips zero-width and invisible unicode control code points.
pub fn sanitize_prompt(prompt: &str) -> Result<String, &'static str> {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return Err("prompt must not be empty");
    }
    if prompt.len() > MAX_PROMPT_BYTES {
        return Err("prompt exceeds maximum allowed byte limit (32KB)");
    }

    // Strip zero-width and format control characters
    let cleaned: String = prompt
        .chars()
        .filter(|&c| match c {
            '\u{200B}' // zero-width space
            | '\u{200C}' // zero-width non-joiner
            | '\u{200D}' // zero-width joiner
            | '\u{FEFF}' // zero-width no-break space / BOM
            | '\u{200E}' // left-to-right mark
            | '\u{200F}' // right-to-left mark
            | '\u{2060}' // word joiner
            => false,
            _ => true,
        })
        .collect();

    let cleaned_trimmed = cleaned.trim();
    if cleaned_trimmed.is_empty() {
        return Err("prompt must not be empty");
    }

    Ok(cleaned)
}

#[derive(Deserialize)]
struct GovernRequest {
    prompt: String,
    signoff: Option<String>,
}

/// Back-compat: bind all interfaces (prefer `serve_bind` with an explicit host).
#[allow(dead_code)]
pub async fn serve(port: u16) {
    serve_bind("127.0.0.1", port, None).await;
}

/// Build and run the server on `bind:port`.
pub async fn serve_bind(bind: &str, port: u16, cli_api_key: Option<String>) {
    let endpoint = crate::init::load_endpoint_from_bp();
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("failed to build HTTP client");
    let model = crate::preflight::detect_ollama_model(&endpoint, &client).await;

    let api_key = cli_api_key
        .or_else(|| std::env::var("ARCHON_API_KEY").ok())
        .or_else(|| std::env::var("SELIN_API_KEY").ok())
        .filter(|k| !k.trim().is_empty());

    let state = Arc::new(AppState {
        client,
        endpoint: endpoint.clone(),
        model: model.clone(),
        limiter: Semaphore::new(MAX_CONCURRENT),
        api_key: api_key.clone(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/govern", post(govern_handler))
        .route("/v1/audit/:run_id", get(audit_handler))
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64KB HTTP request body limit
        .with_state(state);

    let addr = format!("{bind}:{port}");
    if bind == "0.0.0.0" || bind == "::" {
        eprintln!("  [warn] Binding {addr} exposes the governance API on all interfaces. ");
        eprintln!("         Prefer 127.0.0.1 unless this is an intentional deployment.");
    }
    if api_key.is_some() {
        println!("  [auth] API Key authentication active (Bearer / X-API-Key).");
    } else {
        println!("  [warn] Running without API Key authentication. Set ARCHON_API_KEY for network security.");
    }
    println!("ARCHON server listening on http://{addr}");
    println!("  endpoint={endpoint}  model={model}  max_concurrent={MAX_CONCURRENT}");
    println!("  formal artifacts: use `selin verify-artifact` (local MVPC-X), not /v1/govern");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("could not bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
}

fn check_auth(
    headers: &HeaderMap,
    expected_key: &Option<String>,
) -> Result<(), (StatusCode, Json<Value>)> {
    let expected = match expected_key {
        Some(ref key) => key,
        None => return Ok(()), // No auth configured
    };

    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let x_api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());

    let is_valid = if let Some(header) = auth_header {
        if header.starts_with("Bearer ") {
            header
                .strip_prefix("Bearer ")
                .map(|k| k.trim() == expected)
                .unwrap_or(false)
        } else {
            header.trim() == expected
        }
    } else if let Some(key) = x_api_key {
        key.trim() == expected
    } else {
        false
    };

    if is_valid {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized: valid API key required" })),
        ))
    }
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "archon-selin",
        "version": env!("CARGO_PKG_VERSION"),
        "mvpc_bridge": "selin verify-artifact (local subprocess)"
    }))
}

async fn govern_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GovernRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&headers, &state.api_key)?;

    let clean_prompt = match sanitize_prompt(&req.prompt) {
        Ok(p) => p,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": e }))));
        }
    };

    let _permit = state.limiter.try_acquire().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server at capacity, retry shortly" })),
        )
    })?;

    let cfg = GovernConfig {
        endpoint: state.endpoint.clone(),
        model: state.model.clone(),
        signoff_token: req.signoff.clone(),
    };
    let fut = govern(&state.client, &cfg, &clean_prompt);
    match tokio::time::timeout(Duration::from_secs(GOVERN_TIMEOUT_SECS), fut).await {
        Ok(outcome) => Ok(Json(serde_json::to_value(outcome).unwrap_or(Value::Null))),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "error": "governance timed out" })),
        )),
    }
}

async fn audit_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&headers, &state.api_key)?;

    let result = tokio::task::spawn_blocking(move || read_run(&run_id))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("audit task failed: {e}") })),
            )
        })?;
    match result {
        Some(v) => Ok(Json(v)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "run_id not found" })),
        )),
    }
}

fn read_run(run_id: &str) -> Option<Value> {
    let conn = open_myelin().ok()?;
    conn.query_row(
        "SELECT run_id, created_at, prompt_hash, v_score, j_penalty, chi_invariant, passed, rejection_reason, model_endpoint, raw_output_snippet
         FROM adccl_runs WHERE run_id = ?1",
        rusqlite::params![run_id],
        |r| {
            Ok(json!({
                "run_id": r.get::<_, String>(0)?,
                "created_at": r.get::<_, String>(1)?,
                "prompt_hash": r.get::<_, String>(2)?,
                "v_score": r.get::<_, f64>(3)?,
                "j_penalty": r.get::<_, f64>(4)?,
                "chi_invariant": r.get::<_, f64>(5)?,
                "passed": r.get::<_, i64>(6)? == 1,
                "rejection_reason": r.get::<_, Option<String>>(7)?,
                "model_endpoint": r.get::<_, String>(8)?,
                "raw_output_snippet": r.get::<_, Option<String>>(9)?,
            }))
        },
    )
    .ok()
}
