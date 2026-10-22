//! ARCHON HTTP server.
//!
//! Long-running local service. Endpoints:
//!   GET  /health            → liveness probe
//!   POST /v1/govern         → govern a prompt, returns the ADCCL verdict
//!   GET  /v1/audit/:run_id  → the stored proof trace for a run
//!
//! Default bind is 127.0.0.1 (local-first). Binding a non-loopback address
//! without an API key is a hard error — see `serve_bind`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    routing::{get, post},
    Json, Router,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use uuid::Uuid;

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

/// Returns true when `bind` is a loopback-only address.
pub fn is_loopback(bind: &str) -> bool {
    matches!(bind, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

/// True when a bind must be refused: non-loopback with no API key. `serve_bind` calls this.
pub fn non_loopback_without_key_is_refused(bind: &str, api_key: Option<String>) -> bool {
    !is_loopback(bind) && api_key.is_none()
}

/// Middleware: attach a unique X-Request-Id to every response.
async fn request_id_middleware(mut req: Request, next: Next) -> axum::response::Response {
    let id = Uuid::new_v4().to_string();
    req.extensions_mut().insert(id.clone());
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "X-Request-Id",
        id.parse().expect("uuid is always a valid header value"),
    );
    resp
}

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
///
/// Binding a non-loopback interface without an API key is refused: the
/// governance API must not be exposed on a network without authentication.
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

    if non_loopback_without_key_is_refused(bind, api_key.clone()) {
        eprintln!(
            "[error] Refusing to bind {bind}:{port} on a non-loopback interface without an API key."
        );
        eprintln!(
            "        Set ARCHON_API_KEY (or SELIN_API_KEY) before starting the server in network mode."
        );
        std::process::exit(1);
    }

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
        .layer(middleware::from_fn(request_id_middleware))
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64KB HTTP request body limit
        .with_state(state);

    let addr = format!("{bind}:{port}");
    if api_key.is_some() {
        println!("  [auth] API Key authentication active (Bearer / X-API-Key).");
    } else {
        println!("  [auth] Loopback-only mode — no API key required on 127.0.0.1.");
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
        None => return Ok(()), // Loopback-only mode, no key configured
    };

    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let x_api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());

    // Constant-time comparison of the presented key (Bearer, raw Authorization, or X-API-Key).
    let candidate = if let Some(header) = auth_header {
        header
            .strip_prefix("Bearer ")
            .map(str::trim)
            .unwrap_or_else(|| header.trim())
            .to_string()
    } else if let Some(key) = x_api_key {
        key.trim().to_string()
    } else {
        String::new()
    };

    use subtle::ConstantTimeEq;
    let is_valid = candidate.as_bytes().ct_eq(expected.as_bytes()).into();

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
