//! `selin run` — CLI front-end over the shared governance pipeline.
//! All the real logic (risk gate → generate → independent verify → chiral
//! verdict → persist) lives in `crate::governance`, so the CLI and the HTTP
//! server behave identically. This module only renders the result for a human.

use reqwest::Client;

use crate::governance::{govern, GovernConfig};
use crate::init::load_endpoint_from_bp;

pub async fn execute_run(prompt: &str) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     ARCHON GOVERNED TASK EXECUTION                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  Prompt: \"{prompt}\"");
    println!();

    let endpoint = load_endpoint_from_bp();
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  [error] Could not build HTTP client: {e}");
            std::process::exit(1);
        }
    };
    let model = crate::preflight::detect_ollama_model(&endpoint, &client).await;

    println!("  Endpoint: {endpoint}");
    println!("  Model:    {model}");
    println!("  Governing…\n");

    let cfg = GovernConfig {
        endpoint,
        model,
        signoff_token: std::env::var("SELIN_SIGNOFF_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty()),
    };
    let out = govern(&client, &cfg, prompt).await;

    println!("  Run ID: {}", out.run_id);
    if out.tier != "Standard" {
        println!("  Action tier: {}", out.tier);
    }
    println!("  ┌─ ADCCL GATE VERDICT ────────────────────────────────────┐");
    println!("  │  source: {}", out.verdict_source);
    println!(
        "  │  V_score: {:.4} | J_penalty: {:.4} | χ: {:.4}",
        out.v_score, out.j_penalty, out.chi
    );
    if out.passed {
        println!("  │  STATUS: ✓ PASSED");
    } else {
        println!(
            "  │  STATUS: ✗ REJECTED — {}",
            out.rejection_reason.as_deref().unwrap_or("ChiralViolation")
        );
    }
    println!("  └─────────────────────────────────────────────────────────┘\n");

    match &out.output {
        Some(text) => println!("  Output:\n  {text}"),
        None => println!("  Output suppressed — response did not clear the governance threshold."),
    }

    println!("\n  Logged to myelin store. Run ID: {}", out.run_id);
    println!(
        "  Use `selin audit {}` to retrieve the proof trace.",
        out.run_id
    );
}
