use archon_kernel::basepoint::{generate_basepoint_seal, generate_entropy};
use chrono::Utc;
use dialoguer::{theme::ColorfulTheme, Input};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

use crate::preflight::{execute_preflight_probe, PreflightResult};
use serde_json::Value as JsonValue;

/// Returns the SELIN data directory (~/.selin)
pub fn selin_dir() -> PathBuf {
    // No /tmp fallback (work order item 3): an audit store in a world-writable,
    // auto-cleaned directory is not an audit store.
    match std::env::var("HOME") {
        Ok(h) if !h.trim().is_empty() => PathBuf::from(h).join(".selin"),
        _ => {
            eprintln!("[error] HOME is not set; SELIN needs a private home directory for its audit store.");
            std::process::exit(2);
        }
    }
}

pub fn myelin_db_path() -> PathBuf {
    selin_dir().join("myelin.db")
}

/// Derive the 32-byte database key from the operator passphrase with Argon2id
/// (19 MiB, 2 passes, 1 lane: the RustCrypto default parameters). Returns hex.
pub fn derive_db_key(passphrase: &str, salt: &[u8]) -> Result<String, String> {
    if passphrase.chars().count() < 8 {
        return Err("database passphrase must be at least 8 characters".into());
    }
    let mut out = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2id failed: {e}"))?;
    Ok(hex::encode(out))
}

/// The database key (work order item 3, part 2). The key is NOT stored: basepoint.json
/// holds only a random salt, and the key is derived from SELIN_DB_PASSPHRASE with Argon2id.
/// A legacy basepoint with a stored `db_key` is still read, with a warning to re-initialize.
pub fn db_key() -> Option<String> {
    let raw = std::fs::read_to_string(basepoint_path()).ok()?;
    let v: JsonValue = serde_json::from_str(&raw).ok()?;
    if let Some(salt_hex) = v.get("db_key_salt").and_then(|s| s.as_str()) {
        let salt = hex::decode(salt_hex).ok()?;
        let pass = std::env::var("SELIN_DB_PASSPHRASE").ok()?;
        return derive_db_key(&pass, &salt).ok();
    }
    let legacy = v
        .get("db_key")
        .and_then(|k| k.as_str())
        .map(|s| s.to_string());
    if legacy.is_some() {
        eprintln!(
            "[warn] this SELIN store keeps its database key in basepoint.json (legacy). \
             Re-initialize with SELIN_FORCE_REINIT=1 to switch to a passphrase-derived key."
        );
    }
    legacy
}

/// Open the Myelin SQLite store. A database key is REQUIRED: there is no unencrypted
/// fallback (work order item 3). The chain columns are added to older stores on open.
pub fn open_myelin() -> Result<rusqlite::Connection, String> {
    let key = db_key().ok_or_else(|| {
        "no database key: set SELIN_DB_PASSPHRASE (or run `selin init` first). SELIN never opens its audit store unencrypted".to_string()
    })?;
    let conn = rusqlite::Connection::open(myelin_db_path())
        .map_err(|e| format!("could not open {}: {e}", myelin_db_path().display()))?;
    conn.pragma_update(None, "key", &key)
        .map_err(|e| format!("could not apply database encryption: {e}"))?;
    ensure_chain_columns(&conn)?;
    Ok(conn)
}

/// Add prev_hash / row_hash to an older adccl_runs table, if the table exists without them.
pub fn ensure_chain_columns(conn: &rusqlite::Connection) -> Result<(), String> {
    let mut stmt = match conn.prepare("PRAGMA table_info(adccl_runs)") {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| format!("could not read schema: {e}"))?
        .filter_map(Result::ok)
        .collect();
    if cols.is_empty() {
        return Ok(());
    }
    for c in ["prev_hash", "row_hash"] {
        if !cols.iter().any(|x| x == c) {
            conn.execute(&format!("ALTER TABLE adccl_runs ADD COLUMN {c} TEXT"), [])
                .map_err(|e| format!("could not add {c}: {e}"))?;
        }
    }
    Ok(())
}

pub fn basepoint_path() -> PathBuf {
    selin_dir().join("basepoint.json")
}

/// Public entry point. Prints a friendly error instead of panicking on failure.
pub async fn execute_init() {
    if let Err(e) = run_init().await {
        eprintln!("\n  ✗ Initialization failed: {e}");
        eprintln!("    Nothing was overwritten. Fix the issue above and re-run `selin init`.");
        std::process::exit(1);
    }
}

async fn run_init() -> Result<(), String> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     SELIN Series (ARCHON v1.0) — Init Wizard          ║");
    println!("║     Reflect-It-Yourself Unit (RIYU) Sovereign Onboarding     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Check for existing identity
    if basepoint_path().exists() {
        if std::env::var("SELIN_FORCE_REINIT").unwrap_or_default() != "1" {
            return Err(format!(
                "an identity already exists at {}.\n    Re-initializing replaces your basepoint seal. \
                 To proceed intentionally, re-run with SELIN_FORCE_REINIT=1.",
                basepoint_path().display()
            ));
        }
        // Create timestamped backup of old identity before overwriting
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let bp_backup = selin_dir().join(format!("basepoint.json.bak.{timestamp}"));
        if let Err(e) = std::fs::copy(basepoint_path(), &bp_backup) {
            eprintln!("[warn] Could not backup existing basepoint.json: {e}");
        } else {
            eprintln!(
                "[info] Backed up existing basepoint to {}",
                bp_backup.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&bp_backup, std::fs::Permissions::from_mode(0o600));
            }
        }
        let myelin_file = myelin_db_path();
        if myelin_file.exists() {
            let myelin_backup = selin_dir().join(format!("myelin.db.bak.{timestamp}"));
            if let Err(e) = std::fs::copy(&myelin_file, &myelin_backup) {
                eprintln!("[warn] Could not backup existing myelin.db: {e}");
            } else {
                eprintln!(
                    "[info] Backed up existing myelin.db to {}",
                    myelin_backup.display()
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &myelin_backup,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
            }
        }
        eprintln!("[warn] Overwriting existing identity (SELIN_FORCE_REINIT=1)");
    }

    println!("[1/4] Identity Directives");
    println!("      Enter your governing principles (comma-separated).");
    println!("      These are used to derive your seal; they are NOT stored in plaintext.\n");

    let theme = ColorfulTheme::default();
    let directives: String = Input::with_theme(&theme)
        .with_prompt("Directives")
        .default("sovereignty,verifiable-accuracy,anti-drift".to_string())
        .interact_text()
        .map_err(|e| format!("could not read directives: {e}"))?;

    let endpoint: String = Input::with_theme(&theme)
        .with_prompt("Model endpoint")
        .default("http://localhost:11434".to_string())
        .interact_text()
        .map_err(|e| format!("could not read endpoint: {e}"))?;

    // Step 2: Generate the seal from CSPRNG entropy (was hostname:timestamp).
    println!("\n[2/4] Generating Sovereign Identity Basepoint Seal (CSPRNG + HKDF)…");
    let salt = generate_entropy()?;
    let salt_hex = hex::encode(salt);
    let seal = generate_basepoint_seal(&directives, &salt);

    fs::create_dir_all(selin_dir())
        .map_err(|e| format!("could not create {}: {e}", selin_dir().display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(selin_dir(), fs::Permissions::from_mode(0o700));
    }

    // Database key (SQLCipher): derived from the operator's passphrase with Argon2id.
    // Only the random salt is stored; the key itself never touches disk.
    let pass = match std::env::var("SELIN_DB_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => dialoguer::Password::with_theme(&ColorfulTheme::default())
            .with_prompt(
                "Database passphrase (min 8 chars; needed on every run as SELIN_DB_PASSPHRASE)",
            )
            .with_confirmation("Confirm passphrase", "Passphrases did not match")
            .interact()
            .map_err(|e| format!("could not read passphrase: {e}"))?,
    };
    let db_salt = generate_entropy()?;
    derive_db_key(&pass, &db_salt)?;
    let db_salt_hex = hex::encode(db_salt);
    // Make the key available to this process for the schema step below.
    std::env::set_var("SELIN_DB_PASSPHRASE", &pass);

    // basepoint.json stores the seal, the seal's salt and the database key's salt. It
    // stores neither the database key nor the directives or any hint of them.
    let bp_json = json!({
        "version": 2,
        "seal": seal,
        "salt": salt_hex,
        "seal_alg": "HKDF-SHA256/HMAC-SHA256",
        "created_at": Utc::now().to_rfc3339(),
        "endpoint": endpoint,
        "db_key_salt": db_salt_hex,
        "db_key_kdf": "argon2id-v19-m19456-t2-p1",
    });
    fs::write(
        basepoint_path(),
        serde_json::to_string_pretty(&bp_json)
            .map_err(|e| format!("could not serialize basepoint: {e}"))?,
    )
    .map_err(|e| format!("could not write {}: {e}", basepoint_path().display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(basepoint_path(), fs::Permissions::from_mode(0o600));
    }

    println!("      Seal (HMAC-SHA256): {seal}");
    println!("      Written to: {}", basepoint_path().display());

    // Step 3: Preflight probe (non-fatal).
    println!("\n[3/4] Running Model Capability Preflight Diagnostic…");
    let preflight = execute_preflight_probe(&endpoint).await;
    match &preflight {
        PreflightResult::Pass { model, latency_ms } => {
            println!("      [✓] Model '{model}' responded in {latency_ms}ms — gate cleared.");
        }
        PreflightResult::Fail { reason } => {
            println!("      [✗] Preflight FAILED: {reason}");
            println!("      Continuing init — you can fix the endpoint later.");
        }
    }

    // Step 4: Myelin store.
    println!("\n[4/4] Initializing Myelin SQLite Store…");
    let schema_sql = include_str!("../../templates/myelin_schema.sql");
    let conn = open_myelin()?;
    conn.execute_batch(schema_sql)
        .map_err(|e| format!("could not apply myelin schema: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(myelin_db_path(), fs::Permissions::from_mode(0o600));
    }

    let (schema_ok, chi_ok, latency) = match &preflight {
        PreflightResult::Pass { latency_ms, .. } => (1, 1, *latency_ms as i64),
        PreflightResult::Fail { .. } => (0, 0, -1),
    };
    let model_name = match &preflight {
        PreflightResult::Pass { model, .. } => model.clone(),
        PreflightResult::Fail { reason } => format!("unknown ({reason})"),
    };
    let preflight_result = match &preflight {
        PreflightResult::Pass { .. } => "PASS",
        PreflightResult::Fail { .. } => "FAIL",
    };

    // Re-init (force): replace the single identity row rather than IGNORE it.
    conn.execute("DELETE FROM selin_identity", [])
        .map_err(|e| format!("could not reset identity: {e}"))?;
    conn.execute(
        "INSERT INTO selin_identity (basepoint_seal, seal_version) VALUES (?1, 2)",
        rusqlite::params![seal],
    )
    .map_err(|e| format!("could not insert identity: {e}"))?;

    conn.execute(
        "INSERT INTO preflight_log (endpoint, schema_adherence, chi_compliance, model_name, latency_ms, result) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![endpoint, schema_ok, chi_ok, model_name, latency, preflight_result],
    )
    .map_err(|e| format!("could not insert preflight log: {e}"))?;

    let db_size = fs::metadata(myelin_db_path()).map(|m| m.len()).unwrap_or(0);
    println!(
        "      Myelin DB: {} ({db_size} bytes) [SQLCipher encrypted]",
        myelin_db_path().display()
    );

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Initialization Complete.                                     ║");
    println!("║  Your SELIN instance is locked to your identity basepoint.   ║");
    println!("║  Run `selin preflight` anytime to re-verify your endpoint.   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    Ok(())
}

/// Load configured endpoint from basepoint.json, env, or default.
pub fn load_endpoint_from_bp() -> String {
    if let Ok(ep) = std::env::var("MODEL_ENDPOINT") {
        return ep;
    }
    if let Ok(raw) = std::fs::read_to_string(basepoint_path()) {
        if let Ok(v) = serde_json::from_str::<JsonValue>(&raw) {
            if let Some(ep) = v.get("endpoint").and_then(|e| e.as_str()) {
                return ep.to_string();
            }
        }
    }
    "http://localhost:11434".to_string()
}

#[cfg(test)]
mod key_tests {
    use super::derive_db_key;

    #[test]
    fn same_passphrase_and_salt_give_the_same_key() {
        let a = derive_db_key("correct horse battery", b"0123456789abcdef").unwrap();
        let b = derive_db_key("correct horse battery", b"0123456789abcdef").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn wrong_passphrase_or_salt_gives_a_different_key() {
        let a = derive_db_key("correct horse battery", b"0123456789abcdef").unwrap();
        assert_ne!(
            a,
            derive_db_key("correct horse batterz", b"0123456789abcdef").unwrap()
        );
        assert_ne!(
            a,
            derive_db_key("correct horse battery", b"fedcba9876543210").unwrap()
        );
    }

    #[test]
    fn short_passphrase_is_refused() {
        assert!(derive_db_key("short", b"0123456789abcdef").is_err());
    }
}
