# Dependencies — Chyren-Archon

## Required to build Archon

| Dep | Notes |
|-----|--------|
| Rust stable (see `rust-toolchain` / CI) | `cargo build -p selin` |
| Optional: local LLM endpoint | Ollama or OpenAI-compatible for `selin run` / `serve` |

## Optional — formal / claim files

| Dep | Notes |
|-----|--------|
| **MVPC-X** `>= 7.3.0` | Standalone install; not bundled |
| `MVPC_BIN` | Default `mvpc` on PATH |

```bash
# separate clone — do not vendor MVPC source into this repo
git clone https://github.com/Mega-Therion/MVPC-X.git
cd MVPC-X && pip install -e ".[all]"
export MVPC_BIN=mvpc
selin verify-artifact ./some/File.lean
```

## Must not depend on

- `chyren-aeon` (private)
- Owner personal identity / myelin from AEON
- Network “notary” for verification

## Env vars

| Var | Role |
|-----|------|
| `MODEL_ENDPOINT` | LLM for generative govern |
| `MVPC_BIN` | Path to MVPC-X CLI |
| `SELIN_REQUIRE_MVPC` | If set, treat missing/failing MVPC as hard failure where wired |
| `VERIFIER_ENDPOINT` / `VERIFIER_MODEL` | The independent verifier. If both leave it identical to the generator, governance refuses (work order item 2). |
| `SELIN_ALLOW_SELF_VERIFY` | Set to `1` to accept the generator as its own verifier; every receipt is then marked `self-verified`. Off by default. |
| `ADCCL_THRESHOLD` | Gate threshold; honoured, but never below the chiral floor 1/√2 ≈ 0.7071. |
| `SELIN_SIGNOFF_KEY` | Operator sign-off key (hex, ≥32 bytes). Without it, no high-risk action can be signed off. |
| `SELIN_SIGNOFF_TOKEN` | Single-use sign-off for one prompt: hex HMAC-SHA256(key, "selin-signoff-v1|" + prompt SHA-256). Tier-1 threats are never overridable. |
| `SELIN_FORCE_REINIT` | Allow identity re-init |
