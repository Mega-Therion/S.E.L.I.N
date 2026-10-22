# Chyren SELIN

<p align="left">
  <a href="https://huggingface.co/datasets/ChyRho/chyren-selin"><img src="https://img.shields.io/badge/Hugging%20Face-ChyRho%2Fchyren--selin-FFD21E?style=flat-square&logo=huggingface&logoColor=black" alt="Hugging Face Dataset"></a>
  <a href="https://orcid.org/0009-0001-1303-7190"><img src="https://img.shields.io/badge/ORCID-0009--0001--1303--7190-A6CE39?style=flat-square&logo=orcid&logoColor=white" alt="ORCID"></a>
  <a href="https://chyren-selin-chyrho.vercel.app"><img src="https://img.shields.io/badge/site-selin-0070f3?style=flat-square&logo=safari&logoColor=white" alt="SELIN site"></a>
  <a href="https://res-nova-atlas.vercel.app"><img src="https://img.shields.io/badge/Research%20Atlas-res--nova-0070f3?style=flat-square&logo=safari&logoColor=white" alt="Res Nova Atlas"></a>
  <a href="https://www.linkedin.com/in/r-w-yett/"><img src="https://img.shields.io/badge/LinkedIn-R.W._Yett-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn"></a>
  <a href="https://x.com/_chyrho_"><img src="https://img.shields.io/badge/X-@__ChyRho__-000000?style=flat-square&logo=x&logoColor=white" alt="X"></a>
</p>

Local-first AI governance node and ARCHON runtime. Passphrase-derived encrypted store. Fail-closed gates. Formal artifact checks, when wanted, go through a local MVPC-X install. This repository does not itself run a Lean kernel.

![SELIN Local-First Governance Boundary](docs/visuals/selin-local-governance.svg)

## System Role & Mission

`chyren-selin` is the open, distributable build of the Chyren stack. `chyren-aeon` is the private core. SELIN is meant to run on the user's own hardware: local-first, no telemetry, passphrase-derived encrypted SQLite store, and fail-closed capability gates.

## What is actually checked

`cargo test --locked` covers the ARCHON kernel: the three-tier gate, the ADCCL govern loop, the identity basepoint, and the risk and verifier modules. `npm test` covers the local Node bridge. A passing test means that gate behaved as the test wrote it. It does not mean a model told the truth, and it does not mean a private AEON memory store is in this tree. Personal memory stays in the private core. See `docs/AIR_GAP_POLICY.md`.

The public site is [chyren-selin-chyrho.vercel.app](https://chyren-selin-chyrho.vercel.app). The product name in the docs is Chyren-Archon. The GitHub repository is **S.E.L.I.N** (Sovereign Encrypted Localized Identity Nestor; renamed from `chyren-selin`, and old URLs redirect).

## Core Architectural Invariants

- **Local boundary**: All personal memory, cryptographic keys, and raw conversation history reside exclusively on local SQLite/encrypted storage.
- **Fail-Closed Execution**: If an external connector, model, or policy evaluator is unreachable or degraded, SELIN fails closed: actions are refused rather than executed without oversight.
- **Strict Connector Capabilities**: External tools operate under fixed capability envelopes (`read_only`, `draft_only`, `write_bounded`). External writes always require local policy approval and a stored, hash-chained receipt.

## Architecture

```
Operator Intent ──► ARCHON Runtime ──► Local Policy Evaluator ──► Bounded Connector ──► Action Receipt
                          │                       │
                          ▼                       ▼
                   Encrypted State        Local Receipt Ledger
                   (SQLite / SQLCipher)    (Replay & Audit)
```

## Toolchain & Services

- **Rust Core**: Native ARCHON kernel and cryptographic primitives in `archon_kernel/` (`Cargo.toml`).
- **Node / Runtime CLI**: Local orchestration bridge and CLI tooling (`package.json`).
- **Self-Hosting**: Deployable via root `Dockerfile` and `docker-compose.yml`.

## Verification & Local Run

```bash
# Verify Rust ARCHON kernel
cargo test --locked

# Verify local Node services
npm test
```

## Claims and their tests

Each claim below is backed by a test that fails when the named guard is removed.

| Claim | Test name | Command |
|---|---|---|
| Tier-1 veto is never overridable by any sign-off | `severe_threat_is_refused_with_every_signoff` | `cargo test -p archon_kernel` |
| High-risk sign-off is a prompt-bound single-use HMAC token | `token_is_bound_to_prompt_and_key_and_single_use` | `cargo test -p archon_kernel` |
| Verifier cannot be the same endpoint as the generator (by default) | `test_verifier_must_be_independent` | `cargo test --test integration` |
| No output without a stored receipt | `passing_answer_is_withheld_when_receipt_cannot_be_stored` | `cargo test --test integration` |
| Hash-chained audit detects tampering | `edited_row_is_caught`, `deleted_row_is_caught` | `cargo test -p selin` |
| Database key is derived from passphrase (Argon2id); never stored | `same_passphrase_and_salt_give_the_same_key` | `cargo test -p selin` |
| Tier-1 screen normalises invisible characters before keyword match | `invisible_characters_do_not_hide_a_severe_phrase` | `cargo test -p archon_kernel` |
| Non-loopback bind without API key is refused (the real binary exits 1) | `serve_refuses_network_bind_without_api_key` | `cargo test --test integration` |
| A high-risk sign-off is redeemed, not trusted, end to end | `high_risk_signoff_is_redeemed_not_trusted_end_to_end` | `cargo test --test integration` |
| Prompt sanitizer strips zero-width injection | `test_sanitize_prompt_strips_zero_width_injection` | `cargo test --test server_tests` |

## How this was built

R.W. Yett directs the work. Much of the code and prose was written with AI coding assistants; those commits carry `Co-Authored-By` trailers. What holds is what `cargo test` and `npm test` check.

---

*Part of the **Chyren · Ψ/Φ** constellation, built on the Psimodulo–Phimodus principle: one mind, invariant across substrates, operating as one integrated whole. Author: R.W. Yett · [github.com/Mega-Therion](https://github.com/Mega-Therion).*
