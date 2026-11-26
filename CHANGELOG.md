# Changelog

All notable changes to ARCHON / SELIN.

---

## [Unreleased] — Cross-language gate conformance

### Changed
- **ADCCL gate domain check (fail-closed)** — the Rust kernel (`AdcclGate::evaluate`) and the JS edge gate (`gate.mjs`) follow one contract: V and J must each be a finite number in [0, 1]. NaN, ±Infinity and any value outside [0, 1] are refused: signal `abort`, `passed` false, `rejection_reason` exactly `DOMAIN_REFUSAL`, χ and mirror χ NaN. The kernel used to clamp a finite out-of-range score into [0, 1], so V = 1.2 was judged as V = 1 and could pass, while the edge gate refused it. Nothing documented clamping as intended (`verifier::extract_scores` already rejects out-of-range scores), so the kernel now refuses as the edge does. The first check is renamed `finiteness` → `domain`, also in `/api/archon/status`.

### Added
- **`archon_kernel/tests/fixtures/selin_gate_vectors.json`** — 71 shared gate vectors: passes, the holes a floor-only gate leaves open, the floor, ceiling, mirror and components bounds exactly, one float either side and ±1e-12, out-of-range scores, NaN and ±Infinity. Printed by `cargo run -q --locked -p archon_kernel --example selin_gate_vectors`, which refuses to print if the kernel's verdict on any row differs from the verdict the row states.
- **`archon_kernel/tests/gate_conformance.rs`** and **`test/gate_vectors.test.mjs`** — the kernel and the edge gate held to every row. CI runs both and diffs a fresh regeneration against the committed file.

---

## [Unreleased] — MVPC-X local bridge

### Added
- **`docs/MVPC_INTEGRATION.md`** — contract: SELIN governs generation; MVPC-X audits formal artifacts; local subprocess only; no personal Chyren; no vendor cloud notary.
- **`selin verify-artifact <path>`** — spawns local `mvpc` (`MVPC_BIN`), `--policy`, `--json`, optional `--run-id` correlation sidecar under `~/.selin/mvpc_witnesses`.
- **`serve --bind`** — default **127.0.0.1** (local-first); Docker CMD uses `0.0.0.0` explicitly.
- **`.gitignore`** — ignore `node_modules/`, local RIYU state, venvs.

### Notes
- χ and MVPC attestation languages are **not** collapsed; both may be stored/correlated.
- Personal AEON/Chyren remains out of band (see AIR_GAP_POLICY).

---

## Prior

See git history for axum server, ADCCL fail-closed verifier, SQLCipher, air-gap policy, and universalize renames.
