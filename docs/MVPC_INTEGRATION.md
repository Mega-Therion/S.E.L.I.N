# SELIN ↔ MVPC-X Integration Contract

**Local-only. No vendor cloud. No personal Chyren/AEON in the open product path.**

---

## 1. Roles

| Component | Job |
|-----------|-----|
| **SELIN (this repo)** | Sovereign RIYU node: identity seal, generative governance (ADCCL χ), myelin audit log |
| **MVPC-X** ([Mega-Therion/MVPC-X](https://github.com/Mega-Therion/MVPC-X)) | Mechanical claim/proof gate: Lean/Coq/Isabelle/Python claims, system self-integrity, witnesses |
| **Personal Chyren / AEON** | Owner-private. **Never** an input source for other users’ SELIN nodes |

```text
User machine
├── selin run / serve     →  LLM governance (χ)
├── selin verify-artifact →  exec local `mvpc` (no network to Mega-Therion)
└── optional: personal AEON (air-gapped from public SELIN releases)
```

---

## 2. Principles

1. **No network between SELIN and MVPC-X** — subprocess / CLI on the same host only.  
2. **MVPC-X is law for formal/claim artifacts** — SELIN must not re-score Lean with χ.  
3. **SELIN remains law for freeform generation** — χ + three-tier gate.  
4. **Both scores may coexist** — e.g. χ-pass + MVPC-REJECTED is a valid, useful outcome.  
5. **Air gap** — public SELIN never imports AEON personal data (`docs/AIR_GAP_POLICY.md`).  
6. **Fail closed** when `SELIN_REQUIRE_MVPC=1` and MVPC is missing or rejects under CI policy.

---

## 3. When to call whom

| Input | Primary gate |
|-------|----------------|
| Chat / freeform prompt | SELIN ADCCL (`selin run` / `POST /v1/govern`) |
| `.lean` `.v` `.thy` `.py` with claims / claim packages | **MVPC-X** via `selin verify-artifact` |
| Model claims “theorem proved” and writes a file | Generative run incomplete until MVPC audits that path |

---

## 4. CLI

```bash
# Discover / install MVPC-X separately, e.g.:
#   pip install -e /path/to/MVPC-X
#   export MVPC_BIN=mvpc

selin verify-artifact path/to/Theorem.lean
selin verify-artifact path/to/claims.py --policy strict
selin verify-artifact path/to/File.lean --json
selin verify-artifact path/to/File.lean --run-id <adccl-run-id>
```

### Environment

| Variable | Meaning |
|----------|---------|
| `MVPC_BIN` | Path or name of MVPC executable (default: `mvpc`) |
| `SELIN_REQUIRE_MVPC` | If `1`, exit non-zero when MVPC missing or audit fails CI-style |
| `SELIN_MVPC_OUT_DIR` | Directory for saved claim JSON (default: `$HOME/.selin/mvpc_witnesses`) |

---

## 5. Data that may cross the boundary

- Local filesystem path to the artifact  
- Artifact content only as MVPC reads it (SELIN does not re-upload)  
- MVPC stdout JSON (claim + embedded witness + integrity session)  
- Optional `run_id` string for operator correlation  

## 5b. Data that must not cross

- AEON / personal Chyren databases or basepoints  
- Automatic phone-home of witnesses  
- “Cloud co-sign by Mega-Therion”  

---

## 6. Attestation languages (do not collapse)

| SELIN | MVPC-X |
|-------|--------|
| χ pass / reject | VERIFIED / CONDITIONAL / REJECTED / UNVERIFIED |
| fail-closed generative | SYSTEM_INTEGRITY_FAILURE, KERNEL_NEVER_RAN |
| `SELIN_SIGNOFF_TOKEN` | `mvpc attest --signer` (now a prompt-bound HMAC token, not a phrase) |
| myelin `adccl_runs` | witness JSON / claim JSON |

Store **both**. A fluent model answer is not a kernel proof.

---

## 7. Trust one-liner

> SELIN governs model output on your node. MVPC-X mechanically audits formal artifacts on your node. Neither requires the other’s vendor cloud; neither is your private identity.

---

## 8. Operator checklist

1. `selin init` + local model endpoint  
2. Install MVPC-X on the same machine; `mvpc integrity --verify-twice`  
3. `selin verify-artifact ./proof.lean`  
4. Read MVPC `checks_unavailable` before trusting green  
5. Keep HTTP bind on `127.0.0.1` unless you knowingly expose a RIYU  

See also: [AIR_GAP_POLICY.md](./AIR_GAP_POLICY.md), [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md), MVPC-X `docs/INPUT_CONTRACT.md` / `SECURITY.md`.
