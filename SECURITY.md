# SELIN Security Policy

## Threat model

SELIN defends against the following:

- **AI output injection / hallucination bypass**: the ADCCL gate (χ ≥ 1/√2) and the verifier independence requirement ensure a model cannot self-certify its own output as safe.
- **Sign-off replay and cross-prompt reuse**: high-risk sign-off tokens are HMAC-bound to the exact prompt hash and are single-use; a replayed or cross-prompt token is rejected.
- **Tier-1 (severe threat) bypass**: Tier-1 vetoes are unconditional — no sign-off, flag, or HTTP field can lift them. This is enforced in code and tested by sabotage (`severe_threat_is_refused_with_every_signoff`).
- **Invisible-character keyword bypass**: prompts are Unicode-normalised before the Tier-1 keyword screen, so zero-width or invisible code-point injections do not bypass the classifier (`invisible_characters_do_not_hide_a_severe_phrase`).
- **Receipt loss**: no output is released unless a hash-chained receipt is successfully written to the encrypted store. A write failure is a hard refusal, not a warning.
- **Audit tampering**: each receipt row is sealed to the hash of its predecessor; `selin audit --verify-chain` detects any edit or deletion.
- **Unauthenticated network exposure**: the server refuses to bind a non-loopback address without an API key. The key comparison is constant-time (via `subtle::ConstantTimeEq`).
- **Supply-chain vulnerabilities in dependencies**: CI runs `cargo audit` and `cargo deny` on every pull request; the Dockerfile and docker-compose pin images by digest.

## What SELIN does NOT defend against

- **Traffic analysis**: local-only deployments are not exposed; network deployments should sit behind a reverse proxy with TLS. SELIN itself does not terminate TLS.
- **Key recovery after compromise**: the database passphrase is the sole recovery secret. There is no key escrow. If it is lost, the encrypted store is unrecoverable.
- **Model truthfulness**: the ADCCL gate scores internal consistency and verifier agreement, not ground-truth factual accuracy. A plausible-sounding hallucination that scores above the threshold will pass.
- **The keyword risk screen is a tripwire, not a firewall**: it catches obvious high-risk prompts. A sufficiently paraphrased harmful request may not trigger it. The gate is a layer, not the only layer.

## API key authentication

When running in network mode (`selin serve --bind 0.0.0.0`), an `ARCHON_API_KEY` environment variable is mandatory. The server exits immediately at startup if the variable is unset. Keys are accepted via `Authorization: Bearer <key>` or `X-API-Key: <key>` headers.

The key comparison uses `subtle::ConstantTimeEq` to prevent timing side-channels.

## Reporting a vulnerability

1. **Do NOT** open a public issue.
2. Email `security@chyren.org` with steps to reproduce, impact assessment, and any relevant payload.
3. The team will acknowledge within 24 hours and issue a CVE advisory upon verification and patching.
