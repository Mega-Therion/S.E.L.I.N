# RYTT seals and the node handshake: specification (DRAFT v0.1, for review)

Work order BLK-302 item 5. **Spec first; no code until this is reviewed.** RY's requirement: SELIN uses RYTT for seals and handshakes.

## The boundary, stated once

RYTT is a **lossless, reversible encoding**: `decode(encode(text)) == text` (RYTT conformance vectors; `proofs/RYTT_standalone.lean`). It is not a cipher, a signature or a key exchange, and it is never used as one. Every security property below comes from reviewed primitives (Ed25519, X25519, ChaCha20-Poly1305 and SHA-256, via the Noise protocol). RYTT gives the bytes a canonical, human-readable form.

## (a) Canonical encoding of a seal and a signed verdict envelope

1. **Payload.** A verdict is a JSON object (`run_id`, `prompt_hash`, `v_score`, `j_penalty`, `chi`, `passed`, `rejection_reason`, `row_hash`, `created_at`).
2. **Canonical bytes.** `C = JCS(payload)`, JSON Canonicalization Scheme (RFC 8785), UTF-8. **The signature is always over `C`**, never over a RYTT rendering.
3. **Signature.** `sig = Ed25519.sign(node_identity_key, "selin-verdict-v1" || C)`.
4. **RYTT envelope.** `E = rytt_core::encode(spec, C_as_text)`. The envelope carries `spec_version` and `vocabulary_hash`, so both nodes can tell they hold the same RYTT grammar.
5. **Wire object.** `{ "rytt": E, "sig": hex(sig), "signer": hex(ed25519_pubkey) }`.
6. **Verification.** Require `E.vocabulary_hash` to be on an allow-list; `C' = rytt_core::decode(spec, E)`; require `JCS(parse(C')) == C'`, i.e. it is already canonical; verify `sig` over `"selin-verdict-v1" || C'`. Any failure means reject.

The basepoint seal (HKDF-SHA256 + HMAC-SHA256) keeps its current construction. Its *display form* is the RYTT encoding of the hex seal.

## (b) Node-to-node handshake

- **Protocol:** Noise `XX` (mutual authentication, identity keys sent encrypted), `Noise_XX_25519_ChaChaPoly_SHA256`, via the reviewed `snow` crate. No custom key exchange.
- **Identity:** each node's static Noise key is X25519. Its Ed25519 verdict-signing key is bound to it by an Ed25519 signature over the X25519 public key, sent in the handshake payload.
- **Messages:** after the handshake, transport messages carry wire objects from (a), so the RYTT-encoded envelopes travel inside the authenticated, encrypted channel.
- **Trust:** a node accepts a peer only if the peer's fingerprint (c) is on its operator-approved list. There is no trust-on-first-use by default.

## (c) Glyph fingerprint a person can compare by eye

- `fp = first_16_bytes(SHA-256("selin-fp-v1" || ed25519_pubkey))`, i.e. 128 bits.
- Display it as `rytt_core::encode(spec, base32(fp))`: a short chord sequence. Two people read their chord strings aloud or side by side.
- 128 bits is chosen so a collision cannot be ground out. A 64-bit "short form" may be shown for convenience, but approval always compares the full 128 bits.

## Dependencies (all reviewed, pinned)

| Purpose | Crate |
|---|---|
| RYTT encode/decode | `rytt-core` 0.1.0, git dependency pinned to RYTT-Sovereign-Semiotics `bdbc971` |
| Ed25519 | `ed25519-dalek` 2.x |
| Noise XX | `snow` 0.9.x |
| JCS | `serde_jcs` (or a vetted equivalent; decided in review) |

## Required tests (from the work order), written before the code they test

1. Round trip against RYTT's `conformance/vectors.json` through SELIN's wrapper.
2. A seal or verdict altered **after** RYTT encoding fails verification (flip one token in `E`; flip one byte in `sig`).
3. Two nodes with different, unapproved keys do not complete the handshake; with approved keys they do.
4. An envelope whose `vocabulary_hash` is not allow-listed is rejected.
5. A non-canonical `C'` (same JSON, different key order) is rejected.

## Open questions for review

1. JCS crate choice, and whether to vendor it.
2. Should verdict envelopes also travel over HTTP (the server API), or only node-to-node?
3. Key rotation: identity-key lifetime, and how approvals migrate.
4. Whether the 64-bit short fingerprint is shown at all.
