//! RYTT seals, signed verdicts and the node handshake (work order item 5).
//!
//! Spec: `docs/RYTT_SEAL_SPEC.md`. RYTT is a lossless, reversible *encoding*. It gives
//! bytes a canonical, human-readable form and is never used as a cipher, signature or
//! key exchange. Every security property here comes from reviewed primitives:
//! Ed25519 (`ed25519-dalek`), and Noise `XX` over X25519/ChaCha20-Poly1305/SHA-256 (`snow`).
//!
//! - A verdict is signed over its JCS (RFC 8785) canonical bytes, then RYTT-encoded.
//!   Opening it checks the grammar is allow-listed, decodes, requires the text to be
//!   canonical already, and verifies the signature. Any failure rejects.
//! - Nodes authenticate with Noise XX. Each binds its Ed25519 verdict key to its Noise
//!   static key with a signature sent inside the encrypted handshake, and accepts a
//!   peer only if the peer's fingerprint is on its operator-approved list.
//! - A fingerprint is 128 bits of SHA-256 over the Ed25519 public key, shown as RYTT
//!   chords so two people can compare it by eye.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rytt_core::{Envelope, RyttSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VERDICT_DOMAIN: &[u8] = b"selin-verdict-v1";
const FINGERPRINT_DOMAIN: &[u8] = b"selin-fp-v1";
const BIND_DOMAIN: &[u8] = b"selin-bind-v1";
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

#[derive(Debug)]
pub enum SealError {
    Rytt(String),
    VocabularyNotAllowed(String),
    NotCanonical,
    BadSignature,
    BadKey,
    Json(String),
    Handshake(String),
    PeerNotApproved([u8; 16]),
    BindingInvalid,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rytt(m) => write!(f, "RYTT: {m}"),
            Self::VocabularyNotAllowed(h) => write!(f, "RYTT vocabulary {h} is not allow-listed"),
            Self::NotCanonical => write!(f, "decoded payload is not JCS-canonical"),
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::BadKey => write!(f, "malformed public key"),
            Self::Json(m) => write!(f, "JSON: {m}"),
            Self::Handshake(m) => write!(f, "handshake: {m}"),
            Self::PeerNotApproved(fp) => {
                write!(f, "peer fingerprint {} is not approved", hex::encode(fp))
            }
            Self::BindingInvalid => {
                write!(f, "peer's Ed25519-to-Noise key binding does not verify")
            }
        }
    }
}
impl std::error::Error for SealError {}

/// The RYTT grammar SELIN is built against (rytt-core pinned at bdbc971).
pub fn spec() -> Result<RyttSpec, SealError> {
    RyttSpec::embedded().map_err(|e| SealError::Rytt(e.to_string()))
}

/// Vocabulary hashes accepted on incoming envelopes: only the pinned grammar.
pub fn default_allow_list() -> Result<Vec<String>, SealError> {
    Ok(vec![spec()?.vocabulary_hash()])
}

/// JCS (RFC 8785) canonical form of a JSON value.
pub fn canonical(payload: &Value) -> Result<String, SealError> {
    serde_jcs::to_string(payload).map_err(|e| SealError::Json(e.to_string()))
}

/// RYTT-encode text through the pinned grammar.
pub fn encode(text: &str) -> Result<Envelope, SealError> {
    rytt_core::encode(&spec()?, text).map_err(|e| SealError::Rytt(e.to_string()))
}

/// RYTT-decode an envelope through the pinned grammar.
pub fn decode(envelope: &Envelope) -> Result<String, SealError> {
    rytt_core::decode(&spec()?, envelope).map_err(|e| SealError::Rytt(e.to_string()))
}

/// What travels on the wire: the RYTT envelope of the canonical payload, and its signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireVerdict {
    pub rytt: Envelope,
    pub sig: String,
    pub signer: String,
}

/// Sign a verdict over its canonical bytes, then RYTT-encode those bytes.
pub fn seal_verdict(key: &SigningKey, payload: &Value) -> Result<WireVerdict, SealError> {
    let c = canonical(payload)?;
    let mut msg = VERDICT_DOMAIN.to_vec();
    msg.extend_from_slice(c.as_bytes());
    let sig = key.sign(&msg);
    Ok(WireVerdict {
        rytt: encode(&c)?,
        sig: hex::encode(sig.to_bytes()),
        signer: hex::encode(key.verifying_key().to_bytes()),
    })
}

/// Open a wire verdict. Returns the payload only if every check passes.
pub fn open_verdict(wire: &WireVerdict, allow: &[String]) -> Result<Value, SealError> {
    if !allow.iter().any(|h| h == &wire.rytt.vocabulary_hash) {
        return Err(SealError::VocabularyNotAllowed(
            wire.rytt.vocabulary_hash.clone(),
        ));
    }
    let c = decode(&wire.rytt)?;
    let value: Value = serde_json::from_str(&c).map_err(|e| SealError::Json(e.to_string()))?;
    if canonical(&value)? != c {
        return Err(SealError::NotCanonical);
    }
    let pk = verifying_key_from_hex(&wire.signer)?;
    let sig_bytes: [u8; 64] = hex::decode(&wire.sig)
        .map_err(|_| SealError::BadSignature)?
        .try_into()
        .map_err(|_| SealError::BadSignature)?;
    let mut msg = VERDICT_DOMAIN.to_vec();
    msg.extend_from_slice(c.as_bytes());
    pk.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| SealError::BadSignature)?;
    Ok(value)
}

fn verifying_key_from_hex(h: &str) -> Result<VerifyingKey, SealError> {
    let b: [u8; 32] = hex::decode(h)
        .map_err(|_| SealError::BadKey)?
        .try_into()
        .map_err(|_| SealError::BadKey)?;
    VerifyingKey::from_bytes(&b).map_err(|_| SealError::BadKey)
}

/// 128-bit fingerprint of an Ed25519 public key.
pub fn fingerprint(pk: &VerifyingKey) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(pk.to_bytes());
    let d = h.finalize();
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&d[..16]);
    fp
}

/// The full 128-bit fingerprint as RYTT chords, for comparing by eye.
pub fn fingerprint_glyphs(pk: &VerifyingKey) -> Result<String, SealError> {
    Ok(encode(&base32(&fingerprint(pk)))?.encoded_display)
}

/// RFC 4648 base32, upper case, no padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A node's long-term identity: an Ed25519 verdict key and a Noise (X25519) static key.
pub struct NodeIdentity {
    pub signing: SigningKey,
    noise_private: Vec<u8>,
    pub noise_public: Vec<u8>,
}

impl NodeIdentity {
    /// Fresh keys from the OS random source.
    pub fn generate() -> Result<Self, SealError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| SealError::Handshake(e.to_string()))?;
        let kp = snow::Builder::new(params()?)
            .generate_keypair()
            .map_err(|e| SealError::Handshake(e.to_string()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
            noise_private: kp.private,
            noise_public: kp.public,
        })
    }

    pub fn fingerprint(&self) -> [u8; 16] {
        fingerprint(&self.signing.verifying_key())
    }

    /// Ed25519 public key followed by its signature over this node's Noise static key.
    fn binding(&self) -> Vec<u8> {
        let mut msg = BIND_DOMAIN.to_vec();
        msg.extend_from_slice(&self.noise_public);
        let mut out = self.signing.verifying_key().to_bytes().to_vec();
        out.extend_from_slice(&self.signing.sign(&msg).to_bytes());
        out
    }
}

fn params() -> Result<snow::params::NoiseParams, SealError> {
    NOISE_PARAMS
        .parse()
        .map_err(|e: snow::Error| SealError::Handshake(e.to_string()))
}

/// Check a peer's binding payload against the Noise static key the handshake proved,
/// and the operator's approved fingerprints. Returns the peer's Ed25519 key.
fn check_binding(
    payload: &[u8],
    remote_static: &[u8],
    approved: &[[u8; 16]],
) -> Result<VerifyingKey, SealError> {
    if payload.len() != 32 + 64 {
        return Err(SealError::BindingInvalid);
    }
    let pk = VerifyingKey::from_bytes(payload[..32].try_into().unwrap())
        .map_err(|_| SealError::BindingInvalid)?;
    let sig = Signature::from_bytes(payload[32..].try_into().unwrap());
    let mut msg = BIND_DOMAIN.to_vec();
    msg.extend_from_slice(remote_static);
    pk.verify(&msg, &sig)
        .map_err(|_| SealError::BindingInvalid)?;
    let fp = fingerprint(&pk);
    if !approved.contains(&fp) {
        return Err(SealError::PeerNotApproved(fp));
    }
    Ok(pk)
}

/// One side of a Noise XX handshake. Drive it with [`Handshake::next_out`] and
/// [`Handshake::take_in`] over any byte transport; when it finishes, [`Handshake::finish`]
/// yields the encrypted transport and the authenticated peer key.
pub struct Handshake {
    state: snow::HandshakeState,
    identity_binding: Vec<u8>,
    approved: Vec<[u8; 16]>,
    initiator: bool,
    step: u8,
    peer: Option<VerifyingKey>,
}

impl Handshake {
    pub fn initiator(me: &NodeIdentity, approved: &[[u8; 16]]) -> Result<Self, SealError> {
        Self::new(me, approved, true)
    }
    pub fn responder(me: &NodeIdentity, approved: &[[u8; 16]]) -> Result<Self, SealError> {
        Self::new(me, approved, false)
    }
    fn new(me: &NodeIdentity, approved: &[[u8; 16]], initiator: bool) -> Result<Self, SealError> {
        let b = snow::Builder::new(params()?)
            .local_private_key(&me.noise_private)
            .map_err(|e| SealError::Handshake(e.to_string()))?;
        let state = if initiator {
            b.build_initiator()
        } else {
            b.build_responder()
        }
        .map_err(|e| SealError::Handshake(e.to_string()))?;
        Ok(Self {
            state,
            identity_binding: me.binding(),
            approved: approved.to_vec(),
            initiator,
            step: 0,
            peer: None,
        })
    }

    /// Produce this side's next handshake message. XX: -> e, <- e ee s es (+binding),
    /// -> s se (+binding).
    pub fn next_out(&mut self) -> Result<Vec<u8>, SealError> {
        let payload: &[u8] = match (self.initiator, self.step) {
            (true, 0) => &[],
            (false, 1) | (true, 2) => &self.identity_binding,
            _ => return Err(SealError::Handshake("not this side's turn to send".into())),
        };
        let mut buf = vec![0u8; 65535];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| SealError::Handshake(e.to_string()))?;
        buf.truncate(n);
        self.step += 1;
        Ok(buf)
    }

    /// Consume the peer's next handshake message; checks the binding when it carries one.
    pub fn take_in(&mut self, msg: &[u8]) -> Result<(), SealError> {
        let mut buf = vec![0u8; 65535];
        let n = self
            .state
            .read_message(msg, &mut buf)
            .map_err(|e| SealError::Handshake(e.to_string()))?;
        let carries_binding = matches!((self.initiator, self.step), (true, 1) | (false, 2));
        if carries_binding {
            let rs = self
                .state
                .get_remote_static()
                .ok_or(SealError::BindingInvalid)?
                .to_vec();
            self.peer = Some(check_binding(&buf[..n], &rs, &self.approved)?);
        }
        self.step += 1;
        Ok(())
    }

    /// The encrypted channel and the peer's authenticated Ed25519 key.
    pub fn finish(self) -> Result<(snow::TransportState, VerifyingKey), SealError> {
        let peer = self
            .peer
            .ok_or_else(|| SealError::Handshake("peer not authenticated".into()))?;
        let t = self
            .state
            .into_transport_mode()
            .map_err(|e| SealError::Handshake(e.to_string()))?;
        Ok((t, peer))
    }
}

/// An authenticated channel: the Noise transport and the peer's Ed25519 key.
pub type Session = (snow::TransportState, VerifyingKey);

/// Run a whole handshake between two in-process sides (tests, local tooling).
pub fn handshake_pair(
    a: &NodeIdentity,
    a_approves: &[[u8; 16]],
    b: &NodeIdentity,
    b_approves: &[[u8; 16]],
) -> Result<(Session, Session), SealError> {
    let mut i = Handshake::initiator(a, a_approves)?;
    let mut r = Handshake::responder(b, b_approves)?;
    r.take_in(&i.next_out()?)?;
    i.take_in(&r.next_out()?)?;
    r.take_in(&i.next_out()?)?;
    Ok((i.finish()?, r.finish()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verdict() -> Value {
        json!({"run_id": "r-1", "prompt_hash": "ab", "v_score": 0.9, "j_penalty": 0.1,
               "chi": 0.9, "passed": true, "rejection_reason": null, "row_hash": "cd",
               "created_at": "2026-10-22T00:00:00Z"})
    }

    // Spec test 1: round trip against RYTT's conformance vectors through SELIN's wrapper.
    #[test]
    fn conformance_vectors_round_trip_through_the_wrapper() {
        let raw = include_str!("../tests/fixtures/rytt_vectors_bdbc971.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let vectors = v["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for vec in vectors {
            let src = vec["source"].as_str().unwrap();
            let env = encode(src).unwrap();
            assert_eq!(
                env.encoded_display,
                vec["encoded_display"].as_str().unwrap(),
                "{}",
                vec["id"]
            );
            assert_eq!(decode(&env).unwrap(), src, "{}", vec["id"]);
        }
    }

    #[test]
    fn a_sealed_verdict_opens_to_the_same_payload() {
        let id = NodeIdentity::generate().unwrap();
        let w = seal_verdict(&id.signing, &verdict()).unwrap();
        assert_eq!(
            open_verdict(&w, &default_allow_list().unwrap()).unwrap(),
            verdict()
        );
    }

    // Spec test 2: tampering after RYTT encoding fails verification.
    #[test]
    fn a_verdict_altered_after_encoding_is_rejected() {
        let id = NodeIdentity::generate().unwrap();
        let allow = default_allow_list().unwrap();
        let good = seal_verdict(&id.signing, &verdict()).unwrap();

        let mut flipped_sig = good.clone();
        let mut s = hex::decode(&flipped_sig.sig).unwrap();
        s[0] ^= 1;
        flipped_sig.sig = hex::encode(s);
        assert!(matches!(
            open_verdict(&flipped_sig, &allow),
            Err(SealError::BadSignature)
        ));

        // Change the payload, re-encode it honestly, keep the old signature.
        let mut forged = good.clone();
        let mut v = verdict();
        v["passed"] = json!(false);
        forged.rytt = encode(&canonical(&v).unwrap()).unwrap();
        assert!(open_verdict(&forged, &allow).is_err());

        // Flip one token inside the envelope itself.
        let mut tok = good.clone();
        let mut chars: Vec<char> = tok.rytt.encoded_display.chars().collect();
        let i = chars
            .iter()
            .position(|c| (0xE000..=0xF8FF).contains(&(*c as u32)))
            .unwrap();
        chars.swap(i, i + 1);
        tok.rytt.encoded_display = chars.into_iter().collect();
        assert!(open_verdict(&tok, &allow).is_err());
    }

    // Spec test 3: unapproved keys do not complete the handshake; approved ones do.
    #[test]
    fn only_approved_nodes_complete_the_handshake() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let stranger = NodeIdentity::generate().unwrap();

        let ((mut ta, pb), (mut tb, pa)) =
            handshake_pair(&a, &[b.fingerprint()], &b, &[a.fingerprint()]).unwrap();
        assert_eq!(pb, b.signing.verifying_key());
        assert_eq!(pa, a.signing.verifying_key());
        // The channel carries a sealed verdict end to end.
        let wire = serde_json::to_vec(&seal_verdict(&a.signing, &verdict()).unwrap()).unwrap();
        let mut ct = vec![0u8; wire.len() + 64];
        let n = ta.write_message(&wire, &mut ct).unwrap();
        let mut pt = vec![0u8; n];
        let m = tb.read_message(&ct[..n], &mut pt).unwrap();
        let got: WireVerdict = serde_json::from_slice(&pt[..m]).unwrap();
        assert_eq!(
            open_verdict(&got, &default_allow_list().unwrap()).unwrap(),
            verdict()
        );

        // Responder does not approve the stranger.
        assert!(matches!(
            handshake_pair(&stranger, &[b.fingerprint()], &b, &[a.fingerprint()]),
            Err(SealError::PeerNotApproved(_))
        ));
        // Initiator does not approve the responder.
        assert!(matches!(
            handshake_pair(&a, &[stranger.fingerprint()], &b, &[a.fingerprint()]),
            Err(SealError::PeerNotApproved(_))
        ));
    }

    #[test]
    fn a_binding_for_a_different_noise_key_is_rejected() {
        let a = NodeIdentity::generate().unwrap();
        let other = NodeIdentity::generate().unwrap();
        // a's Ed25519 binding, presented with someone else's Noise static key.
        assert!(matches!(
            check_binding(&a.binding(), &other.noise_public, &[a.fingerprint()]),
            Err(SealError::BindingInvalid)
        ));
        assert!(check_binding(&a.binding(), &a.noise_public, &[a.fingerprint()]).is_ok());
    }

    // Spec test 4: an envelope from a grammar not on the allow-list is rejected.
    #[test]
    fn a_vocabulary_not_on_the_allow_list_is_rejected() {
        let id = NodeIdentity::generate().unwrap();
        let w = seal_verdict(&id.signing, &verdict()).unwrap();
        assert!(matches!(
            open_verdict(&w, &["0".repeat(64)]),
            Err(SealError::VocabularyNotAllowed(_))
        ));
    }

    // Spec test 5: a non-canonical payload (same JSON, other key order) is rejected.
    #[test]
    fn a_non_canonical_payload_is_rejected() {
        let id = NodeIdentity::generate().unwrap();
        let c = canonical(&verdict()).unwrap();
        let reordered = r#"{"run_id":"r-1","passed":true}"#;
        assert_ne!(
            canonical(&serde_json::from_str(reordered).unwrap()).unwrap(),
            reordered
        );
        let mut msg = b"selin-verdict-v1".to_vec();
        msg.extend_from_slice(reordered.as_bytes());
        let w = WireVerdict {
            rytt: encode(reordered).unwrap(),
            sig: hex::encode(id.signing.sign(&msg).to_bytes()),
            signer: hex::encode(id.signing.verifying_key().to_bytes()),
        };
        assert!(matches!(
            open_verdict(&w, &default_allow_list().unwrap()),
            Err(SealError::NotCanonical)
        ));
        assert!(!c.is_empty());
    }

    #[test]
    fn fingerprints_are_128_bits_and_shown_as_chords() {
        let id = NodeIdentity::generate().unwrap();
        assert_eq!(id.fingerprint().len(), 16);
        assert_eq!(base32(&[0u8; 16]).len(), 26);
        assert_eq!(base32(b"f"), "MY"); // RFC 4648 test vector, unpadded
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        let g = fingerprint_glyphs(&id.signing.verifying_key()).unwrap();
        assert!(!g.is_empty());
        let other = NodeIdentity::generate().unwrap();
        assert_ne!(
            g,
            fingerprint_glyphs(&other.signing.verifying_key()).unwrap()
        );
    }
}
