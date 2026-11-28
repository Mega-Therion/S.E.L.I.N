//! Proof of Work Inversion (PoWI) receipt verification (spec §6.5).
//!
//! A veto, quarantine, or sanction against a peer is valid only when the
//! sanctioning party attaches a **machine-checkable proof of violation** —
//! the burden of proof is inverted onto the accuser. Bare majority votes
//! cannot sanction anyone, and honest minority dissent carries zero penalty:
//! there is simply no receipt type that proves "disagreed with the majority".
//!
//! Three violation kinds are machine-checkable today:
//!
//! - **Broken hash chain** — the receipt carries the *full* audit-chain row
//!   (its fields and `prev_hash`) plus the `row_hash` the subject *claimed*
//!   for it. The evaluator recomputes the chain hash from the presented row
//!   itself (the `selin-receipt-v1` construction, identical to
//!   `selin::governance::row_hash`); the proof holds only when that
//!   recomputation does **not** reproduce the claimed hash. The row is the
//!   evidence — a caller-supplied "recomputed" number is never trusted.
//! - **Failed deterministic check** — the receipt carries a check id, the
//!   expected and observed outputs, the hash of the audit row the check ran
//!   against, and a **checker attestation**: an Ed25519 signature by a
//!   checker key over (row hash, check id, expected, observed). The proof
//!   holds only when expected ≠ observed *and* the attestation verifies
//!   under a checker key the evaluator trusts. Trusted checker keys are
//!   evaluator configuration (see [`PowiReceipt::verify`]), never taken from
//!   the receipt — a proposer signing its own chosen strings proves nothing.
//! - **Verified equivocation** — the receipt carries two *different*
//!   statements, both validly signed by the subject's own key, and the
//!   evidence's subject key must be exactly the receipt's subject: statements
//!   signed by peer A can never sanction peer B. Saying two contradictory
//!   things under one key is the provable offense (BFT accounting slashes
//!   equivocation; it never slashes dissent).
//!
//! Verification is fail-closed and total: a receipt whose issuer signature,
//! attestation, or evidence does not check out proves nothing, and
//! [`evaluate_sanction`] upholds a sanction only for a fully verified receipt.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::rytt_seal;

const POWI_DOMAIN: &[u8] = b"selin-powi-v1";
const EQUIVOCATION_DOMAIN: &[u8] = b"selin-powi-equivocation-v1";
const CHECKER_DOMAIN: &[u8] = b"selin-powi-checker-v1";
/// Domain of the audit receipt chain — must match `selin::governance::row_hash`.
const RECEIPT_CHAIN_DOMAIN: &[u8] = b"selin-receipt-v1";

/// Recompute an audit-chain row hash, byte-for-byte the construction used by
/// the node's audit store (`selin::governance::row_hash`): SHA-256 over the
/// domain, the previous hash, and each field preceded by a `0x1f` separator.
pub fn receipt_chain_hash(prev_hash: &str, fields: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(RECEIPT_CHAIN_DOMAIN);
    h.update(prev_hash.as_bytes());
    for f in fields {
        h.update([0x1f]);
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

/// The exact message a checker signs to attest a deterministic check result:
/// domain-separated, binding the audit row the check ran against, the check
/// id, and both outputs. Changing any of them after signing invalidates the
/// attestation.
pub fn checker_attestation_message(
    audit_row_hash: &str,
    check_id: &str,
    expected: &str,
    observed: &str,
) -> Vec<u8> {
    let mut msg = CHECKER_DOMAIN.to_vec();
    for part in [audit_row_hash, check_id, expected, observed] {
        msg.push(0x1f);
        msg.extend_from_slice(part.as_bytes());
    }
    msg
}

/// Produce a checker attestation as a real checker would: sign
/// [`checker_attestation_message`] with the checker's key. Returns the hex
/// signature; the checker's hex public key is `key.verifying_key()`.
pub fn sign_checker_attestation(
    key: &SigningKey,
    audit_row_hash: &str,
    check_id: &str,
    expected: &str,
    observed: &str,
) -> String {
    let msg = checker_attestation_message(audit_row_hash, check_id, expected, observed);
    hex::encode(key.sign(&msg).to_bytes())
}

/// Sign an equivocation statement as the subject would: domain-separated
/// Ed25519 over the statement's bytes. (Used by issuers of evidence and by
/// tests; a subject's real statements are produced by its own signing path.)
pub fn sign_statement(key: &SigningKey, statement: &str) -> String {
    let mut msg = EQUIVOCATION_DOMAIN.to_vec();
    msg.extend_from_slice(statement.as_bytes());
    hex::encode(key.sign(&msg).to_bytes())
}

/// The machine-checkable evidence attached to a PoWI receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ViolationEvidence {
    /// The subject's audit chain does not recompute. The full row is
    /// presented (`row_fields` chained on `prev_hash`); the evaluator
    /// recomputes its hash itself and compares against `claimed_row_hash`,
    /// the hash the subject claimed for this row.
    BrokenHashChain {
        row_fields: Vec<String>,
        prev_hash: String,
        claimed_row_hash: String,
    },
    /// A deterministic check produced `observed` where `expected` was
    /// required, attested by a trusted checker: `checker_signature` is the
    /// checker's Ed25519 signature over (audit_row_hash, check_id,
    /// expected, observed), verifiable under `checker_key`.
    FailedDeterministicCheck {
        check_id: String,
        expected: String,
        observed: String,
        /// Hex hash of the audit row the check ran against.
        audit_row_hash: String,
        /// Hex Ed25519 public key of the checker that ran the check.
        checker_key: String,
        /// Hex Ed25519 checker attestation (see [`sign_checker_attestation`]).
        checker_signature: String,
    },
    /// The subject signed two different statements with its own key.
    /// `subject_key` must equal the receipt's `subject`.
    VerifiedEquivocation {
        /// Hex Ed25519 public key of the subject.
        subject_key: String,
        statement_a: String,
        statement_b: String,
        signature_a: String,
        signature_b: String,
    },
}

impl ViolationEvidence {
    /// Machine-check the evidence itself. `Ok(())` means the violation is
    /// *proven*; any error means the evidence proves nothing.
    ///
    /// `subject` is the receipt's subject (used to bind equivocation evidence
    /// to the peer actually being sanctioned); `trusted_checkers` is the
    /// evaluator's configured set of hex checker keys whose deterministic
    /// check attestations count as proof.
    fn check(&self, subject: &str, trusted_checkers: &[String]) -> Result<(), PowiError> {
        match self {
            Self::BrokenHashChain {
                row_fields,
                prev_hash,
                claimed_row_hash,
            } => {
                // Authenticate by recomputation from the presented row —
                // never by comparing two caller-supplied numbers.
                let refs: Vec<&str> = row_fields.iter().map(String::as_str).collect();
                let recomputed = receipt_chain_hash(prev_hash, &refs);
                if recomputed == *claimed_row_hash {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "the presented row recomputes to the claimed hash; no break is proven"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::FailedDeterministicCheck {
                check_id,
                expected,
                observed,
                audit_row_hash,
                checker_key,
                checker_signature,
            } => {
                if expected == observed {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "expected and observed outputs agree; no failure is proven".into(),
                    ));
                }
                // The checker must be one the evaluator trusts — configured
                // by the evaluator, never asserted by the receipt.
                if !trusted_checkers.iter().any(|k| k == checker_key) {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "checker key is not in the evaluator's trusted checker set".into(),
                    ));
                }
                let pk = key_from_hex(checker_key)?;
                let sig_bytes: [u8; 64] = hex::decode(checker_signature)
                    .map_err(|_| PowiError::BadSignature)?
                    .try_into()
                    .map_err(|_| PowiError::BadSignature)?;
                let msg =
                    checker_attestation_message(audit_row_hash, check_id, expected, observed);
                pk.verify(&msg, &Signature::from_bytes(&sig_bytes))
                    .map_err(|_| PowiError::BadSignature)?;
                Ok(())
            }
            Self::VerifiedEquivocation {
                subject_key,
                statement_a,
                statement_b,
                signature_a,
                signature_b,
            } => {
                // Bind the evidence to the receipt's subject: statements
                // signed by peer A must not sanction peer B.
                if subject_key != subject {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "equivocation subject key does not match the receipt subject".into(),
                    ));
                }
                if statement_a == statement_b {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "the two statements are identical; no equivocation is proven".into(),
                    ));
                }
                let pk = key_from_hex(subject_key)?;
                verify_statement(&pk, statement_a, signature_a)?;
                verify_statement(&pk, statement_b, signature_b)?;
                Ok(())
            }
        }
    }
}

fn key_from_hex(h: &str) -> Result<VerifyingKey, PowiError> {
    let b: [u8; 32] = hex::decode(h)
        .map_err(|_| PowiError::BadKey)?
        .try_into()
        .map_err(|_| PowiError::BadKey)?;
    VerifyingKey::from_bytes(&b).map_err(|_| PowiError::BadKey)
}

fn verify_statement(pk: &VerifyingKey, statement: &str, sig_hex: &str) -> Result<(), PowiError> {
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|_| PowiError::BadSignature)?
        .try_into()
        .map_err(|_| PowiError::BadSignature)?;
    let mut msg = EQUIVOCATION_DOMAIN.to_vec();
    msg.extend_from_slice(statement.as_bytes());
    pk.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| PowiError::BadSignature)
}

/// A signed PoWI receipt: the only instrument that can uphold a sanction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowiReceipt {
    /// Who or what is sanctioned: a peer fingerprint or artifact hash (hex).
    /// For equivocation evidence this must be the subject's hex public key.
    pub subject: String,
    pub evidence: ViolationEvidence,
    /// Hex Ed25519 public key of the sanctioning node.
    pub issuer: String,
    /// Hex Ed25519 signature over the canonical receipt body.
    pub signature: String,
}

impl PowiReceipt {
    fn body(&self) -> Value {
        json!({
            "subject": self.subject,
            "evidence": self.evidence,
            "issuer": self.issuer,
        })
    }

    /// Issue a receipt: the issuer signs the canonical body. Issuing does not
    /// assert the evidence is sound — [`Self::verify`] decides that, on any
    /// node, without trusting the issuer.
    pub fn issue(
        key: &SigningKey,
        subject: &str,
        evidence: ViolationEvidence,
    ) -> Result<Self, PowiError> {
        let mut receipt = Self {
            subject: subject.to_string(),
            evidence,
            issuer: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let c = rytt_seal::canonical(&receipt.body())
            .map_err(|e| PowiError::Malformed(e.to_string()))?;
        let mut msg = POWI_DOMAIN.to_vec();
        msg.extend_from_slice(c.as_bytes());
        receipt.signature = hex::encode(key.sign(&msg).to_bytes());
        Ok(receipt)
    }

    /// Full verification: the issuer's signature must cover the body, and the
    /// evidence must machine-check against authenticated inputs.
    /// `trusted_checkers` is the evaluator's configured set of hex checker
    /// keys (only consulted by deterministic-check evidence).
    pub fn verify(&self, trusted_checkers: &[String]) -> Result<(), PowiError> {
        let pk = key_from_hex(&self.issuer)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| PowiError::BadSignature)?
            .try_into()
            .map_err(|_| PowiError::BadSignature)?;
        let c =
            rytt_seal::canonical(&self.body()).map_err(|e| PowiError::Malformed(e.to_string()))?;
        let mut msg = POWI_DOMAIN.to_vec();
        msg.extend_from_slice(c.as_bytes());
        pk.verify(&msg, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| PowiError::BadSignature)?;
        self.evidence.check(&self.subject, trusted_checkers)
    }
}

/// The outcome of presenting (or failing to present) a PoWI receipt for a
/// proposed sanction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanctionDecision {
    /// A fully verified PoWI receipt backs the sanction.
    Upheld,
    /// No receipt was presented: a bare vote cannot sanction (§6.5).
    RejectedNoProof,
    /// A receipt was presented but does not verify or proves nothing.
    RejectedInvalidProof,
}

/// Adjudicate a proposed sanction. Fail-closed: anything short of a fully
/// verified receipt rejects the sanction. Honest dissent needs no branch
/// here — no evidence type can prove it, so it can never be upheld.
/// `trusted_checkers` is the evaluator's configured trusted checker set.
pub fn evaluate_sanction(
    receipt: Option<&PowiReceipt>,
    trusted_checkers: &[String],
) -> SanctionDecision {
    match receipt {
        None => SanctionDecision::RejectedNoProof,
        Some(r) => match r.verify(trusted_checkers) {
            Ok(()) => SanctionDecision::Upheld,
            Err(_) => SanctionDecision::RejectedInvalidProof,
        },
    }
}

#[derive(Debug)]
pub enum PowiError {
    BadSignature,
    BadKey,
    Malformed(String),
    EvidenceDoesNotProve(String),
}

impl std::fmt::Display for PowiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::BadKey => write!(f, "malformed public key"),
            Self::Malformed(m) => write!(f, "malformed receipt: {m}"),
            Self::EvidenceDoesNotProve(m) => write!(f, "evidence does not prove a violation: {m}"),
        }
    }
}
impl std::error::Error for PowiError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn checker() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn trusted() -> Vec<String> {
        vec![hex::encode(checker().verifying_key().to_bytes())]
    }

    fn chain_evidence(honest: bool) -> ViolationEvidence {
        let fields = vec!["run-1".to_string(), "2026-11-25T00:00:00Z".to_string()];
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let real = receipt_chain_hash("", &refs);
        ViolationEvidence::BrokenHashChain {
            row_fields: fields,
            prev_hash: String::new(),
            claimed_row_hash: if honest { real } else { "00".repeat(32) },
        }
    }

    fn check_evidence(key: &SigningKey) -> ViolationEvidence {
        let row_hash = receipt_chain_hash("", &["run-1"]);
        ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "sorryAx found".into(),
            checker_signature: sign_checker_attestation(
                key,
                &row_hash,
                "lean-kernel",
                "pass",
                "sorryAx found",
            ),
            checker_key: hex::encode(key.verifying_key().to_bytes()),
            audit_row_hash: row_hash,
        }
    }

    #[test]
    fn a_broken_chain_is_proven_by_recomputation() {
        let r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(false)).unwrap();
        r.verify(&[]).unwrap();
        assert_eq!(
            evaluate_sanction(Some(&r), &[]),
            SanctionDecision::Upheld
        );
    }

    #[test]
    fn an_intact_chain_proves_nothing() {
        // The presented row recomputes to the claimed hash: the "violation"
        // is fabricated, however the receipt is signed.
        let r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(true)).unwrap();
        assert!(matches!(
            r.verify(&[]),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));
        assert_eq!(
            evaluate_sanction(Some(&r), &[]),
            SanctionDecision::RejectedInvalidProof
        );
    }

    #[test]
    fn regression_forged_row_cannot_substitute_for_a_real_audit_row() {
        // Regression (finding 1): the old API upheld a sanction when a
        // caller-chosen "recomputed" number merely mismatched the claimed
        // hash. Now the row itself must be presented: swapping in fabricated
        // row fields whose hash *does* equal the claimed hash proves nothing,
        // because the evaluator recomputes from the presented row.
        let fields = vec!["fabricated-row".to_string()];
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let claimed = receipt_chain_hash("", &refs);
        let ev = ViolationEvidence::BrokenHashChain {
            row_fields: fields,
            prev_hash: String::new(),
            claimed_row_hash: claimed,
        };
        let r = PowiReceipt::issue(&issuer(), "peer-a", ev).unwrap();
        assert_eq!(
            evaluate_sanction(Some(&r), &[]),
            SanctionDecision::RejectedInvalidProof
        );
    }

    #[test]
    fn a_failed_check_needs_a_trusted_checker_attestation() {
        // Legitimate path: a trusted checker attests the failure.
        let good = check_evidence(&checker());
        let r = PowiReceipt::issue(&issuer(), "art-1", good).unwrap();
        r.verify(&trusted()).unwrap();
        assert_eq!(
            evaluate_sanction(Some(&r), &trusted()),
            SanctionDecision::Upheld
        );

        // Expected == observed: nothing failed, even with a real attestation.
        let row_hash = receipt_chain_hash("", &["run-1"]);
        let no_failure = ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "pass".into(),
            checker_signature: sign_checker_attestation(
                &checker(),
                &row_hash,
                "lean-kernel",
                "pass",
                "pass",
            ),
            checker_key: hex::encode(checker().verifying_key().to_bytes()),
            audit_row_hash: row_hash,
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), "art-1", no_failure)
                .unwrap()
                .verify(&trusted()),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));
    }

    #[test]
    fn regression_self_signed_checker_attestation_proves_nothing() {
        // Regression (finding 1): the proposer mints its own "checker" key,
        // signs its own chosen strings, and presents the result. The old
        // public-witness-hash check accepted this; an evaluator that does
        // not trust that key must reject it.
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let ev = check_evidence(&attacker);
        let r = PowiReceipt::issue(&issuer(), "art-1", ev).unwrap();
        assert!(matches!(
            r.verify(&trusted()),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));
        assert_eq!(
            evaluate_sanction(Some(&r), &trusted()),
            SanctionDecision::RejectedInvalidProof
        );
    }

    #[test]
    fn regression_checker_attestation_is_bound_to_row_and_outputs() {
        // Regression (finding 1): an attestation borrowed from another check
        // (different row / observed output) must not verify for this one.
        let row_hash = receipt_chain_hash("", &["run-1"]);
        let borrowed = ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "timeout".into(),
            checker_signature: sign_checker_attestation(
                &checker(),
                &row_hash,
                "lean-kernel",
                "pass",
                "sorryAx found", // attested a different observed output
            ),
            checker_key: hex::encode(checker().verifying_key().to_bytes()),
            audit_row_hash: row_hash,
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), "art-1", borrowed)
                .unwrap()
                .verify(&trusted()),
            Err(PowiError::BadSignature)
        ));
    }

    #[test]
    fn equivocation_needs_two_different_statements_under_one_key() {
        let subject = SigningKey::from_bytes(&[9u8; 32]);
        let subject_key = hex::encode(subject.verifying_key().to_bytes());
        let ev = ViolationEvidence::VerifiedEquivocation {
            subject_key: subject_key.clone(),
            statement_a: "block height 10 is X".into(),
            statement_b: "block height 10 is Y".into(),
            signature_a: sign_statement(&subject, "block height 10 is X"),
            signature_b: sign_statement(&subject, "block height 10 is Y"),
        };
        PowiReceipt::issue(&issuer(), &subject_key, ev)
            .unwrap()
            .verify(&[])
            .unwrap();

        // Same statement twice is not equivocation.
        let same = ViolationEvidence::VerifiedEquivocation {
            subject_key: subject_key.clone(),
            statement_a: "block height 10 is X".into(),
            statement_b: "block height 10 is X".into(),
            signature_a: sign_statement(&subject, "block height 10 is X"),
            signature_b: sign_statement(&subject, "block height 10 is X"),
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), &subject_key, same)
                .unwrap()
                .verify(&[]),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));

        // A statement signed by someone else is not the subject's equivocation.
        let stranger = SigningKey::from_bytes(&[11u8; 32]);
        let forged = ViolationEvidence::VerifiedEquivocation {
            subject_key: subject_key.clone(),
            statement_a: "block height 10 is X".into(),
            statement_b: "block height 10 is Y".into(),
            signature_a: sign_statement(&stranger, "block height 10 is X"),
            signature_b: sign_statement(&subject, "block height 10 is Y"),
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), &subject_key, forged)
                .unwrap()
                .verify(&[]),
            Err(PowiError::BadSignature)
        ));
    }

    #[test]
    fn regression_equivocation_by_peer_a_cannot_sanction_peer_b() {
        // Regression (finding 2): peer A really did equivocate — both
        // statements verify under A's key — but the receipt names peer B as
        // its subject. The old code never compared the two, so B was
        // sanctioned on A's statements. Now the sanction must be rejected.
        let peer_a = SigningKey::from_bytes(&[9u8; 32]);
        let peer_b = SigningKey::from_bytes(&[13u8; 32]);
        let a_key = hex::encode(peer_a.verifying_key().to_bytes());
        let b_key = hex::encode(peer_b.verifying_key().to_bytes());
        let ev = ViolationEvidence::VerifiedEquivocation {
            subject_key: a_key,
            statement_a: "block height 10 is X".into(),
            statement_b: "block height 10 is Y".into(),
            signature_a: sign_statement(&peer_a, "block height 10 is X"),
            signature_b: sign_statement(&peer_a, "block height 10 is Y"),
        };
        let r = PowiReceipt::issue(&issuer(), &b_key, ev).unwrap();
        assert!(matches!(
            r.verify(&[]),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));
        assert_eq!(
            evaluate_sanction(Some(&r), &[]),
            SanctionDecision::RejectedInvalidProof
        );
    }

    #[test]
    fn a_bare_vote_cannot_sanction() {
        assert_eq!(evaluate_sanction(None, &[]), SanctionDecision::RejectedNoProof);
    }

    #[test]
    fn a_tampered_issuer_signature_proves_nothing() {
        let mut r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(false)).unwrap();
        let mut sig = hex::decode(&r.signature).unwrap();
        sig[0] ^= 1;
        r.signature = hex::encode(sig);
        assert!(matches!(r.verify(&[]), Err(PowiError::BadSignature)));
        assert_eq!(
            evaluate_sanction(Some(&r), &[]),
            SanctionDecision::RejectedInvalidProof
        );
    }
}
