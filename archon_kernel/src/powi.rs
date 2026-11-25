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
//! - **Broken hash chain** — the receipt carries the fields and `prev_hash`
//!   of an audit-chain row plus the `row_hash` the subject *claimed* for it.
//!   Recomputing the chain hash (the `selin-receipt-v1` construction, identical
//!   to `selin::governance::row_hash`) and finding a mismatch *is* the proof.
//! - **Failed deterministic check** — the receipt carries a check id, the
//!   expected and observed outputs, and a witness hash binding all three. The
//!   proof holds iff the witness recomputes and expected ≠ observed.
//! - **Verified equivocation** — the receipt carries two *different*
//!   statements, both validly signed by the subject's own key. Saying two
//!   contradictory things under one key is the provable offense (BFT
//!   accounting slashes equivocation; it never slashes dissent).
//!
//! Verification is fail-closed and total: a receipt whose issuer signature,
//! witness, or evidence does not check out proves nothing, and
//! [`evaluate_sanction`] upholds a sanction only for a fully verified receipt.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::rytt_seal;

const POWI_DOMAIN: &[u8] = b"selin-powi-v1";
const EQUIVOCATION_DOMAIN: &[u8] = b"selin-powi-equivocation-v1";
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

/// Witness hash binding a deterministic check's id, expected and observed
/// outputs. A receipt's witness must recompute to exactly this value.
pub fn deterministic_check_witness(
    check_id: &str,
    expected: &str,
    observed: &str,
) -> Result<String, PowiError> {
    let body = json!({
        "check_id": check_id,
        "expected": expected,
        "observed": observed,
    });
    let c = rytt_seal::canonical(&body).map_err(|e| PowiError::Malformed(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(POWI_DOMAIN);
    h.update(c.as_bytes());
    Ok(hex::encode(h.finalize()))
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
    /// The subject's audit chain does not recompute: `claimed_row_hash`
    /// differs from the hash of `fields` chained on `prev_hash`.
    BrokenHashChain {
        fields: Vec<String>,
        prev_hash: String,
        claimed_row_hash: String,
    },
    /// A deterministic check produced `observed` where `expected` was
    /// required; `witness_hash` binds the three values.
    FailedDeterministicCheck {
        check_id: String,
        expected: String,
        observed: String,
        witness_hash: String,
    },
    /// The subject signed two different statements with its own key.
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
    fn check(&self) -> Result<(), PowiError> {
        match self {
            Self::BrokenHashChain {
                fields,
                prev_hash,
                claimed_row_hash,
            } => {
                let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
                let recomputed = receipt_chain_hash(prev_hash, &refs);
                if recomputed == *claimed_row_hash {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "the chain row recomputes to the claimed hash; no break is proven".into(),
                    ));
                }
                Ok(())
            }
            Self::FailedDeterministicCheck {
                check_id,
                expected,
                observed,
                witness_hash,
            } => {
                if expected == observed {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "expected and observed outputs agree; no failure is proven".into(),
                    ));
                }
                let want = deterministic_check_witness(check_id, expected, observed)?;
                if want != *witness_hash {
                    return Err(PowiError::EvidenceDoesNotProve(
                        "witness hash does not bind this check id and outputs".into(),
                    ));
                }
                Ok(())
            }
            Self::VerifiedEquivocation {
                subject_key,
                statement_a,
                statement_b,
                signature_a,
                signature_b,
            } => {
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
    /// evidence must machine-check. Either failure proves nothing.
    pub fn verify(&self) -> Result<(), PowiError> {
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
        self.evidence.check()
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
pub fn evaluate_sanction(receipt: Option<&PowiReceipt>) -> SanctionDecision {
    match receipt {
        None => SanctionDecision::RejectedNoProof,
        Some(r) => match r.verify() {
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

    fn chain_evidence(honest: bool) -> ViolationEvidence {
        let fields = vec!["run-1".to_string(), "2026-11-25T00:00:00Z".to_string()];
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let real = receipt_chain_hash("", &refs);
        ViolationEvidence::BrokenHashChain {
            fields,
            prev_hash: String::new(),
            claimed_row_hash: if honest { real } else { "00".repeat(32) },
        }
    }

    #[test]
    fn a_broken_chain_is_proven_by_recomputation() {
        let r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(false)).unwrap();
        r.verify().unwrap();
        assert_eq!(evaluate_sanction(Some(&r)), SanctionDecision::Upheld);
    }

    #[test]
    fn an_intact_chain_proves_nothing() {
        // The claimed hash matches the recomputation: the "violation" is fabricated.
        let r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(true)).unwrap();
        assert!(matches!(
            r.verify(),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));
        assert_eq!(
            evaluate_sanction(Some(&r)),
            SanctionDecision::RejectedInvalidProof
        );
    }

    #[test]
    fn a_failed_check_needs_a_real_mismatch_and_a_binding_witness() {
        let witness = deterministic_check_witness("lean-kernel", "pass", "sorryAx found").unwrap();
        let good = ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "sorryAx found".into(),
            witness_hash: witness,
        };
        PowiReceipt::issue(&issuer(), "art-1", good)
            .unwrap()
            .verify()
            .unwrap();

        // Expected == observed: nothing failed, whatever the witness says.
        let no_failure = ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "pass".into(),
            witness_hash: deterministic_check_witness("lean-kernel", "pass", "pass").unwrap(),
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), "art-1", no_failure)
                .unwrap()
                .verify(),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));

        // A witness borrowed from another check binds nothing here.
        let borrowed = ViolationEvidence::FailedDeterministicCheck {
            check_id: "lean-kernel".into(),
            expected: "pass".into(),
            observed: "timeout".into(),
            witness_hash: deterministic_check_witness("other-check", "pass", "timeout").unwrap(),
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), "art-1", borrowed)
                .unwrap()
                .verify(),
            Err(PowiError::EvidenceDoesNotProve(_))
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
        PowiReceipt::issue(&issuer(), "peer-b", ev)
            .unwrap()
            .verify()
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
            PowiReceipt::issue(&issuer(), "peer-b", same)
                .unwrap()
                .verify(),
            Err(PowiError::EvidenceDoesNotProve(_))
        ));

        // A statement signed by someone else is not the subject's equivocation.
        let stranger = SigningKey::from_bytes(&[11u8; 32]);
        let forged = ViolationEvidence::VerifiedEquivocation {
            subject_key,
            statement_a: "block height 10 is X".into(),
            statement_b: "block height 10 is Y".into(),
            signature_a: sign_statement(&stranger, "block height 10 is X"),
            signature_b: sign_statement(&subject, "block height 10 is Y"),
        };
        assert!(matches!(
            PowiReceipt::issue(&issuer(), "peer-b", forged)
                .unwrap()
                .verify(),
            Err(PowiError::BadSignature)
        ));
    }

    #[test]
    fn a_bare_vote_cannot_sanction() {
        assert_eq!(evaluate_sanction(None), SanctionDecision::RejectedNoProof);
    }

    #[test]
    fn a_tampered_issuer_signature_proves_nothing() {
        let mut r = PowiReceipt::issue(&issuer(), "peer-a", chain_evidence(false)).unwrap();
        let mut sig = hex::decode(&r.signature).unwrap();
        sig[0] ^= 1;
        r.signature = hex::encode(sig);
        assert!(matches!(r.verify(), Err(PowiError::BadSignature)));
        assert_eq!(
            evaluate_sanction(Some(&r)),
            SanctionDecision::RejectedInvalidProof
        );
    }
}
