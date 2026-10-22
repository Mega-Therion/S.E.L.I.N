//! Three-tier action gate (work order BLK-302 item 1).
//!
//! - Tier 1 (severe / illegal threat): vetoed. **Never overridable**, with or without sign-off.
//! - Tier 2/3 (risk score above 0.7): refused unless a *valid* sign-off is presented.
//! - Standard: permitted.
//!
//! A valid sign-off is not a phrase. It is a token
//! `hex(HMAC-SHA256(key, "selin-signoff-v1|" || prompt_hash))` made with an operator key that
//! the caller never sees in the request. It is bound to one prompt and usable once
//! ([`SignOffLedger`]). A word sent in an HTTP body therefore lifts nothing.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;

/// Risk score above which an action needs a valid sign-off.
pub const SIGNOFF_RISK_THRESHOLD: f64 = 0.7;
const DOMAIN: &[u8] = b"selin-signoff-v1|";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionSecurityLevel {
    /// Normal operation.
    Standard,
    /// Severe / illegal threat: always refused.
    Tier1Veto,
    /// High risk and no valid sign-off: refused.
    Tier2Warning,
    /// High risk with a valid, unused, prompt-bound sign-off: permitted and recorded.
    Tier3AccountabilityLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvaluation {
    pub level: ActionSecurityLevel,
    pub permitted: bool,
    pub prompt_message: Option<String>,
}

/// Compute the sign-off token for a prompt hash with the operator key.
pub fn signoff_token(key: &[u8], prompt_hash: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(DOMAIN);
    mac.update(prompt_hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Remembers tokens already spent, so each sign-off works once.
#[derive(Debug, Default)]
pub struct SignOffLedger {
    used: HashSet<String>,
}

impl SignOffLedger {
    /// True only if `token` is the HMAC of `prompt_hash` under `key` (constant-time compare)
    /// and has not been used before. A successful check spends the token.
    pub fn redeem(&mut self, key: &[u8], prompt_hash: &str, token: &str) -> bool {
        if key.is_empty() || token.is_empty() || self.used.contains(token) {
            return false;
        }
        let Ok(given) = hex::decode(token.trim()) else {
            return false;
        };
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(DOMAIN);
        mac.update(prompt_hash.as_bytes());
        if mac.verify_slice(&given).is_err() {
            return false;
        }
        self.used.insert(token.trim().to_string());
        true
    }
}

pub struct ThreeTierGate;

impl ThreeTierGate {
    /// `signoff_valid` must come from [`SignOffLedger::redeem`], never from caller input directly.
    pub fn evaluate_action(
        risk_score: f64,
        is_illegal_threat: bool,
        signoff_valid: bool,
    ) -> ActionEvaluation {
        if is_illegal_threat {
            return ActionEvaluation {
                level: ActionSecurityLevel::Tier1Veto,
                permitted: false,
                prompt_message: Some("TIER 1 VETO: action flagged as a severe threat. Refused; no sign-off can lift this.".into()),
            };
        }
        if risk_score > SIGNOFF_RISK_THRESHOLD {
            if signoff_valid {
                return ActionEvaluation {
                    level: ActionSecurityLevel::Tier3AccountabilityLock,
                    permitted: true,
                    prompt_message: Some("SIGN-OFF RECORDED: high-risk action permitted under a valid, single-use operator sign-off.".into()),
                };
            }
            return ActionEvaluation {
                level: ActionSecurityLevel::Tier2Warning,
                permitted: false,
                prompt_message: Some("TIER 2: high-risk action refused. A valid operator sign-off for this exact prompt is required.".into()),
            };
        }
        ActionEvaluation {
            level: ActionSecurityLevel::Standard,
            permitted: true,
            prompt_message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"operator-key-established-at-init-0123456789";

    #[test]
    fn severe_threat_is_refused_with_every_signoff() {
        for valid in [false, true] {
            for risk in [0.0, 0.5, 0.71, 1.0] {
                let e = ThreeTierGate::evaluate_action(risk, true, valid);
                assert_eq!(e.level, ActionSecurityLevel::Tier1Veto);
                assert!(
                    !e.permitted,
                    "tier 1 must never be permitted (risk {risk}, signoff {valid})"
                );
            }
        }
    }

    #[test]
    fn high_risk_needs_valid_signoff() {
        assert!(!ThreeTierGate::evaluate_action(0.9, false, false).permitted);
        assert!(ThreeTierGate::evaluate_action(0.9, false, true).permitted);
        assert!(ThreeTierGate::evaluate_action(0.3, false, false).permitted);
    }

    #[test]
    fn a_plain_word_is_not_a_signoff() {
        let mut l = SignOffLedger::default();
        for word in ["yes", "I accept", "hash_sovereign_ack", "deadbeef"] {
            assert!(!l.redeem(KEY, "abc", word), "{word} must not redeem");
        }
    }

    #[test]
    fn token_is_bound_to_prompt_and_key_and_single_use() {
        let mut l = SignOffLedger::default();
        let t = signoff_token(KEY, "prompt-A");
        assert!(!l.redeem(KEY, "prompt-B", &t), "cross-prompt token refused");
        assert!(
            !l.redeem(b"some-other-key", "prompt-A", &t),
            "wrong key refused"
        );
        assert!(l.redeem(KEY, "prompt-A", &t), "correct token accepted once");
        assert!(!l.redeem(KEY, "prompt-A", &t), "replay refused");
    }

    #[test]
    fn empty_key_never_validates() {
        let mut l = SignOffLedger::default();
        let t = signoff_token(b"", "p");
        assert!(!l.redeem(b"", "p", &t));
    }
}
