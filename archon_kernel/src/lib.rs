//! ARCHON Kernel: Anti-drift Runtime Control & Holonomy Orchestration Node.
//!
//! Provides public-safe ADCCL verification, provider adapters, and basepoint seals.

pub mod adccl_gate;
pub mod basepoint;
pub mod provider;
pub mod risk;
pub mod rytt_seal;
pub mod three_tier_gate;
pub mod verifier;

pub use adccl_gate::{
    compute_chiral_invariant, mirror_chi, AdcclGate, GateSignal, VerificationReport, CHIRAL_FLOOR,
    MIRROR_GAP_MIN, SOVEREIGN_CEILING,
};
pub use basepoint::{generate_basepoint_seal, generate_entropy, verify_basepoint_seal};
pub use provider::AdaptiveResilientFormatter;
pub use risk::classify_prompt;
pub use three_tier_gate::{
    signoff_token, ActionEvaluation, ActionSecurityLevel, SignOffLedger, ThreeTierGate,
    SIGNOFF_RISK_THRESHOLD,
};
pub use verifier::{build_verifier_prompt, extract_scores, parse_verifier_strict, FAIL_CLOSED};
