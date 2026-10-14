//! ARCHON Kernel: Anti-drift Runtime Control & Holonomy Orchestration Node.
//!
//! Provides public-safe ADCCL verification, provider adapters, and basepoint seals.

pub mod adccl_gate;
pub mod basepoint;
pub mod hsm_shamir;
pub mod provider;
pub mod risk;
pub mod three_tier_gate;
pub mod verifier;

pub use adccl_gate::{compute_chiral_invariant, AdcclGate, VerificationReport, CHIRAL_FLOOR};
pub use basepoint::{generate_basepoint_seal, generate_entropy, verify_basepoint_seal};
pub use hsm_shamir::{
    initialize_soft_hsm_key, recover_secret_shamir, split_secret_shamir, HsmToken, KeyShare,
};
pub use provider::AdaptiveResilientFormatter;
pub use risk::classify_prompt;
pub use three_tier_gate::{ActionEvaluation, ActionSecurityLevel, ThreeTierGate, Tier3SignOff};
pub use verifier::{build_verifier_prompt, extract_scores, FAIL_CLOSED};
