//! ARCHON Kernel: Anti-drift Runtime Control & Holonomy Orchestration Node.
//!
//! Provides public-safe ADCCL verification, provider adapters, and basepoint seals.

pub mod adccl_gate;
pub mod basepoint;
pub mod memory_tiers;
pub mod powi;
pub mod provider;
pub mod risk;
pub mod rytt_seal;
pub mod samo_envelope;
pub mod staging_pool;
pub mod three_tier_gate;
pub mod verifier;

pub use adccl_gate::{
    compute_chiral_invariant, mirror_chi, AdcclGate, GateSignal, VerificationReport, CHIRAL_FLOOR,
    MIRROR_GAP_MIN, SOVEREIGN_CEILING,
};
pub use basepoint::{generate_basepoint_seal, generate_entropy, verify_basepoint_seal};
pub use memory_tiers::{
    attestation_from_seed, canon_attestation_message, canon_witness_hash, sign_canon_attestation,
    CanonAttestation, MemoryError, MemoryRecord, MemoryStore, MemoryTier, CANON_QUORUM,
    MEMORY_ARTIFACTS_DDL,
};
pub use powi::{
    checker_attestation_message, evaluate_sanction, receipt_chain_hash, sign_checker_attestation,
    sign_statement, PowiError, PowiReceipt, SanctionDecision, ViolationEvidence,
};
pub use provider::AdaptiveResilientFormatter;
pub use risk::classify_prompt;
pub use samo_envelope::{
    content_hash, open_certificate, open_certificate_with_trusted_issuers, open_claim,
    seal_certificate, seal_claim, Certainty, Claim, FalsificationCertificate, SamoError,
};
pub use staging_pool::{
    bridge_attestation_message, sign_bridge_attestation, sign_valid_receipt, valid_receipt_message,
    BridgeAttestation, Neighbor, NeighborTable, StagedArtifact, StagingError, StagingPool,
    StagingState, ValidReceipt, MAX_NEIGHBORHOOD, M_CRIT,
};
pub use three_tier_gate::{
    signoff_token, ActionEvaluation, ActionSecurityLevel, SignOffLedger, ThreeTierGate,
    SIGNOFF_RISK_THRESHOLD,
};
pub use verifier::{
    build_verifier_prompt, extract_scores, parse_verifier_strict, sanction_is_proven, FAIL_CLOSED,
};
