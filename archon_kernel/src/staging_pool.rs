//! Cold-start staging pools and the propagation velocity cap (spec §6.1, §6.2).
//!
//! The overlay is spatially sharded: peers sit in small-world neighborhoods of
//! at most [`MAX_NEIGHBORHOOD`] peers, and unrestricted global broadcast floods
//! are prohibited. Every new Tier-B artifact enters a local **staging pool**
//! with capped outbound fan-out — its mobility `M` (the number of distinct
//! peers it has been released to) must always satisfy `M < M_crit`
//! ([`M_CRIT`]). Global propagation unlocks only after the artifact clears
//! local deterministic checks *and* earns a cross-neighborhood bridge
//! attestation. Low-quality or compromised updates burn out locally instead of
//! reaching the wider network.
//!
//! Newly admitted peers start at near-zero routing weight ([§6.2 zero-trust
//! cold start]); weight accrues only through a verifiable history of valid
//! receipts recorded by the table.
//!
//! Evidence discipline: nothing here counts a bare caller-supplied identifier
//! as an attestation. A bridge attestation is an Ed25519 signature by the
//! attesting shard's key — verified against the pool's configured shard-key
//! registry and deduplicated per shard ([`BridgeAttestation`]). Routing
//! weight rises only per distinct, signature-verified receipt whose attester
//! is in the table's configured registry, deduplicated by receipt id
//! ([`ValidReceipt`]); replaying a receipt earns nothing twice.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Critical mobility threshold: a staged artifact's outbound fan-out `M`
/// always satisfies `M < M_CRIT`. A release that would make `M` reach
/// `M_CRIT` is refused, so a staged artifact can reach at most
/// `M_CRIT - 1` distinct peers before it must be re-staged.
pub const M_CRIT: u32 = 8;

/// Maximum peers per spatial neighborhood (spec §6.1: ~10–50 peers).
pub const MAX_NEIGHBORHOOD: usize = 50;

/// Routing weight of a newly admitted peer: near zero (§6.2).
pub const COLD_START_WEIGHT: f64 = 0.01;

/// Routing weight can never exceed this, however many receipts accrue.
pub const MAX_ROUTING_WEIGHT: f64 = 1.0;

/// Weight gained per valid receipt recorded for a peer.
pub const WEIGHT_PER_RECEIPT: f64 = 0.05;

/// Cross-neighborhood bridge attestations required before global unlock.
pub const BRIDGE_ATTESTATIONS_REQUIRED: u32 = 1;

const BRIDGE_DOMAIN: &[u8] = b"selin-bridge-attestation-v1";
const RECEIPT_DOMAIN: &[u8] = b"selin-valid-receipt-v1";

fn key_from_hex(h: &str) -> Result<VerifyingKey, StagingError> {
    let b: [u8; 32] = hex::decode(h)
        .map_err(|_| StagingError::BadKey)?
        .try_into()
        .map_err(|_| StagingError::BadKey)?;
    VerifyingKey::from_bytes(&b).map_err(|_| StagingError::BadKey)
}

fn verify_hex_signature(
    key_hex: &str,
    msg: &[u8],
    sig_hex: &str,
) -> Result<(), StagingError> {
    let pk = key_from_hex(key_hex)?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|_| StagingError::BadSignature)?
        .try_into()
        .map_err(|_| StagingError::BadSignature)?;
    pk.verify(msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| StagingError::BadSignature)
}

/// An authenticated cross-neighborhood bridge attestation: the attesting
/// shard's key signs the artifact hash together with its own shard id. A bare
/// shard number from a caller attests nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAttestation {
    pub artifact_hash: String,
    pub from_shard: u32,
    /// Hex Ed25519 public key of the attesting shard.
    pub attester_key: String,
    /// Hex Ed25519 signature over (artifact hash, shard id).
    pub signature: String,
}

/// The exact message a shard key signs for a bridge attestation.
pub fn bridge_attestation_message(artifact_hash: &str, from_shard: u32) -> Vec<u8> {
    let mut msg = BRIDGE_DOMAIN.to_vec();
    msg.push(0x1f);
    msg.extend_from_slice(artifact_hash.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(&from_shard.to_le_bytes());
    msg
}

/// Produce a bridge attestation as the attesting shard would.
pub fn sign_bridge_attestation(
    key: &SigningKey,
    artifact_hash: &str,
    from_shard: u32,
) -> BridgeAttestation {
    BridgeAttestation {
        artifact_hash: artifact_hash.to_string(),
        from_shard,
        attester_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(
            key.sign(&bridge_attestation_message(artifact_hash, from_shard))
                .to_bytes(),
        ),
    }
}

/// A verifiable receipt attesting that a peer produced valid work. The
/// attester (a configured, trusted identity — e.g. the node that observed the
/// work) signs the peer fingerprint together with a unique receipt id;
/// the table deduplicates by receipt id, so one receipt can raise a peer's
/// weight exactly once, however often it is presented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidReceipt {
    /// Unique receipt identifier; replaying the same id earns nothing.
    pub receipt_id: String,
    /// Fingerprint of the peer whose work the receipt attests.
    pub peer_fingerprint: String,
    /// Hex Ed25519 public key of the attester.
    pub attester_key: String,
    /// Hex Ed25519 signature over (peer fingerprint, receipt id).
    pub signature: String,
}

/// The exact message an attester signs for a valid receipt.
pub fn valid_receipt_message(peer_fingerprint: &str, receipt_id: &str) -> Vec<u8> {
    let mut msg = RECEIPT_DOMAIN.to_vec();
    msg.push(0x1f);
    msg.extend_from_slice(peer_fingerprint.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(receipt_id.as_bytes());
    msg
}

/// Produce a valid receipt as an attesting node would.
pub fn sign_valid_receipt(
    key: &SigningKey,
    peer_fingerprint: &str,
    receipt_id: &str,
) -> ValidReceipt {
    ValidReceipt {
        receipt_id: receipt_id.to_string(),
        peer_fingerprint: peer_fingerprint.to_string(),
        attester_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(
            key.sign(&valid_receipt_message(peer_fingerprint, receipt_id))
                .to_bytes(),
        ),
    }
}

/// A peer in the spatial neighbor table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighbor {
    /// Peer fingerprint (hex).
    pub fingerprint: String,
    /// Spatial shard / neighborhood id.
    pub shard: u32,
    pub routing_weight: f64,
    /// Count of valid receipts this peer has produced (drives the weight).
    pub valid_receipts: u64,
}

/// The spatial neighbor table: who is near us, in which shard, and how much
/// routing weight their verifiable history has earned them.
#[derive(Debug, Default)]
pub struct NeighborTable {
    neighbors: HashMap<String, Neighbor>,
    /// Configured hex keys whose receipt attestations count. Empty trusts
    /// nobody (fail closed).
    receipt_attesters: HashSet<String>,
    /// Receipt ids already counted, across all peers (replay protection).
    seen_receipt_ids: HashSet<String>,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a key whose [`ValidReceipt`] attestations this table trusts
    /// (hex Ed25519 public key). Receipts from any other key earn no weight.
    pub fn register_receipt_attester(&mut self, attester_key_hex: &str) -> Result<(), StagingError> {
        key_from_hex(attester_key_hex)?;
        self.receipt_attesters.insert(attester_key_hex.to_string());
        Ok(())
    }

    /// Admit a peer into a neighborhood at cold-start weight. Refused when the
    /// neighborhood is already at [`MAX_NEIGHBORHOOD`] or the peer is known.
    pub fn admit(&mut self, fingerprint: &str, shard: u32) -> Result<(), StagingError> {
        if self.neighbors.contains_key(fingerprint) {
            return Err(StagingError::DuplicatePeer(fingerprint.to_string()));
        }
        if self.shard_size(shard) >= MAX_NEIGHBORHOOD {
            return Err(StagingError::NeighborhoodFull(shard));
        }
        self.neighbors.insert(
            fingerprint.to_string(),
            Neighbor {
                fingerprint: fingerprint.to_string(),
                shard,
                routing_weight: COLD_START_WEIGHT,
                valid_receipts: 0,
            },
        );
        Ok(())
    }

    /// Record one valid receipt for a peer and return its new routing weight.
    /// The receipt must be signed by a configured attester over the peer and
    /// a fresh receipt id; forged, untrusted, or replayed receipts are
    /// rejected and earn nothing. Weight is a pure function of the verified
    /// receipt count, clamped to [`MAX_ROUTING_WEIGHT`] — it cannot be
    /// granted, only earned.
    pub fn record_valid_receipt(&mut self, receipt: &ValidReceipt) -> Result<f64, StagingError> {
        if receipt.receipt_id.is_empty() {
            return Err(StagingError::InvalidReceipt("receipt id is empty".into()));
        }
        if !self.receipt_attesters.contains(&receipt.attester_key) {
            return Err(StagingError::UntrustedAttester(receipt.attester_key.clone()));
        }
        verify_hex_signature(
            &receipt.attester_key,
            &valid_receipt_message(&receipt.peer_fingerprint, &receipt.receipt_id),
            &receipt.signature,
        )?;
        if self.seen_receipt_ids.contains(&receipt.receipt_id) {
            return Err(StagingError::DuplicateReceipt(receipt.receipt_id.clone()));
        }
        let n = self
            .neighbors
            .get_mut(&receipt.peer_fingerprint)
            .ok_or_else(|| StagingError::UnknownPeer(receipt.peer_fingerprint.clone()))?;
        n.valid_receipts += 1;
        n.routing_weight = (COLD_START_WEIGHT + WEIGHT_PER_RECEIPT * n.valid_receipts as f64)
            .min(MAX_ROUTING_WEIGHT);
        let weight = n.routing_weight;
        self.seen_receipt_ids.insert(receipt.receipt_id.clone());
        Ok(weight)
    }

    pub fn get(&self, fingerprint: &str) -> Option<&Neighbor> {
        self.neighbors.get(fingerprint)
    }

    pub fn shard_size(&self, shard: u32) -> usize {
        self.neighbors.values().filter(|n| n.shard == shard).count()
    }

    pub fn len(&self) -> usize {
        self.neighbors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.neighbors.is_empty()
    }
}

/// Lifecycle of a staged artifact (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagingState {
    /// In the local pool; no outbound release permitted.
    Staged,
    /// Local deterministic checks passed; still confined to the home shard.
    LocallyCleared,
    /// Local checks + cross-neighborhood bridging done; releases permitted
    /// under the mobility cap.
    GlobalUnlocked,
}

/// One artifact held in the staging pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedArtifact {
    pub artifact_hash: String,
    pub home_shard: u32,
    pub state: StagingState,
    pub local_checks_passed: bool,
    pub bridge_attestations: u32,
    /// Shards that have presented a verified bridge attestation for this
    /// artifact (deduplication: one count per shard, however many keys of
    /// that shard attest).
    pub bridge_attested_shards: Vec<u32>,
    /// Mobility `M`: distinct peers this artifact has been released to.
    /// Invariant: `fanout < M_CRIT` at all times.
    pub fanout: u32,
    pub released_to: Vec<String>,
}

/// The cold-start staging pool for one node's neighborhood.
#[derive(Debug, Default)]
pub struct StagingPool {
    artifacts: HashMap<String, StagedArtifact>,
    /// Configured shard-key registry: shard id → its hex public keys. A
    /// bridge attestation counts only when its key is registered for the
    /// shard it claims to speak for. Empty trusts nobody (fail closed).
    shard_keys: HashMap<u32, HashSet<String>>,
}

impl StagingPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a shard's public key (hex) in the shard-key registry.
    pub fn register_shard_key(
        &mut self,
        shard: u32,
        attester_key_hex: &str,
    ) -> Result<(), StagingError> {
        key_from_hex(attester_key_hex)?;
        self.shard_keys
            .entry(shard)
            .or_default()
            .insert(attester_key_hex.to_string());
        Ok(())
    }

    /// Enter a new artifact into the local staging pool.
    pub fn stage(&mut self, artifact_hash: &str, home_shard: u32) -> Result<(), StagingError> {
        if self.artifacts.contains_key(artifact_hash) {
            return Err(StagingError::DuplicateArtifact(artifact_hash.to_string()));
        }
        self.artifacts.insert(
            artifact_hash.to_string(),
            StagedArtifact {
                artifact_hash: artifact_hash.to_string(),
                home_shard,
                state: StagingState::Staged,
                local_checks_passed: false,
                bridge_attestations: 0,
                bridge_attested_shards: Vec::new(),
                fanout: 0,
                released_to: Vec::new(),
            },
        );
        Ok(())
    }

    /// Record that local deterministic checks passed for a staged artifact.
    pub fn mark_local_checks_passed(&mut self, artifact_hash: &str) -> Result<(), StagingError> {
        let a = self.get_mut(artifact_hash)?;
        a.local_checks_passed = true;
        if a.state == StagingState::Staged {
            a.state = StagingState::LocallyCleared;
        }
        Ok(())
    }

    /// Record an authenticated bridge attestation from a *different*
    /// neighborhood. The attestation's key must be registered for the shard
    /// it claims, its signature must verify over the artifact and shard, and
    /// each shard counts at most once per artifact. A same-shard attestation
    /// is not bridging and is refused.
    pub fn add_bridge_attestation(
        &mut self,
        attestation: &BridgeAttestation,
    ) -> Result<(), StagingError> {
        let home_shard = self
            .get(&attestation.artifact_hash)
            .ok_or_else(|| StagingError::UnknownArtifact(attestation.artifact_hash.clone()))?
            .home_shard;
        if attestation.from_shard == home_shard {
            return Err(StagingError::SameShardAttestation);
        }
        let registered = self
            .shard_keys
            .get(&attestation.from_shard)
            .map(|keys| keys.contains(&attestation.attester_key))
            .unwrap_or(false);
        if !registered {
            return Err(StagingError::UntrustedShardKey {
                shard: attestation.from_shard,
            });
        }
        verify_hex_signature(
            &attestation.attester_key,
            &bridge_attestation_message(&attestation.artifact_hash, attestation.from_shard),
            &attestation.signature,
        )?;
        let a = self.get_mut(&attestation.artifact_hash)?;
        if a.bridge_attested_shards.contains(&attestation.from_shard) {
            return Err(StagingError::DuplicateBridgeAttestation(
                attestation.from_shard,
            ));
        }
        a.bridge_attested_shards.push(attestation.from_shard);
        a.bridge_attestations += 1;
        Ok(())
    }

    /// Unlock global propagation. Requires local checks passed *and* at least
    /// [`BRIDGE_ATTESTATIONS_REQUIRED`] cross-neighborhood attestations.
    pub fn unlock_global(&mut self, artifact_hash: &str) -> Result<(), StagingError> {
        let a = self.get_mut(artifact_hash)?;
        if !a.local_checks_passed {
            return Err(StagingError::NotLocallyCleared);
        }
        if a.bridge_attestations < BRIDGE_ATTESTATIONS_REQUIRED {
            return Err(StagingError::InsufficientBridgeAttestations {
                got: a.bridge_attestations,
                need: BRIDGE_ATTESTATIONS_REQUIRED,
            });
        }
        a.state = StagingState::GlobalUnlocked;
        Ok(())
    }

    /// Release an unlocked artifact to one neighbor. Enforces the mobility
    /// cap: the release is refused if it would make `M` reach `M_CRIT`, so
    /// `M < M_CRIT` holds after every successful release. Returns the new `M`.
    pub fn release(
        &mut self,
        artifact_hash: &str,
        table: &NeighborTable,
        peer_fingerprint: &str,
    ) -> Result<u32, StagingError> {
        if table.get(peer_fingerprint).is_none() {
            return Err(StagingError::UnknownPeer(peer_fingerprint.to_string()));
        }
        let a = self.get_mut(artifact_hash)?;
        if a.state != StagingState::GlobalUnlocked {
            return Err(StagingError::NotUnlocked);
        }
        if a.released_to.iter().any(|p| p == peer_fingerprint) {
            return Err(StagingError::AlreadyReleased(peer_fingerprint.to_string()));
        }
        if a.fanout + 1 >= M_CRIT {
            return Err(StagingError::MobilityCapExceeded {
                m: a.fanout + 1,
                m_crit: M_CRIT,
            });
        }
        a.fanout += 1;
        a.released_to.push(peer_fingerprint.to_string());
        Ok(a.fanout)
    }

    pub fn get(&self, artifact_hash: &str) -> Option<&StagedArtifact> {
        self.artifacts.get(artifact_hash)
    }

    fn get_mut(&mut self, artifact_hash: &str) -> Result<&mut StagedArtifact, StagingError> {
        self.artifacts
            .get_mut(artifact_hash)
            .ok_or_else(|| StagingError::UnknownArtifact(artifact_hash.to_string()))
    }
}

#[derive(Debug)]
pub enum StagingError {
    DuplicatePeer(String),
    NeighborhoodFull(u32),
    UnknownPeer(String),
    DuplicateArtifact(String),
    UnknownArtifact(String),
    SameShardAttestation,
    NotLocallyCleared,
    InsufficientBridgeAttestations { got: u32, need: u32 },
    NotUnlocked,
    MobilityCapExceeded { m: u32, m_crit: u32 },
    AlreadyReleased(String),
    BadKey,
    BadSignature,
    UntrustedShardKey { shard: u32 },
    DuplicateBridgeAttestation(u32),
    UntrustedAttester(String),
    DuplicateReceipt(String),
    InvalidReceipt(String),
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePeer(fp) => write!(f, "peer {fp} is already in the neighbor table"),
            Self::NeighborhoodFull(s) => {
                write!(f, "neighborhood {s} is at the {MAX_NEIGHBORHOOD}-peer cap")
            }
            Self::UnknownPeer(fp) => write!(f, "peer {fp} is not in the neighbor table"),
            Self::DuplicateArtifact(h) => write!(f, "artifact {h} is already staged"),
            Self::UnknownArtifact(h) => write!(f, "artifact {h} is not in the staging pool"),
            Self::SameShardAttestation => {
                write!(
                    f,
                    "a same-shard attestation is not cross-neighborhood bridging"
                )
            }
            Self::NotLocallyCleared => {
                write!(f, "local deterministic checks have not passed")
            }
            Self::InsufficientBridgeAttestations { got, need } => write!(
                f,
                "global unlock needs {need} bridge attestation(s), has {got}"
            ),
            Self::NotUnlocked => write!(f, "artifact is not unlocked for global propagation"),
            Self::MobilityCapExceeded { m, m_crit } => write!(
                f,
                "mobility cap: release would make M = {m}, violating M < M_crit = {m_crit}"
            ),
            Self::AlreadyReleased(fp) => write!(f, "artifact already released to peer {fp}"),
            Self::BadKey => write!(f, "malformed public key"),
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::UntrustedShardKey { shard } => {
                write!(f, "attester key is not registered for shard {shard}")
            }
            Self::DuplicateBridgeAttestation(s) => {
                write!(f, "shard {s} has already attested this artifact")
            }
            Self::UntrustedAttester(k) => {
                write!(f, "receipt attester {k} is not a registered attester")
            }
            Self::DuplicateReceipt(id) => {
                write!(f, "receipt {id} has already been counted")
            }
            Self::InvalidReceipt(m) => write!(f, "invalid receipt: {m}"),
        }
    }
}
impl std::error::Error for StagingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn shard_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_hex(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    fn attester_key() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    fn table_with_attester() -> NeighborTable {
        let mut t = NeighborTable::new();
        t.register_receipt_attester(&key_hex(&attester_key())).unwrap();
        t
    }

    fn table_with_peers(n: usize, shard: u32) -> NeighborTable {
        let mut t = table_with_attester();
        for i in 0..n {
            t.admit(&format!("peer-{i:03}"), shard).unwrap();
        }
        t
    }

    fn unlocked_pool(hash: &str) -> StagingPool {
        let mut p = StagingPool::new();
        p.register_shard_key(2, &key_hex(&shard_key(52))).unwrap();
        p.stage(hash, 1).unwrap();
        p.mark_local_checks_passed(hash).unwrap();
        p.add_bridge_attestation(&sign_bridge_attestation(&shard_key(52), hash, 2))
            .unwrap();
        p.unlock_global(hash).unwrap();
        p
    }

    #[test]
    fn neighborhoods_cap_at_fifty_peers() {
        let mut t = table_with_peers(MAX_NEIGHBORHOOD, 3);
        assert_eq!(t.shard_size(3), MAX_NEIGHBORHOOD);
        assert!(matches!(
            t.admit("one-too-many", 3),
            Err(StagingError::NeighborhoodFull(3))
        ));
        // A different shard still has room.
        t.admit("other-shard-peer", 4).unwrap();
    }

    #[test]
    fn cold_start_weight_is_near_zero_and_accrues_only_via_receipts() {
        let mut t = table_with_attester();
        t.admit("new-peer", 1).unwrap();
        assert_eq!(t.get("new-peer").unwrap().routing_weight, COLD_START_WEIGHT);
        let w = t
            .record_valid_receipt(&sign_valid_receipt(&attester_key(), "new-peer", "r-1"))
            .unwrap();
        assert!((w - (COLD_START_WEIGHT + WEIGHT_PER_RECEIPT)).abs() < 1e-12);
        for i in 0..100 {
            t.record_valid_receipt(&sign_valid_receipt(
                &attester_key(),
                "new-peer",
                &format!("r-x{i}"),
            ))
            .unwrap();
        }
        assert_eq!(
            t.get("new-peer").unwrap().routing_weight,
            MAX_ROUTING_WEIGHT,
            "weight clamps at the maximum however long the history"
        );
        assert!(matches!(
            t.record_valid_receipt(&sign_valid_receipt(&attester_key(), "ghost", "r-ghost")),
            Err(StagingError::UnknownPeer(_))
        ));
    }

    #[test]
    fn regression_replayed_receipt_cannot_raise_weight_twice() {
        // Regression (finding 7): the old API raised weight on every bare
        // call. The same signed receipt presented twice must count once.
        let mut t = table_with_attester();
        t.admit("peer", 1).unwrap();
        let receipt = sign_valid_receipt(&attester_key(), "peer", "r-1");
        t.record_valid_receipt(&receipt).unwrap();
        assert!(matches!(
            t.record_valid_receipt(&receipt),
            Err(StagingError::DuplicateReceipt(_))
        ));
        let n = t.get("peer").unwrap();
        assert_eq!(n.valid_receipts, 1);
        assert!((n.routing_weight - (COLD_START_WEIGHT + WEIGHT_PER_RECEIPT)).abs() < 1e-12);
    }

    #[test]
    fn regression_forged_or_untrusted_receipt_earns_no_weight() {
        // Regression (finding 7): a receipt signed by an unregistered key,
        // and one whose signature was made for a different peer, both fail.
        let mut t = table_with_attester();
        t.admit("peer", 1).unwrap();
        let stranger = SigningKey::from_bytes(&[99u8; 32]);
        assert!(matches!(
            t.record_valid_receipt(&sign_valid_receipt(&stranger, "peer", "r-1")),
            Err(StagingError::UntrustedAttester(_))
        ));
        // Attester key field names the trusted key, but the signature is the
        // stranger's — verification against the named key must fail.
        let mut forged = sign_valid_receipt(&stranger, "peer", "r-2");
        forged.attester_key = key_hex(&attester_key());
        assert!(matches!(
            t.record_valid_receipt(&forged),
            Err(StagingError::BadSignature)
        ));
        // A genuine receipt for a different peer does not transfer.
        let other = sign_valid_receipt(&attester_key(), "someone-else", "r-3");
        assert!(matches!(
            t.record_valid_receipt(&other),
            Err(StagingError::UnknownPeer(_))
        ));
        assert_eq!(t.get("peer").unwrap().valid_receipts, 0);
        assert_eq!(t.get("peer").unwrap().routing_weight, COLD_START_WEIGHT);
    }

    #[test]
    fn unlock_needs_local_checks_and_cross_shard_bridging() {
        let mut p = StagingPool::new();
        p.register_shard_key(2, &key_hex(&shard_key(52))).unwrap();
        p.stage("art", 1).unwrap();
        assert!(matches!(
            p.unlock_global("art"),
            Err(StagingError::NotLocallyCleared)
        ));
        p.mark_local_checks_passed("art").unwrap();
        assert!(matches!(
            p.unlock_global("art"),
            Err(StagingError::InsufficientBridgeAttestations { got: 0, need: 1 })
        ));
        // Same-shard praise is not bridging.
        assert!(matches!(
            p.add_bridge_attestation(&sign_bridge_attestation(&shard_key(51), "art", 1)),
            Err(StagingError::SameShardAttestation)
        ));
        p.add_bridge_attestation(&sign_bridge_attestation(&shard_key(52), "art", 2))
            .unwrap();
        p.unlock_global("art").unwrap();
        assert_eq!(p.get("art").unwrap().state, StagingState::GlobalUnlocked);
    }

    #[test]
    fn regression_bare_shard_id_cannot_unlock_global_propagation() {
        // Regression (finding 6): the old API took a bare `from_shard: u32`
        // and one call unlocked global propagation. Now an attestation must
        // be signed by a key registered for that shard.
        let mut p = StagingPool::new();
        p.register_shard_key(2, &key_hex(&shard_key(52))).unwrap();
        p.stage("art", 1).unwrap();
        p.mark_local_checks_passed("art").unwrap();

        // Unregistered key claiming to speak for shard 2.
        let impostor = SigningKey::from_bytes(&[88u8; 32]);
        assert!(matches!(
            p.add_bridge_attestation(&sign_bridge_attestation(&impostor, "art", 2)),
            Err(StagingError::UntrustedShardKey { shard: 2 })
        ));
        // Shard 2's real key, but the signature is over a different artifact.
        let mut misbound = sign_bridge_attestation(&shard_key(52), "other-art", 2);
        misbound.artifact_hash = "art".to_string();
        assert!(matches!(
            p.add_bridge_attestation(&misbound),
            Err(StagingError::BadSignature)
        ));
        assert!(matches!(
            p.unlock_global("art"),
            Err(StagingError::InsufficientBridgeAttestations { got: 0, need: 1 })
        ));

        // Positive path: the registered shard key attests this artifact.
        p.add_bridge_attestation(&sign_bridge_attestation(&shard_key(52), "art", 2))
            .unwrap();
        // Dedup per shard: a second attestation from shard 2 (even under a
        // second registered key of that shard) counts nothing more.
        p.register_shard_key(2, &key_hex(&shard_key(53))).unwrap();
        assert!(matches!(
            p.add_bridge_attestation(&sign_bridge_attestation(&shard_key(53), "art", 2)),
            Err(StagingError::DuplicateBridgeAttestation(2))
        ));
        assert_eq!(p.get("art").unwrap().bridge_attestations, 1);
        p.unlock_global("art").unwrap();
    }

    #[test]
    fn a_staged_artifact_cannot_be_released_before_unlock() {
        let mut p = StagingPool::new();
        let t = table_with_peers(3, 9);
        p.stage("art", 1).unwrap();
        assert!(matches!(
            p.release("art", &t, "peer-000"),
            Err(StagingError::NotUnlocked)
        ));
    }

    #[test]
    fn mobility_cap_keeps_m_strictly_below_m_crit() {
        let mut p = unlocked_pool("art");
        let t = table_with_peers(20, 9);
        let mut last = 0;
        for i in 0..(M_CRIT - 1) {
            last = p.release("art", &t, &format!("peer-{i:03}")).unwrap();
        }
        assert_eq!(last, M_CRIT - 1);
        assert!(p.get("art").unwrap().fanout < M_CRIT);
        // The next release would make M reach M_CRIT: refused, M unchanged.
        assert!(matches!(
            p.release("art", &t, "peer-019"),
            Err(StagingError::MobilityCapExceeded { m, m_crit })
            if m == M_CRIT && m_crit == M_CRIT
        ));
        assert_eq!(p.get("art").unwrap().fanout, M_CRIT - 1);
    }

    #[test]
    fn release_needs_a_known_peer_and_counts_each_peer_once() {
        let mut p = unlocked_pool("art");
        let t = table_with_peers(3, 9);
        assert!(matches!(
            p.release("art", &t, "stranger"),
            Err(StagingError::UnknownPeer(_))
        ));
        p.release("art", &t, "peer-001").unwrap();
        assert!(matches!(
            p.release("art", &t, "peer-001"),
            Err(StagingError::AlreadyReleased(_))
        ));
        assert_eq!(p.get("art").unwrap().fanout, 1);
    }
}
