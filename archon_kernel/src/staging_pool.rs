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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

impl NeighborTable {
    pub fn new() -> Self {
        Self::default()
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
    /// Weight is a pure function of the receipt count, clamped to
    /// [`MAX_ROUTING_WEIGHT`] — it cannot be granted, only earned.
    pub fn record_valid_receipt(&mut self, fingerprint: &str) -> Result<f64, StagingError> {
        let n = self
            .neighbors
            .get_mut(fingerprint)
            .ok_or_else(|| StagingError::UnknownPeer(fingerprint.to_string()))?;
        n.valid_receipts += 1;
        n.routing_weight = (COLD_START_WEIGHT + WEIGHT_PER_RECEIPT * n.valid_receipts as f64)
            .min(MAX_ROUTING_WEIGHT);
        Ok(n.routing_weight)
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
    /// Mobility `M`: distinct peers this artifact has been released to.
    /// Invariant: `fanout < M_CRIT` at all times.
    pub fanout: u32,
    pub released_to: Vec<String>,
}

/// The cold-start staging pool for one node's neighborhood.
#[derive(Debug, Default)]
pub struct StagingPool {
    artifacts: HashMap<String, StagedArtifact>,
}

impl StagingPool {
    pub fn new() -> Self {
        Self::default()
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

    /// Record a bridge attestation from a *different* neighborhood. A
    /// same-shard attestation is not bridging and is refused.
    pub fn add_bridge_attestation(
        &mut self,
        artifact_hash: &str,
        from_shard: u32,
    ) -> Result<(), StagingError> {
        let a = self.get_mut(artifact_hash)?;
        if from_shard == a.home_shard {
            return Err(StagingError::SameShardAttestation);
        }
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
        }
    }
}
impl std::error::Error for StagingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with_peers(n: usize, shard: u32) -> NeighborTable {
        let mut t = NeighborTable::new();
        for i in 0..n {
            t.admit(&format!("peer-{i:03}"), shard).unwrap();
        }
        t
    }

    fn unlocked_pool(hash: &str) -> StagingPool {
        let mut p = StagingPool::new();
        p.stage(hash, 1).unwrap();
        p.mark_local_checks_passed(hash).unwrap();
        p.add_bridge_attestation(hash, 2).unwrap();
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
        let mut t = NeighborTable::new();
        t.admit("new-peer", 1).unwrap();
        assert_eq!(t.get("new-peer").unwrap().routing_weight, COLD_START_WEIGHT);
        let w = t.record_valid_receipt("new-peer").unwrap();
        assert!((w - (COLD_START_WEIGHT + WEIGHT_PER_RECEIPT)).abs() < 1e-12);
        for _ in 0..100 {
            t.record_valid_receipt("new-peer").unwrap();
        }
        assert_eq!(
            t.get("new-peer").unwrap().routing_weight,
            MAX_ROUTING_WEIGHT,
            "weight clamps at the maximum however long the history"
        );
        assert!(matches!(
            t.record_valid_receipt("ghost"),
            Err(StagingError::UnknownPeer(_))
        ));
    }

    #[test]
    fn unlock_needs_local_checks_and_cross_shard_bridging() {
        let mut p = StagingPool::new();
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
            p.add_bridge_attestation("art", 1),
            Err(StagingError::SameShardAttestation)
        ));
        p.add_bridge_attestation("art", 2).unwrap();
        p.unlock_global("art").unwrap();
        assert_eq!(p.get("art").unwrap().state, StagingState::GlobalUnlocked);
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
