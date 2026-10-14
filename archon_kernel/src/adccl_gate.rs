use serde::{Deserialize, Serialize};

/// The canonical Stiefel identity-preserving minimum threshold.
pub const CHIRAL_FLOOR: f64 = std::f64::consts::FRAC_1_SQRT_2; // 1 / √2 ≈ 0.7071067811865476

/// The overclaim ceiling κ = √0.91 ≈ 0.9539392014169456.
///
/// A χ above it is held for escalation rather than released: the claim may be sound, but a
/// near-perfect score on both axes is the confidence the gate is meant to distrust.
pub const SOVEREIGN_CEILING: f64 = 0.953_939_201_416_945_6;

/// Minimum χ(V, J) − χ(1 − V, J) for a claim to count as distinguishable from its negation.
pub const MIRROR_GAP_MIN: f64 = 0.15;

/// Authoritative Chiral Invariant formula:
/// χ = √ ( V² + (1 - J)² ) / √2
pub fn compute_chiral_invariant(v_gate_score: f64, drift_penalty_j: f64) -> f64 {
    let v_clamped = v_gate_score.clamp(0.0, 1.0);
    let j_clamped = drift_penalty_j.clamp(0.0, 1.0);
    ((v_clamped.powi(2) + (1.0 - j_clamped).powi(2)) / 2.0).sqrt()
}

/// χ of the inverted claim: verifiability flips, hallucination risk does not.
pub fn mirror_chi(v_gate_score: f64, drift_penalty_j: f64) -> f64 {
    compute_chiral_invariant(1.0 - v_gate_score.clamp(0.0, 1.0), drift_penalty_j)
}

/// The three-valued verdict. `passed` is exactly `signal == Execute`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateSignal {
    /// No check refused.
    Execute,
    /// A check held the verdict for escalation; do not act on it.
    Suspend,
    /// A check stopped the verdict outright.
    Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub v_gate_score: f64,
    pub drift_penalty_j: f64,
    pub chiral_invariant: f64,
    pub passed: bool,
    pub rejection_reason: Option<String>,
    /// χ of the inverted claim, for the mirror check.
    pub mirror_chi: f64,
    pub signal: GateSignal,
}

/// The ADCCL gate.
///
/// It is veto-only: five checks run, any one of them can refuse, and none of them can approve.
/// A verdict passes only when no check refused, so adding a check can only make the gate
/// stricter. A floor-only gate (χ ≥ 1/√2 and nothing else) passes three cases it must not:
///
/// * `V = 0, J = 0`: no verifiability at all, χ = 0.7071, on the floor;
/// * `V = 1, J = 1`: the maximum hallucination penalty, χ = 0.7071, on the floor;
/// * `V = 1, J = 0`: χ = 1.0, above the ceiling.
///
/// The checks:
///
/// 1. finiteness: a non-finite score or χ is refused (comparisons against NaN are all false,
///    so without this check NaN would pass every other one);
/// 2. floor: χ below the gate threshold is refused;
/// 3. mirror: χ(V, J) − χ(1 − V, J) below [`MIRROR_GAP_MIN`] is refused;
/// 4. components: V and 1 − J must each be at least [`CHIRAL_FLOOR`], so a strong axis cannot
///    carry a weak one;
/// 5. ceiling: χ above [`SOVEREIGN_CEILING`] is held (suspend), not released.
pub struct AdcclGate {
    pub threshold: f64,
}

impl Default for AdcclGate {
    fn default() -> Self {
        Self {
            threshold: CHIRAL_FLOOR,
        }
    }
}

impl AdcclGate {
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    pub fn evaluate(&self, v_score: f64, j_penalty: f64) -> VerificationReport {
        let chi = compute_chiral_invariant(v_score, j_penalty);
        let m_chi = mirror_chi(v_score, j_penalty);
        let mut halts: Vec<String> = Vec::new();
        let mut holds: Vec<String> = Vec::new();

        if !(v_score.is_finite() && j_penalty.is_finite() && chi.is_finite() && m_chi.is_finite()) {
            halts.push("finiteness: a score or the invariant is not a finite number".to_string());
        } else {
            if chi < self.threshold {
                halts.push(format!(
                    "Chiral Violation: Invariant {:.4} < threshold {:.4}",
                    chi, self.threshold
                ));
            }
            let gap = chi - m_chi;
            if gap < MIRROR_GAP_MIN {
                halts.push(format!(
                    "mirror: the inverted claim scores {:.4} against {:.4} (gap {:.4} < {:.2})",
                    m_chi, chi, gap, MIRROR_GAP_MIN
                ));
            }
            let v_c = v_score.clamp(0.0, 1.0);
            let j_c = 1.0 - j_penalty.clamp(0.0, 1.0);
            if v_c < CHIRAL_FLOOR || j_c < CHIRAL_FLOOR {
                halts.push(format!(
                    "components: V = {:.4} and 1 - J = {:.4} must each be at least {:.4}",
                    v_c, j_c, CHIRAL_FLOOR
                ));
            }
            if chi > SOVEREIGN_CEILING {
                holds.push(format!(
                    "ceiling: invariant {:.4} > {:.4}; held for escalation",
                    chi, SOVEREIGN_CEILING
                ));
            }
        }

        let signal = if !halts.is_empty() {
            GateSignal::Abort
        } else if !holds.is_empty() {
            GateSignal::Suspend
        } else {
            GateSignal::Execute
        };
        let passed = signal == GateSignal::Execute;
        // Report every check that refused, not only the first.
        let rejection_reason = if passed {
            None
        } else {
            Some(
                halts
                    .iter()
                    .chain(holds.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | "),
            )
        };

        VerificationReport {
            v_gate_score: v_score,
            drift_penalty_j: j_penalty,
            chiral_invariant: chi,
            passed,
            rejection_reason,
            mirror_chi: m_chi,
            signal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_fixture_table() {
        // Shared {V, J} -> χ reference table for the formula alone. The 1/√2 row is the on-floor
        // fixed point (V = 1/√2, J = 1 - 1/√2 ⇒ χ = 1/√2). Whether a row passes the gate is
        // tested separately below.
        let inv_sqrt2 = std::f64::consts::FRAC_1_SQRT_2;
        let fixtures = vec![
            (1.0, 0.0, 1.0),
            (0.9, 0.1, 0.9000),
            (inv_sqrt2, 1.0 - inv_sqrt2, inv_sqrt2),
            (0.5, 0.5, 0.5),
            (0.0, 1.0, 0.0),
        ];

        for (v, j, expected_chi) in fixtures {
            let chi = compute_chiral_invariant(v, j);
            assert!(
                (chi - expected_chi).abs() < 1e-4,
                "Fixture fail for V={}, J={}: got {}, expected {}",
                v,
                j,
                chi,
                expected_chi
            );
        }
    }

    #[test]
    fn test_chiral_floor_pass_fail() {
        let gate = AdcclGate::default();
        let pass_report = gate.evaluate(0.9, 0.1);
        assert!(pass_report.passed);
        assert_eq!(pass_report.signal, GateSignal::Execute);

        let fail_report = gate.evaluate(0.4, 0.6);
        assert!(!fail_report.passed);
        assert!(fail_report.rejection_reason.is_some());
    }

    #[test]
    fn zero_verifiability_is_refused() {
        let r = AdcclGate::default().evaluate(0.0, 0.0);
        assert!(
            (r.chiral_invariant - CHIRAL_FLOOR).abs() < 1e-12,
            "sits on the floor"
        );
        assert!(!r.passed);
        assert_eq!(r.signal, GateSignal::Abort);
    }

    #[test]
    fn maximum_hallucination_is_refused() {
        let r = AdcclGate::default().evaluate(1.0, 1.0);
        assert!(
            (r.chiral_invariant - CHIRAL_FLOOR).abs() < 1e-12,
            "sits on the floor"
        );
        assert!(!r.passed);
        assert_eq!(r.signal, GateSignal::Abort);
        let r = AdcclGate::default().evaluate(1.0, 0.9);
        assert!(r.chiral_invariant > CHIRAL_FLOOR, "above the floor");
        assert!(!r.passed, "a 90% hallucination penalty must not pass");
    }

    #[test]
    fn overclaim_is_held_not_released() {
        let r = AdcclGate::default().evaluate(1.0, 0.0);
        assert!((r.chiral_invariant - 1.0).abs() < 1e-12);
        assert!(!r.passed);
        assert_eq!(r.signal, GateSignal::Suspend);
    }

    #[test]
    fn non_finite_scores_are_refused() {
        for (v, j) in [
            (f64::NAN, 0.1),
            (0.9, f64::NAN),
            (f64::INFINITY, 0.1),
            (0.9, f64::NEG_INFINITY),
        ] {
            let r = AdcclGate::default().evaluate(v, j);
            assert!(!r.passed, "V={v} J={j}");
            assert_eq!(r.signal, GateSignal::Abort);
        }
    }

    #[test]
    fn fail_closed_pair_is_refused() {
        let r = AdcclGate::default().evaluate(0.5, 0.5);
        assert!(!r.passed);
    }

    #[test]
    fn every_refusal_is_reported() {
        // V = 0, J = 1 fails the floor, the mirror and the components at once.
        let reason = AdcclGate::default()
            .evaluate(0.0, 1.0)
            .rejection_reason
            .unwrap();
        for word in ["Chiral Violation", "mirror", "components"] {
            assert!(reason.contains(word), "missing {word} in {reason}");
        }
    }

    #[test]
    fn a_pass_means_every_check_is_silent() {
        // Grid over [0, 1]²: whenever the gate passes, each condition holds on its own.
        let gate = AdcclGate::default();
        let mut passes = 0;
        for a in 0..=100 {
            for b in 0..=100 {
                let (v, j) = (a as f64 / 100.0, b as f64 / 100.0);
                let r = gate.evaluate(v, j);
                let chi = compute_chiral_invariant(v, j);
                let ok = (CHIRAL_FLOOR..=SOVEREIGN_CEILING).contains(&chi)
                    && chi - mirror_chi(v, j) >= MIRROR_GAP_MIN
                    && v >= CHIRAL_FLOOR
                    && 1.0 - j >= CHIRAL_FLOOR;
                assert_eq!(r.passed, ok, "V={v} J={j}");
                passes += r.passed as usize;
            }
        }
        assert!(passes > 0, "the gate must still pass something");
    }
}
