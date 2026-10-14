// The ADCCL chiral gate, as specified in archon_kernel/src/adccl_gate.rs.
// This is the same formula and the same floor as the Rust kernel; test/gate.test.mjs holds it to the kernel's
// reference table. It evaluates scores it is given. It does not produce them: V and J come from a verifier.

export const CHIRAL_FLOOR = Math.SQRT1_2; // 1 / sqrt(2)

const clamp01 = (x) => Math.min(1, Math.max(0, x));

// chi = sqrt((V^2 + (1 - J)^2) / 2)
export function computeChiralInvariant(v, j) {
  const vc = clamp01(v);
  const jc = clamp01(j);
  return Math.sqrt((vc * vc + (1 - jc) * (1 - jc)) / 2);
}

// A score is usable only if it is a finite number in [0, 1]. Anything else is refused, never defaulted.
export function validScore(x) {
  return typeof x === 'number' && Number.isFinite(x) && x >= 0 && x <= 1;
}

export function evaluate(v, j, threshold = CHIRAL_FLOOR) {
  if (!validScore(v) || !validScore(j)) {
    return { ok: false, error: 'V and J must each be a number in [0, 1]' };
  }
  const chi = computeChiralInvariant(v, j);
  const passed = chi >= threshold;
  return {
    ok: true,
    v_gate_score: v,
    drift_penalty_j: j,
    chiral_invariant: chi,
    threshold,
    passed,
    rejection_reason: passed ? null : `Chiral Violation: Invariant ${chi.toFixed(4)} < threshold ${threshold.toFixed(4)}`,
  };
}
