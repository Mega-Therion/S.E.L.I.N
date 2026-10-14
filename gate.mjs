// The ADCCL chiral gate, as specified in archon_kernel/src/adccl_gate.rs.
// Same formula, same constants and the same five checks as the Rust kernel; test/gate.test.mjs holds
// both to the same cases. It evaluates scores it is given. It does not produce them: V and J come from
// a verifier.

export const CHIRAL_FLOOR = Math.SQRT1_2; // 1 / sqrt(2)
export const SOVEREIGN_CEILING = 0.9539392014169456; // sqrt(0.91)
export const MIRROR_GAP_MIN = 0.15;

const clamp01 = (x) => Math.min(1, Math.max(0, x));

// chi = sqrt((V^2 + (1 - J)^2) / 2)
export function computeChiralInvariant(v, j) {
  const vc = clamp01(v);
  const jc = clamp01(j);
  return Math.sqrt((vc * vc + (1 - jc) * (1 - jc)) / 2);
}

// chi of the inverted claim: verifiability flips, hallucination risk does not.
export function mirrorChi(v, j) {
  return computeChiralInvariant(1 - clamp01(v), j);
}

// A score is usable only if it is a finite number in [0, 1]. Anything else is refused, never defaulted.
export function validScore(x) {
  return typeof x === 'number' && Number.isFinite(x) && x >= 0 && x <= 1;
}

// Veto-only: every check runs, any one can refuse, none can approve. Passing means no check refused.
export function evaluate(v, j, threshold = CHIRAL_FLOOR) {
  if (!validScore(v) || !validScore(j)) {
    return { ok: false, error: 'V and J must each be a number in [0, 1]' };
  }
  const chi = computeChiralInvariant(v, j);
  const mChi = mirrorChi(v, j);
  const halts = [];
  const holds = [];
  if (chi < threshold) halts.push(`Chiral Violation: Invariant ${chi.toFixed(4)} < threshold ${threshold.toFixed(4)}`);
  if (chi - mChi < MIRROR_GAP_MIN) halts.push(`mirror: the inverted claim scores ${mChi.toFixed(4)} against ${chi.toFixed(4)}`);
  if (v < CHIRAL_FLOOR || 1 - j < CHIRAL_FLOOR) halts.push(`components: V = ${v.toFixed(4)} and 1 - J = ${(1 - j).toFixed(4)} must each be at least ${CHIRAL_FLOOR.toFixed(4)}`);
  if (chi > SOVEREIGN_CEILING) holds.push(`ceiling: invariant ${chi.toFixed(4)} > ${SOVEREIGN_CEILING.toFixed(4)}; held for escalation`);
  const signal = halts.length ? 'abort' : holds.length ? 'suspend' : 'execute';
  const passed = signal === 'execute';
  return {
    ok: true,
    v_gate_score: v,
    drift_penalty_j: j,
    chiral_invariant: chi,
    mirror_chi: mChi,
    threshold,
    signal,
    passed,
    rejection_reason: passed ? null : [...halts, ...holds].join(' | '),
  };
}
