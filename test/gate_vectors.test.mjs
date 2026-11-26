// The JS edge gate against the shared gate conformance vectors.
//
// archon_kernel/tests/fixtures/selin_gate_vectors.json is printed from the Rust kernel by
// archon_kernel/examples/selin_gate_vectors.rs, and the kernel is held to it by
// archon_kernel/tests/gate_conformance.rs. A row matches when the signal, passed and the refusing checks are exactly
// as written, chi and mirror_chi are within 1e-12 (NaN matches only NaN), and the scores come back unchanged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluate, CHIRAL_FLOOR, SOVEREIGN_CEILING, MIRROR_GAP_MIN, DOMAIN_REFUSAL } from '../gate.mjs';

const FILE = new URL('../archon_kernel/tests/fixtures/selin_gate_vectors.json', import.meta.url);
const vectors = JSON.parse(readFileSync(FILE, 'utf8'));

// How close chi and mirror_chi must be to the file's values.
const TOLERANCE = 1e-12;

// The checks the contract names.
const CHECKS = ['domain', 'floor', 'mirror', 'components', 'ceiling'];

// A number as the file writes it: a decimal string, or NaN, Infinity, -Infinity. Number() reads the same double as
// Rust's str::parse::<f64>; the pattern stops it from also reading '' or '0x1' as a number.
const NUMBER = /^(?:NaN|-?Infinity|-?\d+(?:\.\d+)?(?:e-?\d+)?)$/;
function number(text, what) {
  assert.equal(typeof text, 'string', `${what}: ${text} is not a string`);
  assert.match(text, NUMBER, `${what}: ${JSON.stringify(text)} is not a number`);
  return Number(text);
}

// The checks a rejection_reason names, in order, read through the file's tag map.
function refusedBy(reason) {
  if (reason === null) return [];
  return reason.split(' | ').map((part) => {
    const tag = part.split(':')[0];
    return Object.hasOwn(vectors.tags, tag) ? vectors.tags[tag] : `unknown tag ${JSON.stringify(tag)}`;
  });
}

// Within the tolerance, and NaN only for NaN.
const near = (got, want) => (Number.isNaN(want) ? Number.isNaN(got) : Math.abs(got - want) <= TOLERANCE);

test('the vector file is complete and uses the edge gate constants', () => {
  assert.equal(vectors.format, 'selin-gate-conformance');
  assert.equal(vectors.version, 1);
  assert.ok(Object.is(number(vectors.constants.chiral_floor, 'chiral_floor'), CHIRAL_FLOOR), 'chiral_floor');
  assert.ok(Object.is(number(vectors.constants.sovereign_ceiling, 'sovereign_ceiling'), SOVEREIGN_CEILING), 'sovereign_ceiling');
  assert.ok(Object.is(number(vectors.constants.mirror_gap_min, 'mirror_gap_min'), MIRROR_GAP_MIN), 'mirror_gap_min');
  assert.equal(vectors.domain_refusal, DOMAIN_REFUSAL);
  assert.deepEqual(Object.values(vectors.tags).sort(), [...CHECKS].sort(), 'every check has exactly one tag');

  const { rows } = vectors;
  assert.ok(rows.length >= 30, `only ${rows.length} vectors; the file must hold at least 30`);
  assert.equal(new Set(rows.map((r) => r.id)).size, rows.length, 'ids are unique');
  for (const check of CHECKS) {
    assert.ok(rows.some((r) => r.expect.refused_by.includes(check)), `no vector is refused by ${check}`);
  }
  for (const signal of ['execute', 'suspend', 'abort']) {
    assert.ok(rows.some((r) => r.expect.signal === signal), `no vector expects ${signal}`);
  }
});

for (const row of vectors.rows) {
  test(`vector ${row.id}`, () => {
    const v = number(row.v, 'v');
    const j = number(row.j, 'j');
    // A null threshold means the default. Passing null itself would not: chi < null compares against 0.
    const threshold = row.threshold === null ? CHIRAL_FLOOR : number(row.threshold, 'threshold');
    const r = row.threshold === null ? evaluate(v, j) : evaluate(v, j, threshold);
    const { expect } = row;

    assert.equal(r.signal, expect.signal, 'signal');
    assert.equal(r.passed, expect.passed, 'passed');
    assert.equal(r.rejection_reason === null, r.passed, 'rejection_reason is null exactly when passed');
    assert.deepEqual(refusedBy(r.rejection_reason), expect.refused_by, 'refused_by');

    const domain = expect.refused_by.includes('domain');
    assert.equal(r.ok, !domain, 'ok is false only for a domain refusal');
    if (domain) {
      assert.equal(r.rejection_reason, DOMAIN_REFUSAL, 'domain refusal text');
      assert.equal(r.error, DOMAIN_REFUSAL, 'domain refusal error');
    }

    for (const [name, got] of [['chi', r.chiral_invariant], ['mirror_chi', r.mirror_chi]]) {
      const want = number(expect[name], name);
      assert.ok(near(got, want), `${name} ${got}, expected ${want} within ${TOLERANCE}`);
    }
    assert.ok(Object.is(r.v_gate_score, v) && Object.is(r.drift_penalty_j, j), 'the scores come back unchanged');
    assert.ok(Object.is(r.threshold, threshold), 'threshold');
  });
}
