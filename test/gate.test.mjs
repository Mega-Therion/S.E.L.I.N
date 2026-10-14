import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { computeChiralInvariant, mirrorChi, evaluate, CHIRAL_FLOOR, SOVEREIGN_CEILING, MIRROR_GAP_MIN } from '../gate.mjs';
import { handle } from '../index.mjs';

// The reference table of archon_kernel/src/adccl_gate.rs (test_reference_fixture_table).
const S = Math.SQRT1_2;
const FIXTURES = [[1.0, 0.0, 1.0], [0.9, 0.1, 0.9], [S, 1 - S, S], [0.5, 0.5, 0.5], [0.0, 1.0, 0.0]];

test('formula matches the kernel reference table', () => {
  for (const [v, j, chi] of FIXTURES) assert.ok(Math.abs(computeChiralInvariant(v, j) - chi) < 1e-4, `V=${v} J=${j}`);
});

test('floor is 1/sqrt 2; the kernel pass and fail cases agree', () => {
  assert.equal(CHIRAL_FLOOR, Math.SQRT1_2);
  assert.equal(evaluate(0.9, 0.1).passed, true);
  const fail = evaluate(0.4, 0.6);
  assert.equal(fail.passed, false);
  assert.match(fail.rejection_reason, /Chiral Violation/);
});

test('the fail-closed pair (0.5, 0.5) is below the floor', () => {
  assert.equal(evaluate(0.5, 0.5).passed, false);
});

test('missing, non-numeric and out-of-range scores are refused', () => {
  for (const [v, j] of [[undefined, 0.1], [0.9, undefined], ['0.9', 0.1], [NaN, 0.1], [1.2, 0.1], [0.9, -0.1], [Infinity, 0], [null, null]]) {
    assert.equal(evaluate(v, j).ok, false, `V=${v} J=${j}`);
  }
});

async function withServer(fn) {
  const server = createServer(handle);
  await new Promise((r) => server.listen(0, r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const post = (base, body) => fetch(`${base}/api/archon/verify`, { method: 'POST', body });

test('route: same input gives the same verdict (no randomness)', async () => {
  await withServer(async (base) => {
    const a = await (await post(base, JSON.stringify({ V: 0.9, J: 0.1 }))).json();
    const b = await (await post(base, JSON.stringify({ V: 0.9, J: 0.1 }))).json();
    assert.equal(a.chi, b.chi);
    assert.equal(a.passed, true);
    assert.ok(Math.abs(a.chi - 0.9) < 1e-9);
  });
});

test('route: a prompt alone is refused with 422, never passed', async () => {
  await withServer(async (base) => {
    const r = await post(base, JSON.stringify({ prompt: 'anything' }));
    assert.equal(r.status, 422);
    assert.equal((await r.json()).passed, false);
  });
});

test('route: malformed JSON is 400', async () => {
  await withServer(async (base) => assert.equal((await post(base, '{not json')).status, 400));
});

test('status does not claim an armed loop', async () => {
  await withServer(async (base) => {
    const s = await (await fetch(`${base}/api/archon/status`)).json();
    assert.notEqual(s.adccl, 'armed');
    assert.equal(s.gate.floor, Math.SQRT1_2);
  });
});

test('no response names a personal Base44 app', async () => {
  await withServer(async (base) => {
    const status = await (await fetch(`${base}/api/archon/status`)).text();
    const verdict = await (await post(base, JSON.stringify({ V: 0.9, J: 0.1 }))).text();
    assert.doesNotMatch(status + verdict, /base44/i);
  });
});

test('the three holes of a floor-only gate are closed', () => {
  const zero = evaluate(0, 0);
  assert.ok(Math.abs(zero.chiral_invariant - CHIRAL_FLOOR) < 1e-12);
  assert.equal(zero.passed, false);
  assert.equal(zero.signal, 'abort');
  assert.equal(evaluate(1, 1).passed, false);
  assert.equal(evaluate(1, 1).signal, 'abort');
  assert.equal(evaluate(1, 0.9).passed, false);
  const over = evaluate(1, 0);
  assert.equal(over.passed, false);
  assert.equal(over.signal, 'suspend');
});

test('a pass means every check is silent (grid over the unit square)', () => {
  let passes = 0;
  for (let a = 0; a <= 100; a++) {
    for (let b = 0; b <= 100; b++) {
      const v = a / 100, j = b / 100;
      const chi = computeChiralInvariant(v, j);
      const ok = chi >= CHIRAL_FLOOR && chi <= SOVEREIGN_CEILING && chi - mirrorChi(v, j) >= MIRROR_GAP_MIN
        && v >= CHIRAL_FLOOR && 1 - j >= CHIRAL_FLOOR;
      assert.equal(evaluate(v, j).passed, ok, `V=${v} J=${j}`);
      passes += ok ? 1 : 0;
    }
  }
  assert.ok(passes > 0);
});

test('route reports the signal and refuses the zero-verifiability case', async () => {
  await withServer(async (base) => {
    const r = await (await post(base, JSON.stringify({ V: 0, J: 0 }))).json();
    assert.equal(r.passed, false);
    assert.equal(r.signal, 'abort');
  });
});
