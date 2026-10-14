import { createServer } from 'http';
import { pathToFileURL } from 'url';
import { evaluate, CHIRAL_FLOOR, SOVEREIGN_CEILING, MIRROR_GAP_MIN } from './gate.mjs';

const PORT = process.env.PORT || 3000;

function send(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

export function handle(req, res) {
  // CORS: the edge is a stateless formula endpoint and holds no session, so any origin may call it
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-App-Id');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/api/archon/status' || url.pathname === '/') {
    // This deployment runs the gate formula on scores the caller supplies. It runs no verifier and no model,
    // so it does not claim an armed control loop.
    send(res, 200, {
      app: 'Chyren Archon-SELIN Sovereign Engine',
      platform: 'Vercel Serverless',
      adccl: 'formula-only',
      gate: {
        formula: 'chi = sqrt((V^2 + (1 - J)^2) / 2)',
        checks: ['finiteness', 'floor', 'mirror', 'components', 'ceiling'],
        floor: CHIRAL_FLOOR,
        ceiling: SOVEREIGN_CEILING,
        mirror_gap_min: MIRROR_GAP_MIN,
        scores: 'supplied by caller',
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }

  if (url.pathname === '/api/archon/verify' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let parsed;
      try {
        parsed = JSON.parse(body || '{}');
      } catch (err) {
        send(res, 400, { error: 'request body is not JSON' });
        return;
      }
      // Fail closed: without both scores there is nothing to gate, and no verdict is invented.
      const report = evaluate(parsed.V, parsed.J);
      if (!report.ok) {
        send(res, 422, { passed: false, error: report.error });
        return;
      }
      send(res, 200, {
        run_id: crypto.randomUUID(),
        V: report.v_gate_score,
        J: report.drift_penalty_j,
        chi: report.chiral_invariant,
        mirror_chi: report.mirror_chi,
        signal: report.signal,
        threshold: report.threshold,
        passed: report.passed,
        rejection_reason: report.rejection_reason,
        timestamp: new Date().toISOString(),
      });
    });
    return;
  }

  send(res, 404, { error: 'Endpoint not found', path: url.pathname });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createServer(handle).listen(PORT, () => {
    console.log(`Archon-SELIN Vercel Server running on port ${PORT}`);
  });
}
