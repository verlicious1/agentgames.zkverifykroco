/**
 * End-to-end smoke test against a live local server.
 * Run: npm run smoke
 *
 * Starts the agent on a scratch port with a throwaway dev secret, then:
 *   1. GET /health
 *   2. signed preflight
 *   3. signed valid task -> APPROVE + Groth16 proof (verified locally)
 *   4. same task redelivered -> identical cached body
 *   5. bad HMAC -> 401
 *   6. trap task (amount over cap) -> REJECT / AMOUNT_OVERFLOW
 *   7. same proof_tx in a new task -> REJECT / PROOF_REUSED (no proof)
 * Prints timings; every step must pass or the script exits non-zero.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const snarkjs = require('snarkjs');
const { createAgentServer } = require('../src/server');
const { signBody } = require('../src/hmac');

const SECRET = 'smoke-test-secret-32-bytes-xyz!';
const PORT = 18787;
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.PORT = String(PORT);
process.env.SEEN_STORE_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gk-smoke-')), 'seen.json');
delete process.env.KURIER_API_KEY; // local smoke test: no mainnet submission

const BASE = `http://127.0.0.1:${PORT}`;
let failures = 0;
function check(name, ok, extra = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
}

function taskEnvelope(overrides = {}, envOverrides = {}) {
  const now = new Date();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'smoke-001',
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60_000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 5000,
      current_block: 4990,
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xsmoke001',
      ...overrides,
    },
    ...envOverrides,
  };
}

async function post(bodyObj, signature) {
  const raw = JSON.stringify(bodyObj);
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': signature || signBody(SECRET, raw),
    },
    body: raw,
  });
  return { status: res.status, body: await res.text() };
}

(async () => {
  const server = createAgentServer();
  await new Promise((resolve) => server.listen(PORT, resolve));
  console.log(`[smoke] server up on :${PORT}`);
  const vk = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'circuits', 'verification_key.json'), 'utf8'));

  try {
    // 1. Health
    const h = await fetch(`${BASE}/health`);
    const hj = await h.json();
    check('GET /health returns ok', h.status === 200 && hj.ok === true && hj.protocolVersion === 'v1');

    // 2. Preflight
    const pf = { type: 'agent-games.preflight.v1', nonce: 'smoke-nonce' };
    const pfRes = await post(pf);
    const pfj = JSON.parse(pfRes.body);
    check('preflight -> signed { ok: true }', pfRes.status === 200 && pfj.ok === true && pfj.protocolVersion === 'v1');

    // 3. Valid task
    const env = taskEnvelope();
    const t0 = Date.now();
    const res = await post(env);
    const ms = Date.now() - t0;
    const j = JSON.parse(res.body);
    check('valid task -> 200 APPROVE / VALID_CONDITION', res.status === 200 && j.decision === 'APPROVE' && j.reason_code === 'VALID_CONDITION', `${ms} ms`);
    check('response carries a Groth16 proof + 13 public signals', !!j.proof && Array.isArray(j.public_signals) && j.public_signals.length === 13);
    const okVerify = j.proof ? await snarkjs.groth16.verify(vk, j.public_signals, j.proof) : false;
    check('proof verifies locally against the exported verification key', okVerify === true);
    check('task answered well inside the 60 s deadline', ms < 10_000, `${ms} ms`);

    // 4. Redelivery of the same task_id returns the identical body
    const res2 = await post(env);
    check('redelivery returns identical cached body', res2.body === res.body);

    // 5. Bad HMAC -> 401
    const bad = await post(env, 'deadbeef'.repeat(8));
    check('bad HMAC -> 401 invalid_signature', bad.status === 401 && JSON.parse(bad.body).error === 'invalid_signature');

    // 6. Trap: amount over cap (fresh proof_tx — a reused one would
    // correctly hit PROOF_REUSED first, see check 7)
    const trap = taskEnvelope({ amount: '5000', proof_tx: '0xsmoke002' }, { task_id: 'smoke-002' });
    const rTrap = await post(trap);
    const jTrap = JSON.parse(rTrap.body);
    check('trap task -> REJECT / AMOUNT_OVERFLOW with proof', jTrap.decision === 'REJECT' && jTrap.reason_code === 'AMOUNT_OVERFLOW' && !!jTrap.proof);

    // 7. Replay: same proof_tx, new task_id
    const replay = taskEnvelope({ amount: '500' }, { task_id: 'smoke-003' });
    const rReplay = await post(replay);
    const jReplay = JSON.parse(rReplay.body);
    check('reused proof_tx -> REJECT / PROOF_REUSED without proof', jReplay.decision === 'REJECT' && jReplay.reason_code === 'PROOF_REUSED' && !jReplay.proof);
  } catch (err) {
    console.error('[smoke] unexpected error:', err);
    failures++;
  } finally {
    server.close();
  }

  console.log(failures === 0 ? '[smoke] ALL CHECKS PASSED' : `[smoke] ${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})();
