/**
 * Automated tests for the Proof Gatekeeper agent.
 * Run: npm test
 *
 * Covers: HMAC sign/verify, input parsing, the deterministic policy
 * (all six trap classes + boundary semantics), circuit-input construction,
 * real Groth16 proving + local verification against the exported
 * verification key (including the key property that a wrong decision is
 * unprovable), and the full HTTP handler pipeline (401, preflight,
 * approve/reject, idempotent redelivery, proof replay).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const snarkjs = require('snarkjs');

const { loadConfig } = require('../src/config');
const { signBody, verifyBodySignature, deriveSalt, BN128_PRIME } = require('../src/hmac');
const {
  parseUint, parseInput, evaluate, toFieldElement, buildCircuitInputs,
} = require('../src/decision');
const { Prover } = require('../src/prover');
const { AgentHandler } = require('../src/handler');
const { SeenStore } = require('../src/store');

const SECRET = 'test-secret-32-bytes-long-value!';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const CIRCUITS = path.resolve(__dirname, '..', 'circuits');

function baseInput(overrides = {}) {
  return {
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
    proof_tx: '0xabc123',
    ...overrides,
  };
}

function baseEnvelope(inputOverrides = {}, envelopeOverrides = {}) {
  const now = new Date();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_001',
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60_000).toISOString(),
    input: baseInput(inputOverrides),
    ...envelopeOverrides,
  };
}

function testConfig(storePath) {
  return {
    ...loadConfig({}),
    hmacSecret: SECRET,
    kurierApiKey: null,
    circuitsDir: CIRCUITS,
    seenStorePath: storePath,
    kurierPollBudgetMs: 1000,
    kurierPollIntervalMs: 100,
    taskSoftDeadlineMs: 50_000,
  };
}

function tmpStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-test-'));
  return { dir, store: new SeenStore(path.join(dir, 'seen.json')) };
}

// ---------------------------------------------------------------- HMAC
test('hmac: sign/verify roundtrip, wrong secret and tampered body fail', () => {
  const body = Buffer.from(JSON.stringify({ a: 1 }));
  const sig = signBody(SECRET, body);
  assert.equal(sig.length, 64);
  assert.equal(verifyBodySignature(SECRET, body, sig), true);
  // base64 form of the same MAC and sha256= prefix are accepted
  const b64 = Buffer.from(sig, 'hex').toString('base64');
  assert.equal(verifyBodySignature(SECRET, body, b64), true);
  assert.equal(verifyBodySignature(SECRET, body, `sha256=${sig}`), true);
  assert.equal(verifyBodySignature('wrong-secret', body, sig), false);
  assert.equal(verifyBodySignature(SECRET, Buffer.from('{"a":2}'), sig), false);
  assert.equal(verifyBodySignature(SECRET, body, undefined), false);
  assert.equal(verifyBodySignature(SECRET, body, 'not-a-signature'), false);
});

test('hmac: deriveSalt is deterministic and secret-bound', () => {
  const a = deriveSalt(SECRET, 'task-1');
  const b = deriveSalt(SECRET, 'task-1');
  const c = deriveSalt(SECRET, 'task-2');
  const d = deriveSalt('other-secret', 'task-1');
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.notEqual(a, d);
  assert.ok(a < BN128_PRIME);
});

// ---------------------------------------------------------------- parsing
test('parseUint accepts decimal, hex and safe integers; rejects the rest', () => {
  assert.equal(parseUint('123'), 123n);
  assert.equal(parseUint('0x7b'), 123n);
  assert.equal(parseUint(123), 123n);
  assert.equal(parseUint('0'), 0n);
  assert.equal(parseUint('abc'), null);
  assert.equal(parseUint('-1'), null);
  assert.equal(parseUint(1.5), null);
  assert.equal(parseUint(null), null);
  assert.equal(parseUint(''), null);
});

test('parseInput validates structure', () => {
  assert.ok(parseInput(baseInput()));
  assert.equal(parseInput(baseInput({ minimum: 'nope' })), null);
  assert.equal(parseInput(baseInput({ recipient: '' })), null);
  assert.equal(parseInput(undefined), null);
});

// ---------------------------------------------------------------- policy
test('evaluate: valid condition approves; each trap maps to its reason code', () => {
  const seen = new Set();
  const ev = (overrides) => evaluate(parseInput(baseInput(overrides)), (tx) => seen.has(tx));

  assert.deepEqual(ev({}), { decision: 'APPROVE', reason_code: 'VALID_CONDITION', provable: true });
  assert.deepEqual(ev({ proof_vk: '0xdead' }).reason_code, 'VK_SUBSTITUTION');
  assert.deepEqual(ev({ public_balance: '999' }).reason_code, 'THRESHOLD_MISMATCH');
  assert.deepEqual(ev({ current_block: 5000 }).reason_code, 'EXPIRED_CONDITION');
  assert.deepEqual(ev({ recipient: '0x2222222222222222222222222222222222222222' }).reason_code, 'RECIPIENT_MISMATCH');
  assert.deepEqual(ev({ amount: '1001' }).reason_code, 'AMOUNT_OVERFLOW');

  // Boundaries: balance == minimum passes, amount == max passes,
  // current == expiry - 1 passes.
  assert.equal(ev({ public_balance: '1000' }).decision, 'APPROVE');
  assert.equal(ev({ amount: '1000' }).decision, 'APPROVE');
  assert.equal(ev({ current_block: 4999 }).decision, 'APPROVE');
});

test('evaluate: reused proof_tx is PROOF_REUSED and not provable', () => {
  const parsed = parseInput(baseInput());
  const ev = evaluate(parsed, () => true);
  assert.deepEqual(ev, { decision: 'REJECT', reason_code: 'PROOF_REUSED', provable: false });
});

test('toFieldElement: hex reduced mod p, free-form strings hashed, deterministic', () => {
  const a = toFieldElement('0x' + 'ff'.repeat(32));
  assert.ok(BigInt(a) < BN128_PRIME);
  assert.equal(toFieldElement('gk_8d31_x'), toFieldElement('gk_8d31_x'));
  assert.notEqual(toFieldElement('gk_8d31_x'), toFieldElement('gk_8d31_y'));
  assert.equal(toFieldElement('123'), '123');
});

// ---------------------------------------------------------------- proving
test('prover: valid APPROVE input produces a proof that verifies locally', async () => {
  const envelope = baseEnvelope();
  const parsed = parseInput(envelope.input);
  const inputs = buildCircuitInputs(envelope, parsed, 'APPROVE', deriveSalt(SECRET, envelope.task_id));
  const prover = new Prover(CIRCUITS);
  const { proof, publicSignals } = await prover.prove(inputs);
  assert.equal(publicSignals.length, 13);
  assert.equal(publicSignals[11], '1'); // decision signal
  assert.equal(publicSignals[12], toFieldElement(envelope.task_id)); // taskId signal
  const vk = JSON.parse(fs.readFileSync(path.join(CIRCUITS, 'verification_key.json'), 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  assert.equal(proof.protocol, 'groth16');
  assert.equal(proof.curve, 'bn128');
});

test('prover: a trap input proves REJECT, and APPROVE for it is unprovable', async () => {
  const envelope = baseEnvelope({ public_balance: '500' }); // below minimum
  const parsed = parseInput(envelope.input);
  const prover = new Prover(CIRCUITS);
  const rejectInputs = buildCircuitInputs(envelope, parsed, 'REJECT', deriveSalt(SECRET, envelope.task_id));
  const { proof, publicSignals } = await prover.prove(rejectInputs);
  assert.equal(publicSignals[11], '0');
  const vk = JSON.parse(fs.readFileSync(path.join(CIRCUITS, 'verification_key.json'), 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);

  // The circuit enforces decision == AND(checks): claiming APPROVE for a
  // trap input must fail witness generation.
  const approveInputs = buildCircuitInputs(envelope, parsed, 'APPROVE', deriveSalt(SECRET, envelope.task_id));
  await assert.rejects(() => prover.prove(approveInputs));
});

// ---------------------------------------------------------------- handler
test('handler: missing secret -> 500; bad signature -> 401', async () => {
  const { store } = tmpStore();
  const noSecret = new AgentHandler({ ...testConfig(''), hmacSecret: '' }, store);
  const r500 = await noSecret.handlePost(Buffer.from('{}'), 'x');
  assert.equal(r500.status, 500);

  const handler = new AgentHandler(testConfig(''), store);
  const r401 = await handler.handlePost(Buffer.from('{}'), 'bad-signature');
  assert.equal(r401.status, 401);
  assert.equal(JSON.parse(r401.body).error, 'invalid_signature');
});

test('handler: preflight returns signed { ok: true, protocolVersion }', async () => {
  const { store } = tmpStore();
  const handler = new AgentHandler(testConfig(''), store);
  const body = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', nonce: 'n1' }));
  const res = await handler.handlePost(body, signBody(SECRET, body));
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true, protocolVersion: 'v1' });
  assert.equal(verifyBodySignature(SECRET, Buffer.from(res.body), res.signature), true);
});

test('handler: valid task approves with a verifiable proof; redelivery is cached', async () => {
  const { store } = tmpStore();
  const handler = new AgentHandler(testConfig(''), store);
  const envelope = baseEnvelope();
  const body = Buffer.from(JSON.stringify(envelope));
  const res = await handler.handlePost(body, signBody(SECRET, body));
  assert.equal(res.status, 200);
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.decision, 'APPROVE');
  assert.equal(parsed.reason_code, 'VALID_CONDITION');
  assert.ok(parsed.proof);
  assert.equal(parsed.public_signals.length, 13);
  // Response signature verifies.
  assert.equal(verifyBodySignature(SECRET, Buffer.from(res.body), res.signature), true);
  // Without a Kurier key the proof_tx echoes the task's proof reference.
  assert.equal(parsed.proof_tx, '0xabc123');
  // Proof verifies against the exported verification key.
  const vk = JSON.parse(fs.readFileSync(path.join(CIRCUITS, 'verification_key.json'), 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vk, parsed.public_signals, parsed.proof), true);

  // Redelivery of the same task_id returns the identical cached body.
  const res2 = await handler.handlePost(body, signBody(SECRET, body));
  assert.equal(res2.body, res.body);
});

test('handler: trap task rejects with proof; reused proof_tx rejects without proof', async () => {
  const { store } = tmpStore();
  const handler = new AgentHandler(testConfig(''), store);

  const trap = baseEnvelope({ amount: '5000' }, { task_id: 'gk_test_trap' });
  const trapBody = Buffer.from(JSON.stringify(trap));
  const r1 = await handler.handlePost(trapBody, signBody(SECRET, trapBody));
  const p1 = JSON.parse(r1.body);
  assert.equal(p1.decision, 'REJECT');
  assert.equal(p1.reason_code, 'AMOUNT_OVERFLOW');
  assert.ok(p1.proof); // trap rejections are provable

  // Same proof_tx in a NEW task -> PROOF_REUSED, no proof attached.
  const replay = baseEnvelope({ amount: '500' }, { task_id: 'gk_test_replay' });
  const replayBody = Buffer.from(JSON.stringify(replay));
  const r2 = await handler.handlePost(replayBody, signBody(SECRET, replayBody));
  const p2 = JSON.parse(r2.body);
  assert.equal(p2.decision, 'REJECT');
  assert.equal(p2.reason_code, 'PROOF_REUSED');
  assert.equal(p2.proof, undefined);
});

test('handler: malformed JSON and expired deadline fail closed', async () => {
  const { store } = tmpStore();
  const handler = new AgentHandler(testConfig(''), store);

  const badJson = Buffer.from('{not json');
  const r1 = await handler.handlePost(badJson, signBody(SECRET, badJson));
  assert.equal(r1.status, 400);
  assert.equal(JSON.parse(r1.body).reason_code, 'INVALID_TASK');

  const expired = baseEnvelope({}, {
    task_id: 'gk_test_expired',
    deadline_at: new Date(Date.now() - 60_000).toISOString(),
  });
  const expBody = Buffer.from(JSON.stringify(expired));
  const r2 = await handler.handlePost(expBody, signBody(SECRET, expBody));
  assert.equal(JSON.parse(r2.body).decision, 'REJECT');
});
