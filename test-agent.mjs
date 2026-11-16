// test-agent.mjs — replays envelopes through the running gatekeeper server
// and checks decision / reason_code / response signature per case.
//
// Usage: TEST_HMAC_SECRET=<same secret the server runs with> node test-agent.mjs
// (default base URL http://127.0.0.1:3000; override with AGENT_URL env.)
//
// Cases: 1 valid + 1 per trap type (6) + idempotency replay + preflight +
// bad-signature (expect 401) + GET health. State files are NOT cleared:
// every run uses fresh proof_tx values (run nonce), so repeats are safe.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = process.env.AGENT_URL || 'http://127.0.0.1:3000';
const SECRET = process.env.TEST_HMAC_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || '';
if (!SECRET) {
  console.error('FATAL: set TEST_HMAC_SECRET (same secret the server runs with).');
  process.exit(1);
}
const SIGNATURE_HEADER = 'x-agent-games-signature';
const DIR = path.dirname(fileURLToPath(import.meta.url));

const RUN = Date.now().toString(36); // unique per run -> fresh proof_tx values
const VK = '0x7d3a00000000000000000000000000000000000000000000000000000000f291';
const OTHER_VK = '0xa4c100000000000000000000000000000000000000000000000000000000b8ff';
const RECIPIENT = '0xde4200000000000000000000000000000000009f01';
const RECIPIENT_UPPER = '0xDE4200000000000000000000000000000000009F01'; // same address, different case
const OTHER_RECIPIENT = '0xbeef00000000000000000000000000000000000001';

function sign(bodyBuf) {
  return crypto.createHmac('sha256', SECRET).update(bodyBuf).digest('hex');
}

function verifyResponseSignature(rawBody, headerValue) {
  if (!headerValue) return false;
  let sig = String(headerValue).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const expected = sign(rawBody);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function post(obj, { secret = SECRET, rawBody = null } = {}) {
  const body = rawBody ?? Buffer.from(JSON.stringify(obj), 'utf8');
  const res = await fetch(BASE + '/', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [SIGNATURE_HEADER]: crypto.createHmac('sha256', secret).update(body).digest('hex'),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, sigOk: verifyResponseSignature(Buffer.from(text, 'utf8'), res.headers.get(SIGNATURE_HEADER)), json, text };
}

async function get(pathname) {
  const res = await fetch(BASE + pathname, { method: 'GET' });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, sigOk: verifyResponseSignature(Buffer.from(text, 'utf8'), res.headers.get(SIGNATURE_HEADER)), json };
}

function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: '19842201',
    current_block: '19832000',
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT_UPPER, // case differs on purpose: addresses compare case-insensitively
    amount: '500',
    max_transfer: '1000',
    proof_tx: `0x${RUN}a1`,
    ...overrides,
  };
}

function task(taskId, input, mode = 'practice') {
  return { type: 'agent-games.proof-gatekeeper.v1', task_id: taskId, mode, issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input };
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

// ------------------------------------------------------------------ cases --
const validTx = `0x${RUN}a1`;
const validTaskId = `gk_test_${RUN}_valid`;

// 1. Valid condition -> APPROVE / VALID_CONDITION
const r1 = await post(task(validTaskId, baseInput()));
check('valid -> APPROVE/VALID_CONDITION',
  r1.status === 200 && r1.json?.decision === 'APPROVE' && r1.json?.reason_code === 'VALID_CONDITION' && r1.json?.proof_tx === validTx,
  `expected APPROVE/VALID_CONDITION, got ${r1.status} ${JSON.stringify(r1.json)}`);
check('valid response signature verifies', r1.sigOk, r1.sigOk ? '' : 'bad/missing signature header');
const validSignature = r1; // kept for the idempotency comparison

// 2. VK substitution
const r2 = await post(task(`gk_test_${RUN}_vk`, baseInput({ proof_vk: OTHER_VK, proof_tx: `0x${RUN}a2` })));
check('vk_substitution -> REJECT/VK_SUBSTITUTION',
  r2.status === 200 && r2.json?.decision === 'REJECT' && r2.json?.reason_code === 'VK_SUBSTITUTION',
  `expected REJECT/VK_SUBSTITUTION, got ${r2.status} ${JSON.stringify(r2.json)}`);
check('vk response signature verifies', r2.sigOk);

// 3. Threshold mismatch
const r3 = await post(task(`gk_test_${RUN}_threshold`, baseInput({ public_balance: '999', proof_tx: `0x${RUN}a3` })));
check('threshold_mismatch -> REJECT/THRESHOLD_MISMATCH',
  r3.status === 200 && r3.json?.decision === 'REJECT' && r3.json?.reason_code === 'THRESHOLD_MISMATCH',
  `expected REJECT/THRESHOLD_MISMATCH, got ${r3.status} ${JSON.stringify(r3.json)}`);
check('threshold response signature verifies', r3.sigOk);

// 4. Proof reused — same proof_tx as case 1, new task_id
const r4 = await post(task(`gk_test_${RUN}_reuse`, baseInput({ proof_tx: validTx })));
check('proof_reused -> REJECT/PROOF_REUSED',
  r4.status === 200 && r4.json?.decision === 'REJECT' && r4.json?.reason_code === 'PROOF_REUSED',
  `expected REJECT/PROOF_REUSED, got ${r4.status} ${JSON.stringify(r4.json)}`);
check('reuse response signature verifies', r4.sigOk);

// 5. Expired condition
const r5 = await post(task(`gk_test_${RUN}_expired`, baseInput({ current_block: '19842202', proof_tx: `0x${RUN}a5` })));
check('expired_condition -> REJECT/EXPIRED_CONDITION',
  r5.status === 200 && r5.json?.decision === 'REJECT' && r5.json?.reason_code === 'EXPIRED_CONDITION',
  `expected REJECT/EXPIRED_CONDITION, got ${r5.status} ${JSON.stringify(r5.json)}`);
check('expired response signature verifies', r5.sigOk);

// 6. Recipient mismatch
const r6 = await post(task(`gk_test_${RUN}_recipient`, baseInput({ recipient: OTHER_RECIPIENT, proof_tx: `0x${RUN}a6` })));
check('recipient_mismatch -> REJECT/RECIPIENT_MISMATCH',
  r6.status === 200 && r6.json?.decision === 'REJECT' && r6.json?.reason_code === 'RECIPIENT_MISMATCH',
  `expected REJECT/RECIPIENT_MISMATCH, got ${r6.status} ${JSON.stringify(r6.json)}`);
check('recipient response signature verifies', r6.sigOk);

// 7. Amount overflow
const r7 = await post(task(`gk_test_${RUN}_amount`, baseInput({ amount: '1001', proof_tx: `0x${RUN}a7` })));
check('amount_overflow -> REJECT/AMOUNT_OVERFLOW',
  r7.status === 200 && r7.json?.decision === 'REJECT' && r7.json?.reason_code === 'AMOUNT_OVERFLOW',
  `expected REJECT/AMOUNT_OVERFLOW, got ${r7.status} ${JSON.stringify(r7.json)}`);
check('amount response signature verifies', r7.sigOk);

// 8. Idempotency — replay case 1's exact task_id/body -> same stored response,
//    same signature, no re-decision.
const r8 = await post(task(validTaskId, baseInput()));
check('idempotent replay -> same stored APPROVE response',
  r8.status === 200 && r8.json?.decision === 'APPROVE' && r8.json?.reason_code === 'VALID_CONDITION' && JSON.stringify(r8.json) === JSON.stringify(validSignature.json),
  `expected identical APPROVE/VALID_CONDITION, got ${r8.status} ${JSON.stringify(r8.json)}`);
check('idempotent replay -> same signature as first response',
  r8.text === validSignature.text,
  'response body differs from first response');

// 9. Preflight
const r9 = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: `test-${RUN}` });
check('preflight -> {ok:true, protocolVersion:"v1"}',
  r9.status === 200 && r9.json?.ok === true && r9.json?.protocolVersion === 'v1',
  `expected 200 {ok:true, protocolVersion:"v1"}, got ${r9.status} ${JSON.stringify(r9.json)}`);
check('preflight response signature verifies', r9.sigOk);

// 10. Bad signature -> 401
const r10 = await post(task(`gk_test_${RUN}_bad`, baseInput({ proof_tx: `0x${RUN}ab` })), { secret: 'wrong-secret' });
check('bad signature -> 401',
  r10.status === 401,
  `expected 401, got ${r10.status} ${JSON.stringify(r10.json)}`);

// 11. GET health
const r11 = await get('/');
check('GET / -> {ok:true, protocolVersion:"v1"}',
  r11.status === 200 && r11.json?.ok === true && r11.json?.protocolVersion === 'v1',
  `expected 200 {ok:true, protocolVersion:"v1"}, got ${r11.status} ${JSON.stringify(r11.json)}`);

// 12. State files: valid proof recorded exactly once; valid task_id stored once.
let stateOk = false;
let stateDetail = '';
try {
  const seen = JSON.parse(fs.readFileSync(path.join(DIR, 'seen-proofs.json'), 'utf8'));
  const decisions = JSON.parse(fs.readFileSync(path.join(DIR, 'decisions.json'), 'utf8'));
  const count = seen.filter((p) => p === validTx).length;
  stateOk = count === 1 && decisions[validTaskId]?.decision === 'APPROVE' && decisions[validTaskId]?.reason_code === 'VALID_CONDITION';
  stateDetail = `seen count for valid proof_tx = ${count}, stored decision for ${validTaskId} = ${JSON.stringify(decisions[validTaskId])}`;
} catch (err) {
  stateDetail = `could not read state files: ${err.message}`;
}
check('state files: proof recorded once, decision stored', stateOk, stateDetail);

// ---------------------------------------------------------------- summary --
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} checks passed${failed.length ? ` — ${failed.length} FAILED` : ''}`);
process.exit(failed.length ? 1 : 0);
