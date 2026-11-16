// agent-server.mjs — Proof Gatekeeper agent endpoint for Agent Games (@hha09)
// Node stdlib only (http + crypto + fs). Listens on 0.0.0.0:3000.
//
// Protocol (from https://agentgames.zkverify.io/build, text-extracted 2026-11-15):
//  - Platform POSTs signed JSON tasks to this endpoint (any path; it posts to the
//    URL exactly as registered — our public URL is https://hha09-gatekeeper.loca.lt).
//  - Inbound HMAC: x-agent-games-signature over the RAW request body, verified
//    BEFORE parsing JSON. Reject (401) on mismatch.
//  - Preflight {"type":"agent-games.preflight.v1",...} -> {"ok":true,"protocolVersion":"v1"}, signed.
//  - Task {"type":"agent-games.proof-gatekeeper.v1",...} -> {"decision","reason_code","proof_tx"}, signed.
//  - GET on any path -> {"ok":true,"protocolVersion":"v1"} (health check).
//  - 60s hard deadline; fail closed: any error/uncertainty -> REJECT, never APPROVE.
//  - MVP OMISSION (documented, costs -2/provable task): no Groth16 proof +
//    public_signals in the response. Do NOT invent proof values.
//
// Secrets: AGENT_GAMES_HMAC_SECRET (real, from dashboard "Rotate Secret") or
// TEST_HMAC_SECRET (local testing only). Never hardcoded, never logged, never
// written to any file.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import snarkjsPkg from './proof/node_modules/snarkjs/build/main.cjs';
import { keccak256 as ethersKeccak, toUtf8Bytes } from 'ethers';

// ---- one-line tunables (flip after observing a real platform signature) ----
const SIGNATURE_ENCODING = 'hex'; // 'hex' | 'base64' — hex is the default guess; format is undocumented
const SIGNATURE_HEADER = 'x-agent-games-signature';
const PORT = 3000;
const HOST = '0.0.0.0';
const MAX_BODY_BYTES = 1_000_000; // 1 MB cap on inbound bodies

const DIR = path.dirname(fileURLToPath(import.meta.url));
const SEEN_FILE = path.join(DIR, 'seen-proofs.json');
const DECISIONS_FILE = path.join(DIR, 'decisions.json');
const LOG_FILE = path.join(DIR, 'agent.log');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || process.env.TEST_HMAC_SECRET || '';
if (!SECRET) {
  console.error('FATAL: set AGENT_GAMES_HMAC_SECRET (real, from dashboard Rotate Secret) or TEST_HMAC_SECRET (local testing only).');
  process.exit(1);
}
const USING_TEST_SECRET = !process.env.AGENT_GAMES_HMAC_SECRET;

// ---------------------------------------------------------------- state ----
// seen-proofs.json: array of proof_tx strings already decided on.
// decisions.json:   map task_id -> exact response object sent (idempotency).
// Both written atomically (temp file + rename) — these files were truncated to
// 0 bytes twice before in this workspace; never write them in place.

function loadJsonArray(file) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    console.error(`WARN: ${path.basename(file)} unreadable/corrupt (${err.message}) — quarantining and starting empty.`);
    try { fs.renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { /* ignore */ }
    return [];
  }
}

function loadJsonObject(file) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    console.error(`WARN: ${path.basename(file)} unreadable/corrupt (${err.message}) — quarantining and starting empty.`);
    try { fs.renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { /* ignore */ }
    return {};
  }
}

function saveAtomic(file, data) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

const seenProofs = new Set(loadJsonArray(SEEN_FILE).map(String));
const decisions = new Map(Object.entries(loadJsonObject(DECISIONS_FILE)));

function persistState() {
  // Decisions first, then seen: if we crash between the two writes, a replayed
  // task_id still returns its stored decision (idempotency preserved); the
  // worst case is a proof not yet recorded in the seen set.
  saveAtomic(DECISIONS_FILE, JSON.stringify(Object.fromEntries(decisions), null, 2));
  saveAtomic(SEEN_FILE, JSON.stringify([...seenProofs], null, 2));
}

// ----------------------------------------------------------------- HMAC ----

function sign(rawBody) {
  const digest = crypto.createHmac('sha256', SECRET).update(rawBody).digest();
  return SIGNATURE_ENCODING === 'base64' ? digest.toString('base64') : digest.toString('hex');
}

function verifySignature(rawBody, headerValue) {
  if (!headerValue) return false;
  let sig = String(headerValue).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7); // tolerate "sha256=<hex>" style
  const expected = sign(rawBody);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ------------------------------------------------------------- decision ----
// Deterministic, first matching failure wins. Numbers arrive as strings (or
// JSON numbers in the docs' sample) — compare as BigInt either way.
// Addresses compared case-insensitively. VK compared STRICTLY (spec writes
// proof_vk !== registered_vk; a case-only difference in a hex key is the same
// key, but the spec's trap is a different key — follow the spec literally).

function decide(input) {
  const fail = (reason_code) => ({ decision: 'REJECT', reason_code });
  try {
    if (!input || typeof input !== 'object') return fail('INVALID_INPUT');
    const {
      registered_vk, proof_vk, minimum, public_balance,
      expiry_block, current_block, recipient, condition_recipient,
      amount, max_transfer, proof_tx,
    } = input;
    const fields = [registered_vk, proof_vk, minimum, public_balance, expiry_block,
      current_block, recipient, condition_recipient, amount, max_transfer, proof_tx];
    if (fields.some((v) => v === undefined || v === null)) return fail('INVALID_INPUT');

    // 1. VK substitution
    if (String(proof_vk) !== String(registered_vk)) return fail('VK_SUBSTITUTION');
    // 2. Threshold mismatch
    if (BigInt(String(public_balance)) < BigInt(String(minimum))) return fail('THRESHOLD_MISMATCH');
    // 3. Proof reused
    if (seenProofs.has(String(proof_tx))) return fail('PROOF_REUSED');
    // 4. Expired condition
    if (BigInt(String(current_block)) > BigInt(String(expiry_block))) return fail('EXPIRED_CONDITION');
    // 5. Recipient mismatch (case-insensitive)
    if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase()) return fail('RECIPIENT_MISMATCH');
    // 6. Amount overflow
    if (BigInt(String(amount)) > BigInt(String(max_transfer))) return fail('AMOUNT_OVERFLOW');
    // 7. Valid
    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
  } catch {
    return fail('INVALID_INPUT'); // unparseable numbers etc. -> fail closed
  }
}

// ------------------------------------------------------- Groth16 proof ----
// The platform re-verifies a Groth16 proof of the decision against its
// registered verification key; a correct answer WITH a verifying proof scores
// +12, without one +10. Circuit input schema recovered 2026-11-16 by probing
// the official gatekeeper.wasm (13 inputs) and verified locally with snarkjs
// 0.7.6: fullProve + groth16.verify OK, public layout
// [commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
// expiryBlock, currentBlock, recipient, conditionRecipient, amount,
// maxTransfer, decision, taskId]; wrong decisions cannot build a witness
// (assert at GatekeeperEvaluation_79 line 102) — fail-closed by construction.
// Proof generation is best-effort: any error, timeout, or missing input ->
// respond exactly as before (no proof fields). NEVER invent a proof.
// VK hashes and taskId are keccak256 values reduced mod the bn128 field
// prime; addresses are plain integers; salt is a random private nonce.
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CIRCUIT_DIR = path.join(DIR, 'circuits');
const PROVE_TIMEOUT_MS = 8000;

const modP = (x) => ((x % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;

function buildProofInput(taskId, input, decision) {
  const req = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
    'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer', 'proof_tx'];
  if (!input || typeof input !== 'object') return null;
  if (req.some((k) => input[k] === undefined || input[k] === null)) return null;
  if (!taskId || typeof taskId !== 'string') return null;
  try {
    return {
      taskId: modP(BigInt(ethersKeccak(toUtf8Bytes(taskId)))).toString(),
      minimum: modP(BigInt(String(input.minimum))).toString(),
      publicBalance: modP(BigInt(String(input.public_balance))).toString(),
      expiryBlock: modP(BigInt(String(input.expiry_block))).toString(),
      currentBlock: modP(BigInt(String(input.current_block))).toString(),
      recipient: modP(BigInt(String(input.recipient))).toString(),
      conditionRecipient: modP(BigInt(String(input.condition_recipient))).toString(),
      amount: modP(BigInt(String(input.amount))).toString(),
      maxTransfer: modP(BigInt(String(input.max_transfer))).toString(),
      registeredVkHash: modP(BigInt(String(input.registered_vk))).toString(),
      proofVkHash: modP(BigInt(String(input.proof_vk))).toString(),
      salt: modP(BigInt('0x' + crypto.randomBytes(32).toString('hex'))).toString(),
      decision: decision === 'APPROVE' ? '1' : '0',
    };
  } catch { return null; }
}

async function proveDecision(taskId, input, decision) {
  const circuitInput = buildProofInput(taskId, input, decision);
  if (!circuitInput) return null;
  const prove = snarkjsPkg.groth16.fullProve(
    circuitInput,
    path.join(CIRCUIT_DIR, 'gatekeeper.wasm'),
    path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey'),
  ).then((r) => ({ proof: r.proof, publicSignals: r.publicSignals })).catch(() => null);
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), PROVE_TIMEOUT_MS));
  try {
    return await Promise.race([prove, timeout]);
  } catch { return null; }
}

// -------------------------------------------------------------- logging ----
// JSON lines: task_id, mode, decision, reason_code, ms. Never the secret,
// raw bodies, or full envelopes.

function logLine(obj) {
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n');
  } catch (err) {
    console.error('WARN: could not append to agent.log:', err.message);
  }
}

// -------------------------------------------------------------- respond ----

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    [SIGNATURE_HEADER]: sign(body),
  });
  res.end(body);
}

// -------------------------------------------------------------- handler ----

function handleRequest(req, res) {
  const started = Date.now();

  // GET on any path -> health check (signed, like every response).
  if (req.method === 'GET') {
    sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
    return;
  }

  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'method_not_allowed' });
    return;
  }

  const chunks = [];
  let tooLarge = false;
  req.on('data', (chunk) => {
    if (tooLarge) return;
    chunks.push(chunk);
    if (Buffer.concat(chunks).length > MAX_BODY_BYTES) {
      tooLarge = true;
      sendJson(res, 413, { error: 'body_too_large' });
      req.destroy();
    }
  });
  req.on('error', () => { try { res.destroy(); } catch { /* ignore */ } });
  req.on('end', async () => {
    if (tooLarge) return;
    const rawBody = Buffer.concat(chunks);

    // 1. Verify HMAC over the RAW body BEFORE parsing JSON.
    if (!verifySignature(rawBody, req.headers[SIGNATURE_HEADER])) {
      sendJson(res, 401, { error: 'invalid_signature' });
      return;
    }

    // 2. Parse JSON.
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch {
      sendJson(res, 400, { error: 'invalid_json' });
      return;
    }
    if (!envelope || typeof envelope !== 'object') {
      sendJson(res, 400, { error: 'invalid_envelope' });
      return;
    }

    // 3. Preflight handshake.
    if (envelope.type === 'agent-games.preflight.v1') {
      sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
      logLine({ type: 'preflight', agent_id: envelope.agent_id ?? null, ms: Date.now() - started });
      return;
    }

    // 4. Task envelope.
    if (envelope.type === 'agent-games.proof-gatekeeper.v1') {
      const { task_id, mode, input } = envelope;
      if (!task_id || typeof task_id !== 'string') {
        sendJson(res, 400, { error: 'missing_task_id' });
        return;
      }

      // Idempotency: a repeated task_id returns the stored response verbatim
      // (same decision, same signature — signature is deterministic over the
      // same body + secret) WITHOUT re-running logic or re-recording the proof.
      if (decisions.has(task_id)) {
        sendJson(res, 200, decisions.get(task_id));
        logLine({ task_id, mode: mode ?? null, decision: decisions.get(task_id).decision, reason_code: decisions.get(task_id).reason_code, replay: true, ms: Date.now() - started });
        return;
      }

      const result = decide(input);
      const proofTx = input && input.proof_tx !== undefined && input.proof_tx !== null ? String(input.proof_tx) : '';
      const response = { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTx };

      // Best-effort Groth16 proof of the decision. On any failure the
      // response goes out exactly as before (no proof fields) — the decision
      // stays correct, only the +2 proof bonus is missed for that task.
      const proofRes = await proveDecision(task_id, input, result.decision);
      if (proofRes) {
        response.proof = proofRes.proof;
        response.public_signals = proofRes.publicSignals;
      }

      // Record the proof AFTER every decision (approve or reject) — but never
      // for a retried task_id (handled above). Empty proof_tx is not recorded.
      decisions.set(task_id, response);
      if (proofTx) seenProofs.add(proofTx);
      persistState();

      sendJson(res, 200, response);
      logLine({ task_id, mode: mode ?? null, decision: result.decision, reason_code: result.reason_code, ms: Date.now() - started });
      return;
    }

    sendJson(res, 400, { error: 'unknown_type' });
  });
}

const server = http.createServer(handleRequest);
server.listen(PORT, HOST, () => {
  console.log(`gatekeeper listening on ${HOST}:${PORT} (seen=${seenProofs.size} proofs, decisions=${decisions.size})`);
  console.log(`secret source: ${USING_TEST_SECRET ? 'TEST_HMAC_SECRET — TEST ONLY, restart with real AGENT_GAMES_HMAC_SECRET before round 03' : 'AGENT_GAMES_HMAC_SECRET (real)'}`);
  console.log(`signature encoding: ${SIGNATURE_ENCODING} (header ${SIGNATURE_HEADER})`);
});
server.on('error', (err) => {
  console.error('FATAL: server error:', err.message);
  process.exit(1);
});
