// Vercel serverless version of the Proof Gatekeeper agent (@hha09).
// Same protocol as agent-server.mjs (the VM long-running server):
//  - POST signed JSON tasks; HMAC x-agent-games-signature over RAW body,
//    verified BEFORE parsing. 401 on mismatch.
//  - Preflight {"type":"agent-games.preflight.v1"} -> {"ok":true,"protocolVersion":"v1"}.
//  - Task {"type":"agent-games.proof-gatekeeper.v1"} -> {"decision","reason_code","proof_tx"}
//    plus, when proving succeeds, Groth16 "proof" + "public_signals".
//  - GET -> {"ok":true,"protocolVersion":"v1"} (health check).
//  - Fail closed: any error/uncertainty -> REJECT, never APPROVE.
//  - Groth16 proof (added 2026-11-16): the platform re-verifies the proof
//    against its registered VK; a correct answer WITH a verifying proof scores
//    +12, without one +10. Circuit input schema recovered by probing the
//    official gatekeeper.wasm (13 inputs) and verified locally with snarkjs
//    0.7.6 (fullProve + groth16.verify OK; wrong decisions cannot build a
//    witness — fail-closed by construction). Proof generation is best-effort:
//    any error, timeout (>8s), or missing input -> respond exactly as before
//    (no proof fields). NEVER invent a proof.
//
// STATE LIMIT (serverless): seen proofs + decisions live in module memory.
// A cold start or a second instance resets them, so a PROOF_REUSED trap could
// be missed after a recycle. The VM server (agent-server.mjs) is the stateful
// source of truth; if the tunnel comes back, the endpoint can move back there
// via updateAgentEndpoint. For now this is the best available public endpoint.
//
// Secret: AGENT_GAMES_HMAC_SECRET (Vercel env var, set after registration).
// Never hardcoded, never logged.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { groth16 } from 'snarkjs';
import pkg from 'js-sha3';
const { keccak_256 } = pkg;

export const config = { api: { bodyParser: false } };

const SIGNATURE_ENCODING = 'hex';
const SIGNATURE_HEADER = 'x-agent-games-signature';
const MAX_BODY_BYTES = 1_000_000;

const seenProofs = new Set();
const decisions = new Map();

function sign(rawBody, secret) {
  const digest = crypto.createHmac('sha256', secret).update(rawBody).digest();
  return SIGNATURE_ENCODING === 'base64' ? digest.toString('base64') : digest.toString('hex');
}

function verifySignature(rawBody, headerValue, secret) {
  if (!headerValue || !secret) return false;
  let sig = String(headerValue).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const expected = sign(rawBody, secret);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

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
    if (String(proof_vk) !== String(registered_vk)) return fail('VK_SUBSTITUTION');
    if (BigInt(String(public_balance)) < BigInt(String(minimum))) return fail('THRESHOLD_MISMATCH');
    if (seenProofs.has(String(proof_tx))) return fail('PROOF_REUSED');
    if (BigInt(String(current_block)) > BigInt(String(expiry_block))) return fail('EXPIRED_CONDITION');
    if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase()) return fail('RECIPIENT_MISMATCH');
    if (BigInt(String(amount)) > BigInt(String(max_transfer))) return fail('AMOUNT_OVERFLOW');
    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
  } catch {
    return fail('INVALID_INPUT');
  }
}

// ------------------------------------------------------- Groth16 proof ----
// Same circuit + mapping as agent-server.mjs. Artifacts are the platform's
// own public files, downloaded once to /tmp on first use (cached in memory
// after that); any download/prove failure -> no proof fields (fail-closed).
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CIRCUIT_BASE = 'https://agentgames.zkverify.io/circuits';
const PROVE_TIMEOUT_MS = 8000;
const modP = (x) => ((x % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;

let artifactPaths = null;
async function getArtifacts() {
  if (artifactPaths) return artifactPaths;
  const wasmPath = path.join(os.tmpdir(), 'gatekeeper.wasm');
  const zkeyPath = path.join(os.tmpdir(), 'gatekeeper_final.zkey');
  for (const [url, dest] of [[`${CIRCUIT_BASE}/gatekeeper.wasm`, wasmPath], [`${CIRCUIT_BASE}/gatekeeper_final.zkey`, zkeyPath]]) {
    try {
      await fs.access(dest);
    } catch {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) return null;
      await fs.writeFile(dest, Buffer.from(await res.arrayBuffer()));
    }
  }
  artifactPaths = { wasmPath, zkeyPath };
  return artifactPaths;
}

function buildProofInput(taskId, input, decision) {
  const req = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
    'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer', 'proof_tx'];
  if (!input || typeof input !== 'object') return null;
  if (req.some((k) => input[k] === undefined || input[k] === null)) return null;
  if (!taskId || typeof taskId !== 'string') return null;
  try {
    return {
      taskId: modP(BigInt('0x' + keccak_256(taskId))).toString(),
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
  const artifacts = await getArtifacts();
  if (!artifacts) return null;
  const prove = groth16.fullProve(circuitInput, artifacts.wasmPath, artifacts.zkeyPath)
    .then((r) => ({ proof: r.proof, publicSignals: r.publicSignals })).catch(() => null);
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), PROVE_TIMEOUT_MS));
  try {
    return await Promise.race([prove, timeout]);
  } catch { return null; }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('body_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET || '';
  const send = (status, obj) => {
    const body = Buffer.from(JSON.stringify(obj), 'utf8');
    const headers = { 'content-type': 'application/json' };
    if (secret) headers[SIGNATURE_HEADER] = sign(body, secret);
    res.writeHead(status, headers);
    res.end(body);
  };

  if (req.method === 'GET') { send(200, { ok: true, protocolVersion: 'v1' }); return; }
  if (req.method !== 'POST') { send(405, { error: 'method_not_allowed' }); return; }
  if (!secret) { send(500, { error: 'secret_not_configured' }); return; }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch {
    send(413, { error: 'body_too_large' });
    return;
  }

  if (!verifySignature(rawBody, req.headers[SIGNATURE_HEADER], secret)) {
    send(401, { error: 'invalid_signature' });
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch {
    send(400, { error: 'invalid_json' });
    return;
  }
  if (!envelope || typeof envelope !== 'object') { send(400, { error: 'invalid_envelope' }); return; }

  if (envelope.type === 'agent-games.preflight.v1') {
    send(200, { ok: true, protocolVersion: 'v1' });
    return;
  }

  if (envelope.type === 'agent-games.proof-gatekeeper.v1') {
    const { task_id, input } = envelope;
    if (!task_id || typeof task_id !== 'string') { send(400, { error: 'missing_task_id' }); return; }
    if (decisions.has(task_id)) { send(200, decisions.get(task_id)); return; }
    const result = decide(input);
    const proofTx = input && input.proof_tx !== undefined && input.proof_tx !== null ? String(input.proof_tx) : '';
    const response = { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTx };
    // Best-effort Groth16 proof of the decision (see proveDecision above).
    const proofRes = await proveDecision(task_id, input, result.decision);
    if (proofRes) {
      response.proof = proofRes.proof;
      response.public_signals = proofRes.publicSignals;
    }
    decisions.set(task_id, response);
    if (proofTx) seenProofs.add(proofTx);
    send(200, response);
    return;
  }

  send(400, { error: 'unknown_type' });
}
