# agent-games-gatekeeper

Proof Gatekeeper agent for [Agent Games by zkVerify](https://agentgames.zkverify.io) — competition account `@hha09`.

The agent is a public HTTPS endpoint. The platform POSTs signed proof-backed payment tasks; the agent checks every field deterministically and replies APPROVE or REJECT with a reason code, signing every response with the platform-issued HMAC secret.

## Decision rules (first failure wins)

| Check | Reject code |
|---|---|
| proof VK ≠ registered VK | `VK_SUBSTITUTION` |
| public balance < minimum | `THRESHOLD_MISMATCH` |
| proof already used | `PROOF_REUSED` |
| current block > expiry block | `EXPIRED_CONDITION` |
| recipient ≠ condition recipient | `RECIPIENT_MISMATCH` |
| amount > max transfer | `AMOUNT_OVERFLOW` |
| all checks pass | APPROVE / `VALID_CONDITION` |

Fail closed: any error, malformed input, or uncertainty → REJECT. Never approve by default.

## Layout

- `api/agent.js` — the deployed Vercel serverless endpoint (same logic, in-memory state).
- `agent-server.mjs` — the long-running VM server (same logic, state persisted to disk: `seen-proofs.json`, `decisions.json`).
- `test-agent.mjs` — replay harness: 1 valid + 1 per trap type, preflight, bad-signature, idempotency.
- `lt-client.mjs` — minimal localtunnel client (proxy-aware) used to expose the VM server while testing.

## Protocol notes

- HMAC-SHA256 over the raw request/response body, header `x-agent-games-signature`, verified before parsing JSON.
- Preflight: `{"type":"agent-games.preflight.v1",...}` → `{"ok":true,"protocolVersion":"v1"}`.
- Responses are signed; task replays return the stored decision byte-identically (idempotency by `task_id`).
- Groth16 proof: every response carries a `proof` + `public_signals` (snarkjs 0.7.6, official gatekeeper circuit) when proving succeeds — a correct answer with a verifying proof scores +12 instead of +10. Proving is best-effort and fail-closed: any error or timeout (>8s) → the response goes out without proof fields. No proof values are ever invented; wrong decisions cannot build a witness (the circuit asserts at GatekeeperEvaluation_79 line 102).

## Secrets

`AGENT_GAMES_HMAC_SECRET` comes from the Agent Games dashboard ("Rotate Secret"). It is never committed, never logged, never pasted anywhere. Set it as a Vercel env var for the deployed endpoint, or in the environment for the VM server.
