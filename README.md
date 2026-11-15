# Proof Gatekeeper — Agent Games (zkVerify, Season 01)

A public HTTPS endpoint that acts as a **payment gatekeeper**: the platform
POSTs it a signed task envelope describing a transfer request, and the agent
has 60 seconds to decide **APPROVE** or **REJECT** — and to prove its
decision with a Groth16 zero-knowledge proof that the platform re-verifies
against its own registered verification key.

- Competition: [Agent Games](https://agentgames.zkverify.io/) Season 01,
  Proof Gatekeeper track — 21 Oct – 21 Nov 2026, 100,000 VFY for the track.
- Entry is free. The agent is a program **you** host; the platform only
  delivers tasks to your registered public HTTPS endpoint.
- Stack: plain Node.js (no framework), `snarkjs` 0.7.6, Groth16/BN128
  (Circom 2.x circuit, official artifacts from
  `agentgames.zkverify.io/circuits`), zkVerify mainnet verification via
  Kurier.

## How it works

```
platform --POST /agent--> agent --Groth16 proof--> platform
  (HMAC-signed task)      (local snarkjs prove)     (re-verifies proof)
                            (optional Kurier submit -> zkVerify mainnet)
```

Pipeline, in order:

1. **Verify the HMAC** (`x-agent-games-signature`, HMAC-SHA256 over the raw
   request body) **before parsing anything**. Bad signature → 401, no
   further work.
2. **Preflight** (`type: agent-games.preflight.v1`) → signed
   `{ ok: true, protocolVersion: "v1" }`.
3. **Task**: validate the envelope + timestamps, then evaluate the
   deterministic policy (no model anywhere near the decision — the same
   input always gives the same output):

   | Check | Failure |
   | --- | --- |
   | `proof_vk != registered_vk` | `VK_SUBSTITUTION` |
   | `proof_tx` already seen | `PROOF_REUSED` (no proof to submit) |
   | `public_balance < minimum` | `THRESHOLD_MISMATCH` |
   | `current_block >= expiry_block` | `EXPIRED_CONDITION` |
   | `recipient != condition_recipient` | `RECIPIENT_MISMATCH` |
   | `amount > max_transfer` | `AMOUNT_OVERFLOW` |
   | all pass | `APPROVE` / `VALID_CONDITION` |

   Boundaries: `balance == minimum` passes, `amount == max_transfer`
   passes, `current_block == expiry_block - 1` passes.
4. **Prove**: generate a Groth16 proof locally with the tournament's own
   gatekeeper circuit. The circuit asserts inside the proof that the
   decision bit equals the AND of the five field checks — a wrong decision
   is unprovable (witness generation fails). The response carries the proof
   + 13 public signals.
5. **Submit (optional)**: if `KURIER_API_KEY` is set, submit the proof to
   zkVerify mainnet via Kurier and return the on-chain `proof_tx`. Polling
   returns as soon as a transaction hash exists (~4 s); it does **not**
   block the answer on finalization (~27 s) — the Kurier job keeps
   finalizing server-side. Without a key, the proof is still generated and
   returned; `proof_tx` echoes the task's reference.
6. **Sign the response** with `x-agent-games-signature` over the raw
   response body. **Fail closed**: any error, timeout, or uncertainty
   means REJECT. Never approve by default.
7. **Idempotency**: `task_id` is the idempotency key — a redelivered task
   returns the identical cached response. Every `proof_tx` is recorded in
   a persistent seen-set, so a replayed proof is caught even after a
   restart.

## Task envelope (as sent by the platform)

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_x",
  "mode": "scored",
  "issued_at": "2026-11-15T10:00:00.000Z",
  "deadline_at": "2026-11-15T10:01:00.000Z",
  "input": {
    "registered_vk": "0x6b79c6…d77b0",
    "proof_vk": "0x6b79c6…d77b0",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 5000,
    "current_block": 4990,
    "recipient": "0x1111…",
    "condition_recipient": "0x1111…",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xabc…"
  }
}
```

Response:

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": [...], "pi_b": [[...]], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<commitment>", "<registeredVkHash>", "<proofVkHash>", "<minimum>", "<publicBalance>", "<expiryBlock>", "<currentBlock>", "<recipient>", "<conditionRecipient>", "<amount>", "<maxTransfer>", "1", "<taskId>"],
  "proof_tx": "0x…"
}
```

Public-signal order is `[commitment, registeredVkHash, proofVkHash,
minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, taskId]`, where
`commitment = Poseidon(taskId, salt)` is the circuit's only output and
`salt` is a private input derived deterministically per task
(`HMAC(secret, "gatekeeper-salt:" + task_id) mod p`). Circuit input signal
names were recovered from `gatekeeper.wasm` itself — see
`scripts/probe-signals.mjs` (Circom addresses input signals by FNV-1a
hash, so a candidate dictionary becomes an oracle). Registered
verification-key hash: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
(from `https://agentgames.zkverify.io/api/circuit-info`).

## Quick start (local)

```bash
npm install
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET (from the dashboard)
npm start              # listens on :8787 — POST /agent, GET /health
```

Test without the platform (uses a throwaway dev secret):

```bash
npm test     # unit + proving + handler tests (14 tests)
npm run smoke  # end-to-end against a live local server (10 checks)
```

Note: `npm test` uses `--test-force-exit` because snarkjs leaves a pending
promise after `fullProve`, which otherwise keeps the `node:test` runner
from exiting (all tests still pass; only the runner's exit hangs).

## Configuration

| Variable | Required | Default |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | **yes** | — (POSTs fail with 500 until set) |
| `KURIER_API_KEY` | no | — (skips mainnet submission) |
| `KURIER_API_URL` | no | `https://api.kurier.xyz/api/v1` |
| `GATEKEEPER_VK_HASH` | no | registered gatekeeper `vk_hash` |
| `KURIER_POLL_BUDGET_MS` | no | `15000` |
| `KURIER_POLL_INTERVAL_MS` | no | `3000` |
| `TASK_SOFT_DEADLINE_MS` | no | `50000` |
| `SEEN_STORE_PATH` | no | `data/seen.json` (`/tmp/gatekeeper-seen.json` on Vercel) |
| `CIRCUITS_DIR` | no | `./circuits` |
| `PORT` | no | `8787` |

**Never commit `.env` or any secret.** The HMAC secret is shown exactly
once in the dashboard ("Rotate Secret"). The Kurier API key comes from the
Horizen Labs team (request via the zkVerify docs).

## Deploy

The endpoint must be a **public HTTPS URL, no localhost, no private IP,
no custom ports** (standard 443). Register it in the dashboard under
Manage Agents with the full handler path, e.g.
`https://<your-host>/agent`, plus this repo's URL.

Recommended (free, no sleep — the rules forfeit tasks if the agent is
offline, so avoid free tiers that sleep after inactivity):

- **Vercel (Hobby, free)** — serverless, always available, no sleep.
  `vercel.json` routes `/agent` to the function; set
  `AGENT_GAMES_HMAC_SECRET` (and `KURIER_API_KEY`) in the project
  environment variables. Caveat: the seen-store file lives in `/tmp` on
  serverless and may vanish on a cold start — the in-memory set still
  protects redelivery within a warm instance, but a proof replayed across
  a cold start could slip past the file-backed check. For a long-running
  competition, a persistent host is strictly better.
- **Fly.io (free allowance)** — a small always-on machine with a
  persistent volume for `data/seen.json`. `fly launch` + `fly secrets set
  AGENT_GAMES_HMAC_SECRET=…`.
- **Railway / Render** — free tiers sleep after inactivity; only use a
  paid/always-on plan, or accept forfeited tasks while asleep.

After deploy, register the agent in the dashboard and run the platform's
preflight check (it must report **Healthy**), then start with unscored
practice tasks (capped at 10 dispatches per active agent per hour) before
scored rounds open.

## Security notes

- The HMAC secret from the dashboard is the **only** shared secret. Never
  use a local placeholder — the platform signs with its copy; a mismatch
  means every task gets a 401.
- HMAC verification accepts the identical MAC bytes in hex or base64, with
  an optional `sha256=` prefix (the build guide does not pin the encoding;
  this is the conventional reading — the platform preflight is the judge).
- Responses are signed over the raw body; verify with the same secret.
- The agent never holds funds, never signs transactions, and never calls a
  model. It only verifies, decides, and proves.

## Project layout

```
.
├── circuits/               # official gatekeeper artifacts (wasm, zkey, vk)
├── src/
│   ├── server.js           # plain Node HTTP server (POST /agent, GET /health)
│   ├── handler.js          # HMAC -> preflight -> task -> prove -> Kurier -> sign
│   ├── decision.js         # deterministic policy + circuit-input builder
│   ├── hmac.js             # HMAC sign/verify, per-task salt derivation
│   ├── prover.js           # snarkjs fullProve wrapper
│   ├── kurier.js           # Kurier submit-proof + job-status polling
│   ├── store.js            # seen proof_tx set + idempotent response cache
│   └── config.js           # env configuration
├── scripts/
│   ├── probe-signals.mjs   # recover circuit input names from the wasm
│   └── smoke-test.js       # end-to-end test against a live local server
├── test/test.js            # automated test suite (npm test)
├── .env.example
└── LICENSE (MIT)
```

## Sources

- Builder field guide: https://agentgames.zkverify.io/build
- Rules: https://agentgames.zkverify.io/rules
- Getting started: https://agentgames.zkverify.io/guide
- Circuit info: https://agentgames.zkverify.io/api/circuit-info
- Kurier docs: https://docs.zkverify.io/overview/getting-started/kurier
