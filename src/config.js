/**
 * Runtime configuration — everything comes from environment variables.
 * No secret has a default value. The HMAC secret must come from the Agent
 * Games dashboard ("Rotate Secret", shown exactly once at registration)
 * via AGENT_GAMES_HMAC_SECRET.
 */
const fs = require('node:fs');
const path = require('node:path');

function defaultCircuitsDir() {
  const candidates = [
    path.resolve(__dirname, '..', 'circuits'),
    path.resolve(process.cwd(), 'circuits'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'gatekeeper.wasm'))) return c;
  }
  return candidates[0];
}

function defaultSeenStorePath() {
  // Serverless filesystems are read-only except /tmp (e.g. Vercel).
  if (process.env.VERCEL) return '/tmp/gatekeeper-seen.json';
  return path.resolve(process.cwd(), 'data', 'seen.json');
}

function loadConfig(env = process.env) {
  return {
    // 32-byte HMAC secret issued at agent registration. Empty = misconfigured.
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET || '',
    // Kurier mainnet API key. Null = skip zkVerify submission (proofs are
    // still generated and returned locally).
    kurierApiKey: env.KURIER_API_KEY || null,
    kurierApiUrl: env.KURIER_API_URL || 'https://api.kurier.xyz/api/v1',
    // Registered gatekeeper vk_hash on zkVerify mainnet
    // (https://agentgames.zkverify.io/api/circuit-info).
    gatekeeperVkHash:
      env.GATEKEEPER_VK_HASH ||
      '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    circuitsDir: env.CIRCUITS_DIR || defaultCircuitsDir(),
    seenStorePath: env.SEEN_STORE_PATH || defaultSeenStorePath(),
    // Stop polling Kurier after this long; the answer must stay well inside
    // the platform's 60 s task deadline.
    kurierPollBudgetMs: Number(env.KURIER_POLL_BUDGET_MS || 15_000),
    kurierPollIntervalMs: Number(env.KURIER_POLL_INTERVAL_MS || 3_000),
    // Soft internal deadline for the whole task handler.
    taskSoftDeadlineMs: Number(env.TASK_SOFT_DEADLINE_MS || 50_000),
    port: Number(env.PORT || 8787),
  };
}

module.exports = { loadConfig };
