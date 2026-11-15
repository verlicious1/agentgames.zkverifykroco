/**
 * Vercel serverless adapter for the Proof Gatekeeper agent.
 * Routes POST /agent (and GET /agent for the health check) through the same
 * AgentHandler used by the local server.
 *
 * Deploy: `vercel` from the repo root, then set AGENT_GAMES_HMAC_SECRET
 * (and KURIER_API_KEY) in the Vercel project environment variables.
 *
 * Note: on Vercel the seen-store file lives in /tmp and may vanish on a
 * cold start — see README "Deploy" for the operational implication.
 */
const { loadConfig } = require('../src/config');
const { AgentHandler } = require('../src/handler');
const { SeenStore } = require('../src/store');
const { SIGNATURE_HEADER } = require('../src/decision');

let handlerPromise = null;

function getHandler() {
  if (!handlerPromise) {
    handlerPromise = (async () => {
      const cfg = loadConfig();
      return new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
    })();
  }
  return handlerPromise;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_048_576) {
        reject(new Error('payload_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  const handler = await getHandler();

  if (req.method === 'GET') {
    const r = handler.health();
    res.status(r.status).json(JSON.parse(r.body));
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    res.status(413).json({ error: 'payload_too_large' });
    return;
  }

  const signature = req.headers[SIGNATURE_HEADER];
  const result = await handler.handlePost(
    rawBody,
    Array.isArray(signature) ? signature[0] : signature,
  );
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.status(result.status).setHeader('content-type', 'application/json').send(result.body);
};
