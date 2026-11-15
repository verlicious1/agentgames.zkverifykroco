/**
 * Kurier (zkVerify) proof submission — mainnet.
 *
 * Shape from docs.zkverify.io ("Verifying proofs with Kurier") and the
 * /build page:
 *   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
 *   { proofType: "groth16", vkRegistered: true,
 *     proofOptions: { library: "snarkjs", curve: "bn128" },
 *     proofData: { proof, publicSignals, vk: <vk_hash> } }
 *   -> { jobId, optimisticVerify }
 *   GET {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
 *   lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized | Failed
 *
 * The gatekeeper vk_hash is already registered on mainnet, so
 * vkRegistered: true and no register-vk call is needed.
 *
 * Timing reality (measured live by another builder, 2026-11-15): the txHash
 * already exists at the Submitted stage (~4 s), while full Finalized takes
 * ~27 s (once >35 s). Inside a 60 s task window that also includes proving
 * time, waiting for finality is how a correct agent becomes a timing-out
 * agent. So polling returns as soon as a txHash is known; the Kurier job
 * keeps finalizing server-side regardless.
 *
 * This module never throws: any failure returns null, and the caller still
 * answers the task with the proof + public_signals.
 */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function submitProofAndPoll(cfg, proof, publicSignals, budgetMs) {
  if (!cfg.kurierApiKey) {
    console.log('[kurier] KURIER_API_KEY not set — skipping zkVerify submission');
    return null;
  }
  const key = cfg.kurierApiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${cfg.kurierApiUrl}/submit-proof/${key}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: cfg.gatekeeperVkHash },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job.jobId) {
      console.error('[kurier] submit-proof response missing jobId');
      return null;
    }
    console.log(`[kurier] job ${job.jobId} submitted (optimisticVerify=${job.optimisticVerify ?? 'n/a'})`);

    let status = 'Submitted';
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(cfg.kurierPollIntervalMs, Math.max(0, deadline - Date.now())));
      const statusRes = await fetch(`${cfg.kurierApiUrl}/job-status/${key}/${job.jobId}`);
      if (!statusRes.ok) {
        console.error(`[kurier] job-status HTTP ${statusRes.status}`);
        continue;
      }
      const s = await statusRes.json();
      status = s.status || status;
      const txHash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (txHash) lastTxHash = txHash;
      if (status === 'Failed') {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        // The on-chain transaction exists from Submitted onward; return its
        // hash now and let finalization complete server-side at Kurier.
        return { jobId: job.jobId, status, txHash, finalized: status === 'Finalized' };
      }
    }
    console.log(`[kurier] job ${job.jobId} produced no txHash within budget (last status=${status})`);
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error('[kurier] submission error:', err.message);
    return null;
  }
}

module.exports = { submitProofAndPoll };
