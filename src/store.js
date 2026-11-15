/**
 * Seen-set for proof_tx references ("The proof reference has not already
 * been used for another task" — /build Security checklist; PROOF_REUSED trap).
 *
 * An in-memory Set is authoritative for the life of the process; a JSON file
 * backs it across restarts (best-effort: on serverless the file lives in /tmp
 * and may vanish on a cold start — see README for the operational
 * implication). Also keeps a task_id -> serialized response cache so a
 * redelivered task is answered idempotently instead of being misread as
 * proof reuse.
 */
const fs = require('node:fs');
const path = require('node:path');

function normalizeTx(tx) {
  return (tx || '').trim().toLowerCase();
}

class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const data = JSON.parse(raw);
      for (const tx of data.proofTx || []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses || {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing/corrupt file -> start empty (fail-open for storage, fail-closed for policy) */
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error('[seen-store] persist failed:', err.message);
    }
  }

  hasProofTx(proofTx) {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  recordProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key) return;
    if (!this.seenProofTx.has(key)) {
      this.seenProofTx.add(key);
      this.persist();
    }
  }

  getResponse(taskId) {
    return this.responseByTaskId.get(taskId) || null;
  }

  recordResponse(taskId, serializedResponse) {
    if (!this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, serializedResponse);
      this.persist();
    }
  }

  get size() {
    return this.seenProofTx.size;
  }
}

module.exports = { SeenStore, normalizeTx };
