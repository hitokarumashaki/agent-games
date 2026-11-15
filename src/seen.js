// Persistent seen-set (proof_tx reuse detection) + idempotent response cache.
//
// Why this matters: PROOF_REUSED is ~11% of tasks, and the platform may
// retry a delivery after a network failure. A redelivered task_id must get
// its cached response — NOT be misread as a reused proof (the proof_tx in
// a redelivery is the same one we already answered, so without the cache
// the second delivery would wrongly score PROOF_REUSED).
//
// Storage: in-memory Set/Map + a JSON file (default data/seen.json).
// On serverless hosts the file may reset on cold start; a single
// long-lived instance (small VM/container) is the safer host for the
// full 8 rounds. See README "Hosting".
const fs = require('fs');
const path = require('path');

const DEFAULT_PATH = process.env.SEEN_STORE_PATH
  || path.join(__dirname, '..', 'data', 'seen.json');

class SeenStore {
  constructor(filePath = DEFAULT_PATH) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responses = new Map(); // task_id -> { status, body, signature }
    this._load();
  }

  _load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      if (Array.isArray(raw.seenProofTx)) this.seenProofTx = new Set(raw.seenProofTx);
      if (raw.responses && typeof raw.responses === 'object') {
        this.responses = new Map(Object.entries(raw.responses));
      }
    } catch (_) { /* first run: file does not exist yet */ }
  }

  _save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = this.filePath + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({
        seenProofTx: [...this.seenProofTx],
        responses: Object.fromEntries(this.responses),
      }));
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      // Persistence failure must not break the response path; the
      // in-memory set still protects this process lifetime.
      console.error('[seen] failed to persist seen-set:', err.message);
    }
  }

  has(proofTx) { return this.seenProofTx.has(String(proofTx)); }

  /** Record a proof_tx as used. Only call AFTER a decision was made for it (not for redeliveries). */
  markSeen(proofTx) {
    this.seenProofTx.add(String(proofTx));
    this._save();
  }

  getCached(taskId) { return this.responses.get(String(taskId)) || null; }

  setCached(taskId, entry) {
    this.responses.set(String(taskId), entry);
    this._save();
  }
}

module.exports = { SeenStore };
