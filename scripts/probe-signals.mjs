import fs from 'node:fs';
// FNV-1a 64 over the candidate name; Circom WASM witness calculator
// addresses input signals by this hash. getInputSignalSize returns >0
// only for a real input signal -> candidate dictionary becomes an oracle.
function fnv(str) {
  const M = 2n ** 64n;
  let h = 0xcbf29ce484222325n;
  for (const ch of str) { h ^= BigInt(ch.charCodeAt(0)); h = (h * 0x100000001b3n) % M; }
  return h.toString(16).padStart(16, '0');
}
const { WitnessCalculatorBuilder } = await import('circom_runtime');
const wc = await WitnessCalculatorBuilder(fs.readFileSync('circuits/gatekeeper.wasm'));
const ex = wc.instance.exports;
console.log('getInputSize():', ex.getInputSize());
const candidates = ['taskId','registeredVkHash','proofVkHash','minimum','publicBalance','expiryBlock','currentBlock','recipient','conditionRecipient','amount','maxTransfer','decision','salt','proofTxHash','proofTx','balance','threshold','vkHash','commitment','nullifier','proof_tx','task_id'];
for (const name of candidates) {
  const h = fnv(name);
  const size = ex.getInputSignalSize(parseInt(h.slice(0,8),16), parseInt(h.slice(8,16),16));
  if (size > 0) console.log('  input signal:', name, '(size', size + ')');
}
