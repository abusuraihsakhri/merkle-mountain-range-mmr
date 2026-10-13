import {MerkleMountainRange} from './mmr.mjs';

const mmr = new MerkleMountainRange();
const values = [];
const el = id => document.getElementById(id);
const state = {proof: null, consistency: null, checkpoints: []};
const message = (text, ok = true) => {
  el('feedback').textContent = text;
  el('feedback').dataset.kind = ok ? 'success' : 'error';
};
const busy = async task => {
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try { await task(); } catch (error) { message(error.message || 'Unable to process input', false); }
  finally { for (const button of document.querySelectorAll('button')) button.disabled = false; }
};
async function refresh() {
  el('size').textContent = String(mmr.size);
  el('root').textContent = await mmr.root();
  el('peaks').textContent = mmr.peakHashes().map((p, i) => 'Peak ' + (i + 1) + ': ' + p).join('\n') || 'No peaks yet';
  const list = el('leaf-list');
  list.replaceChildren();
  values.forEach((value, index) => {
    const item = document.createElement('li');
    const content = document.createElement('span');
    content.textContent = index + ' · ' + value;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Prove inclusion';
    button.addEventListener('click', () => busy(() => prove(index)));
    item.append(content, button);
    list.append(item);
  });
  el('old-size').max = String(mmr.size);
  if (Number(el('old-size').value) > mmr.size) el('old-size').value = String(mmr.size);
}
async function append(text) {
  if (!text.trim()) throw new Error('Enter nonempty leaf text');
  if (mmr.size >= 1024 || new TextEncoder().encode(text).length > 8192)
    throw new Error('Limit: 1,024 leaves and 8 KiB per leaf');
  state.checkpoints.push(await mmr.root());
  await mmr.append(text);
  values.push(text);
  state.proof = null;
  state.consistency = null;
  el('proof-json').value = '';
  el('consistency-json').value = '';
  await refresh();
  message('Leaf ' + (mmr.size - 1) + ' appended; previous hashes remain unchanged.');
}
async function prove(index) {
  state.proof = await mmr.inclusionProof(index);
  el('proof-json').value = JSON.stringify(state.proof, null, 2);
  el('verify-leaf').value = values[index];
  el('verify-root').value = await mmr.root();
  message('Generated inclusion proof for leaf ' + index + '. Modify text or proof to test tampering.');
}
function download(name, value) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type:'application/json'}));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
el('append-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(async () => { await append(el('new-leaf').value); el('new-leaf').value = ''; });
});
el('sample').addEventListener('click', () => busy(async () => {
  for (const text of ['alpha', 'beta', 'gamma', 'delta', 'epsilon']) await append(text);
  message('Example leaves appended. Select a leaf to create its proof.');
}));
el('reset').addEventListener('click', () => { location.reload(); });
el('verify').addEventListener('click', () => busy(async () => {
  let proof;
  try { proof = JSON.parse(el('proof-json').value); }
  catch { throw new Error('Proof must be valid JSON'); }
  const ok = await MerkleMountainRange.verifyInclusion(el('verify-leaf').value, proof, el('verify-root').value);
  message(ok ? 'Inclusion verified against supplied root.' : 'Verification failed: leaf, proof or root does not match.', ok);
}));
el('export').addEventListener('click', () => busy(async () => {
  const proof = JSON.parse(el('proof-json').value);
  download('mmr-inclusion-proof.json', {leaf: el('verify-leaf').value, root: el('verify-root').value, proof});
}));
el('consistency').addEventListener('click', () => busy(async () => {
  const oldSize = Number(el('old-size').value);
  if (!Number.isSafeInteger(oldSize) || oldSize < 0 || oldSize > mmr.size) throw new Error('Invalid old checkpoint size');
  const proof = await mmr.consistencyProof(oldSize);
  const oldRoot = oldSize === mmr.size ? await mmr.root() : state.checkpoints[oldSize];
  const newRoot = await mmr.root();
  const valid = await MerkleMountainRange.verifyConsistency(oldRoot, newRoot, proof);
  state.consistency = {old_root: oldRoot, new_root: newRoot, proof};
  el('consistency-json').value = JSON.stringify(state.consistency, null, 2);
  message(valid ? 'Append-only extension verified from ' + oldSize + ' to ' + mmr.size + ' leaves.' : 'Consistency verification failed.', valid);
}));
el('export-consistency').addEventListener('click', () => busy(async () => {
  if (!state.consistency) throw new Error('Generate a consistency proof first');
  download('mmr-consistency-proof.json', state.consistency);
}));
busy(refresh);
