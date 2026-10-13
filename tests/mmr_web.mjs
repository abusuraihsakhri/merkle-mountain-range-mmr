import assert from 'node:assert/strict';
import {MerkleMountainRange} from '../web/mmr.mjs';

const items = Array.from({length: 33}, (_, i) => 'event ' + i);
for (const size of [0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 32, 33]) {
  const mmr = new MerkleMountainRange();
  for (const item of items.slice(0, size)) await mmr.append(item);
  assert.equal(mmr.size, size);
  for (let i = 0; i < size; i++) {
    const proof = await mmr.inclusionProof(i);
    assert.equal(await MerkleMountainRange.verifyInclusion(items[i], proof, await mmr.root()), true);
    assert.equal(await MerkleMountainRange.verifyInclusion(items[i] + '!', proof, await mmr.root()), false);
  }
  for (let n = 0; n <= size; n++) {
    const old = new MerkleMountainRange();
    for (const item of items.slice(0, n)) await old.append(item);
    const proof = await mmr.consistencyProof(n);
    assert.equal(await MerkleMountainRange.verifyConsistency(await old.root(), await mmr.root(), proof), true);
    if (proof.appended_hashes.length) {
      proof.appended_hashes[0] = '0'.repeat(64);
      assert.equal(await MerkleMountainRange.verifyConsistency(await old.root(), await mmr.root(), proof), false);
    }
  }
}
const vectors = [
  '084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5',
  '2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b',
  '983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b',
  '29c1439a00ee3e6faf7448a71127ccd3b97d6c877d9b0aa8708ca62a90d5926e',
  '42fc54eeb6352f90cc81fdd5791292cca3974a168208b395b06a76240b24884d',
  'c2c29efc66e6b2ef53c9c609f6774c7419986f8d0f95cd50c3d2fee2f4a2dde3'
];
const example = new MerkleMountainRange();
assert.equal(await example.root(), vectors[0]);
for (const [i, text] of ['alpha', 'beta', 'gamma', 'delta', 'epsilon'].entries()) {
  await example.append(text);
  assert.equal(await example.root(), vectors[i + 1]);
}
console.log('Browser MMR proof tests passed.');
