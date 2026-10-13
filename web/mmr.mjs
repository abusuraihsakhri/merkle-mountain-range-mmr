// SHA-256 MMR protocol shared with merkle_mountain_range/mmr.py.
const encoder = new TextEncoder();
const digest = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = value => {
  if (typeof value !== 'string' || !/^[a-f\d]{64}$/i.test(value)) throw new Error('Invalid SHA-256 hash');
  return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
};
const leafHash = async data => digest(concat(Uint8Array.of(0), encoder.encode(data)));
const parent = async (left, right) => digest(concat(Uint8Array.of(1), left, right));
async function bag(peaks) {
  if (peaks.length === 0) return digest(Uint8Array.of(3));
  let root = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; --i) root = await digest(concat(Uint8Array.of(2), peaks[i], root));
  return root;
}
const layout = n => {
  const ranges = [];
  let offset = 0;
  for (let h = Math.floor(Math.log2(n)); h >= 0; --h) {
    const width = 2 ** h;
    if (n >= width) { ranges.push({start: offset, height: h}); offset += width; n -= width; }
  }
  return ranges;
};
async function pushHash(peaks, hash) {
  let height = 0;
  while (peaks.length && peaks[peaks.length - 1].height === height) {
    const left = peaks.pop();
    hash = await parent(left.hash, hash);
    height++;
  }
  peaks.push({height, hash});
}
export class MerkleMountainRange {
  constructor() { this.leaves = []; this.peaks = []; }
  get size() { return this.leaves.length; }
  async append(text) {
    if (typeof text !== 'string') throw new TypeError('Leaf must be text');
    const hash = await leafHash(text);
    this.leaves.push(hash);
    await pushHash(this.peaks, hash);
    return this.size - 1;
  }
  async root() { return hex(await bag(this.peaks.map(p => p.hash))); }
  peakHashes() { return this.peaks.map(p => hex(p.hash)); }
  async inclusionProof(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.size) throw new RangeError('Invalid index');
    const ranges = layout(this.size);
    const peakIndex = ranges.findIndex(r => index >= r.start && index < r.start + 2 ** r.height);
    const {start, height} = ranges[peakIndex];
    let level = this.leaves.slice(start, start + 2 ** height);
    let offset = index - start;
    const siblings = [];
    for (let step = 0; step < height; step++) {
      siblings.push({side: offset % 2 ? 'left' : 'right', hash: hex(level[offset ^ 1])});
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(await parent(level[i], level[i + 1]));
      level = next;
      offset = Math.floor(offset / 2);
    }
    return {index, size: this.size, siblings, peaks: this.peakHashes(), peak_index: peakIndex};
  }
  async consistencyProof(oldSize) {
    if (!Number.isSafeInteger(oldSize) || oldSize < 0 || oldSize > this.size) throw new RangeError('Invalid old size');
    const oldPeaks = [];
    for (const hash of this.leaves.slice(0, oldSize)) await pushHash(oldPeaks, hash);
    return {old_size: oldSize, new_size: this.size,
      old_peaks: oldPeaks.map(p => hex(p.hash)),
      appended_hashes: this.leaves.slice(oldSize).map(hex)};
  }
  static async verifyInclusion(text, proof, expectedRoot) {
    try {
      if (typeof text !== 'string' || !proof || !Number.isSafeInteger(proof.size) ||
          !Number.isSafeInteger(proof.index) || !Number.isSafeInteger(proof.peak_index) ||
          proof.index < 0 || proof.index >= proof.size) return false;
      const ranges = layout(proof.size);
      if (!Array.isArray(proof.peaks) || proof.peaks.length !== ranges.length ||
          !Array.isArray(proof.siblings)) return false;
      const p = proof.peak_index;
      if (p < 0 || p >= ranges.length) return false;
      const {start, height} = ranges[p];
      if (proof.index < start || proof.index >= start + 2 ** height || proof.siblings.length !== height) return false;
      const peaks = proof.peaks.map(unhex);
      let node = await leafHash(text);
      let offset = proof.index - start;
      for (const sibling of proof.siblings) {
        if (!sibling || sibling.side !== (offset % 2 ? 'left' : 'right')) return false;
        const s = unhex(sibling.hash);
        node = offset % 2 ? await parent(s, node) : await parent(node, s);
        offset = Math.floor(offset / 2);
      }
      if (hex(node) !== hex(peaks[p])) return false;
      return hex(await bag(peaks)) === hex(unhex(expectedRoot));
    } catch { return false; }
  }
  static async verifyConsistency(oldRoot, newRoot, proof) {
    try {
      if (!proof || !Number.isSafeInteger(proof.old_size) || !Number.isSafeInteger(proof.new_size) ||
          proof.old_size < 0 || proof.new_size < proof.old_size ||
          !Array.isArray(proof.old_peaks) || !Array.isArray(proof.appended_hashes)) return false;
      const ranges = layout(proof.old_size);
      if (proof.old_peaks.length !== ranges.length ||
          proof.appended_hashes.length !== proof.new_size - proof.old_size) return false;
      const original = proof.old_peaks.map(unhex);
      if (hex(await bag(original)) !== hex(unhex(oldRoot))) return false;
      const peaks = original.map((hash, i) => ({height: ranges[i].height, hash}));
      for (const next of proof.appended_hashes) await pushHash(peaks, unhex(next));
      return hex(await bag(peaks.map(p => p.hash))) === hex(unhex(newRoot));
    } catch { return false; }
  }
}
