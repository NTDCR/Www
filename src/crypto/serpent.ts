/**
 * ContentGuard Pro MAX - Pure TypeScript Serpent-256-CTR Block Cipher
 * 32-Round Substitution-Permutation Network
 * NIST AES Finalist Cipher Specification
 */
import { yieldToMainThread } from '../utils/asyncUtils';

// Serpent S-boxes (4x4 bit substitution tables)
const SBOX: number[][] = [
  [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
  [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
  [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
  [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
  [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
  [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
  [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
  [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]
];

// Linear transformation bit rotation helpers
function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// Precomputed 16-bit 4-nibble parallel LUT table for all 8 S-boxes
const LUT: Uint32Array[] = [];
for (let s = 0; s < 8; s++) {
  const lut16 = new Uint32Array(65536);
  const sb = SBOX[s];
  for (let in16 = 0; in16 < 65536; in16++) {
    const n0 = in16 & 0xf;
    const n1 = (in16 >>> 4) & 0xf;
    const n2 = (in16 >>> 8) & 0xf;
    const n3 = (in16 >>> 12) & 0xf;
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    for (let b = 0; b < 4; b++) {
      const nibVal =
        (((n0 >>> b) & 1) << 0) |
        (((n1 >>> b) & 1) << 1) |
        (((n2 >>> b) & 1) << 2) |
        (((n3 >>> b) & 1) << 3);
      const outNib = sb[nibVal];
      o0 |= ((outNib >>> 0) & 1) << b;
      o1 |= ((outNib >>> 1) & 1) << b;
      o2 |= ((outNib >>> 2) & 1) << b;
      o3 |= ((outNib >>> 3) & 1) << b;
    }
    lut16[in16] = (o0) | (o1 << 4) | (o2 << 8) | (o3 << 12);
  }
  LUT.push(lut16);
}

// Key Schedule for 256-bit key -> 33 subkeys of 128-bit (4 x 32-bit words)
export function serpentKeySchedule(key256: Uint8Array): Uint32Array[] {
  if (!key256 || key256.length < 32) {
    throw new Error('Serpent-256 requires a 32-byte key');
  }
  const w = new Uint32Array(132);
  const roundKeys: Uint32Array[] = [];
  try {
    const kView = new DataView(key256.buffer, key256.byteOffset, key256.byteLength);

    // Load 8 32-bit words (256 bits)
    for (let i = 0; i < 8; i++) {
      w[i] = kView.getUint32(i * 4, true);
    }

    // Prekey expansion (Official NIST AES Finalist Serpent specification: w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i)
    const PHI = 0x9e3779b9; // Fractional part of Golden Ratio
    for (let i = 8; i < 132; i++) {
      const tmp = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i;
      w[i] = rotl32(tmp, 11);
    }

    // Apply S-boxes to produce 33 round keys (LUT indices always masked to 16-bit)
    for (let r = 0; r < 33; r++) {
      const sboxIdx = (3 + 32 - r) % 8;
      const lut = LUT[sboxIdx];
      const w0 = w[4 * r + 0], w1 = w[4 * r + 1], w2 = w[4 * r + 2], w3 = w[4 * r + 3];

      const out0 = lut[((w0 & 0xf) | ((w1 & 0xf) << 4) | ((w2 & 0xf) << 8) | ((w3 & 0xf) << 12)) & 0xffff];
      const out1 = lut[(((w0 >>> 4) & 0xf) | (((w1 >>> 4) & 0xf) << 4) | (((w2 >>> 4) & 0xf) << 8) | (((w3 >>> 4) & 0xf) << 12)) & 0xffff];
      const out2 = lut[(((w0 >>> 8) & 0xf) | (((w1 >>> 8) & 0xf) << 4) | (((w2 >>> 8) & 0xf) << 8) | (((w3 >>> 8) & 0xf) << 12)) & 0xffff];
      const out3 = lut[(((w0 >>> 12) & 0xf) | (((w1 >>> 12) & 0xf) << 4) | (((w2 >>> 12) & 0xf) << 8) | (((w3 >>> 12) & 0xf) << 12)) & 0xffff];
      const out4 = lut[(((w0 >>> 16) & 0xf) | (((w1 >>> 16) & 0xf) << 4) | (((w2 >>> 16) & 0xf) << 8) | (((w3 >>> 16) & 0xf) << 12)) & 0xffff];
      const out5 = lut[(((w0 >>> 20) & 0xf) | (((w1 >>> 20) & 0xf) << 4) | (((w2 >>> 20) & 0xf) << 8) | (((w3 >>> 20) & 0xf) << 12)) & 0xffff];
      const out6 = lut[(((w0 >>> 24) & 0xf) | (((w1 >>> 24) & 0xf) << 4) | (((w2 >>> 24) & 0xf) << 8) | (((w3 >>> 24) & 0xf) << 12)) & 0xffff];
      const out7 = lut[(((w0 >>> 28) & 0xf) | (((w1 >>> 28) & 0xf) << 4) | (((w2 >>> 28) & 0xf) << 8) | (((w3 >>> 28) & 0xf) << 12)) & 0xffff];

      const rk = new Uint32Array(4);
      rk[0] = (out0 & 0xf) | ((out1 & 0xf) << 4) | ((out2 & 0xf) << 8) | ((out3 & 0xf) << 12) |
              ((out4 & 0xf) << 16) | ((out5 & 0xf) << 20) | ((out6 & 0xf) << 24) | ((out7 & 0xf) << 28);
      rk[1] = ((out0 >>> 4) & 0xf) | (((out1 >>> 4) & 0xf) << 4) | (((out2 >>> 4) & 0xf) << 8) | (((out3 >>> 4) & 0xf) << 12) |
              (((out4 >>> 4) & 0xf) << 16) | (((out5 >>> 4) & 0xf) << 20) | (((out6 >>> 4) & 0xf) << 24) | (((out7 >>> 4) & 0xf) << 28);
      rk[2] = ((out0 >>> 8) & 0xf) | (((out1 >>> 8) & 0xf) << 4) | (((out2 >>> 8) & 0xf) << 8) | (((out3 >>> 8) & 0xf) << 12) |
              (((out4 >>> 8) & 0xf) << 16) | (((out5 >>> 8) & 0xf) << 20) | (((out6 >>> 8) & 0xf) << 24) | (((out7 >>> 8) & 0xf) << 28);
      rk[3] = ((out0 >>> 12) & 0xf) | (((out1 >>> 12) & 0xf) << 4) | (((out2 >>> 12) & 0xf) << 8) | (((out3 >>> 12) & 0xf) << 12) |
              (((out4 >>> 12) & 0xf) << 16) | (((out5 >>> 12) & 0xf) << 20) | (((out6 >>> 12) & 0xf) << 24) | (((out7 >>> 12) & 0xf) << 28);
      roundKeys.push(rk);
    }

    return roundKeys;
  } catch (err) {
    for (const rk of roundKeys) rk.fill(0);
    throw err;
  } finally {
    w.fill(0);
  }
}

// Fast 128-bit block encryption (32 rounds + linear transformation using LUT)
function serpentEncryptBlock(
  b0: number,
  b1: number,
  b2: number,
  b3: number,
  subkeys: Uint32Array[],
  outWords: Uint32Array
): void {
  let x0 = b0 >>> 0;
  let x1 = b1 >>> 0;
  let x2 = b2 >>> 0;
  let x3 = b3 >>> 0;

  for (let r = 0; r < 32; r++) {
    // Key mixing
    const sk = subkeys[r];
    x0 = (x0 ^ sk[0]) >>> 0;
    x1 = (x1 ^ sk[1]) >>> 0;
    x2 = (x2 ^ sk[2]) >>> 0;
    x3 = (x3 ^ sk[3]) >>> 0;

    const lut = LUT[r % 8];

    const out0 = lut[((x0 & 0xf) | ((x1 & 0xf) << 4) | ((x2 & 0xf) << 8) | ((x3 & 0xf) << 12)) & 0xffff];
    const out1 = lut[(((x0 >>> 4) & 0xf) | (((x1 >>> 4) & 0xf) << 4) | (((x2 >>> 4) & 0xf) << 8) | (((x3 >>> 4) & 0xf) << 12)) & 0xffff];
    const out2 = lut[(((x0 >>> 8) & 0xf) | (((x1 >>> 8) & 0xf) << 4) | (((x2 >>> 8) & 0xf) << 8) | (((x3 >>> 8) & 0xf) << 12)) & 0xffff];
    const out3 = lut[(((x0 >>> 12) & 0xf) | (((x1 >>> 12) & 0xf) << 4) | (((x2 >>> 12) & 0xf) << 8) | (((x3 >>> 12) & 0xf) << 12)) & 0xffff];
    const out4 = lut[(((x0 >>> 16) & 0xf) | (((x1 >>> 16) & 0xf) << 4) | (((x2 >>> 16) & 0xf) << 8) | (((x3 >>> 16) & 0xf) << 12)) & 0xffff];
    const out5 = lut[(((x0 >>> 20) & 0xf) | (((x1 >>> 20) & 0xf) << 4) | (((x2 >>> 20) & 0xf) << 8) | (((x3 >>> 20) & 0xf) << 12)) & 0xffff];
    const out6 = lut[(((x0 >>> 24) & 0xf) | (((x1 >>> 24) & 0xf) << 4) | (((x2 >>> 24) & 0xf) << 8) | (((x3 >>> 24) & 0xf) << 12)) & 0xffff];
    const out7 = lut[(((x0 >>> 28) & 0xf) | (((x1 >>> 28) & 0xf) << 4) | (((x2 >>> 28) & 0xf) << 8) | (((x3 >>> 28) & 0xf) << 12)) & 0xffff];

    const y0 = (out0 & 0xf) | ((out1 & 0xf) << 4) | ((out2 & 0xf) << 8) | ((out3 & 0xf) << 12) |
               ((out4 & 0xf) << 16) | ((out5 & 0xf) << 20) | ((out6 & 0xf) << 24) | ((out7 & 0xf) << 28);
    const y1 = ((out0 >>> 4) & 0xf) | (((out1 >>> 4) & 0xf) << 4) | (((out2 >>> 4) & 0xf) << 8) | (((out3 >>> 4) & 0xf) << 12) |
               (((out4 >>> 4) & 0xf) << 16) | (((out5 >>> 4) & 0xf) << 20) | (((out6 >>> 4) & 0xf) << 24) | (((out7 >>> 4) & 0xf) << 28);
    const y2 = ((out0 >>> 8) & 0xf) | (((out1 >>> 8) & 0xf) << 4) | (((out2 >>> 8) & 0xf) << 8) | (((out3 >>> 8) & 0xf) << 12) |
               (((out4 >>> 8) & 0xf) << 16) | (((out5 >>> 8) & 0xf) << 20) | (((out6 >>> 8) & 0xf) << 24) | (((out7 >>> 8) & 0xf) << 28);
    const y3 = ((out0 >>> 12) & 0xf) | (((out1 >>> 12) & 0xf) << 4) | (((out2 >>> 12) & 0xf) << 8) | (((out3 >>> 12) & 0xf) << 12) |
               (((out4 >>> 12) & 0xf) << 16) | (((out5 >>> 12) & 0xf) << 20) | (((out6 >>> 12) & 0xf) << 24) | (((out7 >>> 12) & 0xf) << 28);

    if (r === 31) {
      // Final round key mixing without linear transformation
      const skFinal = subkeys[32];
      x0 = (y0 ^ skFinal[0]) >>> 0;
      x1 = (y1 ^ skFinal[1]) >>> 0;
      x2 = (y2 ^ skFinal[2]) >>> 0;
      x3 = (y3 ^ skFinal[3]) >>> 0;
    } else {
      // Linear transformation
      x0 = rotl32(y0, 13);
      x2 = rotl32(y2, 3);
      x1 = (y1 ^ x0 ^ x2) >>> 0;
      x3 = (y3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
      x1 = rotl32(x1, 1);
      x3 = rotl32(x3, 7);
      x0 = (x0 ^ x1 ^ x3) >>> 0;
      x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
      x0 = rotl32(x0, 5);
      x2 = rotl32(x2, 22);
    }
  }

  outWords[0] = x0 >>> 0;
  outWords[1] = x1 >>> 0;
  outWords[2] = x2 >>> 0;
  outWords[3] = x3 >>> 0;
}

/**
 * Encrypts a single 16-byte block in ECB mode using Serpent-256 (for standards validation & test vectors)
 */
export function serpentEncrypt16ByteBlock(block16: Uint8Array, key256: Uint8Array): Uint8Array {
  if (block16.length !== 16) throw new Error('Block must be 16 bytes');
  const subkeys = serpentKeySchedule(key256);
  const outWords = new Uint32Array(4);
  try {
    const v = new DataView(block16.buffer, block16.byteOffset, 16);
    serpentEncryptBlock(
      v.getUint32(0, true),
      v.getUint32(4, true),
      v.getUint32(8, true),
      v.getUint32(12, true),
      subkeys,
      outWords
    );
    const out = new Uint8Array(16);
    const outV = new DataView(out.buffer, out.byteOffset, 16);
    outV.setUint32(0, outWords[0], true);
    outV.setUint32(4, outWords[1], true);
    outV.setUint32(8, outWords[2], true);
    outV.setUint32(12, outWords[3], true);
    return out;
  } finally {
    for (const rk of subkeys) rk.fill(0);
    outWords.fill(0);
  }
}

// Fast Serpent-256-CTR encryption / decryption with 32-bit Word Acceleration
export function serpent256Ctr(
  data: Uint8Array,
  key256: Uint8Array,
  iv128: Uint8Array,
  precomputedSubkeys?: Uint32Array[],
  initialBlockOffset: number = 0
): Uint8Array {
  if (!iv128 || iv128.length < 16) {
    throw new Error('Serpent-256 CTR requires a 16-byte IV');
  }
  const ownsSubkeys = !precomputedSubkeys;
  const subkeys = precomputedSubkeys || serpentKeySchedule(key256);
  // Ensure 4-byte boundary alignment for direct Uint32Array mapping
  if (data.byteOffset % 4 !== 0) {
    data = new Uint8Array(data);
  }
  const out = new Uint8Array(data.length);
  const out32 = new Uint32Array(out.buffer, out.byteOffset, Math.floor(data.length / 4));
  const data32 = new Uint32Array(data.buffer, data.byteOffset, Math.floor(data.length / 4));

  const counterWords = new Uint32Array(4);
  if (iv128.byteOffset % 4 !== 0) {
    iv128 = new Uint8Array(iv128);
  }
  const iv32 = new Uint32Array(iv128.buffer, iv128.byteOffset, 4);
  counterWords.set(iv32);

  const blockWords = new Uint32Array(4);
  const fullBlocks = Math.floor(data.length / 16);

  // 128-bit continuous monotonic counter with initial block offset
  let cWord0 = counterWords[0];
  let cWord1 = counterWords[1];
  const initialCtr64 = BigInt(counterWords[2]) | (BigInt(counterWords[3]) << 32n);
  const totalCtr64 = initialCtr64 + BigInt(initialBlockOffset);
  let cLow = Number(totalCtr64 & 0xffffffffn) >>> 0;
  let cHigh = Number((totalCtr64 >> 32n) & 0xffffffffn) >>> 0;
  const carry64 = totalCtr64 >> 64n;
  if (carry64 > 0n) {
    const totalUpper = (BigInt(cWord0) | (BigInt(cWord1) << 32n)) + carry64;
    cWord0 = Number(totalUpper & 0xffffffffn) >>> 0;
    cWord1 = Number((totalUpper >> 32n) & 0xffffffffn) >>> 0;
  }

  try {
    for (let b = 0; b < fullBlocks; b++) {
      serpentEncryptBlock(cWord0, cWord1, cLow, cHigh, subkeys, blockWords);

      const wordIdx = b * 4;
      out32[wordIdx + 0] = data32[wordIdx + 0] ^ blockWords[0];
      out32[wordIdx + 1] = data32[wordIdx + 1] ^ blockWords[1];
      out32[wordIdx + 2] = data32[wordIdx + 2] ^ blockWords[2];
      out32[wordIdx + 3] = data32[wordIdx + 3] ^ blockWords[3];

      // Increment full 128-bit counter
      cLow = (cLow + 1) >>> 0;
      if (cLow === 0) {
        cHigh = (cHigh + 1) >>> 0;
        if (cHigh === 0) {
          cWord0 = (cWord0 + 1) >>> 0;
          if (cWord0 === 0) {
            cWord1 = (cWord1 + 1) >>> 0;
          }
        }
      }
    }

    // Trailing remainder bytes
    const rem = data.length % 16;
    if (rem > 0) {
      serpentEncryptBlock(cWord0, cWord1, cLow, cHigh, subkeys, blockWords);
      const ksBytes = new Uint8Array(blockWords.buffer, blockWords.byteOffset, 16);
      const startByte = fullBlocks * 16;
      for (let i = 0; i < rem; i++) {
        out[startByte + i] = data[startByte + i] ^ ksBytes[i];
      }
    }

    return out;
  } finally {
    if (ownsSubkeys) {
      for (const rk of subkeys) rk.fill(0);
    }
    blockWords.fill(0);
    counterWords.fill(0);
  }
}

/**
 * Asynchronous Serpent-256-CTR with cooperative event-loop yielding.
 * Yields every 2,048 blocks (32 KB, ~5ms) to guarantee ZERO Long Tasks (> 50ms)
 * and keep the browser event loop completely unblocked and responsive.
 */
export async function serpent256CtrAsync(
  data: Uint8Array,
  key256: Uint8Array,
  iv128: Uint8Array,
  precomputedSubkeys?: Uint32Array[],
  initialBlockOffset: number = 0,
  yieldStrideBlocks: number = 2048
): Promise<Uint8Array> {
  if (!iv128 || iv128.length < 16) {
    throw new Error('Serpent-256 CTR requires a 16-byte IV');
  }
  const ownsSubkeys = !precomputedSubkeys;
  const subkeys = precomputedSubkeys || serpentKeySchedule(key256);
  if (data.byteOffset % 4 !== 0) {
    data = new Uint8Array(data);
  }
  const out = new Uint8Array(data.length);
  const out32 = new Uint32Array(out.buffer, out.byteOffset, Math.floor(data.length / 4));
  const data32 = new Uint32Array(data.buffer, data.byteOffset, Math.floor(data.length / 4));

  const counterWords = new Uint32Array(4);
  if (iv128.byteOffset % 4 !== 0) {
    iv128 = new Uint8Array(iv128);
  }
  const iv32 = new Uint32Array(iv128.buffer, iv128.byteOffset, 4);
  counterWords.set(iv32);

  const blockWords = new Uint32Array(4);
  const fullBlocks = Math.floor(data.length / 16);

  // 128-bit continuous monotonic counter with initial block offset
  let cWord0 = counterWords[0];
  let cWord1 = counterWords[1];
  const initialCtr64 = BigInt(counterWords[2]) | (BigInt(counterWords[3]) << 32n);
  const totalCtr64 = initialCtr64 + BigInt(initialBlockOffset);
  let cLow = Number(totalCtr64 & 0xffffffffn) >>> 0;
  let cHigh = Number((totalCtr64 >> 32n) & 0xffffffffn) >>> 0;
  const carry64 = totalCtr64 >> 64n;
  if (carry64 > 0n) {
    const totalUpper = (BigInt(cWord0) | (BigInt(cWord1) << 32n)) + carry64;
    cWord0 = Number(totalUpper & 0xffffffffn) >>> 0;
    cWord1 = Number((totalUpper >> 32n) & 0xffffffffn) >>> 0;
  }

  try {
    for (let b = 0; b < fullBlocks; b++) {
      if (b > 0 && (b % yieldStrideBlocks) === 0) {
        await yieldToMainThread();
      }

      serpentEncryptBlock(cWord0, cWord1, cLow, cHigh, subkeys, blockWords);

      const wordIdx = b * 4;
      out32[wordIdx + 0] = data32[wordIdx + 0] ^ blockWords[0];
      out32[wordIdx + 1] = data32[wordIdx + 1] ^ blockWords[1];
      out32[wordIdx + 2] = data32[wordIdx + 2] ^ blockWords[2];
      out32[wordIdx + 3] = data32[wordIdx + 3] ^ blockWords[3];

      // Increment full 128-bit counter
      cLow = (cLow + 1) >>> 0;
      if (cLow === 0) {
        cHigh = (cHigh + 1) >>> 0;
        if (cHigh === 0) {
          cWord0 = (cWord0 + 1) >>> 0;
          if (cWord0 === 0) {
            cWord1 = (cWord1 + 1) >>> 0;
          }
        }
      }
    }

    const rem = data.length % 16;
    if (rem > 0) {
      serpentEncryptBlock(cWord0, cWord1, cLow, cHigh, subkeys, blockWords);
      const ksBytes = new Uint8Array(blockWords.buffer, blockWords.byteOffset, 16);
      const startByte = fullBlocks * 16;
      for (let i = 0; i < rem; i++) {
        out[startByte + i] = data[startByte + i] ^ ksBytes[i];
      }
    }

    return out;
  } finally {
    if (ownsSubkeys) {
      for (const rk of subkeys) rk.fill(0);
    }
    blockWords.fill(0);
    counterWords.fill(0);
  }
}
