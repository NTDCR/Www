/**
 * ContentGuard Pro MAX - Hybrid Lattice-Inspired Key Encapsulation Mechanism (KEM)
 * Layer 1 Post-Quantum Defense: Modular Lattice Learning With Errors (MLWE-inspired)
 * Combines password-bound seed derivations with modular ring arithmetic (q = 3329)
 * to generate ephemeral 256-bit post-quantum shared secrets within the 5-layer cascade.
 *
 * Decapsulation implements a Fujisaki-Okamoto-style re-encryption check with implicit
 * rejection via the secret z value (ML-KEM-inspired; not NIST byte-compatible).
 */

import { generateSecureRandomBytes } from './safeRandom';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

export const KYBER_K = 4; // Kyber-1024 rank
export const KYBER_N = 256; // Ring degree R_q = Z_q[X]/(X^256 + 1)
export const KYBER_Q = 3329; // Modulus (q = 3329)

export interface KyberKeyPair {
  publicKey: Uint8Array; // 1568 bytes
  secretKey: Uint8Array; // 3168 bytes
}

export interface KyberEncapsulation {
  ciphertext: Uint8Array; // 1568 bytes
  sharedSecret: Uint8Array; // 32 bytes (256-bit post-quantum key)
}

/**
 * SHA-256 and SHA-512 cryptographic hash helpers with Web Crypto and Noble fallback
 */
async function hashSha512(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const buf = await crypto.subtle.digest('SHA-512', data);
      return new Uint8Array(buf);
    } catch {}
  }
  return sha512(data);
}

async function hashSha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', data);
      return new Uint8Array(buf);
    } catch {}
  }
  return sha256(data);
}

/** Constant-time equality for equal-length buffers (local; avoids cascadeEngine import cycle). */
function ctEqual(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0 ? 1 : 0;
}

/** Constant-time select: mask is 0 or 1; returns a if mask===1 else b. */
function ctSelect(mask: number, a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  const m = (-(mask & 1)) & 0xff;
  const nm = ~m & 0xff;
  for (let i = 0; i < a.length; i++) {
    out[i] = ((a[i] & m) | (b[i] & nm)) & 0xff;
  }
  return out;
}

function zeroize(...buffers: (Uint8Array | Uint16Array | Uint32Array | Int16Array | Int16Array[] | Int16Array[][] | null | undefined)[]) {
  for (const b of buffers) {
    if (!b) continue;
    if (Array.isArray(b)) {
      for (const sub of b) {
        if (Array.isArray(sub)) {
          for (const poly of sub) if (poly) poly.fill(0);
        } else if (sub) {
          sub.fill(0);
        }
      }
    } else {
      b.fill(0);
    }
  }
}

/**
 * Expand 4x4 matrix A of polynomials (16 polynomials = 4096 coefficients) via XOF counter
 */
async function expandMatrixCoeffs(rho: Uint8Array): Promise<Int16Array[][]> {
  const A: Int16Array[][] = [];
  for (let i = 0; i < KYBER_K; i++) {
    A[i] = [];
    for (let j = 0; j < KYBER_K; j++) {
      const coeffs = new Int16Array(KYBER_N);
      const seed = new Uint8Array(34);
      seed.set(rho, 0);
      seed[32] = i;
      seed[33] = j;

      let filled = 0;
      let counter = 0;
      const inp = new Uint8Array(38);
      inp.set(seed, 0);
      const viewInp = new DataView(inp.buffer, inp.byteOffset, inp.byteLength);

      while (filled < KYBER_N) {
        viewInp.setUint32(34, counter++, true);
        const hash = await hashSha256(inp);
        const hashView = new DataView(hash.buffer, hash.byteOffset, hash.byteLength);

        for (let off = 0; off <= hash.byteLength - 2 && filled < KYBER_N; off += 2) {
          const val = hashView.getUint16(off, true);
          if (val < 61440) { // 61440 = 3329 * 18
            coeffs[filled++] = val % KYBER_Q;
          }
        }
      }
      A[i][j] = coeffs;
    }
  }
  return A;
}

/**
 * Authentic Centered Binomial Distribution (CBD_2) sampling:
 * Takes 128 pseudo-random bytes (1024 bits) and samples 256 coefficients in {-2, -1, 0, 1, 2}:
 * For each coefficient: (b0 + b1) - (b2 + b3)
 */
async function sampleCbd2(seed: Uint8Array, nonce: number): Promise<Int16Array> {
  const poly = new Int16Array(KYBER_N);
  const inp1 = new Uint8Array(seed.length + 1);
  inp1.set(seed, 0);
  inp1[seed.length] = nonce;
  const hash1 = await hashSha512(inp1);

  const inp2 = new Uint8Array(seed.length + 1);
  inp2.set(seed, 0);
  inp2[seed.length] = nonce + 64;
  const hash2 = await hashSha512(inp2);

  const bytes = new Uint8Array(128);
  bytes.set(hash1, 0);
  bytes.set(hash2, 64);

  for (let i = 0; i < KYBER_N; i++) {
    const byte = bytes[Math.floor(i / 2)];
    const bits = (i % 2 === 0) ? (byte & 0x0f) : (byte >>> 4);
    const b0 = (bits >>> 0) & 1;
    const b1 = (bits >>> 1) & 1;
    const b2 = (bits >>> 2) & 1;
    const b3 = (bits >>> 3) & 1;
    poly[i] = (b0 + b1) - (b2 + b3);
  }

  bytes.fill(0);
  hash1.fill(0);
  hash2.fill(0);
  return poly;
}

/**
 * 12-bit polynomial packing (256 coefficients -> 384 bytes)
 */
function pack12(poly: Int16Array): Uint8Array {
  const out = new Uint8Array(384);
  for (let i = 0; i < 128; i++) {
    const c0 = ((poly[2 * i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    const c1 = ((poly[2 * i + 1] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    out[3 * i + 0] = c0 & 0xff;
    out[3 * i + 1] = ((c0 >>> 8) & 0x0f) | ((c1 & 0x0f) << 4);
    out[3 * i + 2] = (c1 >>> 4) & 0xff;
  }
  return out;
}

function unpack12(bytes: Uint8Array): Int16Array {
  const poly = new Int16Array(KYBER_N);
  for (let i = 0; i < 128; i++) {
    const b0 = bytes[3 * i + 0];
    const b1 = bytes[3 * i + 1];
    const b2 = bytes[3 * i + 2];
    poly[2 * i] = b0 | ((b1 & 0x0f) << 8);
    poly[2 * i + 1] = (b1 >>> 4) | (b2 << 4);
  }
  return poly;
}

/**
 * Compress / Decompress u vector (d_u = 11 bits) -> 352 bytes per polynomial
 */
function compressU(poly: Int16Array): Uint8Array {
  const out = new Uint8Array(352);
  const coeffs11 = new Uint16Array(KYBER_N);
  for (let i = 0; i < KYBER_N; i++) {
    const c = ((poly[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    coeffs11[i] = Math.round((c * 2048) / KYBER_Q) & 0x7ff;
  }
  for (let i = 0; i < 32; i++) {
    const c = coeffs11.subarray(i * 8, (i + 1) * 8);
    const o = i * 11;
    out[o + 0] = c[0] & 0xff;
    out[o + 1] = ((c[0] >>> 8) & 0x07) | ((c[1] & 0x1f) << 3);
    out[o + 2] = ((c[1] >>> 5) & 0x3f) | ((c[2] & 0x03) << 6);
    out[o + 3] = (c[2] >>> 2) & 0xff;
    out[o + 4] = ((c[2] >>> 10) & 0x01) | ((c[3] & 0x7f) << 1);
    out[o + 5] = ((c[3] >>> 7) & 0x0f) | ((c[4] & 0x0f) << 4);
    out[o + 6] = ((c[4] >>> 4) & 0x7f) | ((c[5] & 0x01) << 7);
    out[o + 7] = (c[5] >>> 1) & 0xff;
    out[o + 8] = ((c[5] >>> 9) & 0x03) | ((c[6] & 0x3f) << 2);
    out[o + 9] = ((c[6] >>> 6) & 0x1f) | ((c[7] & 0x07) << 5);
    out[o + 10] = (c[7] >>> 3) & 0xff;
  }
  return out;
}

function decompressU(bytes: Uint8Array): Int16Array {
  const poly = new Int16Array(KYBER_N);
  for (let i = 0; i < 32; i++) {
    const o = i * 11;
    const b = bytes.subarray(o, o + 11);
    const c0 = b[0] | ((b[1] & 0x07) << 8);
    const c1 = (b[1] >>> 3) | ((b[2] & 0x3f) << 5);
    const c2 = (b[2] >>> 6) | (b[3] << 2) | ((b[4] & 0x01) << 10);
    const c3 = (b[4] >>> 1) | ((b[5] & 0x0f) << 7);
    const c4 = (b[5] >>> 4) | ((b[6] & 0x7f) << 4);
    const c5 = (b[6] >>> 7) | (b[7] << 1) | ((b[8] & 0x03) << 9);
    const c6 = (b[8] >>> 2) | ((b[9] & 0x1f) << 6);
    const c7 = (b[9] >>> 5) | (b[10] << 3);
    const raw = [c0, c1, c2, c3, c4, c5, c6, c7];
    for (let j = 0; j < 8; j++) {
      poly[i * 8 + j] = Math.round((raw[j] * KYBER_Q) / 2048);
    }
  }
  return poly;
}

/**
 * Compress / Decompress v polynomial (d_v = 5 bits) -> 160 bytes
 */
function compressV(poly: Int16Array): Uint8Array {
  const out = new Uint8Array(160);
  const coeffs5 = new Uint8Array(KYBER_N);
  for (let i = 0; i < KYBER_N; i++) {
    const c = ((poly[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    coeffs5[i] = Math.round((c * 32) / KYBER_Q) & 0x1f;
  }
  for (let i = 0; i < 32; i++) {
    const c = coeffs5.subarray(i * 8, (i + 1) * 8);
    const o = i * 5;
    out[o + 0] = c[0] | ((c[1] & 0x07) << 5);
    out[o + 1] = (c[1] >>> 3) | (c[2] << 2) | ((c[3] & 0x01) << 7);
    out[o + 2] = (c[3] >>> 1) | ((c[4] & 0x0f) << 4);
    out[o + 3] = (c[4] >>> 4) | (c[5] << 1) | ((c[6] & 0x03) << 6);
    out[o + 4] = (c[6] >>> 2) | (c[7] << 3);
  }
  return out;
}

function decompressV(bytes: Uint8Array): Int16Array {
  const poly = new Int16Array(KYBER_N);
  for (let i = 0; i < 32; i++) {
    const o = i * 5;
    const b = bytes.subarray(o, o + 5);
    const c0 = b[0] & 0x1f;
    const c1 = (b[0] >>> 5) | ((b[1] & 0x03) << 3);
    const c2 = (b[1] >>> 2) & 0x1f;
    const c3 = (b[1] >>> 7) | ((b[2] & 0x0f) << 1);
    const c4 = (b[2] >>> 4) | ((b[3] & 0x01) << 4);
    const c5 = (b[3] >>> 1) & 0x1f;
    const c6 = (b[3] >>> 6) | ((b[4] & 0x07) << 2);
    const c7 = b[4] >>> 3;
    const raw = [c0, c1, c2, c3, c4, c5, c6, c7];
    for (let j = 0; j < 8; j++) {
      poly[i * 8 + j] = Math.round((raw[j] * KYBER_Q) / 32);
    }
  }
  return poly;
}

/**
 * Polynomial multiplication in R_q = Z_q[X] / (X^256 + 1)
 * Computes exact negative-wrapped polynomial convolution modulo X^256 + 1
 */
export function polyMulRq(f: Int16Array | Uint16Array, g: Int16Array | Uint16Array): Int16Array {
  const h = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    const fi = f[i];
    if (fi === 0) continue;
    for (let j = 0; j < 256; j++) {
      if (i + j < 256) {
        h[i + j] += fi * g[j];
      } else {
        h[i + j - 256] -= fi * g[j];
      }
    }
  }
  const res = new Int16Array(256);
  for (let i = 0; i < 256; i++) {
    res[i] = ((h[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
  }
  return res;
}

/**
 * CPA-PKE Encrypt: produces 1568-byte ciphertext from public key, message m, and coins r
 */
async function cpaEncrypt(
  publicKey: Uint8Array,
  m: Uint8Array,
  rCoins: Uint8Array
): Promise<Uint8Array> {
  const rho = publicKey.subarray(0, 32);
  const A = await expandMatrixCoeffs(rho);

  // Unpack t vector (4 polynomials x 384 bytes)
  const t: Int16Array[] = [];
  for (let i = 0; i < KYBER_K; i++) {
    t.push(unpack12(publicKey.subarray(32 + i * 384, 32 + (i + 1) * 384)));
  }

  // Sample lattice error vectors r, e1 (k=4 polynomials), and e2 (1 polynomial) via CBD_2
  const r: Int16Array[] = [];
  const e1: Int16Array[] = [];
  for (let i = 0; i < KYBER_K; i++) {
    r.push(await sampleCbd2(rCoins, i));
    e1.push(await sampleCbd2(rCoins, 4 + i));
  }
  const e2 = await sampleCbd2(rCoins, 8);

  // u = A^T * r + e1:
  const u: Int16Array[] = [];
  for (let j = 0; j < KYBER_K; j++) {
    const uj = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_K; i++) {
      const prod = polyMulRq(A[i][j], r[i]);
      for (let n = 0; n < KYBER_N; n++) uj[n] = (uj[n] + prod[n]) % KYBER_Q;
    }
    for (let n = 0; n < KYBER_N; n++) uj[n] = ((uj[n] + e1[j][n]) % KYBER_Q + KYBER_Q) % KYBER_Q;
    u.push(uj);
  }

  // v = t^T * r + e2 + round(q/2) * m:
  const v = new Int16Array(KYBER_N);
  for (let i = 0; i < KYBER_K; i++) {
    const prod = polyMulRq(t[i], r[i]);
    for (let n = 0; n < KYBER_N; n++) v[n] = (v[n] + prod[n]) % KYBER_Q;
  }
  const halfQ = Math.round(KYBER_Q / 2);
  for (let n = 0; n < KYBER_N; n++) {
    const bit = (m[Math.floor(n / 8)] >>> (n % 8)) & 1;
    v[n] = ((v[n] + e2[n] + bit * halfQ) % KYBER_Q + KYBER_Q) % KYBER_Q;
  }

  // Pack ciphertext: 4 * 352 bytes (u) + 160 bytes (v) = 1568 bytes
  const ciphertext = new Uint8Array(1568);
  for (let i = 0; i < KYBER_K; i++) {
    const compUi = compressU(u[i]);
    ciphertext.set(compUi, i * 352);
    compUi.fill(0);
  }
  const compV = compressV(v);
  ciphertext.set(compV, 1408);
  compV.fill(0);

  // Securely wipe lattice working vectors
  zeroize(A, t, r, e1, e2, u, v);

  return ciphertext;
}

/**
 * Implicit-rejection pseudo secret when inputs are invalid
 */
async function implicitRejectPseudoSecret(
  ciphertext: Uint8Array | null | undefined,
  secretKey: Uint8Array | null | undefined
): Promise<Uint8Array> {
  const cHash = await hashSha256(ciphertext && ciphertext.length > 0 ? ciphertext : new Uint8Array(0));
  const seed = new Uint8Array(64);
  if (secretKey && secretKey.length >= 3168) {
    seed.set(secretKey.subarray(1536 + 1568 + 32, 1536 + 1568 + 64), 0);
  }
  seed.set(cHash, 32);
  const out = await hashSha256(seed);
  seed.fill(0);
  return out;
}

/**
 * Generate Kyber-1024 Keypair from seed (Level 5 Post-Quantum)
 * Public key: 1568 bytes (32-byte seed rho + 1536-byte vector t)
 * Secret key: 3168 bytes (1536-byte vector s + 1568-byte pk + 32-byte H(pk) + 32-byte z)
 */
export async function kyber1024KeyGen(seed?: Uint8Array): Promise<KyberKeyPair> {
  const d = seed || generateSecureRandomBytes(64);
  const hash512 = await hashSha512(d);

  const rho = hash512.slice(0, 32);
  const sigma = hash512.slice(32, 64);

  const pk = new Uint8Array(1568);
  const sk = new Uint8Array(3168);

  let A: Int16Array[][] | null = null;
  const s: Int16Array[] = [];
  const e: Int16Array[] = [];
  const t: Int16Array[] = [];
  let pkHash: Uint8Array | null = null;
  let z: Uint8Array | null = null;

  try {
    pk.set(rho, 0);

    // Expand 4x4 matrix A
    A = await expandMatrixCoeffs(rho);

    // Sample s (4 polynomials) and e (4 polynomials) via CBD_2
    for (let i = 0; i < KYBER_K; i++) {
      s.push(await sampleCbd2(sigma, i));
      e.push(await sampleCbd2(sigma, 4 + i));
    }

    // Compute t = A * s + e (matrix-vector multiplication over R_q)
    for (let i = 0; i < KYBER_K; i++) {
      const ti = new Int16Array(KYBER_N);
      for (let j = 0; j < KYBER_K; j++) {
        const prod = polyMulRq(A[i][j], s[j]);
        for (let n = 0; n < KYBER_N; n++) ti[n] = (ti[n] + prod[n]) % KYBER_Q;
      }
      for (let n = 0; n < KYBER_N; n++) ti[n] = ((ti[n] + e[i][n]) % KYBER_Q + KYBER_Q) % KYBER_Q;
      t.push(ti);
    }

    // Pack public key: rho (32 bytes) + t (4 x 384 bytes = 1536 bytes) = 1568 bytes
    for (let i = 0; i < KYBER_K; i++) {
      const packedT = pack12(t[i]);
      pk.set(packedT, 32 + i * 384);
      packedT.fill(0);
    }

    // Pack secret key: s (4 x 384 bytes = 1536 bytes) + pk (1568 bytes) + H(pk) (32 bytes) + z (32 bytes) = 3168 bytes
    for (let i = 0; i < KYBER_K; i++) {
      const packedS = pack12(s[i]);
      sk.set(packedS, i * 384);
      packedS.fill(0);
    }
    sk.set(pk, 1536);

    pkHash = await hashSha256(pk);
    sk.set(pkHash, 1536 + 1568);

    z = generateSecureRandomBytes(32);
    sk.set(z, 1536 + 1568 + 32);

    return { publicKey: pk, secretKey: sk };
  } finally {
    zeroize(hash512, rho, sigma, A, s, e, t, pkHash, z);
  }
}

/**
 * Kyber-1024 Encapsulate
 * Produces 1568-byte PQC ciphertext and 256-bit shared secret
 */
export async function kyber1024Encapsulate(publicKey: Uint8Array): Promise<KyberEncapsulation> {
  const m = generateSecureRandomBytes(32);
  let pkHash: Uint8Array | null = null;
  let mAndPk: Uint8Array | null = null;
  let kr: Uint8Array | null = null;
  let kBar: Uint8Array | null = null;
  let rCoins: Uint8Array | null = null;
  let kAndC: Uint8Array | null = null;
  let ciphertext: Uint8Array | null = null;

  try {
    pkHash = await hashSha256(publicKey);

    // (K_bar, r) = G(m || H(pk))
    mAndPk = new Uint8Array(64);
    mAndPk.set(m, 0);
    mAndPk.set(pkHash, 32);
    kr = await hashSha512(mAndPk);

    kBar = kr.slice(0, 32);
    rCoins = kr.slice(32, 64);

    // CPA-PKE Encryption
    ciphertext = await cpaEncrypt(publicKey, m, rCoins);

    // Final shared secret K = H(K_bar || H(c))
    const cHash = await hashSha256(ciphertext);
    kAndC = new Uint8Array(64);
    kAndC.set(kBar, 0);
    kAndC.set(cHash, 32);
    const sharedSecret = await hashSha256(kAndC);

    return {
      ciphertext,
      sharedSecret
    };
  } finally {
    zeroize(m, pkHash, mAndPk, kr, kBar, rCoins, kAndC);
  }
}

/**
 * Kyber-1024 Decapsulate with Fujisaki-Okamoto re-encryption + implicit rejection
 */
export async function kyber1024Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  if (!ciphertext || ciphertext.length < 1568 || !secretKey || secretKey.length < 3168) {
    return implicitRejectPseudoSecret(ciphertext, secretKey);
  }

  const pk = secretKey.subarray(1536, 1536 + 1568);
  const pkHash = secretKey.slice(1536 + 1568, 1536 + 1568 + 32);
  const z = secretKey.slice(1536 + 1568 + 32, 1536 + 1568 + 64);

  // Unpack s vector (4 polynomials x 384 bytes)
  const s: Int16Array[] = [];
  for (let i = 0; i < KYBER_K; i++) {
    s.push(unpack12(secretKey.subarray(i * 384, (i + 1) * 384)));
  }

  // Decompress u vector (4 polynomials x 352 bytes = 1408 bytes)
  const u: Int16Array[] = [];
  for (let i = 0; i < KYBER_K; i++) {
    u.push(decompressU(ciphertext.subarray(i * 352, (i + 1) * 352)));
  }

  // Decompress v polynomial (160 bytes at offset 1408)
  const v = decompressV(ciphertext.subarray(1408, 1408 + 160));

  const recoveredM = new Uint8Array(32);
  let mAndPk: Uint8Array | null = null;
  let kr: Uint8Array | null = null;
  let kBar: Uint8Array | null = null;
  let rCoins: Uint8Array | null = null;
  let cPrime: Uint8Array | null = null;
  let kOkBuf: Uint8Array | null = null;
  let kRejBuf: Uint8Array | null = null;

  try {
    // Decrypt: v - s^T * u
    const sTu = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_K; i++) {
      const prod = polyMulRq(s[i], u[i]);
      for (let n = 0; n < KYBER_N; n++) sTu[n] = (sTu[n] + prod[n]) % KYBER_Q;
    }

    const quarterQ = Math.round(KYBER_Q / 4);
    const threeQuarterQ = Math.round((3 * KYBER_Q) / 4);

    for (let n = 0; n < KYBER_N; n++) {
      let diff = (v[n] - sTu[n]) % KYBER_Q;
      diff = (diff + KYBER_Q) % KYBER_Q;
      let bit = (diff >= quarterQ && diff <= threeQuarterQ) ? 1 : 0;
      if (bit === 1) {
        recoveredM[Math.floor(n / 8)] |= (1 << (n % 8));
      }
    }

    // FO re-encryption check: (K_bar, r) = G(m' || H(pk))
    mAndPk = new Uint8Array(64);
    mAndPk.set(recoveredM, 0);
    mAndPk.set(pkHash, 32);
    kr = await hashSha512(mAndPk);
    kBar = kr.slice(0, 32);
    rCoins = kr.slice(32, 64);

    cPrime = await cpaEncrypt(pk, recoveredM, rCoins);
    const match = ctEqual(ciphertext.subarray(0, 1568), cPrime);

    // Constant-time select between valid shared secret and implicit rejection secret
    const cHash = await hashSha256(ciphertext.subarray(0, 1568));
    kOkBuf = new Uint8Array(64);
    kOkBuf.set(kBar, 0);
    kOkBuf.set(cHash, 32);
    const kOk = await hashSha256(kOkBuf);

    kRejBuf = new Uint8Array(64);
    kRejBuf.set(z, 0);
    kRejBuf.set(cHash, 32);
    const kRej = await hashSha256(kRejBuf);

    const sharedSecret = ctSelect(match, kOk, kRej);
    zeroize(kOk, kRej, sTu);
    return sharedSecret;
  } finally {
    zeroize(s, u, v, recoveredM, mAndPk, kr, kBar, rCoins, cPrime, kOkBuf, kRejBuf, pkHash, z);
  }
}
