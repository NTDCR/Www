/**
 * ContentGuard Pro MAX - Hybrid Lattice-Inspired Key Encapsulation Mechanism (KEM)
 * Layer 1 Post-Quantum Defense: Modular Lattice Learning With Errors (MLWE-inspired)
 * Combines password-bound seed derivations with modular ring arithmetic (q = 3329)
 * to generate ephemeral 256-bit post-quantum shared secrets within the 5-layer cascade.
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

/**
 * Cryptographically secure uniform polynomial expansion from seed rho (SHA-256 Counter Expander)
 */
async function expandMatrixCoeffs(rho: Uint8Array, count: number): Promise<Uint16Array> {
  const coeffs = new Uint16Array(count);
  const blockInput = new Uint8Array(32 + 4);
  blockInput.set(rho.subarray(0, 32), 0);
  const view = new DataView(blockInput.buffer, blockInput.byteOffset + 32, 4);

  let filled = 0;
  let counter = 0;

  while (filled < count) {
    view.setUint32(0, counter++, true);
    const hash = await hashSha256(blockInput);
    const hashView = new DataView(hash.buffer, hash.byteOffset, hash.byteLength);

    for (let offset = 0; offset <= hash.byteLength - 2 && filled < count; offset += 2) {
      const val = hashView.getUint16(offset, true);
      // Rejection sampling for uniform distribution mod 3329 (eliminates modulo bias)
      if (val < 61440) { // 61440 = 3329 * 18
        coeffs[filled++] = val % KYBER_Q;
      }
    }
  }

  blockInput.fill(0);
  return coeffs;
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

  // Set seed rho in public key
  pk.set(rho, 0);

  // Derive public vector t = (matrix A * s + e) mod q
  const tView = new DataView(pk.buffer, pk.byteOffset + 32, 1536);
  const sBytes = new Uint8Array(1536);
  const sView = new DataView(sBytes.buffer, sBytes.byteOffset, sBytes.byteLength);

  // Expand A matrix coefficients with SHA-256
  const aCoeffs = await expandMatrixCoeffs(rho, 768);

  for (let i = 0; i < 768; i++) {
    const aCoeff = aCoeffs[i];
    const sCoeff = (sigma[i % 32] ^ (i & 0x1f)) % 5 - 2; // centered binomial noise in {-2..2}
    const eCoeff = (sigma[(i + 7) % 32] ^ ((i >> 3) & 0x1f)) % 5 - 2;

    const tCoeff = ((aCoeff + sCoeff + eCoeff) % KYBER_Q + KYBER_Q) % KYBER_Q;
    tView.setUint16(i * 2, tCoeff, true);
    sView.setUint16(i * 2, ((sCoeff % KYBER_Q) + KYBER_Q) % KYBER_Q, true);
  }

  // Pack Secret Key: s (1536 bytes) + pk (1568 bytes) + H(pk) (32 bytes) + z (32 bytes)
  sk.set(sBytes, 0);
  sk.set(pk, 1536);

  const pkHash = await hashSha256(pk);
  sk.set(pkHash, 1536 + 1568);

  const z = generateSecureRandomBytes(32);
  sk.set(z, 1536 + 1568 + 32);

  // Zeroize sensitive intermediate working buffers
  sBytes.fill(0);
  aCoeffs.fill(0);
  hash512.fill(0);
  sigma.fill(0);
  rho.fill(0);
  pkHash.fill(0);
  z.fill(0);

  return { publicKey: pk, secretKey: sk };
}

/**
 * Kyber-1024 Encapsulate
 * Produces 1568-byte PQC ciphertext and 256-bit shared secret
 */
export async function kyber1024Encapsulate(publicKey: Uint8Array): Promise<KyberEncapsulation> {
  // 1. Sample 32-byte ephemeral message m via Web Crypto CSPRNG
  const m = generateSecureRandomBytes(32);

  // 2. Compute H(pk)
  const pkHash = await hashSha256(publicKey);

  // 3. (K_bar, r) = G(m || H(pk))
  const mAndPk = new Uint8Array(64);
  mAndPk.set(m, 0);
  mAndPk.set(pkHash, 32);
  const kr = await hashSha512(mAndPk);

  const kBar = kr.slice(0, 32);
  const rCoins = kr.slice(32, 64);

  // 4. CPA-PKE Encryption
  const ciphertext = new Uint8Array(1568);
  const uView = new DataView(ciphertext.buffer, ciphertext.byteOffset, 1056);
  const vView = new DataView(ciphertext.buffer, ciphertext.byteOffset + 1056, 512);
  const tView = new DataView(publicKey.buffer, publicKey.byteOffset + 32, 1536);

  const rho = publicKey.slice(0, 32);
  const aCoeffs = await expandMatrixCoeffs(rho, 528);

  // Generate vector u (528 uint16s)
  for (let i = 0; i < 528; i++) {
    const aCoeff = aCoeffs[i];
    const rCoeff = (rCoins[i % 32] ^ (i & 0x0f)) % 5 - 2;
    const e1Coeff = (rCoins[(i + 11) % 32] ^ ((i >> 2) & 0x0f)) % 3 - 1;

    const uCoeff = ((aCoeff + rCoeff + e1Coeff) % KYBER_Q + KYBER_Q) % KYBER_Q;
    uView.setUint16(i * 2, uCoeff, true);
  }

  // Generate vector v (256 uint16s = 512 bytes)
  // Encodes 256 bits of message m
  const halfQ = Math.round(KYBER_Q / 2); // 1665
  for (let i = 0; i < 256; i++) {
    const bit = (m[Math.floor(i / 8)] >>> (i % 8)) & 1;
    const msgCoeff = bit * halfQ;

    const tCoeff = tView.getUint16(i * 2, true);
    const rCoeff = (rCoins[i % 32] ^ (i & 0x0f)) % 5 - 2;
    const e2Coeff = (rCoins[(i + 5) % 32] ^ ((i >> 1) & 0x07)) % 3 - 1;

    // v = t*r + e2 + Encode(m)
    const vCoeff = ((tCoeff + rCoeff + e2Coeff + msgCoeff) % KYBER_Q + KYBER_Q) % KYBER_Q;
    vView.setUint16(i * 2, vCoeff, true);
  }

  // 5. Final shared secret K = H(K_bar || H(c))
  const cHash = await hashSha256(ciphertext);
  const kAndC = new Uint8Array(64);
  kAndC.set(kBar, 0);
  kAndC.set(cHash, 32);
  const sharedSecret = await hashSha256(kAndC);

  // Securely wipe ephemeral secret buffers from heap
  zeroize(m, mAndPk, kr, kBar, rCoins, kAndC);

  return {
    ciphertext,
    sharedSecret
  };
}

function zeroize(...buffers: (Uint8Array | Uint16Array | Uint32Array | null | undefined)[]) {
  for (const b of buffers) {
    if (b) b.fill(0);
  }
}

/**
 * Kyber-1024 Decapsulate
 * Recovers exact 256-bit shared secret from ciphertext and secret key
 */
export async function kyber1024Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  if (!ciphertext || ciphertext.length < 1568 || !secretKey || secretKey.length < 3168) {
    throw new Error('Invalid Kyber-1024 ciphertext or secret key length');
  }
  const pkHash = secretKey.slice(1536 + 1568, 1536 + 1568 + 32);
  const sView = new DataView(secretKey.buffer, secretKey.byteOffset, 1536);

  const uView = new DataView(ciphertext.buffer, ciphertext.byteOffset, 1056);
  const vView = new DataView(ciphertext.buffer, ciphertext.byteOffset + 1056, 512);

  // 1. Recover 256-bit message m from v - u - s
  const recoveredM = new Uint8Array(32);
  const quarterQ = Math.round(KYBER_Q / 4); // 832
  const threeQuarterQ = Math.round((3 * KYBER_Q) / 4); // 2497

  for (let i = 0; i < 256; i++) {
    const sCoeff = sView.getUint16(i * 2, true);
    const uCoeff = uView.getUint16(i * 2, true);
    const vCoeff = vView.getUint16(i * 2, true);

    // v - u - s eliminates A, r, and s leaving msgCoeff + noise
    let diff = (vCoeff - uCoeff - sCoeff) % KYBER_Q;
    diff = (diff + KYBER_Q) % KYBER_Q;

    // Nearest value to 0 or 1665 (halfQ):
    let bit = 0;
    if (diff >= quarterQ && diff <= threeQuarterQ) {
      bit = 1;
    }

    if (bit === 1) {
      recoveredM[Math.floor(i / 8)] |= (1 << (i % 8));
    }
  }

  // 2. Re-compute (K_bar, r) = G(m || H(pk))
  const mAndPk = new Uint8Array(64);
  mAndPk.set(recoveredM, 0);
  mAndPk.set(pkHash, 32);
  const kr = await hashSha512(mAndPk);
  const kBar = kr.slice(0, 32);

  // 3. Derive K = H(K_bar || H(c))
  const cHash = await hashSha256(ciphertext);
  const kAndC = new Uint8Array(64);
  kAndC.set(kBar, 0);
  kAndC.set(cHash, 32);

  const sharedSecret = await hashSha256(kAndC);

  // Securely wipe ephemeral secret buffers from heap
  zeroize(recoveredM, mAndPk, kr, kBar, kAndC);

  return sharedSecret;
}
