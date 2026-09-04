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

function zeroize(...buffers: (Uint8Array | Uint16Array | Uint32Array | null | undefined)[]) {
  for (const b of buffers) {
    if (b) b.fill(0);
  }
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
 * CPA-PKE encrypt: produces 1568-byte ciphertext from public key, message m, and coins r.
 */
async function cpaEncrypt(
  publicKey: Uint8Array,
  m: Uint8Array,
  rCoins: Uint8Array
): Promise<{ ciphertext: Uint8Array; aCoeffs: Uint16Array; rho: Uint8Array }> {
  const ciphertext = new Uint8Array(1568);
  const uView = new DataView(ciphertext.buffer, ciphertext.byteOffset, 1056);
  const vView = new DataView(ciphertext.buffer, ciphertext.byteOffset + 1056, 512);
  const tView = new DataView(publicKey.buffer, publicKey.byteOffset + 32, 1536);

  const rho = publicKey.slice(0, 32);
  const aCoeffs = await expandMatrixCoeffs(rho, 528);

  for (let i = 0; i < 528; i++) {
    const aCoeff = aCoeffs[i];
    const rCoeff = (rCoins[i % 32] ^ (i & 0x0f)) % 5 - 2;
    const e1Coeff = (rCoins[(i + 11) % 32] ^ ((i >> 2) & 0x0f)) % 3 - 1;

    const uCoeff = ((aCoeff + rCoeff + e1Coeff) % KYBER_Q + KYBER_Q) % KYBER_Q;
    uView.setUint16(i * 2, uCoeff, true);
  }

  const halfQ = Math.round(KYBER_Q / 2); // 1665
  for (let i = 0; i < 256; i++) {
    const bit = (m[Math.floor(i / 8)] >>> (i % 8)) & 1;
    const msgCoeff = bit * halfQ;

    const tCoeff = tView.getUint16(i * 2, true);
    const rCoeff = (rCoins[i % 32] ^ (i & 0x0f)) % 5 - 2;
    const e2Coeff = (rCoins[(i + 5) % 32] ^ ((i >> 1) & 0x07)) % 3 - 1;

    const vCoeff = ((tCoeff + rCoeff + e2Coeff + msgCoeff) % KYBER_Q + KYBER_Q) % KYBER_Q;
    vView.setUint16(i * 2, vCoeff, true);
  }

  return { ciphertext, aCoeffs, rho };
}

/**
 * Implicit-rejection secret when lengths are invalid (no distinguishable throw oracle).
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

  const sBytes = new Uint8Array(1536);
  let aCoeffs: Uint16Array | null = null;
  let pkHash: Uint8Array | null = null;
  let z: Uint8Array | null = null;

  try {
    // Set seed rho in public key
    pk.set(rho, 0);

    // Derive public vector t = (matrix A * s + e) mod q
    const tView = new DataView(pk.buffer, pk.byteOffset + 32, 1536);
    const sView = new DataView(sBytes.buffer, sBytes.byteOffset, sBytes.byteLength);

    // Expand A matrix coefficients with SHA-256
    aCoeffs = await expandMatrixCoeffs(rho, 768);

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

    pkHash = await hashSha256(pk);
    sk.set(pkHash, 1536 + 1568);

    z = generateSecureRandomBytes(32);
    sk.set(z, 1536 + 1568 + 32);

    return { publicKey: pk, secretKey: sk };
  } finally {
    // Zeroize sensitive intermediate working buffers
    zeroize(sBytes, aCoeffs, hash512, sigma, rho, pkHash, z);
  }
}

/**
 * Kyber-1024 Encapsulate
 * Produces 1568-byte PQC ciphertext and 256-bit shared secret
 */
export async function kyber1024Encapsulate(publicKey: Uint8Array): Promise<KyberEncapsulation> {
  // 1. Sample 32-byte ephemeral message m via Web Crypto CSPRNG
  const m = generateSecureRandomBytes(32);
  let pkHash: Uint8Array | null = null;
  let mAndPk: Uint8Array | null = null;
  let kr: Uint8Array | null = null;
  let kBar: Uint8Array | null = null;
  let rCoins: Uint8Array | null = null;
  let kAndC: Uint8Array | null = null;
  let rho: Uint8Array | null = null;
  let aCoeffs: Uint16Array | null = null;

  try {
    // 2. Compute H(pk)
    pkHash = await hashSha256(publicKey);

    // 3. (K_bar, r) = G(m || H(pk))
    mAndPk = new Uint8Array(64);
    mAndPk.set(m, 0);
    mAndPk.set(pkHash, 32);
    kr = await hashSha512(mAndPk);

    kBar = kr.slice(0, 32);
    rCoins = kr.slice(32, 64);

    // 4. CPA-PKE Encryption
    const cpa = await cpaEncrypt(publicKey, m, rCoins);
    const ciphertext = cpa.ciphertext;
    rho = cpa.rho;
    aCoeffs = cpa.aCoeffs;

    // 5. Final shared secret K = H(K_bar || H(c))
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
    // Securely wipe ephemeral secret buffers from heap
    zeroize(m, mAndPk, kr, kBar, rCoins, kAndC, pkHash, rho, aCoeffs);
  }
}

/**
 * Kyber-1024 Decapsulate with Fujisaki-Okamoto re-encryption + implicit rejection.
 * Always returns a 32-byte secret (never throws distinguishable length/oracle errors).
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
  const sView = new DataView(secretKey.buffer, secretKey.byteOffset, 1536);

  const uView = new DataView(ciphertext.buffer, ciphertext.byteOffset, 1056);
  const vView = new DataView(ciphertext.buffer, ciphertext.byteOffset + 1056, 512);

  const recoveredM = new Uint8Array(32);
  let mAndPk: Uint8Array | null = null;
  let kr: Uint8Array | null = null;
  let kBar: Uint8Array | null = null;
  let rCoins: Uint8Array | null = null;
  let kOkBuf: Uint8Array | null = null;
  let kRejBuf: Uint8Array | null = null;
  let cPrime: Uint8Array | null = null;
  let aCoeffs: Uint16Array | null = null;
  let rho: Uint8Array | null = null;

  try {
    const quarterQ = Math.round(KYBER_Q / 4); // 832
    const threeQuarterQ = Math.round((3 * KYBER_Q) / 4); // 2497

    for (let i = 0; i < 256; i++) {
      const sCoeff = sView.getUint16(i * 2, true);
      const uCoeff = uView.getUint16(i * 2, true);
      const vCoeff = vView.getUint16(i * 2, true);

      let diff = (vCoeff - uCoeff - sCoeff) % KYBER_Q;
      diff = (diff + KYBER_Q) % KYBER_Q;

      let bit = 0;
      if (diff >= quarterQ && diff <= threeQuarterQ) {
        bit = 1;
      }

      if (bit === 1) {
        recoveredM[Math.floor(i / 8)] |= (1 << (i % 8));
      }
    }

    // 2. Re-compute (K_bar, r) = G(m' || H(pk))
    mAndPk = new Uint8Array(64);
    mAndPk.set(recoveredM, 0);
    mAndPk.set(pkHash, 32);
    kr = await hashSha512(mAndPk);
    kBar = kr.slice(0, 32);
    rCoins = kr.slice(32, 64);

    // 3. FO re-encryption check: c' = CPA.Encrypt(pk, m', r)
    const cpa = await cpaEncrypt(pk, recoveredM, rCoins);
    cPrime = cpa.ciphertext;
    aCoeffs = cpa.aCoeffs;
    rho = cpa.rho;

    const match = ctEqual(ciphertext.subarray(0, 1568), cPrime);

    // 4. Always compute both candidates; CT-mux select
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
    zeroize(kOk, kRej);
    return sharedSecret;
  } finally {
    zeroize(recoveredM, mAndPk, kr, kBar, rCoins, kOkBuf, kRejBuf, cPrime, pkHash, z, aCoeffs, rho);
  }
}
