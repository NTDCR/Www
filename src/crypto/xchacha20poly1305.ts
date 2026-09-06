/**
 * ContentGuard Pro MAX - Audited XChaCha20-Poly1305 Engine
 * Backed by @noble/ciphers (audited by Cure53, RFC 8439 compliant)
 * 100% Client-Side & Air-Gapped execution
 */

import { xchacha20poly1305, xchacha20, chacha20 } from '@noble/ciphers/chacha.js';

/**
 * ChaCha20 / XChaCha20 Stream cipher processor
 */
export function chacha20Process(
  key: Uint8Array,
  nonce12or24: Uint8Array,
  initialCounter: number = 0,
  input: Uint8Array,
  output?: Uint8Array
): Uint8Array {
  if (nonce12or24.length === 24) {
    return xchacha20(key, nonce12or24, input, output, initialCounter);
  }
  return chacha20(key, nonce12or24, input, output, initialCounter);
}

/**
 * Audited XChaCha20-Poly1305 AEAD Encryption
 */
export function xchacha20Poly1305Encrypt(
  plaintext: Uint8Array,
  key32: Uint8Array,
  nonce24: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const cipher = xchacha20poly1305(key32, nonce24, aad);
  const ctAndTag = cipher.encrypt(plaintext);
  try {
    // Noble returns ciphertext || 16-byte Poly1305 tag
    const tag = ctAndTag.slice(ctAndTag.length - 16);
    const ciphertext = ctAndTag.slice(0, ctAndTag.length - 16);
    return { ciphertext, tag };
  } finally {
    ctAndTag.fill(0);
  }
}

/**
 * Audited XChaCha20-Poly1305 AEAD Decryption
 */
export function xchacha20Poly1305Decrypt(
  ciphertext: Uint8Array,
  tag: Uint8Array,
  key32: Uint8Array,
  nonce24: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array | null {
  let combined: Uint8Array | null = null;
  try {
    const cipher = xchacha20poly1305(key32, nonce24, aad);
    combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);
    return cipher.decrypt(combined);
  } catch {
    return null;
  } finally {
    if (combined) combined.fill(0);
  }
}
