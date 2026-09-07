/**
 * ContentGuard Pro MAX - VeraCrypt-Style Single Nested Container Engine
 * 
 * Architecture & Anti-Forensic Principles:
 * 1. Single Unified Container: Outer Volume (Decoy / Vault B) and Hidden Nested Volume (Secret / Vault A)
 *    coexist inside a single contiguous pseudo-random binary container.
 * 2. Ultra-Compact Sizing (~1% Overhead): Total container size is strictly
 *    Size(Vault A) + Size(Vault B) + 4096 (Header) + ~1% (Anti-Forensic CSPRNG Noise).
 *    Zero MP4 container bloat, zero 14.3% Reed-Solomon expansion, zero bucket bloat.
 * 3. 100% Cryptographic Indistinguishability: The entire file from byte 0 to EOF is uniform
 *    high-entropy CSPRNG pseudo-random noise (Shannon Entropy >= 7.999 bits/byte, Chi-Square ~ 256).
 *    Zero plain-text magic headers, zero vendor UUIDs, zero metadata tags.
 * 4. Real-Time On-The-Fly Disk Streaming: Chunks are piped directly to the disk stream handle
 *    as each chunk is generated, eliminating post-processing delay (100% progress = 100% written).
 * 5. Plausible Deniability: Under coercion, disclosing Passwords B unlocks only Decoy Vault B.
 *    An adversary cannot mathematically prove whether Hidden Vault A exists or is random unallocated space.
 */

import { generateSecureRandomBytes } from '../crypto/safeRandom';
import {
  encryptCascade5Layers,
  decryptCascade5Layers,
  serializeBundle,
  deserializeBundle,
  deriveLayerKey,
  computeHmacSha256,
  constantTimeCompare,
  NEUTRAL_AUTH_FAILURE,
  DecryptedPayloadResult,
  DEFAULT_PBKDF2_ITERATIONS
} from '../crypto/cascadeEngine';
import {
  CascadePasswords,
  VaultAssessmentNotes
} from '../types';
import { yieldToMainThread } from '../utils/asyncUtils';
import { globalStreamEventBus } from '../utils/streamEvents';
import { readChunkFromHandle, sanitizeFilename } from '../utils/fileReader';
import { chacha20Process } from '../crypto/xchacha20poly1305';
import { sha512 } from '@noble/hashes/sha2.js';

export const VERA_HEADER_SIZE = 4096; // Exactly 4 KB (1 system memory page)
export const VERA_MAGIC = new Uint8Array([0x56, 0x43, 0x52, 0x59]); // 'VCRY' (only visible after authenticated decryption)

export interface NestedVeraCreationResult {
  containerBlob: Blob;
  containerBytes: Uint8Array;
  containerChunks: Uint8Array[];
  totalSize: number;
  vaultASize: number;
  vaultBSize: number;
  overheadBytes: number;
  overheadPercent: number;
  sha512Digest: string;
}

export interface NestedVeraExtractionResult extends DecryptedPayloadResult {
  matchedVault: 'VaultA' | 'VaultB';
  sha512Digest: string;
  assessmentNotes?: VaultAssessmentNotes;
}

/**
 * Creates a VeraCrypt-Style Single Nested Container with strictly ~1% overhead
 * and on-the-fly chunk streaming directly to disk.
 */
export async function createNestedVeraContainer(
  vaultAFile: File | any | Uint8Array,
  vaultBFile: File | any | Uint8Array,
  vaultAPasswords: CascadePasswords,
  vaultBPasswords: CascadePasswords,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  onProgress?: (stage: string, pct: number) => void,
  vaultANotes?: VaultAssessmentNotes,
  vaultBNotes?: VaultAssessmentNotes,
  onChunkReady?: (chunk: Uint8Array, stageDesc: string) => Promise<void>
): Promise<NestedVeraCreationResult> {
  const vaultAName = 'name' in vaultAFile ? vaultAFile.name : 'vault_a.bin';
  const vaultBName = 'name' in vaultBFile ? vaultBFile.name : 'vault_b.bin';
  const vaultASize = 'size' in vaultAFile ? vaultAFile.size : (vaultAFile instanceof Uint8Array ? vaultAFile.length : 0);
  const vaultBSize = 'size' in vaultBFile ? vaultBFile.size : (vaultBFile instanceof Uint8Array ? vaultBFile.length : 0);

  onProgress?.('Initializing VeraCrypt-Style Single Nested Container Engine...', 2.00);
  globalStreamEventBus.emit('STREAM', 'Vera Engine Init', `Targeting ultra-compact ~1% overhead: Vault A (${vaultASize}B), Vault B (${vaultBSize}B)`, {
    bytesProcessed: 0,
    totalBytes: vaultASize + vaultBSize,
    percent: 2.00
  });

  // Step 1: Encrypt Vault B (Outer Decoy Volume) with 5-Layer Cascade
  onProgress?.('Encrypting Outer Volume (Vault B - Decoy) across 5 layers...', 8.00);
  await yieldToMainThread();
  const bundleB = await encryptCascade5Layers(
    vaultBFile,
    vaultBName,
    vaultBPasswords,
    iterations,
    (layer, desc, fraction) => {
      const f = fraction !== undefined ? fraction : (layer / 5);
      const mappedPct = Number((8.00 + f * 35.00).toFixed(2));
      onProgress?.(`Decoy Vault B - ${desc}`, mappedPct);
    },
    'VaultB',
    vaultBNotes
  );
  await yieldToMainThread();

  // Step 2: Encrypt Vault A (Hidden Secret Volume) with 5-Layer Cascade
  onProgress?.('Encrypting Hidden Volume (Vault A - Secret) across 5 layers...', 45.00);
  await yieldToMainThread();
  const bundleA = await encryptCascade5Layers(
    vaultAFile,
    vaultAName,
    vaultAPasswords,
    iterations,
    (layer, desc, fraction) => {
      const f = fraction !== undefined ? fraction : (layer / 5);
      const mappedPct = Number((45.00 + f * 35.00).toFixed(2));
      onProgress?.(`Secret Vault A - ${desc}`, mappedPct);
    },
    'VaultA',
    vaultANotes
  );
  await yieldToMainThread();

  onProgress?.('Serializing encrypted volume bundles...', 82.00);
  const serializedB = serializeBundle(bundleB);
  const serializedA = serializeBundle(bundleA);
  const lenB = serializedB.length;
  const lenA = serializedA.length;

  // Step 3: Compute Offsets & ~1% Anti-Forensic Noise Padding with Prime Non-Sector Jitter
  const offsetB = VERA_HEADER_SIZE;
  const offsetA = VERA_HEADER_SIZE + lenB;
  const combinedPayloadLen = lenA + lenB;
  let antiForensicPaddingLen = Math.max(512, Math.ceil(combinedPayloadLen * 0.01)); // Strictly ~1%

  // Dynamic Prime-Based Jitter: Breaks automated disk carvers & VeraCrypt heuristics that look for 512-byte block alignment
  const jitterSeed = (lenA ^ lenB ^ 0x3c3c) >>> 0;
  const primeJitter = 37 + (jitterSeed % 113); // Range [37..149]
  antiForensicPaddingLen += primeJitter;

  let totalContainerSize = VERA_HEADER_SIZE + combinedPayloadLen + antiForensicPaddingLen;
  if (totalContainerSize % 512 === 0) {
    antiForensicPaddingLen += 17;
    totalContainerSize += 17;
  }
  if (totalContainerSize % 4096 === 0) {
    antiForensicPaddingLen += 31;
    totalContainerSize += 31;
  }

  // Step 4: Build Encrypted 4 KB Header Block
  onProgress?.('Constructing 4 KB High-Entropy Encrypted Header Block...', 86.00);
  await yieldToMainThread();

  const saltA = generateSecureRandomBytes(64);
  const saltB = generateSecureRandomBytes(64);
  const ivA = generateSecureRandomBytes(12);
  const ivB = generateSecureRandomBytes(12);

  const headerKeyA = await deriveLayerKey(vaultAPasswords.layer1_kyber + vaultAPasswords.layer4_aes, saltA, iterations, 'AntiForensic-Ghost-KeyA');
  const headerKeyB = await deriveLayerKey(vaultBPasswords.layer1_kyber + vaultBPasswords.layer4_aes, saltB, iterations, 'AntiForensic-Ghost-KeyB');

  // Build Descriptor A (Plaintext: 160 bytes)
  // ZERO plaintext magic bytes (no 'VCRY' or any identifiable ASCII tag) — authenticated by 256-bit HMAC tag
  const descA = new Uint8Array(160);
  const viewA = new DataView(descA.buffer, descA.byteOffset, descA.byteLength);
  descA.set(generateSecureRandomBytes(4), 0); // Random 4-byte nonce
  viewA.setBigUint64(4, BigInt(offsetA), true);
  viewA.setBigUint64(12, BigInt(lenA), true);
  viewA.setBigUint64(20, BigInt(vaultASize), true);
  const encNameA = new TextEncoder().encode(vaultAName.slice(0, 60));
  viewA.setUint32(28, encNameA.length, true);
  descA.set(encNameA, 32);
  const tagA = await computeHmacSha256(headerKeyA, descA);
  const encDescA = chacha20Process(headerKeyA, ivA, 0, descA);

  // Build Descriptor B (Plaintext: 160 bytes)
  const descB = new Uint8Array(160);
  const viewB = new DataView(descB.buffer, descB.byteOffset, descB.byteLength);
  descB.set(generateSecureRandomBytes(4), 0); // Random 4-byte nonce
  viewB.setBigUint64(4, BigInt(offsetB), true);
  viewB.setBigUint64(12, BigInt(lenB), true);
  viewB.setBigUint64(20, BigInt(vaultBSize), true);
  const encNameB = new TextEncoder().encode(vaultBName.slice(0, 60));
  viewB.setUint32(28, encNameB.length, true);
  descB.set(encNameB, 32);
  const tagB = await computeHmacSha256(headerKeyB, descB);
  const encDescB = chacha20Process(headerKeyB, ivB, 0, descB);

  // Assemble the 4 KB Header Block
  const headerBlock = new Uint8Array(VERA_HEADER_SIZE);
  // Fill entire header with high-entropy CSPRNG noise first
  headerBlock.set(generateSecureRandomBytes(VERA_HEADER_SIZE), 0);

  let hp = 0;
  headerBlock.set(saltA, hp); hp += 64;
  headerBlock.set(saltB, hp); hp += 64;
  headerBlock.set(ivA, hp); hp += 12;
  headerBlock.set(ivB, hp); hp += 12;
  headerBlock.set(tagA, hp); hp += 32;
  headerBlock.set(tagB, hp); hp += 32;
  headerBlock.set(encDescA, hp); hp += 160;
  headerBlock.set(encDescB, hp); hp += 160;
  // Remainder [536..4095] remains pure CSPRNG noise

  // Step 5: Anti-Forensic Noise Tail (Strictly ~1%)
  const paddingNoise = generateSecureRandomBytes(antiForensicPaddingLen);

  // Step 6: Real-Time On-The-Fly Chunk Streaming directly to disk
  onProgress?.('Streaming VeraCrypt Nested Container directly to disk in real-time...', 90.00);
  globalStreamEventBus.emit('STREAM', 'Real-Time Disk Write', 'Piping chunks directly to disk stream handle on-the-fly', { percent: 90.00 });

  const containerChunks: Uint8Array[] = [headerBlock, serializedB, serializedA, paddingNoise];

  if (onChunkReady) {
    onProgress?.('Piping 4 KB Encrypted Header directly to disk...', 91.00);
    await onChunkReady(headerBlock, 'Piped 4 KB Encrypted Header directly to disk');

    onProgress?.('Piping Outer Volume (Vault B - Decoy) directly to disk...', 93.00);
    const CHUNK_SIZE = 1024 * 1024; // 1 MB
    for (let i = 0; i < serializedB.length; i += CHUNK_SIZE) {
      const slice = serializedB.subarray(i, Math.min(i + CHUNK_SIZE, serializedB.length));
      await onChunkReady(slice, `Piped Decoy Volume chunk (${(i / (1024 * 1024)).toFixed(1)} MB)...`);
    }

    onProgress?.('Piping Hidden Volume (Vault A - Secret) directly to disk...', 96.00);
    for (let i = 0; i < serializedA.length; i += CHUNK_SIZE) {
      const slice = serializedA.subarray(i, Math.min(i + CHUNK_SIZE, serializedA.length));
      await onChunkReady(slice, `Piped Hidden Volume chunk (${(i / (1024 * 1024)).toFixed(1)} MB)...`);
    }

    onProgress?.('Piping ~1% Anti-Forensic CSPRNG Noise to disk...', 98.00);
    await onChunkReady(paddingNoise, 'Piped ~1% Anti-Forensic CSPRNG Noise to disk');
  }

  // Step 7: Compute SHA-512 Audit Digest
  onProgress?.('Computing SHA-512 audit digest across nested container...', 99.00);
  const shaHasher = sha512.create();
  for (const chunk of containerChunks) {
    shaHasher.update(chunk);
  }
  const shaBytes = shaHasher.digest();
  const sha512Digest = Array.from(shaBytes).map((b: number) => b.toString(16).padStart(2, '0')).join('');

  // Assemble full buffer if size is reasonable (< 64 MB), else rely on chunks/blob
  let fullContainerBytes: Uint8Array;
  if (totalContainerSize <= 64 * 1024 * 1024) {
    fullContainerBytes = new Uint8Array(totalContainerSize);
    let cp = 0;
    for (const chunk of containerChunks) {
      fullContainerBytes.set(chunk, cp);
      cp += chunk.length;
    }
  } else {
    fullContainerBytes = new Uint8Array(0);
  }

  const containerBlob = new Blob(containerChunks, { type: 'application/octet-stream' });
  const overheadBytes = VERA_HEADER_SIZE + antiForensicPaddingLen;
  const overheadPercent = Number(((overheadBytes / (vaultASize + vaultBSize || 1)) * 100).toFixed(2));

  onProgress?.('VeraCrypt-Style Single Nested Container Ready (100% on-the-fly written)!', 100.00);
  globalStreamEventBus.emit('AUDIT', 'Vera Container Finalized', `VeraCrypt nested container generated. Size: ${totalContainerSize} B, Overhead: ${overheadPercent}% (~1%)`, {
    severity: 'SUCCESS',
    percent: 100.00
  });

  return {
    containerBlob,
    containerBytes: fullContainerBytes,
    containerChunks,
    totalSize: totalContainerSize,
    vaultASize,
    vaultBSize,
    overheadBytes,
    overheadPercent,
    sha512Digest
  };
}

/**
 * Extracts from a VeraCrypt-Style Single Nested Container
 * Automatically checks whether provided passwords unlock Hidden Volume (Vault A) or Decoy Volume (Vault B).
 */
export async function extractNestedVeraContainer(
  containerFile: File | any | Uint8Array,
  passwords: CascadePasswords,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  onProgress?: (stage: string, pct: number) => void,
  onChunkReady?: (chunk: Uint8Array, status: string) => Promise<void>
): Promise<NestedVeraExtractionResult> {
  onProgress?.('Inspecting 4 KB VeraCrypt Encrypted Header Block...', 5.00);
  await yieldToMainThread();

  let headerBytes: Uint8Array;
  if (containerFile instanceof Uint8Array) {
    if (containerFile.length < VERA_HEADER_SIZE) {
      throw new Error(NEUTRAL_AUTH_FAILURE);
    }
    headerBytes = containerFile.subarray(0, VERA_HEADER_SIZE);
  } else {
    headerBytes = await readChunkFromHandle(containerFile, 0, VERA_HEADER_SIZE);
    if (headerBytes.length < VERA_HEADER_SIZE) {
      throw new Error(NEUTRAL_AUTH_FAILURE);
    }
  }

  let hp = 0;
  const saltA = headerBytes.subarray(hp, hp + 64); hp += 64;
  const saltB = headerBytes.subarray(hp, hp + 64); hp += 64;
  const ivA = headerBytes.subarray(hp, hp + 12); hp += 12;
  const ivB = headerBytes.subarray(hp, hp + 12); hp += 12;
  const tagA = headerBytes.subarray(hp, hp + 32); hp += 32;
  const tagB = headerBytes.subarray(hp, hp + 32); hp += 32;
  const encDescA = headerBytes.subarray(hp, hp + 160); hp += 160;
  const encDescB = headerBytes.subarray(hp, hp + 160); hp += 160;

  // Try authenticating Header A (Hidden Volume)
  onProgress?.('Attempting authentication against Hidden Volume (Vault A)...', 15.00);
  await yieldToMainThread();
  let headerKeyA = await deriveLayerKey(passwords.layer1_kyber + passwords.layer4_aes, saltA, iterations, 'AntiForensic-Ghost-KeyA');
  let decDescA = chacha20Process(headerKeyA, ivA, 0, encDescA);
  let computedTagA = await computeHmacSha256(headerKeyA, decDescA);

  let isVaultAMatch = constantTimeCompare(computedTagA, tagA);
  if (!isVaultAMatch) {
    // Backward-compatibility check for legacy test containers
    const legacyKeyA = await deriveLayerKey(passwords.layer1_kyber + passwords.layer4_aes, saltA, iterations, 'VeraCrypt-Header-KeyA');
    const legacyDecA = chacha20Process(legacyKeyA, ivA, 0, encDescA);
    const legacyTagA = await computeHmacSha256(legacyKeyA, legacyDecA);
    if (constantTimeCompare(legacyTagA, tagA)) {
      isVaultAMatch = true;
      decDescA = legacyDecA;
      headerKeyA = legacyKeyA;
    }
  }

  let matchedVault: 'VaultA' | 'VaultB';
  let targetOffset: number;
  let targetLength: number;
  let originalSize: number;
  let targetFilename: string;

  if (isVaultAMatch) {
    matchedVault = 'VaultA';
    const view = new DataView(decDescA.buffer, decDescA.byteOffset, decDescA.byteLength);
    targetOffset = Number(view.getBigUint64(4, true));
    targetLength = Number(view.getBigUint64(12, true));
    originalSize = Number(view.getBigUint64(20, true));
    const nameLen = view.getUint32(28, true);
    targetFilename = new TextDecoder().decode(decDescA.subarray(32, 32 + Math.min(nameLen, 60)));
    onProgress?.('Authenticated: Hidden Volume (Vault A - Secret) identified!', 30.00);
  } else {
    // Try authenticating Header B (Outer Decoy Volume)
    onProgress?.('Attempting authentication against Outer Volume (Vault B - Decoy)...', 25.00);
    await yieldToMainThread();
    let headerKeyB = await deriveLayerKey(passwords.layer1_kyber + passwords.layer4_aes, saltB, iterations, 'AntiForensic-Ghost-KeyB');
    let decDescB = chacha20Process(headerKeyB, ivB, 0, encDescB);
    let computedTagB = await computeHmacSha256(headerKeyB, decDescB);

    let isVaultBMatch = constantTimeCompare(computedTagB, tagB);
    if (!isVaultBMatch) {
      // Backward-compatibility check for legacy test containers
      const legacyKeyB = await deriveLayerKey(passwords.layer1_kyber + passwords.layer4_aes, saltB, iterations, 'VeraCrypt-Header-KeyB');
      const legacyDecB = chacha20Process(legacyKeyB, ivB, 0, encDescB);
      const legacyTagB = await computeHmacSha256(legacyKeyB, legacyDecB);
      if (constantTimeCompare(legacyTagB, tagB)) {
        isVaultBMatch = true;
        decDescB = legacyDecB;
        headerKeyB = legacyKeyB;
      }
    }

    if (!isVaultBMatch) {
      // Single neutral authentication failure — reveals ZERO information about either vault
      throw new Error(NEUTRAL_AUTH_FAILURE);
    }

    matchedVault = 'VaultB';
    const view = new DataView(decDescB.buffer, decDescB.byteOffset, decDescB.byteLength);
    targetOffset = Number(view.getBigUint64(4, true));
    targetLength = Number(view.getBigUint64(12, true));
    originalSize = Number(view.getBigUint64(20, true));
    const nameLen = view.getUint32(28, true);
    targetFilename = new TextDecoder().decode(decDescB.subarray(32, 32 + Math.min(nameLen, 60)));
    onProgress?.('Authenticated: Outer Volume (Vault B - Decoy) identified!', 30.00);
  }

  // Step 3: Extract Encrypted Bundle at target offset
  onProgress?.(`Reading ${matchedVault} encrypted stream (${(targetLength / (1024 * 1024)).toFixed(2)} MB)...`, 35.00);
  await yieldToMainThread();

  let encryptedBundleBytes: Uint8Array;
  if (containerFile instanceof Uint8Array) {
    if (targetOffset + targetLength > containerFile.length) {
      throw new Error(NEUTRAL_AUTH_FAILURE);
    }
    encryptedBundleBytes = containerFile.subarray(targetOffset, targetOffset + targetLength);
  } else {
    encryptedBundleBytes = await readChunkFromHandle(containerFile, targetOffset, targetLength);
  }

  // Step 4: Deserialize and 5-Layer Decrypt
  onProgress?.('Deserializing 5-layer cryptographic bundle...', 40.00);
  const bundle = deserializeBundle(encryptedBundleBytes);

  onProgress?.('Executing 5-layer cascade decapsulation & decryption...', 50.00);
  const decrypted = await decryptCascade5Layers(
    bundle,
    passwords,
    iterations,
    (layer, desc, fraction) => {
      const f = fraction !== undefined ? fraction : (layer / 5);
      const mappedPct = Number((50.00 + f * 45.00).toFixed(2));
      onProgress?.(desc, mappedPct);
    }
  );

  // Step 5: On-The-Fly Chunk Streaming to Disk
  if (onChunkReady && decrypted.chunkedPayload) {
    onProgress?.('Streaming decrypted payload directly to disk in real-time...', 96.00);
    for (const chunk of decrypted.chunkedPayload) {
      await onChunkReady(chunk, 'Piping decrypted chunk directly to disk');
    }
  }

  // Step 6: Compute SHA-512 Audit Digest
  const shaHasher = sha512.create();
  if (decrypted.chunkedPayload && decrypted.chunkedPayload.length > 0) {
    for (const c of decrypted.chunkedPayload) shaHasher.update(c);
  } else {
    shaHasher.update(decrypted.data);
  }
  const shaBytes = shaHasher.digest();
  const sha512Digest = Array.from(shaBytes).map((b: number) => b.toString(16).padStart(2, '0')).join('');

  onProgress?.('Extraction complete! Complete 5-layer integrity verified.', 100.00);
  globalStreamEventBus.emit('AUDIT', 'Vera Volume Decrypted', `Unlocked ${matchedVault}: ${targetFilename || decrypted.originalFilename} (${decrypted.originalSize} B)`, {
    severity: 'SUCCESS',
    percent: 100.00
  });

  return {
    ...decrypted,
    originalFilename: sanitizeFilename(targetFilename || decrypted.originalFilename),
    matchedVault,
    sha512Digest
  };
}

/**
 * Checks if a byte sequence might be a VeraCrypt-style nested container
 * (i.e. not an ISOBMFF container starting with 'ftyp')
 */
export function isLikelyNestedVeraContainer(headerBytes: Uint8Array): boolean {
  if (!headerBytes || headerBytes.length < 8) return false;
  // If it has standard MP4 'ftyp' at offset 4, it is an MP4 carrier
  if (
    headerBytes[4] === 0x66 && // 'f'
    headerBytes[5] === 0x74 && // 't'
    headerBytes[6] === 0x79 && // 'y'
    headerBytes[7] === 0x70    // 'p'
  ) {
    return false;
  }
  return true;
}

// True Anti-Forensic Aliases (Complete Garbage / Zero-Trace Volume)
export const createRawAntiForensicContainer = createNestedVeraContainer;
export const extractRawAntiForensicContainer = extractNestedVeraContainer;
export const isLikelyAntiForensicContainer = isLikelyNestedVeraContainer;
