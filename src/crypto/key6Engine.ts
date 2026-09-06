/**
 * ContentGuard 1024-Bit Verifiable Unique Container Fingerprint & Identity Engine (Key 6)
 * 
 * Cryptographic Architecture:
 * 1. Dynamic CSPRNG Per-File Salt:
 *    - Whenever Key 6 is entered, a fresh 64-byte CSPRNG salt is bound per file/container session.
 *    - Even with the exact same Key 6, every file generates a completely distinct, fresh 1024-bit Unique ID.
 * 2. 1024-Bit ID Derivation:
 *    - Derived via PBKDF2-HMAC-SHA512 (iterations) + HKDF-SHA512 expansion to 128 bytes (1024 bits = 256 hex chars).
 * 3. Independent XOR One-Time Keystream Masking (Pure Garbage Form):
 *    - An independent 128-byte keystream mask is derived from Key 6 + Salt via HKDF-SHA512.
 *    - Raw 1024-bit ID is XOR-masked: `encryptedId = rawId ^ maskStream`.
 *    - Stored independently from the main 5-layer file payload as high-entropy uniform garbage (7.999+ bits/byte).
 * 4. Reed-Solomon RS(255, 223) Error Correction:
 *    - The K6 metadata block (salt, XOR-encrypted ID, commitment tag) is encoded with Reed-Solomon forward error correction.
 *    - Any burst damage or carrier corruption is auto-repaired prior to verification.
 * 5. Pre-Decryption Verification & Extraction:
 *    - When the container is loaded and Key 6 is entered, Reed-Solomon auto-repairs the block.
 *    - Key 6 unmasks the XOR stream and verifies the HMAC-SHA256 commitment tag in constant-time.
 *    - Correct Key 6 -> Displays the exact same 1024-bit Unique ID generated during creation.
 *    - Incorrect Key 6 -> Zero disclosure (fails constant-time check, 0 metadata leaked).
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { generateSecureRandomBytes } from './safeRandom';
import { constantTimeCompare, zeroizeBuffer, fastPbkdf2HmacSha512, DEFAULT_PBKDF2_ITERATIONS } from './cascadeEngine';
import { encodeRSStream, decodeRSStream } from './reedSolomon';

export interface Key6IdentityState {
  key6: string;
  uniqueId1024Hex: string;
  salt64: Uint8Array;
  verified: boolean;
  isGenerating: boolean;
}

export interface Key6ContainerBlock {
  salt64: Uint8Array;              // 64 bytes
  encryptedId128: Uint8Array;      // 128 bytes (XOR-masked 1024-bit ID)
  commitmentTag32: Uint8Array;     // 32 bytes (HMAC-SHA256 commitment)
  rsEncodedData: Uint8Array;       // Reed-Solomon protected stream
}

/**
 * Generates a fresh 64-byte CSPRNG salt for a new container/file protection session
 */
export function generateFreshKey6Salt(): Uint8Array {
  return generateSecureRandomBytes(64);
}

/**
 * Derives a 1024-bit (128 bytes = 256 hex chars) Unique ID from Key 6 and Salt,
 * and produces its XOR-masked garbage form + HMAC commitment tag.
 */
export async function deriveAndMask1024BitId(
  key6: string,
  salt64: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  vaultLabel: 'VaultA' | 'VaultB' = 'VaultA'
): Promise<{
  rawId128: Uint8Array;
  hexString: string;
  encryptedId128: Uint8Array;
  commitmentTag32: Uint8Array;
  rsBlock: Uint8Array;
}> {
  if (!key6 || key6 === '' || salt64.length < 64) {
    return {
      rawId128: new Uint8Array(0),
      hexString: '',
      encryptedId128: new Uint8Array(0),
      commitmentTag32: new Uint8Array(0),
      rsBlock: new Uint8Array(0)
    };
  }

  const enc = new TextEncoder();
  const keyBytes = enc.encode(key6);
  let stretched: Uint8Array | null = null;
  let rawId128: Uint8Array | null = null;
  let xorMask128: Uint8Array | null = null;
  let tagKey: Uint8Array | null = null;
  let unencodedBlock: Uint8Array | null = null;

  try {
    // 1. Hardware-accelerated PBKDF2-HMAC-SHA512 stretching (64 bytes)
    stretched = await fastPbkdf2HmacSha512(keyBytes, salt64, iterations, 64);

    // 2. HKDF-SHA512 expansion to raw 1024 bits (128 bytes)
    rawId128 = hkdf(
      sha512,
      stretched,
      salt64.subarray(0, 32),
      enc.encode(`ContentGuard-1024Bit-UniqueId-${vaultLabel}`),
      128 // 1024 bits = 128 bytes
    );

    // 3. Hex representation (256 hex characters)
    let hexString = '';
    for (let i = 0; i < rawId128.length; i++) {
      hexString += rawId128[i].toString(16).padStart(2, '0');
    }

    // 4. Derive independent 128-byte XOR keystream mask for Garbage Form
    xorMask128 = hkdf(
      sha512,
      stretched,
      salt64.subarray(32, 64),
      enc.encode(`ContentGuard-Key6-XOR-GarbageMask-${vaultLabel}`),
      128
    );

    // 5. Independent XOR encryption (turns 1024-bit ID into indistinguishable pseudo-random noise)
    const encryptedId128 = new Uint8Array(128);
    for (let i = 0; i < 128; i++) {
      encryptedId128[i] = rawId128[i] ^ xorMask128[i];
    }

    // 6. Derive 32-byte Verification Commitment Tag (HMAC-SHA256 of raw ID)
    tagKey = hkdf(
      sha256,
      stretched.subarray(0, 32),
      salt64.subarray(16, 48),
      enc.encode(`ContentGuard-Key6-CommitmentTag-${vaultLabel}`),
      32
    );
    const commitmentTag32 = hmac(sha256, tagKey, rawId128);

    // 7. Pack into raw 224-byte payload: [salt64 (64B) + encryptedId128 (128B) + commitmentTag32 (32B)]
    unencodedBlock = new Uint8Array(64 + 128 + 32);
    unencodedBlock.set(salt64, 0);
    unencodedBlock.set(encryptedId128, 64);
    unencodedBlock.set(commitmentTag32, 64 + 128);

    // 8. Apply NASA CCSDS / ISO Reed-Solomon RS(255, 223) Error Correction on the K6 block
    const { encodedData: rsBlock } = encodeRSStream(unencodedBlock);

    const result = {
      rawId128,
      hexString,
      encryptedId128,
      commitmentTag32,
      rsBlock
    };
    // Transfer ownership of returned ID so finally does not wipe the live result
    rawId128 = null;
    return result;
  } finally {
    // Zeroize sensitive keys and temporary buffers (rawId128 wiped on exception only)
    zeroizeBuffer(keyBytes, stretched, xorMask128, tagKey, unencodedBlock, rawId128);
  }
}

/**
 * Pre-Decryption Unmasking and Verification of Key 6 against a container's RS-protected K6 block:
 * 1. Decodes & repairs Reed-Solomon stream
 * 2. Unpacks salt, encrypted ID, and commitment tag
 * 3. Re-derives XOR mask with user's Key 6
 * 4. Recovers raw 1024-bit ID and verifies HMAC commitment in constant-time
 * 5. Returns exact 1024-bit Hex on match, or empty string on failure.
 */
export async function unmaskAndVerifyKey6FromRSBlock(
  key6: string,
  rsBlockData: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  vaultLabel: 'VaultA' | 'VaultB' = 'VaultA'
): Promise<{ valid: boolean; uniqueId1024Hex: string; repairedErrors: number }> {
  if (!key6 || key6 === '' || !rsBlockData || rsBlockData.length === 0) {
    return { valid: false, uniqueId1024Hex: '', repairedErrors: 0 };
  }

  let keyBytes: Uint8Array | null = null;
  let stretched: Uint8Array | null = null;
  let xorMask128: Uint8Array | null = null;
  let tagKey: Uint8Array | null = null;
  let recoveredRawId128: Uint8Array | null = null;
  let repairedBlock: Uint8Array | null = null;

  try {
    // 1. Reed-Solomon auto-repair
    const rsDecoded = decodeRSStream(rsBlockData);
    repairedBlock = rsDecoded.data;
    const recoveredErrors = rsDecoded.recoveredErrors;
    if (repairedBlock.length < 224) {
      return { valid: false, uniqueId1024Hex: '', repairedErrors: 0 };
    }

    const salt64 = repairedBlock.subarray(0, 64);
    const encryptedId128 = repairedBlock.subarray(64, 64 + 128);
    const expectedCommitmentTag32 = repairedBlock.subarray(64 + 128, 64 + 128 + 32);

    const enc = new TextEncoder();
    keyBytes = enc.encode(key6);

    // 2. Hardware-accelerated PBKDF2 stretching
    stretched = await fastPbkdf2HmacSha512(keyBytes, salt64, iterations, 64);

    // 3. Derive XOR keystream mask
    xorMask128 = hkdf(
      sha512,
      stretched,
      salt64.subarray(32, 64),
      enc.encode(`ContentGuard-Key6-XOR-GarbageMask-${vaultLabel}`),
      128
    );

    // 4. Unmask 1024-bit ID
    recoveredRawId128 = new Uint8Array(128);
    for (let i = 0; i < 128; i++) {
      recoveredRawId128[i] = encryptedId128[i] ^ xorMask128[i];
    }

    // 5. Derive Tag Key and recompute commitment tag
    tagKey = hkdf(
      sha256,
      stretched.subarray(0, 32),
      salt64.subarray(16, 48),
      enc.encode(`ContentGuard-Key6-CommitmentTag-${vaultLabel}`),
      32
    );
    const calculatedCommitmentTag = hmac(sha256, tagKey, recoveredRawId128);

    // 6. Constant-time comparison
    const matches = constantTimeCompare(calculatedCommitmentTag, expectedCommitmentTag32);

    if (matches) {
      let hexString = '';
      for (let i = 0; i < recoveredRawId128.length; i++) {
        hexString += recoveredRawId128[i].toString(16).padStart(2, '0');
      }
      return { valid: true, uniqueId1024Hex: hexString, repairedErrors: recoveredErrors };
    } else {
      // Zero-disclosure: empty ID, no syndrome/hamming/repair leak on failure
      return { valid: false, uniqueId1024Hex: '', repairedErrors: 0 };
    }
  } catch {
    return { valid: false, uniqueId1024Hex: '', repairedErrors: 0 };
  } finally {
    zeroizeBuffer(keyBytes, stretched, xorMask128, tagKey, recoveredRawId128, repairedBlock);
  }
}

/**
 * Formats a 256-hex character (1024-bit) string into human-readable 8-character chunks
 */
export function format1024BitIdFormatted(hex: string): string {
  if (!hex || hex.length !== 256) return hex;
  const blocks: string[] = [];
  for (let i = 0; i < 256; i += 8) {
    blocks.push(hex.substring(i, i + 8));
  }
  return blocks.join(' ');
}

/**
 * Generates a high-entropy default password for Key 6
 */
export function generateRandomKey6String(label: string = 'MasterKey6'): string {
  const bytes = generateSecureRandomBytes(16);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `KEY6-${label}-${hex.substring(0, 8).toUpperCase()}-${hex.substring(8, 16).toUpperCase()}-${hex.substring(16, 24).toUpperCase()}`;
}
