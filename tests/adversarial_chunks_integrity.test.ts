/**
 * ContentGuard Pro MAX - Deep Adversarial Chunks & Integrity Test Suite
 * Exhaustive adversarial testing for:
 *  1. Chunk Reordering & Permutation (Transposition attacks)
 *  2. Chunk Truncation & Drop (Partial/tail/head chunk loss)
 *  3. Chunk Bit-Flipping Matrix (Single-bit corruption across header, middle, tail chunks)
 *  4. Cross-Boundary Chunk Slicing (Arbitrary offset spanning across chunk boundaries)
 *  5. Rogue Chunk Injection & Replay (Duplicate chunks, zero-chunk injection)
 *  6. Incremental vs Monolithic Chunk Hashing Parity
 *  7. Streaming Forward Progress & Deadlock Circuit Breaker
 */

import {
  encryptCascade5Layers,
  decryptCascade5Layers,
  serializeBundle,
  deserializeBundle,
  constantTimeCompare,
  computeFullPayloadSha256Async
} from '../src/crypto/cascadeEngine';
import {
  createStreamingFileHandle,
  readChunkFromHandle,
  streamFileIn1MbChunks,
  STRICT_CHUNK_SIZE
} from '../src/utils/fileReader';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';

interface TestResult {
  id: string;
  name: string;
  passed: boolean;
  timeMs: number;
  details?: string;
}

const results: TestResult[] = [];

async function runChunkTest(id: string, name: string, fn: () => Promise<void>) {
  const t0 = performance.now();
  try {
    await fn();
    const dt = performance.now() - t0;
    results.push({ id, name, passed: true, timeMs: Number(dt.toFixed(2)) });
    console.log(`[PASS] ${id}: ${name} (${dt.toFixed(2)} ms)`);
  } catch (err: any) {
    const dt = performance.now() - t0;
    results.push({ id, name, passed: false, timeMs: Number(dt.toFixed(2)), details: err?.message });
    console.error(`[FAIL] ${id}: ${name} (${dt.toFixed(2)} ms) -> ${err?.message}`);
  }
}

const defaultPw = {
  layer1_kyber: 'chkPass1', layer2_serpent: 'chkPass2', layer3_xchacha: 'chkPass3',
  layer4_aes: 'chkPass4', layer5_otp: 'chkPass5'
};

export async function runChunksIntegrityAdversarialSuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX — ADVERSARIAL CHUNKS & INTEGRITY SUITE');
  console.log('========================================================================\n');

  // ===========================================================================
  // SECTION 1: CHUNK REORDERING & PERMUTATION ATTACKS
  // ===========================================================================
  console.log('--- SECTION 1: CHUNK REORDERING & PERMUTATION ATTACKS ---');

  await runChunkTest('CHUNK-ADV-01', 'Chunk Swapping / Transposition Attack Detection', async () => {
    // Create a 2.5 MB payload (Chunk 0 = 1MB, Chunk 1 = 1MB, Chunk 2 = 0.5MB)
    const testData = generateSecureRandomBytes(2500 * 1024);
    const bundle = await encryptCascade5Layers(testData, 'test_reorder.bin', defaultPw, 1000);
    const serialized = serializeBundle(bundle);

    // Header length is stored in first 4 bytes
    const metaLen = new DataView(serialized.buffer, serialized.byteOffset, 4).getUint32(0, true);
    const payloadStart = metaLen;

    // Swap Chunk 0 (1 MB) and Chunk 1 (1 MB) in the serialized payload
    const tampered = new Uint8Array(serialized);
    const c0 = tampered.slice(payloadStart, payloadStart + STRICT_CHUNK_SIZE);
    const c1 = tampered.slice(payloadStart + STRICT_CHUNK_SIZE, payloadStart + 2 * STRICT_CHUNK_SIZE);

    tampered.set(c1, payloadStart);
    tampered.set(c0, payloadStart + STRICT_CHUNK_SIZE);

    // Verify HMAC-SHA256 catches chunk transposition
    let caught = false;
    try {
      const badBundle = deserializeBundle(tampered);
      await decryptCascade5Layers(badBundle, defaultPw, 1000);
    } catch (err: any) {
      caught = true;
      if (!err.message.includes('Authentication Failed') && !err.message.includes('mismatch')) {
        throw new Error(`Unexpected error on chunk swap: ${err.message}`);
      }
    }

    if (!caught) {
      throw new Error('CRITICAL: Chunk transposition attack was not detected by integrity verifier!');
    }
  });

  await runChunkTest('CHUNK-ADV-02', 'Direct Chunk Decryption Detects Offset Mismatch & Missing Magic', async () => {
    // Encrypt 2 distinct chunks
    const testData = generateSecureRandomBytes(2 * 1024 * 1024);
    const bundle = await encryptCascade5Layers(testData, 'direct_offset.bin', defaultPw, 1000);

    const chunk0 = bundle.chunkedPayload![0];
    const chunk1 = bundle.chunkedPayload![1];

    // If Chunk 1 is swapped into offset 0 and decrypted with offset 0:
    // It will decrypt to garbage because AES/ChaCha/Serpent keystreams are offset-dependent.
    // When decrypted at wrong offset, the inner header magic 'CGV1' will be corrupted.
    const badDecrypted = deserializeBundle(serializeBundle({
      ...bundle,
      payload: new Uint8Array(0),
      chunkedPayload: [chunk1, chunk0] // Swapped
    }));

    let caught = false;
    try {
      await decryptCascade5Layers(badDecrypted, defaultPw, 1000);
    } catch {
      caught = true;
    }

    if (!caught) {
      throw new Error('Offset-dependent keystream failed to invalidate swapped chunk!');
    }
  });

  // ===========================================================================
  // SECTION 2: CHUNK TRUNCATION & DROP ATTACKS
  // ===========================================================================
  console.log('\n--- SECTION 2: CHUNK TRUNCATION & DROP ATTACKS ---');

  await runChunkTest('CHUNK-ADV-03', 'Tail Chunk Drop Attack Detection', async () => {
    const testData = generateSecureRandomBytes(2500 * 1024);
    const bundle = await encryptCascade5Layers(testData, 'tail_drop.bin', defaultPw, 1000);
    const serialized = serializeBundle(bundle);

    // Drop last 500 KB chunk completely
    const truncated = serialized.subarray(0, serialized.length - (500 * 1024));

    let caught = false;
    try {
      const badBundle = deserializeBundle(truncated);
      await decryptCascade5Layers(badBundle, defaultPw, 1000);
    } catch {
      caught = true;
    }

    if (!caught) {
      throw new Error('CRITICAL: Tail chunk truncation was silently accepted!');
    }
  });

  await runChunkTest('CHUNK-ADV-04', 'Zero-Byte Payload & Odd-Size Chunk Slicing Boundaries', async () => {
    // Odd byte sizes: 1, 15, 16, 63, 64, 1023, 1048575, 1048577
    const oddSizes = [1, 15, 16, 63, 64, 1023, 1048575, 1048577];
    for (const sz of oddSizes) {
      const data = generateSecureRandomBytes(sz);
      const name = `odd_${sz}.bin`;
      const bundle = await encryptCascade5Layers(data, name, defaultPw, 1000);
      const serialized = serializeBundle(bundle);
      const deserialized = deserializeBundle(serialized);
      const decrypted = await decryptCascade5Layers(deserialized, defaultPw, 1000);

      if (!constantTimeCompare(data, decrypted.data)) {
        throw new Error(`Chunked integrity mismatch on odd size ${sz} bytes!`);
      }
      if (decrypted.originalFilename !== name) {
        throw new Error(`Filename corrupted on size ${sz}`);
      }
    }
  });

  // ===========================================================================
  // SECTION 3: CHUNK BIT-FLIPPING MATRIX
  // ===========================================================================
  console.log('\n--- SECTION 3: CHUNK BIT-FLIPPING MATRIX ---');

  await runChunkTest('CHUNK-ADV-05', 'Single-Bit Corruption across Every Chunk Position', async () => {
    const testData = generateSecureRandomBytes(3 * 1024 * 1024);
    const bundle = await encryptCascade5Layers(testData, 'flip_matrix.bin', defaultPw, 1000);
    const serialized = serializeBundle(bundle);

    const metaLen = new DataView(serialized.buffer, serialized.byteOffset, 4).getUint32(0, true);
    const payloadStart = metaLen;

    // Test flip positions:
    // 1. In Chunk 0 (byte 100)
    // 2. In Chunk 1 (byte 1,048,576 + 500)
    // 3. In Chunk 2 (byte 2,097,152 + 500)
    const flipOffsets = [
      payloadStart + 100,
      payloadStart + STRICT_CHUNK_SIZE + 500,
      payloadStart + (2 * STRICT_CHUNK_SIZE) + 500
    ];

    for (const offset of flipOffsets) {
      const tampered = new Uint8Array(serialized);
      tampered[offset] ^= 0x01; // flip lowest bit

      let caught = false;
      try {
        const badBundle = deserializeBundle(tampered);
        await decryptCascade5Layers(badBundle, defaultPw, 1000);
      } catch {
        caught = true;
      }

      if (!caught) {
        throw new Error(`Single-bit corruption at byte offset ${offset} was NOT caught by HMAC integrity!`);
      }
    }
  });

  // ===========================================================================
  // SECTION 4: CROSS-BOUNDARY SLICE READER STRESS (`readChunkFromHandle`)
  // ===========================================================================
  console.log('\n--- SECTION 4: CROSS-BOUNDARY SLICE READER STRESS ---');

  await runChunkTest('CHUNK-ADV-06', 'Cross-Boundary Multi-Chunk Slice Assembly Precision', async () => {
    // 3 MB random buffer
    const flatBytes = generateSecureRandomBytes(3 * 1024 * 1024);
    const handle = createStreamingFileHandle(flatBytes, 'cross_boundary.bin');

    // 1. Slice starting near end of Chunk 0 and spanning into Chunk 1
    const offset1 = STRICT_CHUNK_SIZE - 50; // 50 bytes in Chunk 0, 150 bytes in Chunk 1
    const size1 = 200;
    const slice1 = await readChunkFromHandle(handle, offset1, size1);
    const expected1 = flatBytes.subarray(offset1, offset1 + size1);
    if (!constantTimeCompare(slice1, expected1)) {
      throw new Error('readChunkFromHandle failed 2-chunk boundary crossing slice assembly!');
    }

    // 2. Giant slice spanning across all 3 chunks (Chunk 0, Chunk 1, Chunk 2)
    const offset2 = 500000;
    const size2 = 2 * 1024 * 1024; // 2 MB spanning across boundaries
    const slice2 = await readChunkFromHandle(handle, offset2, size2);
    const expected2 = flatBytes.subarray(offset2, offset2 + size2);
    if (!constantTimeCompare(slice2, expected2)) {
      throw new Error('readChunkFromHandle failed 3-chunk multi-boundary slice assembly!');
    }

    // 3. Slice right at the exact boundary
    const offset3 = STRICT_CHUNK_SIZE;
    const size3 = 100;
    const slice3 = await readChunkFromHandle(handle, offset3, size3);
    const expected3 = flatBytes.subarray(offset3, offset3 + size3);
    if (!constantTimeCompare(slice3, expected3)) {
      throw new Error('readChunkFromHandle failed exact boundary slice!');
    }
  });

  await runChunkTest('CHUNK-ADV-07', 'Pathological Slice Reader Boundaries (Negative & Overflow)', async () => {
    const flatBytes = generateSecureRandomBytes(1000);
    const handle = createStreamingFileHandle(flatBytes, 'pathological.bin');

    // Negative offset
    const negSlice = await readChunkFromHandle(handle, -10, 100);
    if (negSlice.length !== 0) throw new Error('Negative offset did not return empty array');

    // Non-positive chunkSize
    const zeroChunk = await readChunkFromHandle(handle, 10, 0);
    if (zeroChunk.length !== 0) throw new Error('Zero chunkSize did not return empty array');

    const negChunk = await readChunkFromHandle(handle, 10, -50);
    if (negChunk.length !== 0) throw new Error('Negative chunkSize did not return empty array');

    // Offset beyond EOF
    const eofSlice = await readChunkFromHandle(handle, 2000, 100);
    if (eofSlice.length !== 0) throw new Error('Offset beyond EOF did not return empty array');

    // Slicing past EOF must return only available bytes without padding
    const tailSlice = await readChunkFromHandle(handle, 950, 100);
    if (tailSlice.length !== 50) {
      throw new Error(`Expected 50 remaining bytes, got ${tailSlice.length}`);
    }
    const expectedTail = flatBytes.subarray(950, 1000);
    if (!constantTimeCompare(tailSlice, expectedTail)) {
      throw new Error('Tail slice bytes mismatch');
    }
  });

  // ===========================================================================
  // SECTION 5: CHUNK INJECTION & REPLAY ATTACKS
  // ===========================================================================
  console.log('\n--- SECTION 5: CHUNK INJECTION & REPLAY ATTACKS ---');

  await runChunkTest('CHUNK-ADV-08', 'Rogue Chunk Injection & Chunk Duplication Defense', async () => {
    const testData = generateSecureRandomBytes(2 * 1024 * 1024);
    const bundle = await encryptCascade5Layers(testData, 'injection.bin', defaultPw, 1000);
    const serialized = serializeBundle(bundle);

    const metaLen = new DataView(serialized.buffer, serialized.byteOffset, 4).getUint32(0, true);

    // Inject 1 MB of zeros between Chunk 0 and Chunk 1
    const injected = new Uint8Array(serialized.length + STRICT_CHUNK_SIZE);
    const p1 = metaLen + STRICT_CHUNK_SIZE;
    injected.set(serialized.subarray(0, p1), 0);
    injected.fill(0x00, p1, p1 + STRICT_CHUNK_SIZE);
    injected.set(serialized.subarray(p1), p1 + STRICT_CHUNK_SIZE);

    let caught = false;
    try {
      const badBundle = deserializeBundle(injected);
      await decryptCascade5Layers(badBundle, defaultPw, 1000);
    } catch {
      caught = true;
    }

    if (!caught) {
      throw new Error('CRITICAL: 1 MB rogue chunk injection was not detected!');
    }
  });

  // ===========================================================================
  // SECTION 6: INCREMENTAL VS MONOLITHIC CHUNK HASHING PARITY
  // ===========================================================================
  console.log('\n--- SECTION 6: INCREMENTAL VS MONOLITHIC CHUNK HASHING PARITY ---');

  await runChunkTest('CHUNK-ADV-09', 'Streaming Chunked SHA-256 Parity with Monolithic Digest', async () => {
    // Test uneven 2.37 MB payload
    const data = generateSecureRandomBytes(2370 * 1024);

    const asyncDigest = await computeFullPayloadSha256Async(data);

    // Compute standard monolithic digest via WebCrypto
    let monoDigest: Uint8Array;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const buf = await crypto.subtle.digest('SHA-256', data);
      monoDigest = new Uint8Array(buf);
    } else {
      const { sha256 } = await import('@noble/hashes/sha2.js');
      monoDigest = sha256(data);
    }

    if (!constantTimeCompare(asyncDigest, monoDigest)) {
      throw new Error('Chunked streaming SHA-256 diverged from monolithic SHA-256 digest!');
    }
  });

  // ===========================================================================
  // SECTION 7: STREAMING FORWARD PROGRESS & DEADLOCK CIRCUIT BREAKER
  // ===========================================================================
  console.log('\n--- SECTION 7: STREAMING FORWARD PROGRESS & DEADLOCK BREAKER ---');

  await runChunkTest('CHUNK-ADV-10', 'Stream Generator Deadlock Circuit Breaker on Stalled Chunks', async () => {
    // Broken source: size says 5MB, but slice always returns empty buffer
    const deadSource = {
      name: 'broken.bin',
      size: 5 * 1024 * 1024,
      slice: () => new Blob([]),
      arrayBuffer: async () => new ArrayBuffer(0)
    };

    let abortedWithError = false;
    const t0 = performance.now();
    try {
      for await (const _chunk of streamFileIn1MbChunks(deadSource as any)) {
        // Should never produce chunks
      }
    } catch (err: any) {
      abortedWithError = true;
      if (!err.message.includes('streaming halted') && !err.message.includes('Unable to read')) {
        throw new Error(`Unexpected deadlock message: ${err.message}`);
      }
    }
    const elapsed = performance.now() - t0;

    if (!abortedWithError) {
      throw new Error('Streaming generator did not abort on empty chunk source!');
    }
    if (elapsed > 100) {
      throw new Error(`Deadlock breaker took too long (${elapsed.toFixed(2)} ms > 100ms)!`);
    }
  });

  // Summary
  console.log('\n========================================================================');
  console.log('         ADVERSARIAL CHUNKS & INTEGRITY SUMMARY');
  console.log('========================================================================');
  console.table(results.map(r => ({
    ID: r.id,
    Name: r.name,
    Status: r.passed ? 'PASSED' : 'FAILED',
    'Time (ms)': r.timeMs
  })));

  const total = results.length;
  const passed = results.filter(r => r.passed).length;
  const failed = total - passed;

  console.log(`\nTotal Adversarial Chunk Tests: ${total} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) {
    throw new Error('One or more adversarial chunk & integrity tests failed!');
  }
}

// CLI Execution
runChunksIntegrityAdversarialSuite().catch(err => {
  console.error('\nFatal in Adversarial Chunks Suite:', err);
  process.exit(1);
});
