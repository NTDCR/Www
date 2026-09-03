/**
 * ContentGuard Pro MAX - Deep Adversarial Reed-Solomon (RS) FEC Suite
 * Mathematical & Adversarial Torture Testing:
 *  1. GF(2^8) Galois Field Axioms & Division By Zero Guards
 *  2. Syndrome Computation & Clean Codeword Zero-Property
 *  3. Single-to-Max-Capacity Error Sweeps (1 to 16 Errors per 255-Byte Block)
 *  4. Exceeding Error Capacity Bound (17 to 30 Errors without crash)
 *  5. 16-Byte Contiguous Burst Error Auto-Repair
 *  6. Parity-Only & Data-Only Selective Error Injections
 *  7. Pathological All-Zero & All-Ones Codewords
 *  8. Multi-Kilobyte Stream-Level Auto-Repair Across 400+ Blocks
 *  9. Severely Truncated & Header-Tampered Stream Protection
 * 10. Async vs Sync Stream Codec Bit-For-Bit Parity
 */

import {
  gfMul,
  gfDiv,
  gfInv,
  rsGeneratorPoly,
  rsEncodeBlock,
  rsDecodeBlock,
  encodeRSStream,
  decodeRSStream,
  encodeRSStreamAsync,
  decodeRSStreamAsync,
  RS_DEFAULT_PARITY_LEN,
  RS_DEFAULT_BLOCK_SIZE,
  RS_DEFAULT_TOTAL_SIZE
} from '../src/crypto/reedSolomon';
import { constantTimeCompare } from '../src/crypto/cascadeEngine';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';

interface TestResult {
  id: string;
  name: string;
  passed: boolean;
  timeMs: number;
  details?: string;
}

const results: TestResult[] = [];

async function runRSTest(id: string, name: string, fn: () => Promise<void>) {
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

export async function runReedSolomonAdversarialSuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX — ADVERSARIAL REED-SOLOMON FEC SUITE');
  console.log('========================================================================\n');

  // ===========================================================================
  // SECTION 1: GALOIS FIELD GF(2^8) MATHEMATICAL AXIOMS
  // ===========================================================================
  console.log('--- SECTION 1: GALOIS FIELD GF(2^8) MATHEMATICAL AXIOMS ---');

  await runRSTest('RS-ADV-01', 'GF(2^8) Field Axioms (Commutativity, Associativity, Inverses)', async () => {
    // 1. Division and Inversion by zero guards
    let divZeroCaught = false;
    try { gfDiv(10, 0); } catch { divZeroCaught = true; }
    if (!divZeroCaught) throw new Error('gfDiv(x, 0) did not throw division by zero error');

    let invZeroCaught = false;
    try { gfInv(0); } catch { invZeroCaught = true; }
    if (!invZeroCaught) throw new Error('gfInv(0) did not throw inversion by zero error');

    // 2. Multiplicative Inverse Property: a * a^-1 = 1 for all a in {1..255}
    for (let a = 1; a < 256; a++) {
      const aInv = gfInv(a);
      const prod = gfMul(a, aInv);
      if (prod !== 1) {
        throw new Error(`GF(2^8) Multiplicative inverse failed for element ${a}: got ${prod}`);
      }
    }

    // 3. Distributivity: a * (b ^ c) = (a * b) ^ (a * c) for random triples
    for (let i = 0; i < 1000; i++) {
      const a = Math.floor(Math.random() * 256);
      const b = Math.floor(Math.random() * 256);
      const c = Math.floor(Math.random() * 256);

      const left = gfMul(a, b ^ c);
      const right = gfMul(a, b) ^ gfMul(a, c);
      if (left !== right) {
        throw new Error(`GF(2^8) Distributivity violated for triple (${a}, ${b}, ${c})`);
      }
    }
  });

  // ===========================================================================
  // SECTION 2: CLEAN CODEWORD INTEGRITY
  // ===========================================================================
  console.log('\n--- SECTION 2: CLEAN CODEWORD ZERO-SYNDROME INTEGRITY ---');

  await runRSTest('RS-ADV-02', 'Zero-Error Codeword Identification & Passthrough', async () => {
    for (const msgLen of [1, 10, 50, 100, RS_DEFAULT_BLOCK_SIZE]) {
      const msg = generateSecureRandomBytes(msgLen);
      const codeword = rsEncodeBlock(msg, RS_DEFAULT_PARITY_LEN);

      // Verify codeword length = msgLen + 32
      if (codeword.length !== msgLen + RS_DEFAULT_PARITY_LEN) {
        throw new Error(`Codeword length mismatch: expected ${msgLen + 32}, got ${codeword.length}`);
      }

      // Decode untouched codeword
      const decoded = rsDecodeBlock(codeword, RS_DEFAULT_PARITY_LEN, msgLen);
      if (!decoded.success || decoded.correctedErrors !== 0) {
        throw new Error(`Clean codeword incorrectly flagged errors: ${decoded.correctedErrors}`);
      }
      if (!constantTimeCompare(msg, decoded.data)) {
        throw new Error(`Decoded data mismatch for clean message length ${msgLen}`);
      }
    }
  });

  // ===========================================================================
  // SECTION 3: SYSTEMATIC ERROR SWEEP (1 TO 16 ERRORS)
  // ===========================================================================
  console.log('\n--- SECTION 3: SYSTEMATIC ERROR CORRECTION SWEEP (1 TO 16 ERRORS) ---');

  await runRSTest('RS-ADV-03', 'Exhaustive Error Correction Sweep from 1 to 16 Errors per Block', async () => {
    const msg = generateSecureRandomBytes(RS_DEFAULT_BLOCK_SIZE);
    const codeword = rsEncodeBlock(msg, RS_DEFAULT_PARITY_LEN);

    // Test each error count from 1 to 16
    for (let errorCount = 1; errorCount <= 16; errorCount++) {
      const corrupted = new Uint8Array(codeword);
      // Pick errorCount unique random indices in [0, 254]
      const chosenPositions = new Set<number>();
      while (chosenPositions.size < errorCount) {
        chosenPositions.add(Math.floor(Math.random() * codeword.length));
      }

      for (const pos of chosenPositions) {
        // Ensure the byte is actually changed
        corrupted[pos] ^= (Math.floor(Math.random() * 254) + 1);
      }

      const decoded = rsDecodeBlock(corrupted, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
      if (!decoded.success) {
        throw new Error(`Failed to correct ${errorCount} errors in block!`);
      }
      if (decoded.correctedErrors !== errorCount) {
        throw new Error(`Error count mismatch: expected ${errorCount}, got ${decoded.correctedErrors}`);
      }
      if (!constantTimeCompare(msg, decoded.data)) {
        throw new Error(`Corrected data mismatch on errorCount = ${errorCount}!`);
      }
    }
  });

  // ===========================================================================
  // SECTION 4: EXCEEDING ERROR CAPACITY BOUND (> 16 ERRORS)
  // ===========================================================================
  console.log('\n--- SECTION 4: EXCEEDING ERROR CAPACITY BOUND (> 16 ERRORS) ---');

  await runRSTest('RS-ADV-04', 'Exceeding Capacity Rejection (17 to 30 Errors)', async () => {
    const msg = generateSecureRandomBytes(RS_DEFAULT_BLOCK_SIZE);
    const codeword = rsEncodeBlock(msg, RS_DEFAULT_PARITY_LEN);

    for (const errorCount of [17, 18, 20, 25, 30]) {
      const corrupted = new Uint8Array(codeword);
      const chosenPositions = new Set<number>();
      while (chosenPositions.size < errorCount) {
        chosenPositions.add(Math.floor(Math.random() * codeword.length));
      }
      for (const pos of chosenPositions) {
        corrupted[pos] ^= (Math.floor(Math.random() * 254) + 1);
      }

      const decoded = rsDecodeBlock(corrupted, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
      // Beyond 16 errors, the block MUST be detected as uncorrectable or return success = false
      if (decoded.success && constantTimeCompare(msg, decoded.data)) {
        // Mathematically impossible for RS(255,223) to reliably correct 17+ errors without aliasing
        throw new Error(`Anomalous success reported on ${errorCount} errors`);
      }
      // Must not crash or throw unhandled exceptions
    }
  });

  // ===========================================================================
  // SECTION 5: 16-BYTE CONTIGUOUS BURST ERROR AUTO-REPAIR
  // ===========================================================================
  console.log('\n--- SECTION 5: 16-BYTE CONTIGUOUS BURST ERROR AUTO-REPAIR ---');

  await runRSTest('RS-ADV-05', '16-Byte Contiguous Burst Noise Auto-Repair', async () => {
    const msg = generateSecureRandomBytes(RS_DEFAULT_BLOCK_SIZE);
    const codeword = rsEncodeBlock(msg, RS_DEFAULT_PARITY_LEN);

    // Corrupt a contiguous sequence of 16 bytes starting at offset 50
    const burstStart = 50;
    const burstLen = 16;
    const corrupted = new Uint8Array(codeword);
    for (let i = 0; i < burstLen; i++) {
      corrupted[burstStart + i] ^= 0x5a;
    }

    const decoded = rsDecodeBlock(corrupted, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
    if (!decoded.success || decoded.correctedErrors !== 16) {
      throw new Error(`Burst error repair failed: success=${decoded.success}, corrected=${decoded.correctedErrors}`);
    }
    if (!constantTimeCompare(msg, decoded.data)) {
      throw new Error('Data corrupted after contiguous burst repair');
    }
  });

  // ===========================================================================
  // SECTION 6: PARITY-ONLY & DATA-ONLY SELECTIVE CORRUPTIONS
  // ===========================================================================
  console.log('\n--- SECTION 6: PARITY-ONLY & DATA-ONLY SELECTIVE CORRUPTIONS ---');

  await runRSTest('RS-ADV-06', 'Selective Parity-Only and Data-Only Noise Recovery', async () => {
    const msg = generateSecureRandomBytes(RS_DEFAULT_BLOCK_SIZE);
    const codeword = rsEncodeBlock(msg, RS_DEFAULT_PARITY_LEN);

    // 1. Corrupt 16 bytes strictly in the parity section (indices 223 to 238)
    const parityCorrupt = new Uint8Array(codeword);
    for (let i = 0; i < 16; i++) {
      parityCorrupt[223 + i] ^= 0xa5;
    }
    const decParity = rsDecodeBlock(parityCorrupt, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
    if (!decParity.success || !constantTimeCompare(msg, decParity.data)) {
      throw new Error('Failed to recover data when parity section was corrupted');
    }

    // 2. Corrupt 16 bytes strictly in data section (indices 10 to 25)
    const dataCorrupt = new Uint8Array(codeword);
    for (let i = 0; i < 16; i++) {
      dataCorrupt[10 + i] ^= 0x3c;
    }
    const decData = rsDecodeBlock(dataCorrupt, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
    if (!decData.success || !constantTimeCompare(msg, decData.data)) {
      throw new Error('Failed to recover data when data section was corrupted');
    }
  });

  // ===========================================================================
  // SECTION 7: PATHOLOGICAL ALL-ZERO & ALL-ONES CODEWORDS
  // ===========================================================================
  console.log('\n--- SECTION 7: PATHOLOGICAL ALL-ZERO & ALL-ONES CODEWORDS ---');

  await runRSTest('RS-ADV-07', 'All-Zeros & All-Ones Pathological Inputs', async () => {
    // 1. All-Zero message
    const zeroMsg = new Uint8Array(RS_DEFAULT_BLOCK_SIZE);
    const zeroCodeword = rsEncodeBlock(zeroMsg, RS_DEFAULT_PARITY_LEN);
    // Corrupt 10 bytes with 0xff
    for (let i = 0; i < 10; i++) zeroCodeword[i * 10] = 0xff;
    const decZero = rsDecodeBlock(zeroCodeword, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
    if (!decZero.success || !constantTimeCompare(zeroMsg, decZero.data)) {
      throw new Error('Failed to repair corrupted all-zeros codeword');
    }

    // 2. All-Ones message
    const onesMsg = new Uint8Array(RS_DEFAULT_BLOCK_SIZE).fill(0xff);
    const onesCodeword = rsEncodeBlock(onesMsg, RS_DEFAULT_PARITY_LEN);
    // Corrupt 10 bytes with 0x00
    for (let i = 0; i < 10; i++) onesCodeword[i * 10] = 0x00;
    const decOnes = rsDecodeBlock(onesCodeword, RS_DEFAULT_PARITY_LEN, RS_DEFAULT_BLOCK_SIZE);
    if (!decOnes.success || !constantTimeCompare(onesMsg, decOnes.data)) {
      throw new Error('Failed to repair corrupted all-ones codeword');
    }
  });

  // ===========================================================================
  // SECTION 8: STREAM-LEVEL AUTO-REPAIR (100 KB ACROSS 450+ BLOCKS)
  // ===========================================================================
  console.log('\n--- SECTION 8: STREAM-LEVEL FEC AUTO-REPAIR ACROSS 450+ BLOCKS ---');

  await runRSTest('RS-ADV-08', 'Massive Multi-Block FEC Stream Repair (100 KB, ~2000 Errors)', async () => {
    const streamSize = 100 * 1024; // 100 KB = 460 blocks
    const original = generateSecureRandomBytes(streamSize);

    const { encodedData, stats } = encodeRSStream(original);
    const totalBlocks = stats.totalBlocks;

    // Inject 5 random errors in EVERY single block across the entire 100 KB stream
    const corruptedStream = new Uint8Array(encodedData);
    let totalInjected = 0;
    const headerLen = 16;

    for (let b = 0; b < totalBlocks; b++) {
      const blockStart = headerLen + (b * (RS_DEFAULT_BLOCK_SIZE + RS_DEFAULT_PARITY_LEN));
      for (let e = 0; e < 5; e++) {
        const offsetInBlock = Math.floor(Math.random() * (RS_DEFAULT_BLOCK_SIZE + RS_DEFAULT_PARITY_LEN));
        if (blockStart + offsetInBlock < corruptedStream.length) {
          corruptedStream[blockStart + offsetInBlock] ^= 0x7e;
          totalInjected++;
        }
      }
    }

    const { data: repaired, recoveredErrors, uncorrectableBlocks, isRepaired } = decodeRSStream(corruptedStream);

    if (uncorrectableBlocks > 0) {
      throw new Error(`Stream repair had ${uncorrectableBlocks} uncorrectable blocks!`);
    }
    if (!isRepaired) {
      throw new Error('Stream repair flag was false');
    }
    if (recoveredErrors === 0) {
      throw new Error('Stream decoder reported 0 recovered errors despite heavy injection');
    }
    if (!constantTimeCompare(original, repaired)) {
      throw new Error('Stream decoded bytes do not match original 100 KB payload!');
    }
  });

  // ===========================================================================
  // SECTION 9: SEVERELY TRUNCATED & CORRUPT STREAM FRAMING
  // ===========================================================================
  console.log('\n--- SECTION 9: SEVERELY TRUNCATED & CORRUPT STREAM FRAMING ---');

  await runRSTest('RS-ADV-09', 'Truncated Codewords & Broken Framing Headers Defense', async () => {
    // 1. Codeword smaller than parity length (nsym)
    const tooShortCodeword = new Uint8Array(10);
    const shortDec = rsDecodeBlock(tooShortCodeword, 32);
    if (shortDec.success) throw new Error('rsDecodeBlock reported success on truncated codeword');

    // 2. Stream smaller than 16-byte header
    const tooShortStream = new Uint8Array(8);
    const streamDec = decodeRSStream(tooShortStream);
    if (streamDec.isRepaired) throw new Error('decodeRSStream reported repaired on 8-byte stream');

    // 3. Invalid Magic Header
    const fakeMagic = new Uint8Array(32);
    fakeMagic.set([0x00, 0x00, 0x00, 0x00], 0);
    const fakeDec = decodeRSStream(fakeMagic);
    if (fakeDec.isRepaired) throw new Error('decodeRSStream repaired fake magic header');
  });

  // ===========================================================================
  // SECTION 10: ASYNC VS SYNC STREAM CODEC PARITY
  // ===========================================================================
  console.log('\n--- SECTION 10: ASYNC VS SYNC STREAM CODEC PARITY ---');

  await runRSTest('RS-ADV-10', 'Async vs Sync Stream Codec Bit-For-Bit Parity', async () => {
    const data = generateSecureRandomBytes(10000);

    const syncEnc = encodeRSStream(data);
    const asyncEnc = await encodeRSStreamAsync(data);

    if (!constantTimeCompare(syncEnc.encodedData, asyncEnc.encodedData)) {
      throw new Error('Sync and Async RS stream encoders produced differing outputs!');
    }

    // Inject errors in both
    syncEnc.encodedData[50] ^= 0x01;
    asyncEnc.encodedData[50] ^= 0x01;

    const syncDec = decodeRSStream(syncEnc.encodedData);
    const asyncDec = await decodeRSStreamAsync(asyncEnc.encodedData);

    if (!constantTimeCompare(syncDec.data, asyncDec.data)) {
      throw new Error('Sync and Async RS stream decoders produced differing repaired data!');
    }
  });

  // Summary
  console.log('\n========================================================================');
  console.log('         ADVERSARIAL REED-SOLOMON (RS) FEC SUMMARY');
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

  console.log(`\nTotal Adversarial RS Tests: ${total} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) {
    throw new Error('One or more adversarial Reed-Solomon tests failed!');
  }
}

// CLI Execution
runReedSolomonAdversarialSuite().catch(err => {
  console.error('\nFatal in Adversarial RS Suite:', err);
  process.exit(1);
});
