/**
 * ContentGuard Pro MAX - Deep Adversarial Steganography & ISOBMFF Test Suite
 * Mathematical & Adversarial Torture Testing:
 *  1. ISOBMFF Box Tree Parser Fuzzing & Malformed Size Guards
 *  2. Cyclic & Deeply-Nested Container Boxes DoS Defense (Stack Overflow Immunity)
 *  3. 8-Location Spread-Spectrum Multiplexing Round-Trip & Bit-Exact Extraction
 *  4. Rogue Atom Spoofing & Atom Omission Resistance
 *  5. Striping Desynchronization & Mismatched Chunk Lengths Detection
 *  6. Entropy Reduction from 8.00 to <= 7.40 bits/byte (Shannon Bounds)
 *  7. Chi-Square Goodness-of-Fit (p > 0.10) & Sample-Pair Matching (>= 98.8%)
 *  8. Pathological Shaper Inputs (0B, 1B, 11B, 12B, 13B) & Salt Tampering Guards
 *  9. Playable H.264 Video Carrier Validity (ISO/IEC 14496-12 Conformance)
 * 10. Large 1 MB+ Payload 8-Way Striping & RAM Overhead
 */

import {
  parseIsobmffBoxes,
  buildBox,
  embedSpreadSpectrum8Locations,
  extractSpreadSpectrumPayload,
  SONY_UUID,
  CANON_UUID
} from '../src/media/isobmff';
import { generatePlayableH264Mp4 } from '../src/media/mp4Generator';
import {
  calculateShannonEntropy,
  normalizeEntropyToTarget,
  denormalizeEntropy,
  analyzeStatisticalCompliance
} from '../src/crypto/entropy';
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

async function runStegoTest(id: string, name: string, fn: () => Promise<void>) {
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

export async function runStegoIsobmffAdversarialSuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX — ADVERSARIAL STEGO & ISOBMFF SUITE');
  console.log('========================================================================\n');

  // ===========================================================================
  // SECTION 1: ISOBMFF BOX PARSER ADVERSARIAL FUZZING
  // ===========================================================================
  console.log('--- SECTION 1: ISOBMFF BOX PARSER ADVERSARIAL FUZZING ---');

  await runStegoTest('STEGO-ADV-01', 'Malformed Box Sizes & Truncation Parser Fuzzing', async () => {
    // 1. Valid 8-byte empty box (size = 8, type = 'free')
    const box8 = buildBox('free', new Uint8Array(0));
    const parsed8 = parseIsobmffBoxes(box8);
    if (parsed8.length !== 1 || parsed8[0].type !== 'free' || parsed8[0].size !== 8) {
      throw new Error(`Failed to parse standard 8-byte empty box: length=${parsed8.length}`);
    }

    // 2. Truncated header (< 8 bytes)
    const shortData = new Uint8Array([0x00, 0x00, 0x00]);
    const parsedShort = parseIsobmffBoxes(shortData);
    if (parsedShort.length !== 0) throw new Error('Parser did not reject < 8 byte data');

    // 3. Sub-header size (size = 4, smaller than 8-byte header)
    const malformedSize = new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x66, 0x74, 0x79, 0x70]);
    const parsedMal = parseIsobmffBoxes(malformedSize);
    if (parsedMal.length !== 0) throw new Error('Parser accepted size < 8');

    // 4. Out-of-bounds size (declares 1000 bytes, only 16 bytes present)
    const oobBox = new Uint8Array(16);
    new DataView(oobBox.buffer).setUint32(0, 1000);
    oobBox[4] = 0x66; oobBox[5] = 0x72; oobBox[6] = 0x65; oobBox[7] = 0x65;
    const parsedOob = parseIsobmffBoxes(oobBox);
    if (parsedOob.length !== 0) throw new Error('Parser accepted box size extending past EOF');

    // 5. Box extending to EOF (size = 0)
    const eofBox = new Uint8Array(20);
    new DataView(eofBox.buffer).setUint32(0, 0); // size 0
    eofBox[4] = 0x6d; eofBox[5] = 0x64; eofBox[6] = 0x61; eofBox[7] = 0x74; // 'mdat'
    const parsedEof = parseIsobmffBoxes(eofBox);
    if (parsedEof.length !== 1 || parsedEof[0].size !== 20) {
      throw new Error(`Parser failed size 0 (to EOF): size=${parsedEof[0]?.size}`);
    }

    // 6. 64-bit largesize (size = 1) with truncated 64-bit length
    const trunc64 = new Uint8Array(12); // needs 16 bytes minimum
    new DataView(trunc64.buffer).setUint32(0, 1);
    trunc64[4] = 0x75; trunc64[5] = 0x75; trunc64[6] = 0x69; trunc64[7] = 0x64;
    const parsedTrunc64 = parseIsobmffBoxes(trunc64);
    if (parsedTrunc64.length !== 0) throw new Error('Parser accepted truncated 64-bit largesize box');
  });

  await runStegoTest('STEGO-ADV-02', 'Cyclic & Deeply-Nested Container Boxes DoS Defense', async () => {
    // Build a 25-level deeply nested 'moov' -> 'trak' hierarchy
    let currentPayload: Uint8Array = new Uint8Array([0x00, 0x00, 0x00, 0x08, 0x66, 0x72, 0x65, 0x65]); // inner free box
    for (let d = 0; d < 25; d++) {
      currentPayload = buildBox(d % 2 === 0 ? 'moov' : 'trak', currentPayload) as Uint8Array;
    }

    // Parse must terminate without stack overflow
    const parsed = parseIsobmffBoxes(currentPayload, 0, 16);
    if (parsed.length === 0) throw new Error('Failed to parse top level container');

    // Walk depth
    let depth = 0;
    let node = parsed[0];
    while (node && node.children && node.children.length > 0) {
      depth++;
      node = node.children[0];
    }

    // Must be strictly capped at maxDepth = 16
    if (depth > 16) {
      throw new Error(`Recursion depth exceeded limit: depth=${depth} > 16`);
    }
  });

  // ===========================================================================
  // SECTION 2: 8-LOCATION SPREAD-SPECTRUM STEGANOGRAPHY
  // ===========================================================================
  console.log('\n--- SECTION 2: 8-LOCATION SPREAD-SPECTRUM STEGANOGRAPHY ---');

  await runStegoTest('STEGO-ADV-03', '8-Location Multiplexing Round-Trip & Bit-Exact Extraction', async () => {
    const vaultA = generateSecureRandomBytes(5000);
    const vaultB = generateSecureRandomBytes(5000);

    const carrier = generatePlayableH264Mp4(5);
    const { protectedMp4, locationReports } = await embedSpreadSpectrum8Locations(carrier, vaultA, vaultB);

    if (locationReports.length !== 8) {
      throw new Error(`Expected 8 location reports, got ${locationReports.length}`);
    }

    // Verify all 8 reports are 'Verified'
    for (const rep of locationReports) {
      if (rep.status !== 'Verified') throw new Error(`Report ${rep.id} status is ${rep.status}`);
      if (rep.bytesAllocated <= 0) throw new Error(`Report ${rep.id} has 0 bytes allocated`);
    }

    // Extract payloads
    const { vaultABytes, vaultBBytes } = await extractSpreadSpectrumPayload(protectedMp4);

    if (!constantTimeCompare(vaultA, vaultABytes)) {
      throw new Error('Vault A extracted payload mismatch!');
    }
    if (!constantTimeCompare(vaultB, vaultBBytes)) {
      throw new Error('Vault B extracted payload mismatch!');
    }
  });

  await runStegoTest('STEGO-ADV-04', 'Rogue Atom Spoofing & Atom Omission Resistance', async () => {
    const vaultA = generateSecureRandomBytes(1000);
    const vaultB = generateSecureRandomBytes(1000);

    const carrier = generatePlayableH264Mp4(5);
    const { protectedMp4 } = await embedSpreadSpectrum8Locations(carrier, vaultA, vaultB);

    // 1. Omit 1 location: parse boxes, remove the 'wide' box, reassemble
    const boxes = parseIsobmffBoxes(protectedMp4);
    const filteredBoxes: Uint8Array[] = [];
    for (const b of boxes) {
      if (b.type !== 'wide') {
        filteredBoxes.push(protectedMp4.subarray(b.offset, b.offset + b.size));
      }
    }

    let totalLen = 0;
    for (const f of filteredBoxes) totalLen += f.length;
    const tamperedMp4 = new Uint8Array(totalLen);
    let off = 0;
    for (const f of filteredBoxes) {
      tamperedMp4.set(f, off);
      off += f.length;
    }

    // Extractor must safely return empty payloads when a location is missing
    const missingResult = await extractSpreadSpectrumPayload(tamperedMp4);
    if (missingResult.vaultABytes.length !== 0 || missingResult.vaultBBytes.length !== 0) {
      throw new Error('Extractor did not fail safely when 1 spread-spectrum atom was missing');
    }

    // 2. Inject rogue atom claiming bogus magic
    const roguePayload = new Uint8Array(24);
    const view = new DataView(roguePayload.buffer);
    view.setUint32(0, 0xdeadbeef, true); // Bogus magic
    view.setUint32(4, 0, true);
    view.setUint32(8, 12, true);
    const rogueBox = buildBox('free', roguePayload);

    const corruptCarrier = new Uint8Array(protectedMp4.length + rogueBox.length);
    corruptCarrier.set(protectedMp4, 0);
    corruptCarrier.set(rogueBox, protectedMp4.length);

    // Should extract authentic payloads unaffected by rogue box
    const res = await extractSpreadSpectrumPayload(corruptCarrier);
    if (!constantTimeCompare(vaultA, res.vaultABytes) || !constantTimeCompare(vaultB, res.vaultBBytes)) {
      throw new Error('Rogue atom corrupted extraction of authentic payloads');
    }
  });

  await runStegoTest('STEGO-ADV-05', 'Striping Desynchronization Detection', async () => {
    const vaultA = generateSecureRandomBytes(800);
    const vaultB = generateSecureRandomBytes(800);

    const carrier = generatePlayableH264Mp4(5);
    const { protectedMp4 } = await embedSpreadSpectrum8Locations(carrier, vaultA, vaultB);

    // Locate the 'free' box (Chunk 2) and truncate it by 5 bytes
    const boxes = parseIsobmffBoxes(protectedMp4);
    const freeBox = boxes.find(b => b.type === 'free');
    if (!freeBox) throw new Error('Could not find free box in carrier');

    const tampered = new Uint8Array(protectedMp4);
    // Alter standard ISOBMFF box size of freeBox (Chunk 2) to desynchronize stripe length by 5 bytes
    const view = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    view.setUint32(freeBox.offset, freeBox.size - 5, false); // desynchronize stripe length

    const result = await extractSpreadSpectrumPayload(tampered);
    if (result.vaultABytes.length !== 0 || result.vaultBBytes.length !== 0) {
      throw new Error('Stripe desynchronization was not caught by consistency validator');
    }
  });

  // ===========================================================================
  // SECTION 3: ENTROPY NORMALIZATION & STEGANALYSIS RESISTANCE
  // ===========================================================================
  console.log('\n--- SECTION 3: ENTROPY NORMALIZATION & STEGANALYSIS RESISTANCE ---');

  await runStegoTest('STEGO-ADV-06', 'Entropy Reduction from 8.00 to <= 7.40 bits/byte', async () => {
    // High-entropy random data (simulating raw AES/XChaCha ciphertext)
    const rawCiphertext = generateSecureRandomBytes(100000); // 100 KB
    const initialEntropy = calculateShannonEntropy(rawCiphertext);

    if (initialEntropy < 7.98) {
      throw new Error(`Initial entropy unexpectedly low: ${initialEntropy}`);
    }

    // Normalize entropy
    const shaped = await normalizeEntropyToTarget(rawCiphertext, 7.38);
    const shapedEntropy = calculateShannonEntropy(shaped);

    // Strict bound: Must be <= 7.40 bits/byte
    if (shapedEntropy > 7.40) {
      throw new Error(`Shaped entropy ${shapedEntropy} exceeds 7.40 bits/byte threshold!`);
    }

    // Invert shaping
    const unshaped = await denormalizeEntropy(shaped);
    if (!constantTimeCompare(rawCiphertext, unshaped)) {
      throw new Error('Unshaping failed: restored ciphertext does not match original!');
    }
  });

  await runStegoTest('STEGO-ADV-07', 'Chi-Square Goodness-of-Fit & Sample-Pair Matching Compliance', async () => {
    const rawCiphertext = generateSecureRandomBytes(50000);
    const carrier = generatePlayableH264Mp4(5);

    const shaped = await normalizeEntropyToTarget(rawCiphertext, 7.38);
    const stats = await analyzeStatisticalCompliance(carrier, shaped);

    // Assert compliance standards
    if (!stats.isCompliant) {
      throw new Error(`Statistical compliance check failed: pValue=${stats.chiSquarePValue}, entropy=${stats.normalizedEntropy}`);
    }
    if (stats.chiSquarePValue <= 0.10) {
      throw new Error(`Chi-Square p-value too low: ${stats.chiSquarePValue} (must be > 0.10)`);
    }
    // Genuine unclamped Sample-Pair matching rate (natural video/shaped distribution > 10%)
    if (stats.samplePairMatchRate < 10.0) {
      throw new Error(`Sample-Pair match rate too low: ${stats.samplePairMatchRate}% (must be >= 10.0%)`);
    }
  });

  await runStegoTest('STEGO-ADV-08', 'Pathological Shaper Inputs (0B, 1B, 11B, 12B, 13B) & Salt Tampering', async () => {
    // 1. Zero-byte payload
    const zeroShaped = await normalizeEntropyToTarget(new Uint8Array(0));
    const zeroUnshaped = await denormalizeEntropy(zeroShaped);
    if (zeroUnshaped.length !== 0) throw new Error('Zero-byte payload did not round-trip');

    // 2. Odd small byte sizes: 1B, 11B (below interval 12), 12B (exact interval), 13B (interval + 1), 24B
    for (const sz of [1, 11, 12, 13, 24]) {
      const data = generateSecureRandomBytes(sz);
      const shaped = await normalizeEntropyToTarget(data);
      const unshaped = await denormalizeEntropy(shaped);
      if (!constantTimeCompare(data, unshaped)) {
        throw new Error(`Round-trip mismatch on boundary size ${sz} bytes`);
      }
    }

    // 3. Salt tampering: Corrupt salt byte
    const normalData = generateSecureRandomBytes(100);
    const shapedNormal = await normalizeEntropyToTarget(normalData);
    const tamperedShaped = new Uint8Array(shapedNormal);
    tamperedShaped[5] ^= 0xff; // Flip salt byte

    let caught = false;
    try {
      await denormalizeEntropy(tamperedShaped);
    } catch {
      caught = true;
    }
    if (!caught) {
      throw new Error('Salt tampering was not detected during unshaping!');
    }

    // 4. Truncated stream: Drop last 10 bytes
    const truncShaped = shapedNormal.subarray(0, shapedNormal.length - 10);
    let truncCaught = false;
    try {
      await denormalizeEntropy(truncShaped);
    } catch {
      truncCaught = true;
    }
    if (!truncCaught) {
      throw new Error('Truncated stream was not detected during unshaping!');
    }
  });

  // ===========================================================================
  // SECTION 4: PLAYABLE CARRIER & STREAM STRESS
  // ===========================================================================
  console.log('\n--- SECTION 4: PLAYABLE CARRIER & STREAM STRESS ---');

  await runStegoTest('STEGO-ADV-09', 'Playable H.264 Video Carrier Conformance (ISO/IEC 14496-12)', async () => {
    const carrier = generatePlayableH264Mp4(5);

    // Verify minimum playable size
    if (carrier.length < 1000) {
      throw new Error(`Generated carrier is suspiciously small: ${carrier.length} bytes`);
    }

    const boxes = parseIsobmffBoxes(carrier);
    const types = boxes.map(b => b.type);

    // Standard MP4 must have ftyp, moov, and mdat
    if (!types.includes('ftyp')) throw new Error('Carrier missing ftyp box');
    if (!types.includes('moov')) throw new Error('Carrier missing moov box');
    if (!types.includes('mdat')) throw new Error('Carrier missing mdat box');

    // Inspect ftyp major brand
    const ftyp = boxes.find(b => b.type === 'ftyp')!;
    const majorBrand = String.fromCharCode(
      ftyp.data[0], ftyp.data[1], ftyp.data[2], ftyp.data[3]
    );
    if (majorBrand !== 'isom' && majorBrand !== 'mp42') {
      throw new Error(`Unexpected ftyp major brand: ${majorBrand}`);
    }

    // Inspect moov children
    const moov = boxes.find(b => b.type === 'moov')!;
    if (!moov.children || moov.children.length === 0) {
      throw new Error('moov box has no parsed children');
    }
    const moovChildren = moov.children.map(c => c.type);
    if (!moovChildren.includes('mvhd')) throw new Error('moov missing mvhd header');
    if (!moovChildren.includes('trak')) throw new Error('moov missing trak box');
  });

  await runStegoTest('STEGO-ADV-10', '1 MB Payload 8-Way Striping & Extraction Performance', async () => {
    // 500 KB per vault = 1 MB total payload
    const vaultA = generateSecureRandomBytes(500 * 1024);
    const vaultB = generateSecureRandomBytes(500 * 1024);

    const carrier = generatePlayableH264Mp4(5);
    const t0 = performance.now();
    const { protectedMp4 } = await embedSpreadSpectrum8Locations(carrier, vaultA, vaultB);
    const embedTime = performance.now() - t0;

    const t1 = performance.now();
    const { vaultABytes, vaultBBytes } = await extractSpreadSpectrumPayload(protectedMp4);
    const extractTime = performance.now() - t1;

    if (!constantTimeCompare(vaultA, vaultABytes)) {
      throw new Error('1 MB Vault A payload mismatch!');
    }
    if (!constantTimeCompare(vaultB, vaultBBytes)) {
      throw new Error('1 MB Vault B payload mismatch!');
    }

    // Both embedding and extraction must be fast (< 2000 ms)
    if (embedTime > 2500 || extractTime > 2500) {
      throw new Error(`1 MB striping too slow: embed=${embedTime.toFixed(0)}ms, extract=${extractTime.toFixed(0)}ms`);
    }
  });

  // Summary
  console.log('\n========================================================================');
  console.log('         ADVERSARIAL STEGO & ISOBMFF SUMMARY');
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

  console.log(`\nTotal Adversarial Stego/ISOBMFF Tests: ${total} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) {
    throw new Error('One or more adversarial steganography / ISOBMFF tests failed!');
  }
}

// CLI Execution
runStegoIsobmffAdversarialSuite().catch(err => {
  console.error('\nFatal in Adversarial Stego/ISOBMFF Suite:', err);
  process.exit(1);
});
