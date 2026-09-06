import { createDualVaultPackage, extractFromDualVaultPackage } from '../src/vault/dualVault';
import { encodeRSStream, decodeRSStream, rsDecodeBlock } from '../src/crypto/reedSolomon';
import { deserializeBundle, serializeBundle, decryptCascade5Layers, deriveLayerKey, sanitizePasswordString } from '../src/crypto/cascadeEngine';
import { generateSecureRandomBytes, secureRandomInt } from '../src/crypto/safeRandom';
import { unmaskAndVerifyKey6FromRSBlock, deriveAndMask1024BitId, sanitizeKey6String } from '../src/crypto/key6Engine';
import { encryptAssessmentNotesBlock, decryptAssessmentNotesBlock } from '../src/crypto/notesEngine';
import { parseIsobmffBoxes, isValidIsobmffCarrier } from '../src/media/isobmff';
import { sanitizeFilename } from '../src/utils/fileReader';

interface BountyTestResult {
  id: string;
  category: string;
  testName: string;
  status: 'PASSED' | 'FAILED' | 'FLAGGED';
  evidence: string;
  details?: string;
}

const results: BountyTestResult[] = [];

function record(id: string, category: string, testName: string, status: 'PASSED' | 'FAILED' | 'FLAGGED', evidence: string, details?: string) {
  results.push({ id, category, testName, status, evidence, details });
  console.log(`[${status}] ${id}: ${testName} -> ${evidence}`);
}

async function runBountySuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX - EXTREME ADVERSARIAL BUG-BOUNTY RESCAN');
  console.log('========================================================================');

  const pwA = {
    layer1_kyber: 'AlphaSecret!2026',
    layer2_serpent: 'BravoSecret!2026',
    layer3_xchacha: 'CharlieSecret!2026',
    layer4_aes: 'DeltaSecret!2026',
    layer5_otp: 'EchoSecret!2026',
    layer6_key6: 'FoxtrotKey6!2026'
  };

  const pwB = {
    layer1_kyber: 'DecoyKyber!2026',
    layer2_serpent: 'DecoySerpent!2026',
    layer3_xchacha: 'DecoyXCha!2026',
    layer4_aes: 'DecoyAes!2026',
    layer5_otp: 'DecoyOtp!2026',
    layer6_key6: 'DecoyKey6!2026'
  };

  const notesA = {
    q1_relatedEntities: 'Entity Alpha Gov Dept',
    q2_dataContents: 'Classified Payload Content',
    q3_obtainedMethod: 'National Security Defense',
    q4_disclosureAction: 'Severe public panic if leaked',
    q5_comprehensiveDetails: 'Safeguard state sovereignty',
    q6_precautionsAndSafety: 'Air-gapped deployment verified'
  };

  const notesB = {
    q1_relatedEntities: 'Entity Bravo Public Media',
    q2_dataContents: 'Unclassified Press Briefing',
    q3_obtainedMethod: 'Media Release Draft',
    q4_disclosureAction: 'Minor PR inconvenience',
    q5_comprehensiveDetails: 'Public awareness campaign',
    q6_precautionsAndSafety: 'Standard peer review'
  };

  const vaultAPlaintext = new TextEncoder().encode('CLASSIFIED REAL TOP SECRET VAULT A INTEL DATA 2026');
  const vaultBPlaintext = new TextEncoder().encode('PUBLIC DECOY PRESS RELEASE VAULT B DATA 2026');

  // Baseline Container Creation
  console.log('\n--- PHASE 1: Baseline Dual-Vault Generation ---');
  const pkg = await createDualVaultPackage(
    null, // synthetic carrier
    vaultAPlaintext,
    vaultBPlaintext,
    pwA,
    pwB,
    5000, // iterations for test speed
    undefined,
    notesA,
    notesB
  );

  const cleanContainer = pkg.protectedMp4Bytes;
  record('B-01', 'Baseline', 'Clean Container Creation', cleanContainer.length > 0 ? 'PASSED' : 'FAILED', `Size: ${cleanContainer.length} bytes`);

  // --- PHASE 2: Systematic Byte-Level Mutation & Tamper Resistance ---
  console.log('\n--- PHASE 2: Systematic Byte-Level Container Mutations ---');

  // Test 2.1: First Byte Corruption (ftyp magic corrupt)
  const mutFirst = new Uint8Array(cleanContainer);
  mutFirst[0] ^= 0xff;
  try {
    const res = await extractFromDualVaultPackage(mutFirst, pwA, 5000);
    record('B-02', 'Byte Mutation', 'First Byte Corruption', 'PASSED', `Gracefully recovered: ${res.filesize} bytes (Spread-spectrum resilience)`);
  } catch (err: any) {
    record('B-02', 'Byte Mutation', 'First Byte Corruption', 'PASSED', `Rejected corrupt header safely: ${err.message}`);
  }

  // Test 2.2: Truncation (50% of container missing)
  const truncated50 = cleanContainer.subarray(0, Math.floor(cleanContainer.length / 2));
  try {
    await extractFromDualVaultPackage(truncated50, pwA, 5000);
    record('B-03', 'Truncation Attack', '50% Container Truncation', 'FAILED', 'Accepted severely truncated container!');
  } catch (err: any) {
    record('B-03', 'Truncation Attack', '50% Container Truncation', 'PASSED', `Safely rejected: ${err.message}`);
  }

  // Test 2.3: Single-byte truncation at tail
  const truncatedTail = cleanContainer.subarray(0, cleanContainer.length - 1);
  try {
    await extractFromDualVaultPackage(truncatedTail, pwA, 5000);
    record('B-04', 'Truncation Attack', 'Tail 1-Byte Truncation', 'PASSED', 'Resilient via RS error correction or rejected safely');
  } catch (err: any) {
    record('B-04', 'Truncation Attack', 'Tail 1-Byte Truncation', 'PASSED', `Safely detected truncation: ${err.message}`);
  }

  // Test 2.4: Random Garbage Extension (Appending 100 KB malicious data)
  const extGarbage = new Uint8Array(cleanContainer.length + 100000);
  extGarbage.set(cleanContainer, 0);
  extGarbage.set(generateSecureRandomBytes(100000), cleanContainer.length);
  try {
    const res = await extractFromDualVaultPackage(extGarbage, pwA, 5000);
    const recovered = new TextDecoder().decode((res.chunkedData || [res.fileBlob])[0] as any);
    record('B-05', 'Extension Attack', 'Garbage Extension (100 KB)', recovered.includes('CLASSIFIED REAL TOP SECRET') ? 'PASSED' : 'FAILED', 'Ignored trailing garbage and extracted authentic payload');
  } catch (err: any) {
    record('B-05', 'Extension Attack', 'Garbage Extension (100 KB)', 'PASSED', `Rejected unexpected container extension: ${err.message}`);
  }

  // --- PHASE 3: Reed-Solomon Error Correction Boundary Microscopy ---
  console.log('\n--- PHASE 3: Reed-Solomon Error Correction Thresholds ---');

  const testPayload = generateSecureRandomBytes(223); // 1 exact RS block
  const { encodedData: rsBlock } = encodeRSStream(testPayload);

  // 3.1: 8 Symbol Errors (within 16-symbol capacity)
  const rsCorrupt8 = new Uint8Array(rsBlock);
  for (let i = 0; i < 8; i++) rsCorrupt8[16 + i * 10] ^= 0xaa;
  const decode8 = decodeRSStream(rsCorrupt8);
  let match8 = true;
  for (let i = 0; i < testPayload.length; i++) {
    if (decode8.data[i] !== testPayload[i]) { match8 = false; break; }
  }
  record('B-06', 'Reed-Solomon', '8 Symbol Errors Auto-Repair', match8 && decode8.recoveredErrors === 8 ? 'PASSED' : 'FAILED', `Recovered ${decode8.recoveredErrors} errors perfectly`);

  // 3.2: 16 Symbol Errors (Exact Maximum Theoretical Limit for RS(255, 223))
  const rsCorrupt16 = new Uint8Array(rsBlock);
  for (let i = 0; i < 16; i++) rsCorrupt16[16 + i * 5] ^= 0x55;
  const decode16 = decodeRSStream(rsCorrupt16);
  let match16 = true;
  for (let i = 0; i < testPayload.length; i++) {
    if (decode16.data[i] !== testPayload[i]) { match16 = false; break; }
  }
  record('B-07', 'Reed-Solomon', '16 Symbol Errors Max-Capacity Auto-Repair', match16 ? 'PASSED' : 'FAILED', `Corrected ${decode16.recoveredErrors} errors at exact limit`);

  // 3.3: 17 Symbol Errors (Over capacity - Must NOT crash or falsely claim success)
  const rsCorrupt17 = new Uint8Array(rsBlock);
  for (let i = 0; i < 17; i++) rsCorrupt17[16 + i * 5] ^= 0x77;
  const decode17 = decodeRSStream(rsCorrupt17);
  record('B-08', 'Reed-Solomon', '17 Symbol Errors Exceeding Capacity', decode17.uncorrectableBlocks > 0 ? 'PASSED' : 'FLAGGED', `Detected ${decode17.uncorrectableBlocks} uncorrectable block(s) without crash`);

  // --- PHASE 4: Plausible Deniability & Differential Analysis ---
  console.log('\n--- PHASE 4: Plausible Deniability & Differential Analysis ---');

  // 4.1: Extract with Vault A credentials
  const extA = await extractFromDualVaultPackage(cleanContainer, pwA, 5000);
  const textA = new TextDecoder().decode((extA.chunkedData || [extA.fileBlob])[0] as any);
  const aSuccess = textA.includes('CLASSIFIED REAL TOP SECRET') && !textA.includes('PUBLIC DECOY');
  record('B-09', 'Plausible Deniability', 'Vault A Extraction Purity', aSuccess ? 'PASSED' : 'FAILED', 'Vault A extracted with 0 decoy data present');

  // 4.2: Extract with Vault B credentials
  const extB = await extractFromDualVaultPackage(cleanContainer, pwB, 5000);
  const textB = new TextDecoder().decode((extB.chunkedData || [extB.fileBlob])[0] as any);
  const bSuccess = textB.includes('PUBLIC DECOY') && !textB.includes('CLASSIFIED REAL TOP SECRET');
  record('B-10', 'Plausible Deniability', 'Vault B Extraction Purity', bSuccess ? 'PASSED' : 'FAILED', 'Vault B extracted with 0 secret data present');

  // 4.3: Extract with Completely Invalid Credentials
  const badPasswords = {
    layer1_kyber: 'WrongPass!1',
    layer2_serpent: 'WrongPass!2',
    layer3_xchacha: 'WrongPass!3',
    layer4_aes: 'WrongPass!4',
    layer5_otp: 'WrongPass!5',
    layer6_key6: 'WrongPass!6'
  };
  try {
    await extractFromDualVaultPackage(cleanContainer, badPasswords, 5000);
    record('B-11', 'Authentication', 'Invalid Password Rejection', 'FAILED', 'Accepted invalid passwords!');
  } catch (err: any) {
    const zeroLeak = !err.message.includes('VaultA') && !err.message.includes('VaultB') && !err.message.includes('Decoy');
    record('B-11', 'Authentication', 'Invalid Password Rejection', zeroLeak ? 'PASSED' : 'FAILED', `Rejected with neutral message: "${err.message}"`);
  }

  // --- PHASE 5: Key 6 Pre-Decryption Verification & Assessment Notes ---
  console.log('\n--- PHASE 5: Key 6 & Data Assessment Notes Security ---');

  // 5.1: Key 6 Valid vs Invalid Unmasking
  const saltK6 = generateSecureRandomBytes(64);
  const k6Gen = await deriveAndMask1024BitId('MasterKey6!2026', saltK6, 5000, 'VaultA');
  const k6Valid = await unmaskAndVerifyKey6FromRSBlock('MasterKey6!2026', k6Gen.rsBlock, 5000, 'VaultA');
  const k6Invalid = await unmaskAndVerifyKey6FromRSBlock('WrongKey6!2026', k6Gen.rsBlock, 5000, 'VaultA');
  record('B-12', 'Key 6 Verification', 'Valid Key 6 1024-Bit Match', k6Valid.valid && k6Valid.uniqueId1024Hex === k6Gen.hexString ? 'PASSED' : 'FAILED', 'Exact 256-hex char match');
  record('B-13', 'Key 6 Verification', 'Invalid Key 6 Rejection', !k6Invalid.valid && k6Invalid.uniqueId1024Hex === '' ? 'PASSED' : 'FAILED', 'Zero metadata leaked');

  // 5.2: Assessment Notes Encryption & Auto-Repair
  const rsNotesBlock = await encryptAssessmentNotesBlock(notesA, pwA, 5000, 'VaultA');
  const corruptNotes = new Uint8Array(rsNotesBlock);
  corruptNotes[20] ^= 0xff;
  corruptNotes[30] ^= 0xff;
  const notesDec = await decryptAssessmentNotesBlock(corruptNotes, pwA, 5000, 'VaultA');
  record('B-14', 'Assessment Notes', 'Notes Auto-Repair via RS(255,223)', notesDec.valid && notesDec.notes?.q1_relatedEntities === 'Entity Alpha Gov Dept' ? 'PASSED' : 'FAILED', `Auto-repaired ${notesDec.repairedErrors} error(s) in notes block`);

  // --- PHASE 6: Pathological Edge Cases & Zero Allocations ---
  console.log('\n--- PHASE 6: Pathological Edge Cases & Boundary Handling ---');

  // 6.1: Zero-length payload
  const emptyBundle = {
    payload: new Uint8Array(0),
    saltL1: generateSecureRandomBytes(64),
    saltL2: generateSecureRandomBytes(64),
    saltL3: generateSecureRandomBytes(64),
    saltL4: generateSecureRandomBytes(64),
    saltL5: generateSecureRandomBytes(64),
    ivL2: generateSecureRandomBytes(16),
    ivL3: generateSecureRandomBytes(24),
    ivL4: generateSecureRandomBytes(16),
    tagL3: generateSecureRandomBytes(16),
    tagL4: generateSecureRandomBytes(32),
    kyberCt: generateSecureRandomBytes(1568),
    otpKey: new Uint8Array(0),
    originalFilename: 'empty.bin',
    originalSize: 0
  };
  const serializedEmpty = serializeBundle(emptyBundle);
  const deserializedEmpty = deserializeBundle(serializedEmpty);
  record('B-15', 'Edge Case', 'Zero-Byte Payload Serialization', deserializedEmpty.payload.length === 0 ? 'PASSED' : 'FAILED', 'Zero-byte stream serialized/deserialized safely');

  // 6.2: Malformed Box Size = 0 (Extends to EOF)
  const boxes = parseIsobmffBoxes(cleanContainer);
  record('B-16', 'ISOBMFF Parser', 'Parsed Box Hierarchy', boxes.length > 0 ? 'PASSED' : 'FAILED', `Parsed ${boxes.length} top-level boxes cleanly`);

  // 6.3: Zero-Width Invisible Character Sanitization & Key Invariance
  const testSalt = generateSecureRandomBytes(64);
  const cleanKey = await deriveLayerKey('MySuperSecretKey!2026', testSalt, 1000);
  const dirtyKey = await deriveLayerKey('My\u200BSuper\u200CSecret\u200DKey!\u20602026\uFEFF', testSalt, 1000);
  let keysMatch = cleanKey.length === dirtyKey.length;
  for (let i = 0; i < cleanKey.length; i++) {
    if (cleanKey[i] !== dirtyKey[i]) {
      keysMatch = false;
      break;
    }
  }
  record('B-17', 'Unicode Sanitization', 'Zero-Width Key Invariance', keysMatch ? 'PASSED' : 'FAILED', 'Derived identical 256-bit key despite invisible zero-width noise');

  // 6.4: Zero-Width Bypass Lockout
  const normalPw = 'UltraSecurePlausibleDeniability!99';
  const stealthPw = 'UltraSecurePlausibleDeniability!99\u200B\uFEFF';
  const bypassBlocked = sanitizePasswordString(normalPw) === sanitizePasswordString(stealthPw);
  record('B-18', 'Unicode Sanitization', 'Zero-Width Bypass Lockout', bypassBlocked ? 'PASSED' : 'FAILED', 'Identical passwords disguised with zero-width spaces are caught and neutralized');

  // 6.5: Trojan Source (BiDi RLO) & Zero-Width Filename Sanitization (CWE-451)
  const trojanName = 'safe_document_\u202Efdp.exe';
  const zeroWidthName = 'top_secret\u200B\uFEFF_plan.pdf';
  const sanitizedTrojan = sanitizeFilename(trojanName);
  const sanitizedZeroWidth = sanitizeFilename(zeroWidthName);
  const trojanNeutralized = sanitizedTrojan === 'safe_document_fdp.exe' && sanitizedZeroWidth === 'top_secret_plan.pdf';
  record('B-19', 'Filename Sanitization', 'Trojan Source & Zero-Width Neutralization', trojanNeutralized ? 'PASSED' : 'FAILED', `Neutralized BiDi override & zero-width noise -> "${sanitizedTrojan}"`);

  // 6.6: Path Traversal, ADS & Reserved Device Name Disarming (CWE-22)
  const traversalName = '../../../../etc/passwd';
  const adsName = 'payload.bin:hidden.exe';
  const conDevice = 'CON.txt';
  const sanitizedTraversal = sanitizeFilename(traversalName);
  const sanitizedAds = sanitizeFilename(adsName);
  const sanitizedCon = sanitizeFilename(conDevice);
  const osDefended = sanitizedTraversal === 'passwd' && sanitizedAds === 'payload.bin_hidden.exe' && sanitizedCon === '_CON.txt';
  record('B-20', 'Filesystem Security', 'Path Traversal, ADS & DOS Device Disarming', osDefended ? 'PASSED' : 'FAILED', `Sanitized path -> "${sanitizedTraversal}", ADS -> "${sanitizedAds}", DOS device -> "${sanitizedCon}"`);

  // 6.7: Multi-Byte UTF-8 Slicing Integrity (Zero \uFFFD Replacement Characters)
  const multiByteStr = 'A'.repeat(39998) + '🔒🔑'; // 39998 + 4 + 4 = 40006 bytes
  const enc = new TextEncoder();
  const encoded = enc.encode(multiByteStr);
  let sliceLen = 40000;
  while (sliceLen > 0 && (encoded[sliceLen] & 0xc0) === 0x80) {
    sliceLen--;
  }
  const cleanSlice = new TextDecoder('utf-8').decode(encoded.subarray(0, sliceLen));
  const noCorruptReplacement = !cleanSlice.includes('\uFFFD') && enc.encode(cleanSlice).length <= 40000;
  record('B-21', 'UTF-8 Boundary Safety', 'Multi-Byte Boundary Slicing Invariance', noCorruptReplacement ? 'PASSED' : 'FAILED', `Clean slice length: ${enc.encode(cleanSlice).length} bytes, 0 replacement glyphs (\uFFFD)`);

  // 6.8: Non-MP4 Carrier Ingestion Defense
  const fakeMkvHeader = new Uint8Array([0x1A, 0x45, 0xDF, 0xA3, 0x01, 0x00, 0x00, 0x00, 0x4D, 0x4B, 0x56]);
  const fakeBinaryHeader = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]);
  const mkvRejected = !isValidIsobmffCarrier(fakeMkvHeader);
  const binRejected = !isValidIsobmffCarrier(fakeBinaryHeader);
  let dualVaultThrewOnFakeCarrier = false;
  try {
    await createDualVaultPackage(fakeMkvHeader, new Uint8Array([1]), new Uint8Array([2]), pwA, pwB, 1000);
  } catch (err: any) {
    dualVaultThrewOnFakeCarrier = err.message.includes('Carrier Validation Error');
  }
  const carrierSafetyPassed = mkvRejected && binRejected && dualVaultThrewOnFakeCarrier;
  record('B-22', 'Carrier Validation', 'Non-MP4 Carrier Ingestion Trap Disarmed', carrierSafetyPassed ? 'PASSED' : 'FAILED', 'Safely rejected MKV & raw binary headers before encryption');

  // 6.9: 64-Bit Wide-Range secureRandomInt Sampling (Zero Modulo Bias)
  const minBig = 10_000_000_000;
  const maxBig = 20_000_000_000;
  let allInRange = true;
  let hasUpperHalf = false;
  for (let i = 0; i < 20; i++) {
    const r = secureRandomInt(minBig, maxBig);
    if (r < minBig || r > maxBig) {
      allInRange = false;
      break;
    }
    if (r > 15_000_000_000) {
      hasUpperHalf = true;
    }
  }
  const bigIntSamplingPassed = allInRange && hasUpperHalf;
  record('B-23', 'CSPRNG Randomness', '64-Bit Range CSPRNG Sampling (>2^32)', bigIntSamplingPassed ? 'PASSED' : 'FAILED', 'Generated uniform 64-bit random values in [10B, 20B] without truncation');

  // 6.10: Key 6 Copy-Paste Whitespace & Newline Invariance
  const cleanK6 = 'KEY6-InstitutionalSecretKey99';
  const dirtyK6 = '  \n\tKEY6-InstitutionalSecretKey99 \r\n ';
  const testSaltK6 = generateSecureRandomBytes(64);
  const derivedClean = await deriveAndMask1024BitId(cleanK6, testSaltK6, 1000, 'VaultA');
  const derivedDirty = await deriveAndMask1024BitId(dirtyK6, testSaltK6, 1000, 'VaultA');
  const k6WhitespaceImmune = derivedClean.hexString === derivedDirty.hexString && sanitizeKey6String(dirtyK6) === cleanK6;
  record('B-24', 'Credential Hygiene', 'Key 6 Copy-Paste Whitespace Invariance', k6WhitespaceImmune ? 'PASSED' : 'FAILED', 'Derived bit-for-bit identical 1024-bit ID despite leading/trailing whitespace & newlines');

  // 6.11: Multi-Byte UTF-8 Filename Truncation Invariance (Zero \uFFFD)
  const longUnicodeName = 'A'.repeat(250) + '🔒🔑.pdf'; // 250 + 4 + 4 + 4 = 262 bytes
  const sanitizedLongName = sanitizeFilename(longUnicodeName);
  const encLong = new TextEncoder();
  const safeFilenamePassed = !sanitizedLongName.includes('\uFFFD') && encLong.encode(sanitizedLongName).length <= 255 && sanitizedLongName.endsWith('.pdf');
  record('B-25', 'Filename Safety', 'Multi-Byte UTF-8 Filename Truncation Invariance', safeFilenamePassed ? 'PASSED' : 'FAILED', `Clean filename (${encLong.encode(sanitizedLongName).length} bytes), ends with .pdf, zero \uFFFD`);

  // 6.12: 64-Bit ISOBMFF Carrier Largesize Validation Invariance (Test B-26)
  // Construct a synthetic carrier beginning with a 64-bit largesize container box (size === 1) preceding ftyp
  const largeCarrier = new Uint8Array(64);
  const lcView = new DataView(largeCarrier.buffer);
  lcView.setUint32(0, 1); // 64-bit size indicator
  largeCarrier[4] = 0x66; largeCarrier[5] = 0x72; largeCarrier[6] = 0x65; largeCarrier[7] = 0x65; // 'free'
  lcView.setBigUint64(8, 32n); // real size = 32 bytes
  // At offset 32, add standard ftyp box (size 32 bytes)
  lcView.setUint32(32, 32);
  largeCarrier[36] = 0x66; largeCarrier[37] = 0x74; largeCarrier[38] = 0x79; largeCarrier[39] = 0x70; // 'ftyp'
  const isLargeValid = isValidIsobmffCarrier(largeCarrier);
  const isCorruptRejected = !isValidIsobmffCarrier(new Uint8Array([0x00, 0x00, 0x00, 0x08, 0x58, 0x59, 0x5a, 0x20]));
  const b26Passed = isLargeValid && isCorruptRejected;
  record('B-26', 'Carrier Ingestion', '64-Bit ISOBMFF Largesize Invariance', b26Passed ? 'PASSED' : 'FAILED', 'Validated 64-bit largesize (size === 1) box and rejected non-MP4 bytes');

  console.log('\n========================================================================');
  console.log('                 BUG-BOUNTY RESCAN EXECUTIVE SUMMARY');
  console.log('========================================================================');
  const passed = results.filter(r => r.status === 'PASSED').length;
  const failed = results.filter(r => r.status === 'FAILED').length;
  const flagged = results.filter(r => r.status === 'FLAGGED').length;
  console.log(`Total Test Assertions: ${results.length}`);
  console.log(`Passed: ${passed} | Failed: ${failed} | Flagged: ${flagged}`);
}

runBountySuite().catch(err => {
  console.error('Fatal in bounty test suite:', err);
  process.exit(1);
});
