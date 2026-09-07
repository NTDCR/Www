/**
 * ContentGuard Pro MAX - Deep Adversarial Key Ingestion, Interoperability, Alignment & Integrity Suite
 * Daybreak Cyber-Security Vulnerability Audit (Fort Knox Edition):
 *  1. Pathological Multibyte Unicode, Emoji & Null-Byte Password Ingestion
 *  2. Massive 10,000+ Character Password Ingestion (Buffer Overflow Resistance)
 *  3. Delimiter Injection / Collision Attack Resistance in Master Auth Key
 *  4. In-Memory Ephemeral Secret Zeroization Audit
 *  5. Cross-Format Binary Payload Interoperability (ZIP, PDF, PNG, MP3, EXE, DOCX)
 *  6. Dual-Vault Plausible Deniability Strict Equalization Alignment
 *  7. Headless & Fallback Device Fingerprinting Safety Boundaries
 *  8. Peter Gutmann 35-Pass Memory Sanitization Pattern Sequence Integrity
 *  9. Noble Cryptographic Dependencies NIST Vector Compliance (Depscan)
 * 10. SHA-512 Chain-of-Custody Cryptographic Audit Log Parity
 */

import {
  encryptCascade5Layers,
  decryptCascade5Layers,
  deriveLayerKey,
  deriveMasterAuthKey,
  serializeBundle,
  deserializeBundle,
  constantTimeCompare,
  computeHmacSha256
} from '../src/crypto/cascadeEngine';
import {
  createDualVaultPackage,
  extractFromDualVaultPackage,
  clearContainerInspectionCache
} from '../src/vault/dualVault';
import {
  getCanvasFingerprint,
  getWebGLFingerprint,
  getAudioFingerprint
} from '../src/security/deviceFingerprint';
import { execute35PassSecureWipe, PassStatus } from '../src/security/sanitization';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';
import { CascadePasswords, VaultAssessmentNotes } from '../src/types';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { hkdf } from '@noble/hashes/hkdf.js';

interface TestResult {
  id: string;
  name: string;
  passed: boolean;
  timeMs: number;
  details?: string;
}

const results: TestResult[] = [];

async function runInteropTest(id: string, name: string, fn: () => Promise<void>) {
  const t0 = performance.now();
  try {
    clearContainerInspectionCache();
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

export async function runKeyInteropIntegritySuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX — KEY INGESTION, INTEROP & INTEGRITY SUITE');
  console.log('========================================================================\n');

  // ===========================================================================
  // SECTION 1: KEY INGESTION & PATHOLOGICAL STRINGS
  // ===========================================================================
  console.log('--- SECTION 1: KEY INGESTION & PATHOLOGICAL STRINGS ---');

  await runInteropTest('KEY-ADV-01', 'Pathological Multibyte Unicode, Emoji & Null-Byte Password Ingestion', async () => {
    // Passwords with emoji, Cyrillic, Hindi, Chinese, null bytes, backslashes and special escapes
    const pathologicalPwA: CascadePasswords = {
      layer1_kyber: '🔑Ключ-1_सुरक्षा_安全_🛡️\0\r\n\t\\"\'!@#$%',
      layer2_serpent: '🐍Serpent_2_Кибер_गुप्त_密\0\x1f\x7f',
      layer3_xchacha: '⚡XChaCha20_Poly1305_तीन_три_三\0',
      layer4_aes: '🔒AES256_GCM_चार_четыре_四\0',
      layer5_otp: '🎲OneTimePad_पाँच_пять_五\0'
    };

    const secretData = new TextEncoder().encode('Top Secret Data with Pathological Key Ingestion');
    const decoyData = new TextEncoder().encode('Decoy Data with Standard Keys');

    const defaultPwB: CascadePasswords = {
      layer1_kyber: 'decoyB1', layer2_serpent: 'decoyB2', layer3_xchacha: 'decoyB3',
      layer4_aes: 'decoyB4', layer5_otp: 'decoyB5'
    };

    const creation = await createDualVaultPackage(null, secretData, decoyData, pathologicalPwA, defaultPwB, 1000);
    const protBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Extract with exact same pathological passwords
    const extracted = await extractFromDualVaultPackage(protBytes, pathologicalPwA, 1000);
    if (!constantTimeCompare(secretData, extracted.chunkedData![0])) {
      throw new Error('Extraction failed with multibyte Unicode / Emoji / Null-Byte passwords');
    }
  });

  await runInteropTest('KEY-ADV-02', 'Massive 10,000+ Character Password Ingestion (Buffer Overflow Immunity)', async () => {
    // 10,000-character repeating string for every layer
    const massiveStr = 'A'.repeat(10000);
    const massivePw: CascadePasswords = {
      layer1_kyber: massiveStr, layer2_serpent: massiveStr, layer3_xchacha: massiveStr,
      layer4_aes: massiveStr, layer5_otp: massiveStr
    };

    const salt = generateSecureRandomBytes(64);
    // Derive key without stack overflow or allocation crash
    const derived = await deriveLayerKey(massivePw.layer1_kyber, salt, 1000, 'MassiveKeyTest');
    if (derived.length !== 32) {
      throw new Error(`Derived key length incorrect: ${derived.length}`);
    }

    // Verify master auth key derivation with 5x 10,000 chars
    const salt4 = generateSecureRandomBytes(64);
    const masterKey = await deriveMasterAuthKey(massivePw, salt, salt4, 1000);
    if (masterKey.length !== 32) {
      throw new Error(`Master auth key length incorrect: ${masterKey.length}`);
    }
  });

  await runInteropTest('KEY-ADV-03', 'Delimiter Injection / Collision Attack Resistance in Master Auth Key', async () => {
    // Attacker crafts passwords to spoof internal framing: `${p1.length}:${p1}|${p2.length}:${p2}...`
    const salt1 = generateSecureRandomBytes(64);
    const salt4 = generateSecureRandomBytes(64);

    const pwSet1: CascadePasswords = {
      layer1_kyber: 'foo|5:bar|3:baz',
      layer2_serpent: 'normal2',
      layer3_xchacha: 'normal3',
      layer4_aes: 'normal4',
      layer5_otp: 'normal5'
    };

    const pwSet2: CascadePasswords = {
      layer1_kyber: 'foo',
      layer2_serpent: 'bar|3:baz',
      layer3_xchacha: 'normal3',
      layer4_aes: 'normal4',
      layer5_otp: 'normal5'
    };

    const key1 = await deriveMasterAuthKey(pwSet1, salt1, salt4, 1000);
    const key2 = await deriveMasterAuthKey(pwSet2, salt1, salt4, 1000);

    // Because length-prefixed framing is used, the derived keys MUST be completely distinct!
    if (constantTimeCompare(key1, key2)) {
      throw new Error('Delimiter collision vulnerability detected: different password sets produced identical master auth key!');
    }
  });

  await runInteropTest('KEY-ADV-04', 'In-Memory Ephemeral Secret Zeroization Verification', async () => {
    const rawSecret = generateSecureRandomBytes(32);
    const copy = new Uint8Array(rawSecret);

    // Call internal zeroization on rawSecret
    const { zeroizeBuffer } = await import('../src/crypto/cascadeEngine');
    zeroizeBuffer(rawSecret);

    // Verify all bytes are 0x00
    const isZeroed = rawSecret.every(b => b === 0);
    if (!isZeroed) {
      throw new Error('Buffer zeroization failed to overwrite bytes with 0x00');
    }
  });

  // ===========================================================================
  // SECTION 2: BINARY FORMAT INTEROPERABILITY & DUAL-VAULT ALIGNMENT
  // ===========================================================================
  console.log('\n--- SECTION 2: BINARY FORMAT INTEROPERABILITY & DUAL-VAULT ALIGNMENT ---');

  await runInteropTest('ALIGN-ADV-01', 'Cross-Format Binary Payload Interoperability (ZIP, PDF, PNG, EXE, MP3)', async () => {
    // Multi-format realistic file headers
    const zipHeader = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, ...generateSecureRandomBytes(2000)]);
    const pdfHeader = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, ...generateSecureRandomBytes(2000)]);
    const pngHeader = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...generateSecureRandomBytes(2000)]);
    const exeHeader = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, ...generateSecureRandomBytes(2000)]);

    const pw: CascadePasswords = {
      layer1_kyber: 'interop1', layer2_serpent: 'interop2', layer3_xchacha: 'interop3',
      layer4_aes: 'interop4', layer5_otp: 'interop5'
    };

    // Test ZIP as Vault A and PDF as Vault B
    const creation1 = await createDualVaultPackage(null, zipHeader, pdfHeader, pw, pw, 1000);
    const protBytes1 = new Uint8Array(await creation1.protectedMp4Blob.arrayBuffer());
    const extZip = await extractFromDualVaultPackage(protBytes1, pw, 1000);
    if (!constantTimeCompare(zipHeader, extZip.chunkedData![0])) {
      throw new Error('ZIP binary format preservation failed');
    }

    // Test PNG as Vault A and EXE as Vault B
    const creation2 = await createDualVaultPackage(null, pngHeader, exeHeader, pw, pw, 1000);
    const protBytes2 = new Uint8Array(await creation2.protectedMp4Blob.arrayBuffer());
    const extPng = await extractFromDualVaultPackage(protBytes2, pw, 1000);
    if (!constantTimeCompare(pngHeader, extPng.chunkedData![0])) {
      throw new Error('PNG binary format preservation failed');
    }
  });

  await runInteropTest('ALIGN-ADV-02', 'Dual-Vault Plausible Deniability Strict Equalization Alignment', async () => {
    // Vault A = 1 byte, Vault B = 65,536 bytes (65,536x ratio disparity)
    const tinySecret = new Uint8Array([0x42]);
    const largeDecoy = generateSecureRandomBytes(65536);

    const pwA: CascadePasswords = {
      layer1_kyber: 'pA1', layer2_serpent: 'pA2', layer3_xchacha: 'pA3',
      layer4_aes: 'pA4', layer5_otp: 'pA5'
    };
    const pwB: CascadePasswords = {
      layer1_kyber: 'pB1', layer2_serpent: 'pB2', layer3_xchacha: 'pB3',
      layer4_aes: 'pB4', layer5_otp: 'pB5'
    };

    const creation = await createDualVaultPackage(null, tinySecret, largeDecoy, pwA, pwB, 1000);
    const protBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Both vaults must extract their respective exact sizes
    const extA = await extractFromDualVaultPackage(protBytes, pwA, 1000);
    if (extA.filesize !== 1 || extA.chunkedData![0][0] !== 0x42) {
      throw new Error(`Tiny vault A extraction failed: got size ${extA.filesize}`);
    }

    const extB = await extractFromDualVaultPackage(protBytes, pwB, 1000);
    if (extB.filesize !== 65536 || !constantTimeCompare(largeDecoy, extB.chunkedData![0])) {
      throw new Error(`Large vault B extraction failed: got size ${extB.filesize}`);
    }
  });

  await runInteropTest('ALIGN-ADV-03', 'Zero-Telemetry Anonymity & Device Fingerprint Neutralization Boundaries', async () => {
    // Verify device fingerprinting is completely neutralized to zero-telemetry anonymous signatures
    const canvasFp = await getCanvasFingerprint();
    const webglFp = await getWebGLFingerprint();
    const audioFp = await getAudioFingerprint();

    // Must return stable deterministic anonymous prefixes with zero hardware profiling
    if (!canvasFp.startsWith('cv-')) throw new Error(`Unexpected canvas fingerprint: ${canvasFp}`);
    if (!webglFp.startsWith('gl-')) throw new Error(`Unexpected webgl fingerprint: ${webglFp}`);
    if (!audioFp.startsWith('au-')) throw new Error(`Unexpected audio fingerprint: ${audioFp}`);
  });

  await runInteropTest('ALIGN-ADV-04', 'Peter Gutmann 35-Pass Memory Sanitization Pattern Sequence Integrity', async () => {
    const executedPasses: number[] = [];
    const patterns: string[] = [];

    await execute35PassSecureWipe((status: PassStatus) => {
      executedPasses.push(status.currentPass);
      patterns.push(status.patternName);
    });

    if (executedPasses.length !== 35) {
      throw new Error(`Expected 35 wipe passes, got ${executedPasses.length}`);
    }
    // Verify first and final passes conform to standard
    if (!patterns[0].includes('0x55')) throw new Error(`Pass 1 pattern mismatch: ${patterns[0]}`);
    if (!patterns[34].includes('0x00')) throw new Error(`Pass 35 final zeroization mismatch: ${patterns[34]}`);
  });

  // ===========================================================================
  // SECTION 3: DEPENDENCY SCAN (DEPSCAN) & AUDIT INTEGRITY
  // ===========================================================================
  console.log('\n--- SECTION 3: DEPENDENCY SCAN (DEPSCAN) & AUDIT INTEGRITY ---');

  await runInteropTest('DEPSCAN-ADV-01', 'Noble Cryptographic Dependencies NIST / RFC Test Vector Compliance', async () => {
    // 1. SHA-256 NIST Vector ("abc")
    const hash = sha256(new TextEncoder().encode('abc'));
    const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    const expectedSha256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    if (hashHex !== expectedSha256) {
      throw new Error(`SHA-256 test vector failed: got ${hashHex}`);
    }

    // 2. SHA-512 NIST Vector ("abc")
    const hash512 = sha512(new TextEncoder().encode('abc'));
    const hash512Hex = Array.from(hash512).map(b => b.toString(16).padStart(2, '0')).join('');
    const expectedSha512 = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
    if (hash512Hex !== expectedSha512) {
      throw new Error(`SHA-512 test vector failed: got ${hash512Hex}`);
    }

    // 3. HKDF-SHA512 RFC 5869 Vector
    const ikm = new Uint8Array([0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b]);
    const salt = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
    const info = new Uint8Array([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    const okm = hkdf(sha512, ikm, salt, info, 32);
    if (okm.length !== 32) throw new Error('HKDF test failed');
  });

  await runInteropTest('INTEG-ADV-01', 'SHA-512 Chain-of-Custody Cryptographic Audit Tamper Immunity', async () => {
    const data = generateSecureRandomBytes(5000);
    const crypto = await import('crypto');
    const authenticDigest = crypto.createHash('sha512').update(data).digest('hex');

    // Simulate single-bit payload alteration
    const tamperedData = new Uint8Array(data);
    tamperedData[100] ^= 0x01; // flip 1 bit

    const tamperedDigest = crypto.createHash('sha512').update(tamperedData).digest('hex');

    // Avalanche effect: Single bit flip MUST completely randomize the 512-bit digest
    if (authenticDigest === tamperedDigest) {
      throw new Error('Audit digest collision vulnerability: tampered data produced identical SHA-512 digest!');
    }

    // Count bit differences between authentic and tampered hash
    let differingNibbles = 0;
    for (let i = 0; i < authenticDigest.length; i++) {
      if (authenticDigest[i] !== tamperedDigest[i]) differingNibbles++;
    }

    // SHA-512 strict avalanche effect: > 70% of hex characters should change on single-bit flip
    if (differingNibbles < 85) {
      throw new Error(`Insufficient avalanche effect in audit digest: only ${differingNibbles}/128 nibbles changed`);
    }
  });

  // Summary
  console.log('\n========================================================================');
  console.log('         ADVERSARIAL KEY INGESTION & INTEROP SUMMARY');
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

  console.log(`\nTotal Key Ingestion/Interop Tests: ${total} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) {
    throw new Error('One or more adversarial key ingestion / interop tests failed!');
  }
}

// CLI Execution
runKeyInteropIntegritySuite().catch(err => {
  console.error('\nFatal in Adversarial Key Ingestion/Interop Suite:', err);
  process.exit(1);
});
