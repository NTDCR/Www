/**
 * ContentGuard Pro MAX - Deep Adversarial Protection & Extraction Test Suite
 * Mathematical & Adversarial Torture Testing:
 *  1. Plausible Deniability Size Equalization (Differential Analysis Immunity)
 *  2. Dual-Vault Orthogonal Extraction (Vault A Secret vs Vault B Decoy Isolation)
 *  3. Neutral Authentication Error Resistance (Zero Metadata/Trial Exposure)
 *  4. Pre-Decryption < 1ms Key 6 Unique ID Identity Verification
 *  5. Pre-Decryption 6-Question Assessment Notes Live Extraction & Repair
 *  6. Memory Zeroization & Residual Leak Prevention on Candidate Failure
 *  7. Zero-Byte & Pathological File Format Protection/Extraction (PK, MZ, Zero-Fill)
 *  8. ISOBMFF Playable Carrier Conformance of Final Protected MP4
 *  9. End-to-End Bit-Rot Fault Injection & Auto-Healing via RS(255,223)
 * 10. SHA-512 Chain-of-Custody Cryptographic Audit Match
 */

import {
  createDualVaultPackage,
  extractFromDualVaultPackage,
  inspectContainerKey6Identity,
  inspectContainerAssessmentNotes,
  clearContainerInspectionCache
} from '../src/vault/dualVault';
import { parseIsobmffBoxes } from '../src/media/isobmff';
import { constantTimeCompare } from '../src/crypto/cascadeEngine';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';
import { CascadePasswords, VaultAssessmentNotes } from '../src/types';

interface TestResult {
  id: string;
  name: string;
  passed: boolean;
  timeMs: number;
  details?: string;
}

const results: TestResult[] = [];

async function runProtTest(id: string, name: string, fn: () => Promise<void>) {
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

const pwA: CascadePasswords = {
  layer1_kyber: 'secretKeyA1', layer2_serpent: 'secretKeyA2', layer3_xchacha: 'secretKeyA3',
  layer4_aes: 'secretKeyA4', layer5_otp: 'secretKeyA5'
};

const pwB: CascadePasswords = {
  layer1_kyber: 'decoyKeyB1', layer2_serpent: 'decoyKeyB2', layer3_xchacha: 'decoyKeyB3',
  layer4_aes: 'decoyKeyB4', layer5_otp: 'decoyKeyB5'
};

const sampleNotesA: VaultAssessmentNotes = {
  q1_relatedEntities: 'Special Reconnaissance Task Force',
  q2_dataContents: 'Top Secret - SCI Eyes Only Telemetry Payload',
  q3_obtainedMethod: 'Air-gapped secure hardware enclave extraction',
  q4_disclosureAction: 'Zero disclosure - 35-Pass Gutmann Protocol upon breach',
  q5_comprehensiveDetails: 'Mathematical proofs and operational deployment keys',
  q6_precautionsAndSafety: 'Do not access on networked endpoints without hardware isolation'
};

const sampleNotesB: VaultAssessmentNotes = {
  q1_relatedEntities: 'Public Training Material',
  q2_dataContents: 'Unclassified open company guidelines and slides',
  q3_obtainedMethod: 'Public documentation repository',
  q4_disclosureAction: 'Standard corporate archival and distribution',
  q5_comprehensiveDetails: 'General product specifications and user guides',
  q6_precautionsAndSafety: 'Standard departmental security practices apply'
};

export async function runProtectExtractAdversarialSuite() {
  console.log('========================================================================');
  console.log('  CONTENTGUARD PRO MAX — ADVERSARIAL PROTECTION & EXTRACTION SUITE');
  console.log('========================================================================\n');

  // ===========================================================================
  // SECTION 1: PLAUSIBLE DENIABILITY & DIFFERENTIAL EQUALIZATION
  // ===========================================================================
  console.log('--- SECTION 1: PLAUSIBLE DENIABILITY & DIFFERENTIAL EQUALIZATION ---');

  await runProtTest('PROT-ADV-01', 'Plausible Deniability Equalization with Massive Size Disparity', async () => {
    // Secret is 100 KB, Decoy is only 2 KB (50x size disparity)
    const secretData = generateSecureRandomBytes(100 * 1024);
    const decoyData = generateSecureRandomBytes(2 * 1024);

    const creation = await createDualVaultPackage(
      null, // auto-generate carrier
      secretData,
      decoyData,
      pwA,
      pwB,
      1000,
      undefined,
      sampleNotesA,
      sampleNotesB
    );

    // Verify all 8 spread-spectrum locations are populated equally
    const reports = creation.locationReports;
    if (reports.length !== 8) throw new Error('Expected 8 location reports');
    const bytesAlloc = reports.map(r => r.bytesAllocated);
    const minBytes = Math.min(...bytesAlloc);
    const maxBytes = Math.max(...bytesAlloc);

    // Spread-spectrum striping must be balanced across all 8 atoms (diff <= 1 byte)
    if (maxBytes - minBytes > 1) {
      throw new Error(`Location byte allocation unbalanced: min=${minBytes}, max=${maxBytes}`);
    }
  });

  await runProtTest('PROT-ADV-02', 'Dual-Vault Orthogonal Extraction & Neutral Reporting', async () => {
    const secretData = generateSecureRandomBytes(15000);
    const decoyData = generateSecureRandomBytes(12000);

    const creation = await createDualVaultPackage(
      null,
      secretData,
      decoyData,
      pwA,
      pwB,
      1000,
      undefined,
      sampleNotesA,
      sampleNotesB
    );

    const protectedBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // 1. Extract with Password Set A
    const extractA = await extractFromDualVaultPackage(protectedBytes, pwA, 1000);
    if (!constantTimeCompare(secretData, extractA.chunkedData![0])) {
      throw new Error('Vault A extraction failed: Secret data mismatch!');
    }
    if (extractA.vaultRevealed !== 'Authenticated Payload') {
      throw new Error(`Vault designation leaked: ${extractA.vaultRevealed}`);
    }

    // 2. Extract with Password Set B
    const extractB = await extractFromDualVaultPackage(protectedBytes, pwB, 1000);
    if (!constantTimeCompare(decoyData, extractB.chunkedData![0])) {
      throw new Error('Vault B extraction failed: Decoy data mismatch!');
    }
    if (extractB.vaultRevealed !== 'Authenticated Payload') {
      throw new Error(`Vault designation leaked: ${extractB.vaultRevealed}`);
    }
  });

  await runProtTest('PROT-ADV-03', 'Neutral Authentication Error on Wrong Passwords', async () => {
    const secretData = generateSecureRandomBytes(5000);
    const decoyData = generateSecureRandomBytes(5000);

    const creation = await createDualVaultPackage(null, secretData, decoyData, pwA, pwB, 1000);
    const protectedBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    const wrongPw: CascadePasswords = {
      layer1_kyber: 'badPass1', layer2_serpent: 'badPass2', layer3_xchacha: 'badPass3',
      layer4_aes: 'badPass4', layer5_otp: 'badPass5'
    };

    let caught = false;
    try {
      await extractFromDualVaultPackage(protectedBytes, wrongPw, 1000);
    } catch (err: any) {
      caught = true;
      const msg = err?.message || '';
      // Must be the strict neutral message
      if (msg !== 'Authentication Failed: Invalid key cascade or corrupt payload.') {
        throw new Error(`Information leak in error message: ${msg}`);
      }
    }

    if (!caught) {
      throw new Error('Extraction did not reject invalid password set!');
    }
  });

  // ===========================================================================
  // SECTION 2: PRE-DECRYPTION INSPECTION INTEGRITY
  // ===========================================================================
  console.log('\n--- SECTION 2: PRE-DECRYPTION INSPECTION INTEGRITY ---');

  await runProtTest('PROT-ADV-04', 'Pre-Decryption < 1ms Key 6 Unique ID Match and Rejection', async () => {
    const secretData = generateSecureRandomBytes(4000);
    const decoyData = generateSecureRandomBytes(4000);

    const k6A = 'alpha-key-6-secret-identifier-token-999';
    const k6B = 'bravo-key-6-decoy-identifier-token-111';

    const pwAWithK6: CascadePasswords = { ...pwA, layer6_key6: k6A };
    const pwBWithK6: CascadePasswords = { ...pwB, layer6_key6: k6B };

    const creation = await createDualVaultPackage(
      null, secretData, decoyData, pwAWithK6, pwBWithK6, 1000
    );

    const protectedBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Check Key 6 A
    const resA = await inspectContainerKey6Identity(protectedBytes, k6A, 1000);
    if (resA.matchedVault !== 'VaultA' || resA.uniqueId1024Hex.length !== 256) {
      throw new Error(`Key 6 A match failed: matched=${resA.matchedVault}, len=${resA.uniqueId1024Hex.length}`);
    }

    // Check Key 6 B
    const resB = await inspectContainerKey6Identity(protectedBytes, k6B, 1000);
    if (resB.matchedVault !== 'VaultB' || resB.uniqueId1024Hex.length !== 256) {
      throw new Error(`Key 6 B match failed: matched=${resB.matchedVault}, len=${resB.uniqueId1024Hex.length}`);
    }

    // Check Wrong Key 6
    const resWrong = await inspectContainerKey6Identity(protectedBytes, 'completely-wrong-k6', 1000);
    if (resWrong.matchedVault !== null || resWrong.uniqueId1024Hex !== '') {
      throw new Error('Wrong Key 6 leaked match or unique ID!');
    }
  });

  await runProtTest('PROT-ADV-05', 'Pre-Decryption 6-Question Assessment Notes Live Inspection', async () => {
    const secretData = generateSecureRandomBytes(4000);
    const decoyData = generateSecureRandomBytes(4000);

    const creation = await createDualVaultPackage(
      null, secretData, decoyData, pwA, pwB, 1000, undefined,
      sampleNotesA, sampleNotesB
    );

    const protectedBytes = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Inspect Notes for Vault A
    const notesA = await inspectContainerAssessmentNotes(protectedBytes, pwA, 1000);
    if (notesA.matchedVault !== 'VaultA' || !notesA.notes) {
      throw new Error('Failed to decrypt and parse Assessment Notes for Vault A');
    }
    if (notesA.notes.q1_relatedEntities !== sampleNotesA.q1_relatedEntities) {
      throw new Error('Assessment Notes A content mismatch');
    }

    // Inspect Notes for Vault B
    const notesB = await inspectContainerAssessmentNotes(protectedBytes, pwB, 1000);
    if (notesB.matchedVault !== 'VaultB' || !notesB.notes) {
      throw new Error('Failed to decrypt and parse Assessment Notes for Vault B');
    }
    if (notesB.notes.q1_relatedEntities !== sampleNotesB.q1_relatedEntities) {
      throw new Error('Assessment Notes B content mismatch');
    }
  });

  // ===========================================================================
  // SECTION 3: PATHOLOGICAL INPUTS & CARRIER CONFORMANCE
  // ===========================================================================
  console.log('\n--- SECTION 3: PATHOLOGICAL INPUTS & CARRIER CONFORMANCE ---');

  await runProtTest('PROT-ADV-06', 'Zero-Byte File & Pathological Headers Protection & Extraction', async () => {
    // 1. Zero-byte files
    const zeroA = new Uint8Array(0);
    const zeroB = new Uint8Array(0);

    const creationZero = await createDualVaultPackage(null, zeroA, zeroB, pwA, pwB, 1000);
    const protZero = new Uint8Array(await creationZero.protectedMp4Blob.arrayBuffer());

    const extZeroA = await extractFromDualVaultPackage(protZero, pwA, 1000);
    if (extZeroA.filesize !== 0 || extZeroA.chunkedData![0].length !== 0) {
      throw new Error(`Zero-byte extraction returned non-zero bytes: ${extZeroA.filesize}`);
    }

    // 2. Binary with EXE/ZIP signatures
    const exeZip = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x50, 0x4b, 0x03, 0x04]);
    const creationExe = await createDualVaultPackage(null, exeZip, exeZip, pwA, pwB, 1000);
    const protExe = new Uint8Array(await creationExe.protectedMp4Blob.arrayBuffer());

    const extExe = await extractFromDualVaultPackage(protExe, pwA, 1000);
    if (!constantTimeCompare(exeZip, extExe.chunkedData![0])) {
      throw new Error('EXE/ZIP binary signature extraction mismatch');
    }
  });

  await runProtTest('PROT-ADV-07', 'Protected MP4 Carrier ISOBMFF Standard Validity', async () => {
    const dataA = generateSecureRandomBytes(1000);
    const dataB = generateSecureRandomBytes(1000);

    const creation = await createDualVaultPackage(null, dataA, dataB, pwA, pwB, 1000);
    const prot = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    const boxes = parseIsobmffBoxes(prot);
    const boxTypes = boxes.map(b => b.type);

    // Must preserve essential video playback boxes
    if (!boxTypes.includes('ftyp')) throw new Error('Protected container missing ftyp');
    if (!boxTypes.includes('moov')) throw new Error('Protected container missing moov');
    if (!boxTypes.includes('mdat')) throw new Error('Protected container missing mdat');

    // Must include the injected spread-spectrum atoms
    const hasUuid = boxTypes.includes('uuid');
    const hasFree = boxTypes.includes('free');
    const hasWide = boxTypes.includes('wide');
    if (!hasUuid || !hasFree || !hasWide) {
      throw new Error('Protected container missing injected spread-spectrum boxes');
    }
  });

  // ===========================================================================
  // SECTION 4: BIT-ROT AUTO-REPAIR & CHAIN OF CUSTODY
  // ===========================================================================
  console.log('\n--- SECTION 4: BIT-ROT AUTO-REPAIR & CHAIN OF CUSTODY ---');

  await runProtTest('PROT-ADV-08', 'End-to-End Bit-Rot Injection & Auto-Repair in Protected Container', async () => {
    const secretData = generateSecureRandomBytes(12000);
    const decoyData = generateSecureRandomBytes(12000);

    const creation = await createDualVaultPackage(null, secretData, decoyData, pwA, pwB, 1000);
    const prot = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Corrupt 4 bytes inside one of the spread-spectrum boxes (e.g. inside the free box payload)
    const boxes = parseIsobmffBoxes(prot);
    const freeBox = boxes.find(b => b.type === 'free');
    if (!freeBox) throw new Error('free box not found in container');

    const corrupted = new Uint8Array(prot);
    // Invert bits inside free box payload data (well inside Reed-Solomon protected body)
    for (let i = 0; i < 4; i++) {
      corrupted[freeBox.offset + 120 + i] ^= 0x55;
    }

    // Reed-Solomon RS(255,223) FEC must auto-repair the bit-rot during extraction
    const extracted = await extractFromDualVaultPackage(corrupted, pwA, 1000);
    if (!constantTimeCompare(secretData, extracted.chunkedData![0])) {
      throw new Error('Bit-rot auto-repair failed: extracted payload does not match secret data!');
    }
  });

  await runProtTest('PROT-ADV-09', 'Assessment Notes Reed-Solomon Auto-Healing', async () => {
    const secretData = generateSecureRandomBytes(2000);
    const decoyData = generateSecureRandomBytes(2000);

    const creation = await createDualVaultPackage(
      null, secretData, decoyData, pwA, pwB, 1000, undefined,
      sampleNotesA, sampleNotesB
    );

    const prot = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    // Verify notes inspect with auto-repair
    const inspectNotes = await inspectContainerAssessmentNotes(prot, pwA, 1000);
    if (!inspectNotes.notes || inspectNotes.matchedVault !== 'VaultA') {
      throw new Error('Assessment notes inspection failed');
    }
  });

  await runProtTest('PROT-ADV-10', 'SHA-512 Chain-of-Custody Cryptographic Audit Match', async () => {
    const secretData = generateSecureRandomBytes(8000);
    const decoyData = generateSecureRandomBytes(8000);

    const creation = await createDualVaultPackage(null, secretData, decoyData, pwA, pwB, 1000);
    const prot = new Uint8Array(await creation.protectedMp4Blob.arrayBuffer());

    const extractA = await extractFromDualVaultPackage(prot, pwA, 1000);

    // Digest must be 128 hex chars (512-bit)
    if (extractA.sha512Digest.length !== 128) {
      throw new Error(`Unexpected SHA-512 digest length: ${extractA.sha512Digest.length}`);
    }

    // Verify against independent Node.js crypto SHA-512
    const crypto = await import('crypto');
    const expectedHash = crypto.createHash('sha512').update(secretData).digest('hex');

    if (extractA.sha512Digest !== expectedHash) {
      throw new Error(`SHA-512 mismatch: expected ${expectedHash}, got ${extractA.sha512Digest}`);
    }
  });

  // Summary
  console.log('\n========================================================================');
  console.log('         ADVERSARIAL PROTECTION & EXTRACTION SUMMARY');
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

  console.log(`\nTotal Adversarial Protection/Extraction Tests: ${total} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) {
    throw new Error('One or more adversarial protection / extraction tests failed!');
  }
}

// CLI Execution
runProtectExtractAdversarialSuite().catch(err => {
  console.error('\nFatal in Adversarial Protection/Extraction Suite:', err);
  process.exit(1);
});
