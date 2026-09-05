/**
 * ContentGuard Pro MAX - Comprehensive Data Assessment Notes Cryptographic Engine
 * 
 * Cryptographic Architecture:
 * 1. Independent Cascade Encryption (K1-K6):
 *    - Encrypts the 6 mandatory Data Assessment questions & answers with Layer 1 AES-256-GCM,
 *      Layer 2 XChaCha20-Poly1305, and Layer 3 Serpent-256-CTR.
 * 2. Independent XOR Keystream Masking (High-Entropy Garbage Form):
 *    - Applies an independent one-time HKDF-derived keystream mask, rendering the ciphertext indistinguishable
 *      from uniform CSPRNG noise (7.999+ bits/byte entropy).
 * 3. Reed-Solomon RS(255, 223) Error Correction:
 *    - The notes envelope is protected with forward error correction, ensuring damage tolerance and auto-repair.
 * 4. Separate Payload Independence:
 *    - Stored in its own dedicated block independent from the media payload.
 * 5. Pre-Decryption Verification & Inspection:
 *    - Decodes RS, unmasks XOR garbage, validates HMAC in constant time, and decrypts the assessment notes
 *      for preview before final extraction.
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { generateSecureRandomBytes, generateCSPRNGKeystream } from './safeRandom';
import { constantTimeCompare, zeroizeBuffer, fastPbkdf2HmacSha512, DEFAULT_PBKDF2_ITERATIONS } from './cascadeEngine';
import { serpent256Ctr } from './serpent';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20Poly1305Encrypt, xchacha20Poly1305Decrypt } from './xchacha20poly1305';
import { encodeRSStream, decodeRSStream } from './reedSolomon';
import { CascadePasswords, VaultAssessmentNotes, createEmptyAssessmentNotes, isAssessmentNotesComplete } from '../types';

/** Maximum plaintext JSON size for assessment notes (DoS bound). */
const NOTES_JSON_MAX_BYTES = 256 * 1024;

const NOTES_SCHEMA_KEYS = [
  'q1_relatedEntities',
  'q2_dataContents',
  'q3_obtainedMethod',
  'q4_disclosureAction',
  'q5_comprehensiveDetails',
  'q6_precautionsAndSafety',
  'createdAt',
  '_p'
] as const;

const NOTES_REQUIRED_KEYS = [
  'q1_relatedEntities',
  'q2_dataContents',
  'q3_obtainedMethod',
  'q4_disclosureAction',
  'q5_comprehensiveDetails',
  'q6_precautionsAndSafety'
] as const;

/**
 * Safely parse assessment-notes JSON: size cap, prototype-pollution reject, schema allowlist.
 * Returns null on any validation failure (caller maps to neutral invalid result).
 */
export function parseAssessmentNotesJson(jsonStr: string): VaultAssessmentNotes | null {
  if (typeof jsonStr !== 'string' || jsonStr.length > NOTES_JSON_MAX_BYTES) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr, (key, value) => {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error('forbidden');
      }
      return value;
    });
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!(NOTES_SCHEMA_KEYS as readonly string[]).includes(k)) {
      return null;
    }
    if (typeof obj[k] !== 'string') {
      return null;
    }
  }
  for (const req of NOTES_REQUIRED_KEYS) {
    if (typeof obj[req] !== 'string') {
      return null;
    }
  }
  const notes: VaultAssessmentNotes = {
    q1_relatedEntities: obj.q1_relatedEntities as string,
    q2_dataContents: obj.q2_dataContents as string,
    q3_obtainedMethod: obj.q3_obtainedMethod as string,
    q4_disclosureAction: obj.q4_disclosureAction as string,
    q5_comprehensiveDetails: obj.q5_comprehensiveDetails as string,
    q6_precautionsAndSafety: obj.q6_precautionsAndSafety as string
  };
  if (typeof obj.createdAt === 'string') {
    notes.createdAt = obj.createdAt;
  }
  if (typeof obj._p === 'string') {
    notes._p = obj._p;
  }
  return notes;
}

export interface NotesDecryptionResult {
  valid: boolean;
  notes: VaultAssessmentNotes | null;
  error?: string;
  repairedErrors: number;
}

/**
 * Derives combined key material for notes from passwords (K1-K6) and a dedicated 64-byte salt
 */
async function deriveNotesKeyMaterial(
  passwords: CascadePasswords,
  salt64: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  vaultLabel: 'VaultA' | 'VaultB' = 'VaultA'
) {
  const p1 = passwords.layer1_kyber || '';
  const p2 = passwords.layer2_serpent || '';
  const p3 = passwords.layer3_xchacha || '';
  const p4 = passwords.layer4_aes || '';
  const p5 = passwords.layer5_otp || '';
  const p6 = passwords.layer6_key6 || '';
  // Length-prefixed framing eliminates delimiter collision & cross-input key injection
  const rawPwString = `${p1.length}:${p1}|${p2.length}:${p2}|${p3.length}:${p3}|${p4.length}:${p4}|${p5.length}:${p5}|${p6.length}:${p6}`;

  const enc = new TextEncoder();
  const pwBytes = enc.encode(rawPwString);
  let masterSecret: Uint8Array | null = null;

  try {
    // 1. Hardware-accelerated PBKDF2-HMAC-SHA512 (64 bytes master secret)
    masterSecret = await fastPbkdf2HmacSha512(pwBytes, salt64, iterations, 64);

    const infoPrefix = `ContentGuard-AssessmentNotes-${vaultLabel}`;

    // Derive subkeys
    const keyAes = hkdf(sha256, masterSecret.subarray(0, 32), salt64.subarray(0, 32), enc.encode(`${infoPrefix}-AES256`), 32);
    const keyXCha = hkdf(sha256, masterSecret.subarray(32, 64), salt64.subarray(16, 48), enc.encode(`${infoPrefix}-XChaCha20`), 32);
    const keySerpent = hkdf(sha256, masterSecret.subarray(0, 32), salt64.subarray(32, 64), enc.encode(`${infoPrefix}-Serpent256`), 32);
    const xorMaskKey = hkdf(sha512, masterSecret, salt64, enc.encode(`${infoPrefix}-XORMask`), 64);
    const hmacAuthKey = hkdf(sha256, masterSecret.subarray(16, 48), salt64.subarray(0, 32), enc.encode(`${infoPrefix}-HMACAuth`), 32);

    return { keyAes, keyXCha, keySerpent, xorMaskKey, hmacAuthKey };
  } finally {
    zeroizeBuffer(pwBytes, masterSecret);
  }
}

/**
 * Encrypts VaultAssessmentNotes with Cascade (AES-GCM + XChaCha20 + Serpent) + XOR Garbage Masking + Reed-Solomon RS(255, 223)
 */
export async function encryptAssessmentNotesBlock(
  notes: VaultAssessmentNotes,
  passwords: CascadePasswords,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  vaultLabel: 'VaultA' | 'VaultB' = 'VaultA'
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const jsonString = JSON.stringify(notes);
  const plaintext = enc.encode(jsonString);

  // Pre-flight check: Prevent encrypting oversized notes that would silently fail during extraction
  if (plaintext.length > NOTES_JSON_MAX_BYTES) {
    throw new Error(
      `Assessment notes payload (${(plaintext.length / 1024).toFixed(1)} KB) exceeds the maximum allowed size of ${(NOTES_JSON_MAX_BYTES / 1024)} KB. ` +
      `Please shorten your entries to prevent extraction rejection.`
    );
  }

  // 1. Fresh 64-byte CSPRNG salt & nonces
  const salt64 = generateSecureRandomBytes(64);
  const nonceAes = generateSecureRandomBytes(12);
  const nonceXCha = generateSecureRandomBytes(24);
  const ivSerpent = generateSecureRandomBytes(16);

  let keyAes: Uint8Array | null = null;
  let keyXCha: Uint8Array | null = null;
  let keySerpent: Uint8Array | null = null;
  let xorMaskKey: Uint8Array | null = null;
  let hmacAuthKey: Uint8Array | null = null;
  let l1Ciphertext: Uint8Array | null = null;
  let l2Ciphertext: Uint8Array | null = null;
  let l2Combined: Uint8Array | null = null;
  let l3Ciphertext: Uint8Array | null = null;
  let xorStream: Uint8Array | null = null;
  let maskedPayload: Uint8Array | null = null;
  let hmacHeader: Uint8Array | null = null;
  let hmacData: Uint8Array | null = null;
  let envelope: Uint8Array | null = null;

  try {
    // 2. Derive key materials
    const derived = await deriveNotesKeyMaterial(
      passwords,
      salt64,
      iterations,
      vaultLabel
    );
    keyAes = derived.keyAes;
    keyXCha = derived.keyXCha;
    keySerpent = derived.keySerpent;
    xorMaskKey = derived.xorMaskKey;
    hmacAuthKey = derived.hmacAuthKey;

    // 3. Layer 1: Authenticated AES-256-GCM via Audited Noble Ciphers
    const aesGcmCipher = gcm(keyAes, nonceAes);
    l1Ciphertext = aesGcmCipher.encrypt(plaintext);

    // 4. Layer 2: XChaCha20-Poly1305
    const l2Res = xchacha20Poly1305Encrypt(
      l1Ciphertext,
      keyXCha,
      nonceXCha
    );
    l2Ciphertext = l2Res.ciphertext;
    const l2Tag = l2Res.tag;

    // Combine l2Ciphertext + l2Tag (16 bytes)
    l2Combined = new Uint8Array(l2Ciphertext.length + l2Tag.length);
    l2Combined.set(l2Ciphertext, 0);
    l2Combined.set(l2Tag, l2Ciphertext.length);

    // 5. Layer 3: Serpent-256-CTR
    l3Ciphertext = serpent256Ctr(l2Combined, keySerpent, ivSerpent);

    // 6. Independent XOR Keystream Masking (Pure Garbage Form)
    xorStream = await generateCSPRNGKeystream(xorMaskKey, salt64, l3Ciphertext.length);
    maskedPayload = new Uint8Array(l3Ciphertext.length);
    for (let i = 0; i < l3Ciphertext.length; i++) {
      maskedPayload[i] = l3Ciphertext[i] ^ xorStream[i];
    }

    // 7. HMAC-SHA256 Integrity Commitment Tag over the masked block
    hmacHeader = new Uint8Array(64 + 12 + 24 + 16);
    hmacHeader.set(salt64, 0);
    hmacHeader.set(nonceAes, 64);
    hmacHeader.set(nonceXCha, 64 + 12);
    hmacHeader.set(ivSerpent, 64 + 12 + 24);

    hmacData = new Uint8Array(hmacHeader.length + maskedPayload.length);
    hmacData.set(hmacHeader, 0);
    hmacData.set(maskedPayload, hmacHeader.length);

    const commitmentTag32 = hmac(sha256, hmacAuthKey, hmacData);

    // 8. Assemble Raw Unencoded Envelope:
    // [salt64 (64B) + nonceAes (12B) + nonceXCha (24B) + ivSerpent (16B) + commitmentTag32 (32B) + maskedPayload]
    envelope = new Uint8Array(64 + 12 + 24 + 16 + 32 + maskedPayload.length);
    let p = 0;
    envelope.set(salt64, p); p += 64;
    envelope.set(nonceAes, p); p += 12;
    envelope.set(nonceXCha, p); p += 24;
    envelope.set(ivSerpent, p); p += 16;
    envelope.set(commitmentTag32, p); p += 32;
    envelope.set(maskedPayload, p);

    // 9. Apply NASA CCSDS Reed-Solomon RS(255, 223) Forward Error Correction
    const { encodedData: rsNotesBlock } = encodeRSStream(envelope);
    return rsNotesBlock;
  } finally {
    // Clean all sensitive plaintext, intermediate buffers and keys
    zeroizeBuffer(
      plaintext,
      l1Ciphertext,
      l2Ciphertext,
      l2Combined,
      l3Ciphertext,
      xorStream,
      maskedPayload,
      hmacHeader,
      hmacData,
      envelope,
      keyAes,
      keyXCha,
      keySerpent,
      xorMaskKey,
      hmacAuthKey
    );
  }
}

/**
 * Decrypts and auto-repairs VaultAssessmentNotes from an RS-protected Notes Block
 */
export async function decryptAssessmentNotesBlock(
  rsNotesBlock: Uint8Array,
  passwords: CascadePasswords,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  vaultLabel: 'VaultA' | 'VaultB' = 'VaultA'
): Promise<NotesDecryptionResult> {
  if (!rsNotesBlock || rsNotesBlock.length === 0) {
    return { valid: false, notes: null, repairedErrors: 0 };
  }

  let keyAes: Uint8Array | null = null;
  let keyXCha: Uint8Array | null = null;
  let keySerpent: Uint8Array | null = null;
  let xorMaskKey: Uint8Array | null = null;
  let hmacAuthKey: Uint8Array | null = null;
  let l1Ciphertext: Uint8Array | null = null;
  let l2Combined: Uint8Array | null = null;
  let l3Ciphertext: Uint8Array | null = null;
  let xorStream: Uint8Array | null = null;
  let plaintext: Uint8Array | null = null;
  let envelope: Uint8Array | null = null;
  let hmacHeader: Uint8Array | null = null;
  let hmacData: Uint8Array | null = null;

  try {
    // 1. Decode & repair Reed-Solomon error correction
    const rsDecoded = decodeRSStream(rsNotesBlock);
    envelope = rsDecoded.data;
    const recoveredErrors = rsDecoded.recoveredErrors;

    // Header size: 64 (salt) + 12 (nonceAes) + 24 (nonceXCha) + 16 (ivSerpent) + 32 (tag) = 148 bytes
    if (envelope.length < 148) {
      // Zero-disclosure: no structural/header oracle
      return { valid: false, notes: null, repairedErrors: 0 };
    }

    let p = 0;
    const salt64 = envelope.subarray(p, p + 64); p += 64;
    const nonceAes = envelope.subarray(p, p + 12); p += 12;
    const nonceXCha = envelope.subarray(p, p + 24); p += 24;
    const ivSerpent = envelope.subarray(p, p + 16); p += 16;
    const expectedTag32 = envelope.subarray(p, p + 32); p += 32;
    const maskedPayload = envelope.subarray(p);

    // 2. Derive key materials
    const derived = await deriveNotesKeyMaterial(
      passwords,
      salt64,
      iterations,
      vaultLabel
    );
    keyAes = derived.keyAes;
    keyXCha = derived.keyXCha;
    keySerpent = derived.keySerpent;
    xorMaskKey = derived.xorMaskKey;
    hmacAuthKey = derived.hmacAuthKey;

    // 3. Verify HMAC commitment tag in constant-time
    hmacHeader = new Uint8Array(64 + 12 + 24 + 16);
    hmacHeader.set(salt64, 0);
    hmacHeader.set(nonceAes, 64);
    hmacHeader.set(nonceXCha, 64 + 12);
    hmacHeader.set(ivSerpent, 64 + 12 + 24);

    hmacData = new Uint8Array(hmacHeader.length + maskedPayload.length);
    hmacData.set(hmacHeader, 0);
    hmacData.set(maskedPayload, hmacHeader.length);

    const calculatedTag = hmac(sha256, hmacAuthKey, hmacData);
    const matches = constantTimeCompare(calculatedTag, expectedTag32);

    // Always unmask + decrypt path for timing symmetry; discard on HMAC/auth failure
    xorStream = await generateCSPRNGKeystream(xorMaskKey, salt64, maskedPayload.length);
    l3Ciphertext = new Uint8Array(maskedPayload.length);
    for (let i = 0; i < maskedPayload.length; i++) {
      l3Ciphertext[i] = maskedPayload[i] ^ xorStream[i];
    }

    l2Combined = serpent256Ctr(l3Ciphertext, keySerpent, ivSerpent);
    let serpentOk = l2Combined.length >= 16;
    let l2Ciphertext = serpentOk ? l2Combined.subarray(0, l2Combined.length - 16) : new Uint8Array(0);
    let l2Tag = serpentOk ? l2Combined.subarray(l2Combined.length - 16) : new Uint8Array(16);

    l1Ciphertext = serpentOk
      ? xchacha20Poly1305Decrypt(l2Ciphertext, l2Tag, keyXCha, nonceXCha)
      : null;
    const xchachaOk = !!l1Ciphertext;

    let aesOk = false;
    let parsedNotes: VaultAssessmentNotes | null = null;
    if (xchachaOk && l1Ciphertext) {
      try {
        const aesGcmCipher = gcm(keyAes, nonceAes);
        plaintext = aesGcmCipher.decrypt(l1Ciphertext);
        if (plaintext.length > NOTES_JSON_MAX_BYTES) {
          aesOk = false;
          parsedNotes = null;
        } else {
          const dec = new TextDecoder('utf-8');
          const jsonStr = dec.decode(plaintext);
          parsedNotes = parseAssessmentNotesJson(jsonStr);
          aesOk = parsedNotes !== null;
        }
      } catch {
        aesOk = false;
        parsedNotes = null;
      }
    }

    if (!(matches && serpentOk && xchachaOk && aesOk && parsedNotes)) {
      return { valid: false, notes: null, repairedErrors: 0 };
    }

    return {
      valid: true,
      notes: parsedNotes,
      repairedErrors: recoveredErrors
    };
  } catch {
    return {
      valid: false,
      notes: null,
      repairedErrors: 0
    };
  } finally {
    zeroizeBuffer(
      plaintext,
      l1Ciphertext,
      l2Combined,
      l3Ciphertext,
      xorStream,
      hmacHeader,
      hmacData,
      envelope,
      keyAes,
      keyXCha,
      keySerpent,
      xorMaskKey,
      hmacAuthKey
    );
  }
}

/**
 * Question Definitions and Descriptions for UI & Guidance
 */
export interface AssessmentQuestionDef {
  id: keyof VaultAssessmentNotes;
  number: number;
  title: string;
  shortLabel: string;
  description: string;
  placeholder: string;
}

export const ASSESSMENT_QUESTIONS: AssessmentQuestionDef[] = [
  {
    id: 'q1_relatedEntities',
    number: 1,
    title: 'Who or what is this data related to?',
    shortLabel: 'Related Entities & Connections',
    description: 'Identify and name every relevant person, individual, institution, organization, company, authority, government department, agency, group, system, platform, location, project, event, or any other entity that is directly or indirectly connected with the data. Also explain the nature of each connection wherever relevant.',
    placeholder: 'Name all relevant individuals, organizations, institutions, platforms, systems, locations, and the nature of each connection...'
  },
  {
    id: 'q2_dataContents',
    number: 2,
    title: 'What exactly does the data contain?',
    shortLabel: 'Data Nature, Scope & Sensitivity',
    description: 'Describe the complete nature, type, subject matter, scope, purpose, content, meaning, sensitivity, importance, and key information contained in the data. Explain what the data appears to represent, what can reasonably be understood from it, and which parts are particularly significant.',
    placeholder: 'Describe the subject matter, technical/operational scope, sensitivity rating, key records, and specific significant elements...'
  },
  {
    id: 'q3_obtainedMethod',
    number: 3,
    title: 'How was the data obtained?',
    shortLabel: 'Provenance, Chain of Custody & Method',
    description: 'Explain, as completely as possible, how, when, where, from whom, through which source, system, device, platform, communication, document, account, or method the data was received, accessed, collected, generated, discovered, downloaded, transferred, recorded, stored, or otherwise obtained. Clearly distinguish known facts from assumptions or uncertain information.',
    placeholder: 'Detail the acquisition date, source system, device, transfer protocol, intermediary custody, and differentiate facts from assumptions...'
  },
  {
    id: 'q4_disclosureAction',
    number: 4,
    title: 'Who, if anyone, should this data be given, shared with, disclosed to, preserved for, or reported to?',
    shortLabel: 'Recipients & Severity Response Matrix',
    description: 'Assess this according to the nature, sensitivity, seriousness, legality, urgency, possible harm, and potential consequences of the data. Identify the appropriate person, organization, institution, authority, regulator, professional adviser, law-enforcement body, emergency service, or other relevant recipient where applicable.\n\nCategorize the recommended response according to severity:\n- Informational / No Action Required\n- Low Priority\n- Moderate Priority\n- High Priority\n- Critical\n- Emergency / Immediate Action Required\n\nFor each applicable level, explain why that level applies, what should be done, what should not be done, and how urgently action is required.',
    placeholder: 'Specify authorized recipients, legal/regulatory reporting mandates, priority severity level (e.g. Critical, Moderate), and what must/must not be done...'
  },
  {
    id: 'q5_comprehensiveDetails',
    number: 5,
    title: 'Describe everything related to, connected with, arising from, or reasonably relevant to this data in complete detail so that I can achieve maximum mental satisfaction, clarity, and closure regarding the matter.',
    shortLabel: 'Full Context, Analysis & Resolution Details',
    description: 'Examine the matter from all reasonably relevant angles. Include the complete background, context, timeline, persons and entities involved, relationships, circumstances, sources, causes, purposes, events, patterns, dependencies, implications, risks, uncertainties, inconsistencies, responsibilities, obligations, consequences, possible interpretations, possible misunderstandings, alternative explanations, unresolved points, necessary actions, optional actions, follow-ups, closure conditions, and any other direct or indirect aspect that could reasonably matter.\n\nClearly separate:\n- Established facts\n- Reasonable inferences\n- Possibilities\n- Unverified claims\n- Unknown information\n- Matters that cannot be determined from the available data\n\nAlso explain whether anything important may still be missing, what additional information would materially change the assessment, which concerns are genuinely significant, which concerns are minor, and which concerns do not require further attention. The objective is to leave no important issue unexplained, overlooked, confused, or unnecessarily unresolved.',
    placeholder: 'Provide the comprehensive background, complete timeline, known facts vs possibilities, risk analysis, root causes, obligations, and closure criteria in exhaustive detail...'
  },
  {
    id: 'q6_precautionsAndSafety',
    number: 6,
    title: 'What precautions should be followed in relation to this data and in the wider situation surrounding it?',
    shortLabel: 'Precautions, Handling & Risk Mitigation',
    description: 'Provide all reasonable precautions that are:\n- Directly related to the data\n- Indirectly related to the data\n- Relevant to handling, storing, copying, transmitting, deleting, preserving, or sharing the data\n- Relevant to privacy and confidentiality\n- Relevant to cybersecurity and device security\n- Relevant to legal or regulatory exposure\n- Relevant to financial risks\n- Relevant to reputation or professional consequences\n- Relevant to personal or physical safety\n- Relevant to communication with other people\n- Relevant to evidence preservation and documentation\n- Relevant to avoiding accidental misuse, disclosure, alteration, loss, or destruction\n- Relevant even if they appear unrelated at first but could reasonably reduce risk\n\nClearly distinguish essential precautions from optional best practices and explain any actions that should specifically be avoided.',
    placeholder: 'List essential vs optional precautions covering operational security, digital isolation, legal safeguards, safety protocols, and actions strictly to avoid...'
  }
];
