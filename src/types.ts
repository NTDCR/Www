export interface CascadePasswords {
  layer1_kyber: string;
  layer2_serpent: string;
  layer3_xchacha: string;
  layer4_aes: string;
  layer5_otp: string;
  layer6_key6?: string;
}

export interface VaultAssessmentNotes {
  q1_relatedEntities: string;
  q2_dataContents: string;
  q3_obtainedMethod: string;
  q4_disclosureAction: string;
  q5_comprehensiveDetails: string;
  q6_precautionsAndSafety: string;
  createdAt?: string;
  _p?: string;
}

export function createEmptyAssessmentNotes(): VaultAssessmentNotes {
  return {
    q1_relatedEntities: '',
    q2_dataContents: '',
    q3_obtainedMethod: '',
    q4_disclosureAction: '',
    q5_comprehensiveDetails: '',
    q6_precautionsAndSafety: '',
    createdAt: new Date().toISOString()
  };
}

export function isAssessmentNotesComplete(notes?: VaultAssessmentNotes | null): boolean {
  if (!notes) return false;
  return Boolean(
    (notes.q1_relatedEntities || '').trim().length > 0 &&
    (notes.q2_dataContents || '').trim().length > 0 &&
    (notes.q3_obtainedMethod || '').trim().length > 0 &&
    (notes.q4_disclosureAction || '').trim().length > 0 &&
    (notes.q5_comprehensiveDetails || '').trim().length > 0 &&
    (notes.q6_precautionsAndSafety || '').trim().length > 0
  );
}

export interface DualVaultInputs {
  carrierFile: File | null;
  vaultAFile: File | null;
  vaultBFile: File | null;
  vaultAPasswords: CascadePasswords;
  vaultBPasswords: CascadePasswords;
  vaultANotes: VaultAssessmentNotes;
  vaultBNotes: VaultAssessmentNotes;
  pbkdf2Iterations: number;
}

export interface StatisticalMetrics {
  originalEntropy?: number;
  rawEntropy?: number;
  encryptedEntropy?: number;
  containerEntropy?: number;
  normalizedEntropy: number;
  chiSquareValue: number;
  chiSquarePValue: number;
  samplePairMatchRate: number;
  psnrDb: number;
  ssim: number;
  histogramNatural: number[];
  histogramProtected: number[];
  isCompliant: boolean;
}

export interface EmbeddingLocationReport {
  id: string;
  name: string;
  category: string;
  bytesAllocated: number;
  redundancyFactor: number;
  status: string;
  description: string;
}

export interface ProcessProgress {
  stage: string;
  percentage: number;
  currentOperation: string;
  vaultId: 'A' | 'B' | 'both';
  workerId: number;
  throughputMbPerSec: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: 'ENCRYPTION' | 'DECRYPTION' | 'DUAL_VAULT_CREATION' | 'ZEROIZATION' | 'FINGERPRINT_VERIFY' | 'INTEGRITY_CHECK' | 'SYSTEM_INIT';
  vaultTarget: string;
  sha512Digest: string;
  complianceRef: string;
  status: 'SUCCESS' | 'WARNING' | 'ALERT' | 'VERIFIED';
  details?: string;
}

export interface DeviceFingerprint {
  visitorId: string;
  canvasHash: string;
  webglHash: string;
  audioHash: string;
  hardwareConcurrency: number;
  screenResolution: string;
  colorDepth: number;
  timezone: string;
  userAgentHash: string;
  generatedAt: string;
}

export interface RecoveryCode {
  code: string;
  used: boolean;
  index: number;
}

export interface DualVaultCreationResult {
  protectedMp4Blob: Blob;
  protectedMp4Bytes: Uint8Array;
  protectedChunks?: Uint8Array[];
  metrics: StatisticalMetrics;
  locationReports: EmbeddingLocationReport[];
  vaultASize: number;
  vaultBSize: number;
  sha512Digest: string;
}

export interface DualVaultExtractionResult {
  fileBlob: Blob;
  chunkedData?: Uint8Array[];
  filename: string;
  filesize: number;
  vaultRevealed?: string;
  sha512Digest: string;
  assessmentNotes?: VaultAssessmentNotes;
  matchedVault?: 'VaultA' | 'VaultB';
}
