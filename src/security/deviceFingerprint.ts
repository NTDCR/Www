/**
 * ContentGuard Pro MAX - Zero-Knowledge Anonymity & Offline Recovery System
 * Device fingerprinting & hardware telemetry are completely wiped out for anti-forensic privacy.
 * 10 One-Time Emergency Recovery Codes stored in IndexedDB (Feature 49).
 */

import { DeviceFingerprint, RecoveryCode } from '../types';
import { generateSecureRandomBytes } from '../crypto/safeRandom';

/**
 * Zero-telemetry anonymous stubs for interface compatibility.
 * Hardware sniffing, canvas reading, WebGL extraction, and audio synthesis are permanently wiped out.
 */
export async function getCanvasFingerprint(): Promise<string> {
  return 'cv-anonymized-zero-telemetry';
}

export async function getWebGLFingerprint(): Promise<string> {
  return 'gl-anonymized-zero-telemetry';
}

export async function getAudioFingerprint(): Promise<string> {
  return 'au-anonymized-zero-telemetry';
}

export async function generateDeviceFingerprint(): Promise<DeviceFingerprint> {
  return {
    visitorId: 'CGP-ANONYMOUS',
    canvasHash: 'cv-anonymized',
    webglHash: 'gl-anonymized',
    audioHash: 'au-anonymized',
    hardwareConcurrency: 0,
    screenResolution: 'anonymized',
    colorDepth: 0,
    timezone: 'UTC',
    userAgentHash: 'ua-anonymized',
    generatedAt: new Date().toISOString()
  };
}

/**
 * 10 One-Time Recovery Codes stored in IndexedDB (Feature 49)
 */
const DB_NAME = 'ContentGuard_Pro_Security_DB';
const DB_VERSION = 1;
const STORE_NAME = 'recovery_codes';

function openIndexedDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      return reject(new Error('IndexedDB is not supported in this environment'));
    }
    try {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'index' });
        }
      };
      req.onblocked = () => {
        reject(new Error('IndexedDB open blocked: database locked by another tab or connection'));
      };
      req.onsuccess = () => {
        const db = req.result;
        // Auto-close connection immediately if another tab or emergency wipe requests database deletion
        db.onversionchange = () => {
          try { db.close(); } catch {}
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
    }
  });
}

/**
 * Generates 10 CSPRNG One-Time Recovery Codes purely in memory
 * without modifying persistent IndexedDB storage (used for tests and benchmarks).
 */
export function generateRecoveryCodesInMemory(): RecoveryCode[] {
  const codes: RecoveryCode[] = [];
  for (let i = 0; i < 10; i++) {
    const rawBytes = generateSecureRandomBytes(6);
    const code = Array.from(rawBytes)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join('')
      .match(/.{1,4}/g)!
      .join('-');
    codes.push({
      index: i + 1,
      code: `RC-${code}`,
      used: false
    });
  }
  return codes;
}

export async function generateAndStoreRecoveryCodes(): Promise<RecoveryCode[]> {
  const codes = generateRecoveryCodesInMemory();

  try {
    const db = await openIndexedDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.clear();
      for (const item of codes) {
        store.put(item);
      }
      tx.oncomplete = () => {
        try { db.close(); } catch {}
        resolve();
      };
      tx.onerror = () => {
        try { db.close(); } catch {}
        reject(tx.error);
      };
    });
  } catch (err) {
    console.warn('IndexedDB recovery code write fallback to memory:', err);
  }

  return codes;
}

export async function loadStoredRecoveryCodes(): Promise<RecoveryCode[]> {
  try {
    const db = await openIndexedDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => {
        try { db.close(); } catch {}
        if (req.result && req.result.length > 0) {
          resolve(req.result);
        } else {
          // Generate new set if empty
          generateAndStoreRecoveryCodes().then(resolve);
        }
      };
      req.onerror = () => {
        try { db.close(); } catch {}
        generateAndStoreRecoveryCodes().then(resolve);
      };
    });
  } catch {
    return generateAndStoreRecoveryCodes();
  }
}

export async function markRecoveryCodeUsed(index: number, usedState?: boolean): Promise<void> {
  try {
    const db = await openIndexedDB();
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(index);
      req.onsuccess = () => {
        if (req.result) {
          const item = req.result;
          item.used = usedState !== undefined ? usedState : !item.used;
          const putReq = store.put(item);
          putReq.onerror = () => reject(putReq.error);
        }
      };
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => {
        try { db.close(); } catch {}
        resolve();
      };
      tx.onerror = () => {
        try { db.close(); } catch {}
        reject(tx.error);
      };
    });
  } catch (err) {
    console.warn('Could not mark recovery code as used in DB:', err);
  }
}
