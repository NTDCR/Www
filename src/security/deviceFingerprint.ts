/**
 * ContentGuard Pro MAX - Device Security & Hardware Identification
 * Software device identification using Canvas 2D, WebGL 3D, and Web Audio API synthesis
 * 10 One-Time Recovery Codes stored in IndexedDB (Feature 48, 49)
 * Powered by Web Crypto SHA-256 and CSPRNG.
 */

import { DeviceFingerprint, RecoveryCode } from '../types';
import { generateSecureRandomBytes } from '../crypto/safeRandom';

/**
 * Helper to compute SHA-256 hex string from any text
 */
async function sha256Hex(text: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    // Fallback constant-length hex
    let h1 = 0xdeadbeef, h2 = 0x41c64e6d;
    for (let i = 0; i < text.length; i++) {
      const ch = text.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    return Math.abs(h1).toString(16).padStart(8, '0') + Math.abs(h2).toString(16).padStart(8, '0');
  }
}

/**
 * Generates Canvas 2D render fingerprint hash
 */
export async function getCanvasFingerprint(): Promise<string> {
  try {
    if (typeof document === 'undefined') return 'cv-headless-df81';
    const canvas = document.createElement('canvas');
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'canvas-unavailable';

    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial', sans-serif";
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('ContentGuard Pro MAX <drm>', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('ContentGuard Pro MAX <drm>', 4, 17);

    const dataUrl = canvas.toDataURL();
    const hex = await sha256Hex(dataUrl);
    return 'cv-' + hex.slice(0, 12);
  } catch {
    return 'cv-fallback-df81';
  }
}

/**
 * Generates WebGL GPU Renderer & Vendor hash
 */
export async function getWebGLFingerprint(): Promise<string> {
  try {
    if (typeof document === 'undefined') return 'gl-headless';
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'webgl-disabled';

    const debugInfo = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
      const vendor = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';
      const renderer = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
      const hex = await sha256Hex(vendor + '::' + renderer);
      return 'gl-' + hex.slice(0, 12);
    }
    return 'gl-generic';
  } catch {
    return 'gl-fallback';
  }
}

/**
 * Generates Web Audio API synthesis oscillation buffer fingerprint
 */
export async function getAudioFingerprint(): Promise<string> {
  try {
    if (typeof window === 'undefined') return 'au-headless';
    const OfflineContextClass = window.OfflineAudioContext || (window as unknown as { webkitOfflineAudioContext: typeof OfflineAudioContext }).webkitOfflineAudioContext;
    if (!OfflineContextClass) return 'audio-unavailable';

    // Modern future-proof W3C standard: OfflineAudioContext with DynamicsCompressorNode
    // 0 deprecation warnings, deterministic hardware audio DSP render, no audio playback needed
    const ctx = new OfflineContextClass(1, 44100, 44100);
    const oscillator = ctx.createOscillator();
    oscillator.type = 'triangle';
    oscillator.frequency.setValueAtTime(10000, ctx.currentTime);

    const compressor = ctx.createDynamicsCompressor();
    compressor.threshold.setValueAtTime(-50, ctx.currentTime);
    compressor.knee.setValueAtTime(40, ctx.currentTime);
    compressor.ratio.setValueAtTime(12, ctx.currentTime);
    compressor.attack.setValueAtTime(0, ctx.currentTime);
    compressor.release.setValueAtTime(0.25, ctx.currentTime);

    oscillator.connect(compressor);
    compressor.connect(ctx.destination);
    oscillator.start(0);

    const renderedBuffer = await ctx.startRendering();
    const channelData = renderedBuffer.getChannelData(0);
    let sum = 0;
    const step = Math.max(1, Math.floor(channelData.length / 500));
    for (let i = 0; i < channelData.length; i += step) {
      sum += Math.abs(channelData[i]);
    }

    const hex = await sha256Hex('audio-' + sum.toFixed(8));
    return 'au-' + hex.slice(0, 10);
  } catch {
    return 'au-fallback';
  }
}

/**
 * Compiles full device hardware/software fingerprint with SHA-256
 */
export async function generateDeviceFingerprint(): Promise<DeviceFingerprint> {
  const cvHash = await getCanvasFingerprint();
  const glHash = await getWebGLFingerprint();
  const auHash = await getAudioFingerprint();
  const uaStr = typeof navigator !== 'undefined' ? navigator.userAgent : 'ContentGuard-Pro-MAX';
  const uaHash = await sha256Hex(uaStr);

  const hwConcurrency = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency || 8 : 8;
  const scrWidth = typeof window !== 'undefined' && window.screen ? window.screen.width : 1920;
  const scrHeight = typeof window !== 'undefined' && window.screen ? window.screen.height : 1080;
  const clrDepth = typeof window !== 'undefined' && window.screen ? window.screen.colorDepth || 24 : 24;

  const visitorSeed = `${cvHash}:${glHash}:${auHash}:${uaHash}:${hwConcurrency}:${scrWidth}x${scrHeight}`;
  const fullDigest = await sha256Hex(visitorSeed);
  const visitorId = 'CGP-' + fullDigest.slice(0, 12).toUpperCase();

  return {
    visitorId,
    canvasHash: cvHash,
    webglHash: glHash,
    audioHash: auHash,
    hardwareConcurrency: hwConcurrency,
    screenResolution: `${scrWidth}x${scrHeight}`,
    colorDepth: clrDepth,
    timezone: (() => {
      try {
        return (typeof Intl !== 'undefined' && Intl.DateTimeFormat)
          ? Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
          : 'UTC';
      } catch {
        return 'UTC';
      }
    })(),
    userAgentHash: 'ua-' + uaHash.slice(0, 12),
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
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
  });
}

export async function generateAndStoreRecoveryCodes(): Promise<RecoveryCode[]> {
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

  try {
    const db = await openIndexedDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.clear();
    for (const item of codes) {
      store.put(item);
    }
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
        if (req.result && req.result.length > 0) {
          resolve(req.result);
        } else {
          // Generate new set if empty
          generateAndStoreRecoveryCodes().then(resolve);
        }
      };
      req.onerror = () => {
        generateAndStoreRecoveryCodes().then(resolve);
      };
    });
  } catch {
    return generateAndStoreRecoveryCodes();
  }
}

export async function markRecoveryCodeUsed(index: number): Promise<void> {
  try {
    const db = await openIndexedDB();
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(index);
      req.onsuccess = () => {
        if (req.result) {
          const item = req.result;
          item.used = true;
          const putReq = store.put(item);
          putReq.onerror = () => reject(putReq.error);
        }
      };
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (err) {
    console.warn('Could not mark recovery code as used in DB:', err);
  }
}
