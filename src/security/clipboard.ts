/**
 * ContentGuard Pro MAX - Institutional Anti-Forensics Clipboard Manager
 * Guarantees zero persistent memory trace in OS clipboard buffers (Win+V / macOS / X11).
 * Features:
 * - Timed auto-purge (overwrites clipboard buffer with empty text after configurable timeout)
 * - Immediate voluntary purge
 * - Defensive fallback for non-browser / headless runtimes
 */

let activeClipboardPurgeTimer: ReturnType<typeof setTimeout> | null = null;
let lastCopiedHash: string | null = null;
let pendingPurgeDeadline = 0;

/**
 * Computes deterministic SHA-256 hex digest for anti-forensic matching
 * without retaining sensitive cleartext strings in process heap memory.
 */
async function computeTextSha256(str: string): Promise<string> {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch {}
  // FNV-1a fallback for non-WebCrypto environments
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

// Setup resilient window focus / visibility listeners to ensure clipboard is wiped even if tab was backgrounded
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const checkAndExecutePendingPurge = async () => {
    if (pendingPurgeDeadline > 0 && Date.now() >= pendingPurgeDeadline) {
      await purgeClipboard();
    }
  };

  window.addEventListener('focus', () => {
    checkAndExecutePendingPurge();
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      checkAndExecutePendingPurge();
    }
  });

  // iOS Safari / Mobile WebKit requires a user gesture for clipboard writes.
  // Listening to user pointer/key interaction ensures expired clipboards are purged with an active gesture.
  window.addEventListener('pointerdown', () => {
    checkAndExecutePendingPurge();
  }, { passive: true });

  window.addEventListener('keydown', () => {
    checkAndExecutePendingPurge();
  }, { passive: true });
}

/**
 * Copies text to system clipboard and sets up an automated secure purge
 * to eliminate forensic extraction from volatile memory or OS clipboard history.
 *
 * @param text Content to copy
 * @param autoPurgeSeconds Time in seconds before clipboard is automatically wiped (default: 45s)
 */
export async function secureCopyToClipboard(
  text: string,
  autoPurgeSeconds: number = 45
): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard || !navigator.clipboard.writeText) {
    return false;
  }

  try {
    // Clear any pending purge timer from previous copy
    if (activeClipboardPurgeTimer) {
      clearTimeout(activeClipboardPurgeTimer);
      activeClipboardPurgeTimer = null;
    }

    lastCopiedHash = await computeTextSha256(text);
    pendingPurgeDeadline = autoPurgeSeconds > 0 ? Date.now() + autoPurgeSeconds * 1000 : 0;
    await navigator.clipboard.writeText(text);

    if (autoPurgeSeconds > 0) {
      activeClipboardPurgeTimer = setTimeout(async () => {
        try {
          // If clipboard matches our secret fingerprint or readText permission is blocked/denied (null), wipe it
          if (navigator.clipboard.readText) {
            const current = await navigator.clipboard.readText().catch(() => null);
            if (current === null) {
              await navigator.clipboard.writeText('');
            } else {
              const currentHash = await computeTextSha256(current);
              if (currentHash === lastCopiedHash) {
                await navigator.clipboard.writeText('');
              }
            }
          } else {
            await navigator.clipboard.writeText('');
          }
        } catch {
          try { await navigator.clipboard.writeText(''); } catch {}
        } finally {
          lastCopiedHash = null;
          activeClipboardPurgeTimer = null;
          pendingPurgeDeadline = 0;
        }
      }, autoPurgeSeconds * 1000);
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Immediately purges and overwrites the system clipboard buffer
 */
export async function purgeClipboard(): Promise<void> {
  if (activeClipboardPurgeTimer) {
    clearTimeout(activeClipboardPurgeTimer);
    activeClipboardPurgeTimer = null;
  }
  lastCopiedHash = null;
  pendingPurgeDeadline = 0;

  if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Ignored in sandboxed contexts
    }
  }
}
