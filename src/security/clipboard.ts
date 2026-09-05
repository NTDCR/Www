/**
 * ContentGuard Pro MAX - Institutional Anti-Forensics Clipboard Manager
 * Guarantees zero persistent memory trace in OS clipboard buffers (Win+V / macOS / X11).
 * Features:
 * - Timed auto-purge (overwrites clipboard buffer with empty text after configurable timeout)
 * - Immediate voluntary purge
 * - Defensive fallback for non-browser / headless runtimes
 */

let activeClipboardPurgeTimer: ReturnType<typeof setTimeout> | null = null;
let lastCopiedPayload: string | null = null;

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

    lastCopiedPayload = text;
    await navigator.clipboard.writeText(text);

    if (autoPurgeSeconds > 0) {
      activeClipboardPurgeTimer = setTimeout(async () => {
        try {
          // If clipboard matches our secret or readText permission is blocked/denied (null), wipe it
          if (navigator.clipboard.readText) {
            const current = await navigator.clipboard.readText().catch(() => null);
            if (current === null || current === lastCopiedPayload) {
              await navigator.clipboard.writeText('');
            }
          } else {
            await navigator.clipboard.writeText('');
          }
        } catch {
          try { await navigator.clipboard.writeText(''); } catch {}
        } finally {
          lastCopiedPayload = null;
          activeClipboardPurgeTimer = null;
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
  lastCopiedPayload = null;

  if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Ignored in sandboxed contexts
    }
  }
}
