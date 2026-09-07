/**
 * ContentGuard Pro MAX - Async Event Loop Cooperative Scheduling Utilities
 * Prevents main thread starvation, browser freezes, and tab crashes during heavy crypto workloads.
 */

/**
 * Yields execution back to the browser event loop, allowing UI rendering,
 * garbage collection, and user events to process without triggering "Page Unresponsive" crashes.
 */
export async function yieldToMainThread(): Promise<void> {
  // 1. Native modern scheduler.yield() (Chrome 129+, Edge 129+)
  if (typeof (globalThis as any).scheduler?.yield === 'function') {
    try {
      return await (globalThis as any).scheduler.yield();
    } catch {}
  }
  // 2. High-speed zero-delay MessageChannel macrotask (non-throttled in background tabs)
  if (typeof MessageChannel !== 'undefined') {
    return new Promise(resolve => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => {
        channel.port1.close();
        channel.port2.close();
        resolve();
      };
      channel.port2.postMessage(null);
    });
  }
  // 3. Standard fallback
  return new Promise(resolve => setTimeout(resolve, 0));
}

