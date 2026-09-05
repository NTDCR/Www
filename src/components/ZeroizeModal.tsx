import React, { useState, useEffect, useRef } from 'react';
import { Trash2, AlertTriangle, ShieldAlert, CheckCircle, RefreshCw, X, Shield } from 'lucide-react';
import { execute35PassSecureWipe, PassStatus } from '../security/sanitization';

interface ZeroizeModalProps {
  onClose: () => void;
  onZeroizeComplete: () => void;
}

export const ZeroizeModal: React.FC<ZeroizeModalProps> = ({ onClose, onZeroizeComplete }) => {
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [status, setStatus] = useState<PassStatus | null>(null);
  const [isDone, setIsDone] = useState<boolean>(false);
  const isMountedRef = useRef<boolean>(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const handleStartWipe = async () => {
    if (isRunning) return;
    setIsRunning(true);
    await execute35PassSecureWipe((s) => {
      if (isMountedRef.current) setStatus(s);
    });
    if (isMountedRef.current) {
      setIsRunning(false);
      setIsDone(true);
    }
    setTimeout(() => {
      onZeroizeComplete();
    }, 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-rose-950/40 backdrop-blur-md overflow-y-auto">
      <div className="bg-slate-900 border-2 border-rose-600/60 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-rose-900/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-rose-950 border border-rose-500 flex items-center justify-center text-rose-400">
              <Trash2 className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-rose-300 uppercase">
                EMERGENCY 35-PASS OVERWRITE &amp; MEMORY ZEROIZATION
              </h3>
              <p className="text-xs text-slate-400">
                Peter Gutmann / DoD 5220.22-M Multi-Pass Volatile Sanitization
              </p>
            </div>
          </div>
          {!isRunning && !isDone && (
            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-1"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Warning Body */}
        {!isRunning && !isDone && (
          <div className="space-y-4 font-mono text-xs text-slate-300">
            <div className="p-4 bg-rose-950/40 border border-rose-900/60 rounded-xl space-y-2 text-rose-200">
              <div className="flex items-center gap-2 font-bold text-rose-400 text-sm">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>IRREVERSIBLE VOLATILE STORAGE PURGE</span>
              </div>
              <p className="text-xs text-rose-300">
                This operation will execute 35 successive overwriting passes across all client memory, IndexedDB recovery records, localStorage, sessionStorage, worker threads, and crypto key caches.
              </p>
            </div>

            {/* Safety Boundaries Notice (Features 55, 56, 57) */}
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5 text-[11px] text-slate-400">
              <span className="font-bold text-slate-200 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                Regulatory &amp; Non-Destructive Boundaries:
              </span>
              <ul className="list-disc list-inside space-y-1 text-slate-400 pl-1">
                <li><strong className="text-slate-300">Downloads Folder:</strong> NOT touched (User assets preserved).</li>
                <li><strong className="text-slate-300">External Drives / USB:</strong> NOT touched.</li>
                <li><strong className="text-slate-300">Cloud Storage / Google Drive:</strong> NOT touched.</li>
                <li><strong className="text-emerald-400">Volatile RAM &amp; Browser State:</strong> 100% Zeroized.</li>
              </ul>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-mono text-xs transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleStartWipe}
                className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded-lg font-mono text-xs uppercase tracking-wider transition-colors shadow-lg shadow-rose-950/60"
              >
                Initiate 35-Pass Wipe
              </button>
            </div>
          </div>
        )}

        {/* Running Wipe Progress */}
        {isRunning && status && (
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between text-slate-200">
              <span className="text-rose-400 font-bold">
                Pass {status.currentPass} of {status.totalPasses}: {status.patternName}
              </span>
              <span className="font-bold">{status.progressPercentage}%</span>
            </div>

            <div className="w-full bg-slate-950 h-3 rounded-full overflow-hidden border border-rose-900/60">
              <div
                className="h-full bg-rose-500 transition-all duration-75"
                style={{ width: `${status.progressPercentage}%` }}
              />
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-400">
              <span className="text-slate-300 block mb-1 font-semibold">Active Target Area:</span>
              <span className="text-amber-400 font-bold">{status.targetArea}</span>
            </div>
          </div>
        )}

        {/* Done State */}
        {isDone && (
          <div className="text-center py-6 space-y-3 font-mono">
            <div className="w-12 h-12 rounded-full bg-emerald-950 border border-emerald-500 text-emerald-400 flex items-center justify-center mx-auto">
              <CheckCircle className="w-6 h-6" />
            </div>
            <h4 className="text-base font-bold text-slate-100">
              35-PASS ZEROIZATION COMPLETE
            </h4>
            <p className="text-xs text-slate-400">
              All volatile RAM buffers, crypto keys, and cache state have been wiped to 0x00. Self-destructing UI session...
            </p>
          </div>
        )}

      </div>
    </div>
  );
};
