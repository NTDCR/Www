import React, { useState, useEffect, useRef } from 'react';
import { KeyRound, Shield, X, Copy, Check, Printer, RefreshCw, Cpu } from 'lucide-react';
import { DeviceFingerprint, RecoveryCode } from '../types';
import { loadStoredRecoveryCodes, generateAndStoreRecoveryCodes, markRecoveryCodeUsed } from '../security/deviceFingerprint';
import { secureCopyToClipboard } from '../security/clipboard';

interface DeviceSecurityModalProps {
  deviceInfo: DeviceFingerprint | null;
  onClose: () => void;
}

export const DeviceSecurityModal: React.FC<DeviceSecurityModalProps> = ({ deviceInfo, onClose }) => {
  const [recoveryCodes, setRecoveryCodes] = useState<RecoveryCode[]>([]);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const isMountedRef = useRef<boolean>(true);

  useEffect(() => {
    isMountedRef.current = true;
    loadStoredRecoveryCodes().then(codes => {
      if (isMountedRef.current) setRecoveryCodes(codes);
    });
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const handleRegenerateCodes = async () => {
    if (isGenerating) return;
    setIsGenerating(true);
    try {
      const codes = await generateAndStoreRecoveryCodes();
      if (isMountedRef.current) setRecoveryCodes(codes);
    } finally {
      if (isMountedRef.current) setIsGenerating(false);
    }
  };

  const handleToggleCodeUsed = async (index: number) => {
    await markRecoveryCodeUsed(index);
    setRecoveryCodes(prev =>
      prev.map(c => c.index === index ? { ...c, used: !c.used } : c)
    );
  };

  const handleCopyCode = async (code: string, idx: number) => {
    await secureCopyToClipboard(code, 45);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2500);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="printable-area bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-6 my-8">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-blue-950/80 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-slate-100">
                DEVICE IDENTIFICATION &amp; ONE-TIME RECOVERY CODES
              </h3>
              <p className="text-xs text-slate-400">
                Software hardware fingerprinting via Canvas, WebGL &amp; Web Audio API.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors no-print"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Device Fingerprint Details */}
        {deviceInfo && (
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-3">
            <div className="text-xs font-bold text-blue-400 uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4" />
              <span>Hardware / Software Fingerprint Signatures</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-slate-300">
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Device Visitor ID</span>
                <span className="font-bold text-emerald-400">{deviceInfo.visitorId}</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Canvas 2D Hash</span>
                <span className="font-bold text-slate-200">{deviceInfo.canvasHash}</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">WebGL 3D Context Hash</span>
                <span className="font-bold text-slate-200">{deviceInfo.webglHash}</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Web Audio Buffer Hash</span>
                <span className="font-bold text-slate-200">{deviceInfo.audioHash}</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">CPU Concurrency</span>
                <span className="font-bold text-slate-200">{deviceInfo.hardwareConcurrency} Cores</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Screen / Depth</span>
                <span className="font-bold text-slate-200">{deviceInfo.screenResolution} ({deviceInfo.colorDepth}-bit)</span>
              </div>
            </div>
          </div>
        )}

        {/* 10 One-Time Recovery Codes */}
        <div className="space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold uppercase text-slate-200">
                10 One-Time Emergency Recovery Codes (Stored in IndexedDB)
              </h4>
              <p className="text-[11px] text-slate-400">
                Single-use emergency device recovery keys. Print or store physically in a secure vault.
              </p>
            </div>
            <div className="flex items-center gap-2 no-print">
              <button
                type="button"
                onClick={handlePrint}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 transition-colors"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print</span>
              </button>
              <button
                type="button"
                onClick={handleRegenerateCodes}
                disabled={isGenerating}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
                <span>Regenerate</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            {recoveryCodes.map((rc) => (
              <div
                key={rc.code}
                className={`flex items-center justify-between p-2.5 rounded-lg border transition-colors ${
                  rc.used
                    ? 'bg-slate-950/40 border-slate-800/40 text-slate-600 line-through'
                    : 'bg-slate-950/80 border-slate-800 text-slate-200 hover:border-blue-500/40'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500 font-bold">#{rc.index.toString().padStart(2, '0')}</span>
                  <span className="font-semibold tracking-wider">{rc.code}</span>
                </div>
                <div className="flex items-center gap-1.5 no-print">
                  <button
                    type="button"
                    onClick={() => handleToggleCodeUsed(rc.index)}
                    className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
                  >
                    {rc.used ? 'Used' : 'Mark Used'}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleCopyCode(rc.code, rc.index)}
                    className="p-1 text-slate-400 hover:text-emerald-400 transition-colors"
                  >
                    {copiedIdx === rc.index ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};
