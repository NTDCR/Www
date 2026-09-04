import React, { useState } from 'react';
import { Fingerprint, Copy, Check, ShieldCheck, Sparkles, Key, Lock, Eye, EyeOff } from 'lucide-react';
import { format1024BitIdFormatted } from '../crypto/key6Engine';
import { secureCopyToClipboard } from '../security/clipboard';

interface Key6BadgeCardProps {
  title: string;
  vaultType: 'A' | 'B';
  key6Value: string;
  uniqueId1024Hex: string;
  onKey6Change?: (val: string) => void;
  onGenerateRandom?: () => void;
  isReadOnly?: boolean;
  isPreDecrypt?: boolean;
  isVerified?: boolean;
}

export const Key6BadgeCard: React.FC<Key6BadgeCardProps> = ({
  title,
  vaultType,
  key6Value,
  uniqueId1024Hex,
  onKey6Change,
  onGenerateRandom,
  isReadOnly = false,
  isPreDecrypt = false,
  isVerified = false
}) => {
  const [copied, setCopied] = useState(false);
  const [showKey6, setShowKey6] = useState(false);

  const handleCopy = async () => {
    if (!uniqueId1024Hex) return;
    await secureCopyToClipboard(uniqueId1024Hex, 45);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  const isVaultA = vaultType === 'A';
  const accentColor = isVaultA ? 'emerald' : 'amber';

  return (
    <div className={`p-4 rounded-xl border transition-all ${
      isVaultA 
        ? 'bg-slate-950/80 border-emerald-500/40 shadow-lg shadow-emerald-950/20' 
        : 'bg-slate-950/80 border-amber-500/40 shadow-lg shadow-amber-950/20'
    }`}>
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${
            isVaultA ? 'bg-emerald-950 border border-emerald-500/60 text-emerald-400' : 'bg-amber-950 border border-amber-500/60 text-amber-400'
          }`}>
            <Fingerprint className="w-3.5 h-3.5" />
          </div>
          <div>
            <h4 className="text-xs font-mono font-bold text-slate-100 flex items-center gap-1.5">
              <span>{title}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                isVaultA ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
              }`}>
                1024-BIT CSPRNG
              </span>
            </h4>
          </div>
        </div>

        {onGenerateRandom && !isReadOnly && (
          <button
            type="button"
            onClick={onGenerateRandom}
            className={`text-[10px] font-mono flex items-center gap-1 px-2 py-1 rounded transition-colors ${
              isVaultA 
                ? 'bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700 text-emerald-300' 
                : 'bg-amber-950/80 hover:bg-amber-900 border border-amber-700 text-amber-300'
            }`}
          >
            <Sparkles className="w-3 h-3" />
            <span>Generate Random Key 6</span>
          </button>
        )}
      </div>

      {/* Key 6 Input */}
      <div className="mt-3 space-y-1.5 font-mono text-xs">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1 text-slate-300 font-semibold">
            <Key className="w-3 h-3" />
            Key 6 (1024-Bit Identifier Key):
          </span>
          <button
            type="button"
            onClick={() => setShowKey6(!showKey6)}
            className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[10px]"
          >
            {showKey6 ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
            <span>{showKey6 ? 'Hide' : 'Show'}</span>
          </button>
        </div>

        {isReadOnly ? (
          <div className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs truncate select-all">
            {showKey6 ? key6Value : '••••••••••••••••••••••••'}
          </div>
        ) : (
          <input
            type={showKey6 ? 'text' : 'password'}
            value={key6Value}
            onChange={(e) => onKey6Change?.(e.target.value)}
            placeholder={`Enter Key 6 for Vault ${vaultType}...`}
            autoComplete="new-password"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            data-lpignore="true"
            data-1p-ignore="true"
            className={`w-full bg-slate-900 border rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none transition-colors ${
              isVaultA ? 'border-slate-700 focus:border-emerald-500' : 'border-slate-700 focus:border-amber-500'
            }`}
          />
        )}
      </div>

      {/* 1024-Bit Output Display */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 font-mono">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[11px] font-semibold text-slate-400 flex items-center gap-1">
            <ShieldCheck className={`w-3.5 h-3.5 ${isVaultA ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span>Derived 1024-Bit Unique Container ID:</span>
          </span>
          {uniqueId1024Hex ? (
            <button
              type="button"
              onClick={handleCopy}
              className={`flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded transition-all active:scale-95 ${
                copied 
                  ? 'bg-emerald-600 text-slate-950' 
                  : (isVaultA ? 'bg-emerald-950 text-emerald-300 hover:bg-emerald-900 border border-emerald-700' : 'bg-amber-950 text-amber-300 hover:bg-amber-900 border border-amber-700')
              }`}
            >
              {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied! (Auto-wipes in 45s)' : 'Copy 1024-Bit ID'}</span>
            </button>
          ) : (
            <span className="text-[10px] text-slate-500 italic">
              {isPreDecrypt ? 'Enter correct Key 6 to reveal' : 'Awaiting Key 6 input'}
            </span>
          )}
        </div>

        {uniqueId1024Hex ? (
          <div className={`p-2.5 rounded-lg border font-mono text-[10px] leading-relaxed break-all max-h-24 overflow-y-auto select-all ${
            isVaultA 
              ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300' 
              : 'bg-amber-950/30 border-amber-500/30 text-amber-300'
          }`}>
            {uniqueId1024Hex}
          </div>
        ) : (
          <div className="p-2.5 rounded-lg border border-dashed border-slate-800 bg-slate-950/40 text-[10px] text-slate-500 italic text-center">
            {isPreDecrypt ? (
              <span>🔒 Zero-Disclosure Active: Enter Key 6 matching this container to view identical 1024-bit ID</span>
            ) : (
              <span>Enter Key 6 above to generate deterministic 1024-bit CSPRNG Identity Token</span>
            )}
          </div>
        )}

        {uniqueId1024Hex && (
          <div className="flex items-center justify-between text-[9px] text-slate-500 mt-1.5 px-0.5">
            <span>Length: 256 Hex Characters (1024 Bits / 128 Bytes)</span>
            <span className="text-emerald-400 font-semibold">✓ Cryptographically Bound</span>
          </div>
        )}
      </div>
    </div>
  );
};
