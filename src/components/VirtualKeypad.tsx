import React, { useState, useEffect } from 'react';
import { Shield, Key, Eye, EyeOff, RotateCcw, Check } from 'lucide-react';
import { secureShuffle } from '../crypto/safeRandom';

interface VirtualKeypadProps {
  onInput: (char: string) => void;
  onBackspace: () => void;
  onClear: () => void;
  onClose?: () => void;
  title?: string;
}

const DEFAULT_KEYS = [
  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
  'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
  'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', '!',
  'Z', 'X', 'C', 'V', 'B', 'N', 'M', '@', '#', '$',
  '%', '&', '*', '-', '_', '+', '=', '?', '.', '/'
];

export const VirtualKeypad: React.FC<VirtualKeypadProps> = ({
  onInput,
  onBackspace,
  onClear,
  onClose,
  title = 'Secure Randomized Keypad (Shoulder-Surfing / Keylogger Resistant)'
}) => {
  const [keys, setKeys] = useState<string[]>(DEFAULT_KEYS);
  const [isShift, setIsShift] = useState<boolean>(false);

  // Cryptographically secure Fisher-Yates CSPRNG shuffle
  const shuffleKeys = () => {
    setKeys(secureShuffle(DEFAULT_KEYS));
  };

  useEffect(() => {
    shuffleKeys();
  }, []);

  return (
    <div id="virtual-keypad-panel" className="bg-slate-900 border border-emerald-500/30 rounded-xl p-4 shadow-2xl max-w-xl mx-auto backdrop-blur-md">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
        <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs tracking-wide">
          <Shield className="w-4 h-4 text-emerald-400 animate-pulse" />
          <span className="font-semibold">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={shuffleKeys}
            className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-emerald-400 bg-slate-800 hover:bg-slate-700/80 px-2 py-1 rounded transition-colors"
            title="Randomize key coordinates"
          >
            <RotateCcw className="w-3 h-3" />
            Shuffle Layout
          </button>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 text-xs px-2 py-1 bg-slate-800 rounded"
            >
              Close
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-10 gap-1 sm:gap-1.5 mb-3">
        {keys.map((k, idx) => {
          const displayChar = isShift ? k.toUpperCase() : k.toLowerCase();
          return (
            <button
              key={`${k}-${idx}`}
              type="button"
              onClick={() => onInput(displayChar)}
              className="h-9 sm:h-10 bg-slate-800 hover:bg-emerald-500/20 active:bg-emerald-500 text-slate-200 hover:text-emerald-300 font-mono font-bold text-xs sm:text-sm rounded border border-slate-700 hover:border-emerald-500/50 transition-all flex items-center justify-center select-none shadow-sm touch-manipulation"
            >
              {displayChar}
            </button>
          );
        })}
      </div>

      <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
        <button
          type="button"
          onClick={() => setIsShift(!isShift)}
          className={`px-4 py-2 font-mono text-xs rounded border transition-colors ${
            isShift ? 'bg-emerald-600 text-slate-950 font-bold border-emerald-400' : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
          }`}
        >
          {isShift ? 'CAPS [ON]' : 'CAPS [OFF]'}
        </button>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onClear}
            className="px-3 py-2 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 text-xs font-mono rounded border border-rose-800/50 transition-colors"
          >
            Clear All
          </button>
          <button
            type="button"
            onClick={onBackspace}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-amber-300 text-xs font-mono rounded border border-slate-700 transition-colors font-semibold"
          >
            ⌫ Backspace
          </button>
        </div>
      </div>
    </div>
  );
};
