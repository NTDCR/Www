import React from 'react';
import { WifiOff, HardDrive, ShieldCheck, X, Terminal, CheckCircle2, Download } from 'lucide-react';

interface AirGapDeployModalProps {
  onClose: () => void;
}

export const AirGapDeployModal: React.FC<AirGapDeployModalProps> = ({ onClose }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-6 my-8">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <WifiOff className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-slate-100 uppercase">
                AIR-GAPPED &amp; USB DRIVE DEPLOYMENT GUIDE
              </h3>
              <p className="text-xs text-slate-400">
                100% Offline execution • Zero telemetry • Local self-contained bundle
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Steps */}
        <div className="space-y-4 font-mono text-xs text-slate-300">
          
          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500 text-xs flex items-center justify-center">1</span>
              <span>Flash Drive Preparation (Air-Gapped Workstation)</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Format a hardware-encrypted USB flash drive (FAT32/exFAT). Copy the compiled self-contained ContentGuard Pro MAX build (`dist/` directory or single-file offline package) onto the drive.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500 text-xs flex items-center justify-center">2</span>
              <span>Air-Gap Physical Isolation Verification</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Ensure the destination workstation has all network interfaces (Ethernet, Wi-Fi, Bluetooth, NFC, Cellular) physically disconnected or disabled in BIOS/UEFI. Insert the USB drive and launch `index.html` in any modern web browser (Chrome, Safari, Firefox, Edge).
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500 text-xs flex items-center justify-center">3</span>
              <span>Enforced Content Security Policy (CSP) Headers</span>
            </div>
            <div className="bg-slate-900 p-3 rounded border border-slate-800 text-[11px] text-emerald-400 font-mono">
              <code>
                Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'none'; frame-ancestors 'none';
              </code>
            </div>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500 text-xs flex items-center justify-center">4</span>
              <span>Zero-Telemetry &amp; Zero-CDN Verification</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Open DevTools Network tab. Verify that zero outgoing requests occur during encryption, decryption, watermarking, or zeroization operations. All cryptography (Kyber-1024, Serpent-256, XChaCha20, AES-256-CTR, ChaCha20 Masking) runs 100% locally in browser memory and Web Workers.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-mono font-bold text-xs rounded-lg transition-colors"
          >
            Acknowledge Air-Gap Protocol
          </button>
        </div>

      </div>
    </div>
  );
};
