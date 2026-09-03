import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Lock,
  WifiOff,
  Clock,
  Trash2,
  FileCheck,
  Cpu,
  HelpCircle,
  KeyRound,
  HardDrive
} from 'lucide-react';
import { DeviceFingerprint } from '../types';
import { PWAInstallButton } from './PWAInstallButton';

interface HeaderProps {
  deviceInfo: DeviceFingerprint | null;
  onOpenZeroizeModal: () => void;
  onOpenComplianceModal: () => void;
  onOpenBenchmarkModal: () => void;
  onOpenDeviceModal: () => void;
  onOpenAirGapModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  deviceInfo,
  onOpenZeroizeModal,
  onOpenComplianceModal,
  onOpenBenchmarkModal,
  onOpenDeviceModal,
  onOpenAirGapModal
}) => {
  // 12-Hour Session Inactivity Countdown (43200 seconds)
  const [secondsRemaining, setSecondsRemaining] = useState<number>(12 * 3600);

  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsRemaining(prev => {
        if (prev <= 1) {
          // Trigger auto zeroize on session timeout
          onOpenZeroizeModal();
          return 12 * 3600;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [onOpenZeroizeModal]);

  const formatTime = (totalSecs: number) => {
    const hrs = Math.floor(totalSecs / 3600);
    const mins = Math.floor((totalSecs % 3600) / 60);
    const secs = totalSecs % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const resetHeartbeat = () => {
    setSecondsRemaining(12 * 3600);
  };

  return (
    <header id="platform-header" className="border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          
          {/* Brand & Air-Gap Badge */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/50">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-slate-100 font-mono">
                  CONTENTGUARD <span className="text-emerald-400 font-black">PRO MAX</span>
                </h1>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950/90 text-emerald-400 border border-emerald-500/40 font-semibold tracking-wider flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                  LOCKED
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Enterprise DRM • Dual-Vault Watermarking • Post-Quantum Kyber-1024 • Air-Gapped
              </p>
            </div>
          </div>

          {/* Telemetry & Action Badges */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Native PWA Install Action */}
            <PWAInstallButton />

            {/* Air-Gapped CSP indicator */}
            <button
              id="header-airgap-btn"
              type="button"
              onClick={onOpenAirGapModal}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-emerald-500/40 text-slate-300 hover:text-emerald-300 font-mono transition-colors"
              title="Click to view air-gap installation guide"
            >
              <WifiOff className="w-3.5 h-3.5 text-emerald-400" />
              <span>Air-Gapped (No CDN)</span>
            </button>

            {/* 12H Session Timer */}
            <button
              id="header-session-timer-btn"
              type="button"
              onClick={resetHeartbeat}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-500/40 text-slate-300 hover:text-amber-300 font-mono transition-colors"
              title="12-Hour Session Inactivity Timeout. Click to reset heartbeat."
            >
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              <span>Session: <strong className="text-amber-400">{formatTime(secondsRemaining)}</strong></span>
            </button>

            {/* Device ID */}
            {deviceInfo && (
              <button
                id="header-device-btn"
                type="button"
                onClick={onOpenDeviceModal}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-blue-500/40 text-slate-300 hover:text-blue-300 font-mono transition-colors"
                title="Device Fingerprint & 10 Recovery Codes"
              >
                <KeyRound className="w-3.5 h-3.5 text-blue-400" />
                <span className="hidden sm:inline">{deviceInfo.visitorId}</span>
                <span className="sm:hidden">Device</span>
              </button>
            )}

            {/* Benchmark Suite */}
            <button
              id="header-benchmarks-btn"
              type="button"
              onClick={onOpenBenchmarkModal}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-purple-500/40 text-slate-300 hover:text-purple-300 font-mono transition-colors"
              title="65-Feature Automated Benchmark & Verification"
            >
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span>Self-Test</span>
            </button>

            {/* Compliance Proofs */}
            <button
              id="header-compliance-btn"
              type="button"
              onClick={onOpenComplianceModal}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-emerald-500/40 text-slate-300 hover:text-emerald-300 font-mono transition-colors"
              title="Mathematical Security Proofs & Regulatory Matrix"
            >
              <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Proofs & Matrix</span>
            </button>

            {/* 35-Pass Panic Wipe */}
            <button
              id="header-panic-wipe-btn"
              type="button"
              onClick={onOpenZeroizeModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-200 font-mono font-bold transition-all shadow-sm active:scale-95"
              title="Emergency 35-Pass DoD/Gutmann Sanitization & Key Zeroization"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>35-Pass Zeroize</span>
            </button>
          </div>

        </div>
      </div>
    </header>
  );
};
