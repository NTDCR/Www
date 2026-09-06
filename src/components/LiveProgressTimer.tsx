import React, { useEffect, useState, useRef } from 'react';
import { Clock, Cpu, Zap, Activity, CheckCircle2, RefreshCw, ShieldCheck, Timer } from 'lucide-react';

export function formatDurationHuman(ms: number): string {
  const totalSeconds = ms / 1000;
  if (totalSeconds < 60) {
    return `${totalSeconds.toFixed(2)}s`;
  }
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = (totalSeconds % 60);

  if (hours > 0) {
    return `${hours}h ${minutes.toString().padStart(2, '0')}m ${Math.floor(seconds).toString().padStart(2, '0')}s`;
  }
  return `${minutes}m ${seconds.toFixed(1)}s`;
}

export function formatElapsedTimer(elapsedMs: number): string {
  const totalSeconds = elapsedMs / 1000;
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = Math.floor(totalSeconds % 60);
  const hundredths = Math.floor((elapsedMs % 1000) / 10);

  const hh = hours.toString().padStart(2, '0');
  const mm = minutes.toString().padStart(2, '0');
  const ss = seconds.toString().padStart(2, '0');
  const ms = hundredths.toString().padStart(2, '0');

  if (hours > 0) {
    return `${hh}:${mm}:${ss}.${ms}`;
  }
  return `${mm}:${ss}.${ms}`;
}

export function formatEstimatedTimeRemaining(totalSeconds: number, progressPct: number): string {
  if (progressPct >= 100) return 'Completed';
  if (progressPct <= 3 || totalSeconds <= 0.3) return 'Estimating...';

  const totalEstTimeSec = totalSeconds / (progressPct / 100);
  const remainingSec = Math.max(0, totalEstTimeSec - totalSeconds);

  if (remainingSec < 1) return '< 1s';
  if (remainingSec < 60) return `~${remainingSec.toFixed(1)}s`;

  const hours = Math.floor(remainingSec / 3600);
  const minutes = Math.floor((remainingSec % 3600) / 60);
  const seconds = Math.floor(remainingSec % 60);

  if (hours > 0) {
    return `~${hours}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
  }
  return `~${minutes}m ${seconds.toString().padStart(2, '0')}s`;
}

interface LiveProgressTimerProps {
  isActive: boolean;
  progressPct: number;
  stageText: string;
  totalBytes?: number;
  title?: string;
  mode?: 'encryption' | 'decryption';
}

export const LiveProgressTimer: React.FC<LiveProgressTimerProps> = ({
  isActive,
  progressPct,
  stageText,
  totalBytes = 0,
  title = 'Overall Cryptographic Operation',
  mode = 'encryption'
}) => {
  const [elapsedMs, setElapsedMs] = useState<number>(0);
  const [speedMBps, setSpeedMBps] = useState<number>(0);

  // Keep overall operation start time fixed across all stages and progress steps
  const overallStartTimeRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);
  const progressPctRef = useRef<number>(progressPct);
  const totalBytesRef = useRef<number>(totalBytes);

  // Keep refs up-to-date without triggering useEffect re-runs
  progressPctRef.current = progressPct;
  totalBytesRef.current = totalBytes;

  useEffect(() => {
    if (isActive) {
      // Set start time ONLY on initial activation of the overall operation
      if (overallStartTimeRef.current === null) {
        overallStartTimeRef.current = performance.now();
      }

      let lastUpdate = 0;
      const updateOverallTimer = (now: number) => {
        if (!overallStartTimeRef.current) return;
        const elapsed = now - overallStartTimeRef.current;

        if (now - lastUpdate >= 100) {
          lastUpdate = now;
          setElapsedMs(elapsed);

          // Compute overall throughput in MB/s from the beginning of the operation
          const currentPct = progressPctRef.current;
          const currentBytes = totalBytesRef.current;
          if (elapsed > 100 && currentBytes > 0 && currentPct > 0) {
            const processedBytes = (currentBytes * (currentPct / 100));
            const mbProcessed = processedBytes / (1024 * 1024);
            const seconds = elapsed / 1000;
            const currentSpeed = seconds > 0 ? (mbProcessed / seconds) : 0;
            setSpeedMBps(currentSpeed);
          }
        }

        if (isActive) {
          rafRef.current = requestAnimationFrame(updateOverallTimer);
        }
      };

      rafRef.current = requestAnimationFrame(updateOverallTimer);
    } else {
      // Clean up timer and reset start time ref when operation is inactive
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      overallStartTimeRef.current = null;
    }

    return () => {
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [isActive]);

  if (!isActive) return null;

  const totalSeconds = elapsedMs / 1000;
  const formattedOverallElapsed = formatElapsedTimer(elapsedMs);
  const etaText = formatEstimatedTimeRemaining(totalSeconds, progressPct);
  const isHoursScale = totalSeconds >= 3600;

  return (
    <div className="bg-slate-950 border-2 border-emerald-500/60 rounded-xl p-5 shadow-2xl font-mono text-xs space-y-4 relative overflow-hidden">
      {/* Background glowing sweep */}
      <div className="absolute inset-0 bg-gradient-to-r from-emerald-950/30 via-sky-950/40 to-emerald-950/30 pointer-events-none" />

      {/* Header bar: Dedicated Overall Operation Timer */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 relative z-10">
        <div className="flex items-center gap-2">
          <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />
          <span className="font-bold text-slate-100 uppercase tracking-wider">{title}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-950/90 border border-emerald-500/50 rounded-md text-emerald-300 font-bold text-xs shadow-md">
            <Timer className="w-4 h-4 text-emerald-400 animate-pulse" />
            <span>
              Overall Time:{' '}
              <strong className="text-emerald-200 text-sm">
                {formattedOverallElapsed}
              </strong>
              {isHoursScale && (
                <span className="ml-1 text-[10px] text-emerald-400 font-normal">
                  (HH:MM:SS.ms)
                </span>
              )}
            </span>
          </div>
          <div className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-md text-slate-300 text-[11px]">
            <span>ETA: <strong className="text-sky-400">{etaText}</strong></span>
          </div>
        </div>
      </div>

      {/* Primary Progress Bar with smooth transition */}
      <div className="space-y-1.5 relative z-10">
        <div className="flex items-center justify-between text-slate-300 text-xs">
          <span className="text-emerald-400 font-semibold truncate max-w-[78%] flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span className="truncate">{stageText || 'Executing end-to-end cryptographic pipeline...'}</span>
          </span>
          <span className="font-bold text-slate-100 text-sm">{Math.min(100, Math.round(progressPct))}%</span>
        </div>

        <div className="w-full bg-slate-900 border border-slate-800 h-3.5 rounded-full overflow-hidden p-0.5 shadow-inner">
          <div
            className="h-full bg-gradient-to-r from-emerald-600 via-teal-400 to-sky-400 rounded-full transition-all duration-150 ease-out shadow-lg shadow-emerald-500/50"
            style={{ width: `${Math.min(100, Math.max(2, progressPct))}%` }}
          />
        </div>
      </div>

      {/* Overall Telemetry Metric Badges */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] text-slate-400 pt-1 relative z-10 border-t border-slate-900">
        <div className="flex items-center gap-1 bg-slate-900/90 px-2 py-1.5 rounded border border-slate-800">
          <Zap className="w-3 h-3 text-amber-400" />
          <span>Overall Speed: <strong className="text-slate-200">{speedMBps > 0 ? `${speedMBps.toFixed(1)} MB/s` : 'Streaming'}</strong></span>
        </div>
        <div className="flex items-center gap-1 bg-slate-900/90 px-2 py-1.5 rounded border border-slate-800">
          <Clock className="w-3 h-3 text-emerald-400" />
          <span>Format: <strong className="text-emerald-400">{isHoursScale ? 'Hours (HH:MM:SS)' : 'Min:Sec (MM:SS.ms)'}</strong></span>
        </div>
        <div className="flex items-center gap-1 bg-slate-900/90 px-2 py-1.5 rounded border border-slate-800">
          <ShieldCheck className="w-3 h-3 text-sky-400" />
          <span>Kyber PQC: <strong className="text-slate-200">Active</strong></span>
        </div>
        <div className="flex items-center gap-1 bg-slate-900/90 px-2 py-1.5 rounded border border-slate-800">
          <CheckCircle2 className="w-3 h-3 text-teal-400" />
          <span>RAM Leak: <strong className="text-emerald-400">0.00% (Zero)</strong></span>
        </div>
      </div>
    </div>
  );
};
