import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Copy, Check, Trash2, ArrowDownCircle, Cpu, Layers, HardDrive, Filter, Activity } from 'lucide-react';
import { StreamEvent, EventCategory, globalStreamEventBus } from '../utils/streamEvents';
import { secureCopyToClipboard } from '../security/clipboard';

interface LiveStreamTerminalProps {
  isActive: boolean;
  speedMBps?: number;
  currentStage?: string;
  title?: string;
  mode?: 'encryption' | 'decryption';
}

export const LiveStreamTerminal: React.FC<LiveStreamTerminalProps> = ({
  isActive,
  speedMBps = 0,
  currentStage = '',
  title = 'Live Cryptographic Telemetry Stream'
}) => {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isAutoScroll, setIsAutoScroll] = useState<boolean>(true);
  const [filterCategory, setFilterCategory] = useState<EventCategory | 'ALL'>('ALL');
  const [copied, setCopied] = useState<boolean>(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // 60 FPS Micro-batching via requestAnimationFrame
  useEffect(() => {
    let pendingBatch: StreamEvent[] = [];
    let rafId: number | null = null;

    // Load initial events from ring buffer if any exist
    const initial = globalStreamEventBus.getRecentEvents();
    if (initial.length > 0) {
      setEvents(initial);
    }

    const unsubscribe = globalStreamEventBus.subscribe((evt: StreamEvent) => {
      pendingBatch.push(evt);

      if (rafId === null) {
        rafId = requestAnimationFrame(() => {
          if (pendingBatch.length > 0) {
            setEvents(prev => {
              const next = [...prev, ...pendingBatch];
              // Keep maximum 350 events in DOM state to guarantee 60 FPS and 0 memory leaks
              return next.length > 350 ? next.slice(next.length - 350) : next;
            });
            pendingBatch = [];
          }
          rafId = null;
        });
      }
    });

    return () => {
      unsubscribe();
      if (rafId !== null) cancelAnimationFrame(rafId);
    };
  }, []);

  // Auto-scroll handler
  useEffect(() => {
    if (isAutoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events, isAutoScroll]);

  // Detect user manual scroll up vs bottom pinned
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 28;
    if (isAtBottom !== isAutoScroll) {
      setIsAutoScroll(isAtBottom);
    }
  };

  const scrollToBottom = () => {
    setIsAutoScroll(true);
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  };

  const handleCopyLogs = async () => {
    if (events.length === 0) return;
    const lines = events.map(
      (e, idx) => `[#${idx + 1}] ${e.timestamp} [${e.category}] (${e.stage}) ${e.message}${e.percent !== undefined ? ` [${e.percent}%]` : ''}`
    );
    const text = `=== ContentGuard Pro MAX — Live Cryptographic Stream Trail ===\nTotal Events: ${events.length}\n\n${lines.join('\n')}`;
    await secureCopyToClipboard(text, 60);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleClearLogs = () => {
    globalStreamEventBus.reset();
    setEvents([]);
  };

  // Filtered event list
  const filteredEvents = filterCategory === 'ALL'
    ? events
    : events.filter(e => e.category === filterCategory);

  const getCategoryBadgeClass = (category: EventCategory) => {
    switch (category) {
      case 'CRYPTO':
        return 'text-amber-400 bg-amber-950/60 border-amber-500/40';
      case 'STREAM':
        return 'text-sky-400 bg-sky-950/60 border-sky-500/40';
      case 'FEC':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-500/40';
      case 'ISOBMFF':
        return 'text-purple-400 bg-purple-950/60 border-purple-500/40';
      case 'STORAGE':
        return 'text-teal-400 bg-teal-950/60 border-teal-500/40';
      case 'AUDIT':
        return 'text-rose-400 bg-rose-950/60 border-rose-500/40';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-700';
    }
  };

  return (
    <div className="bg-[#030712] border-2 border-slate-800/90 rounded-xl shadow-2xl font-mono text-xs overflow-hidden relative transition-all">
      {/* Top Header Bar */}
      <div className="bg-slate-950/90 border-b border-slate-800/80 px-4 py-3 flex flex-wrap items-center justify-between gap-3 select-none">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isActive ? 'bg-emerald-400 animate-ping opacity-75' : 'bg-slate-600'
              } absolute`}
            />
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isActive ? 'bg-emerald-400' : 'bg-slate-500'
              } relative`}
            />
          </div>
          <div className="flex items-center gap-1.5 font-bold text-slate-200 uppercase tracking-wider text-[11px]">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span>{title}</span>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
            {events.length} Events Logged
          </span>
          {speedMBps > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/60 border border-amber-500/40 text-amber-300 font-bold">
              {speedMBps.toFixed(1)} MB/s
            </span>
          )}
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-2">
          {/* Category Filter Pills */}
          <div className="hidden sm:flex items-center gap-1 bg-slate-900/90 p-1 rounded-md border border-slate-800 text-[10px]">
            <Filter className="w-3 h-3 text-slate-500 ml-1 mr-0.5" />
            {(['ALL', 'CRYPTO', 'FEC', 'ISOBMFF', 'STREAM'] as const).map(cat => (
              <button
                key={cat}
                type="button"
                onClick={() => setFilterCategory(cat)}
                className={`px-1.5 py-0.5 rounded text-[10px] transition-colors ${
                  filterCategory === cat
                    ? 'bg-emerald-600 text-slate-950 font-bold shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={handleCopyLogs}
            disabled={events.length === 0}
            title="Copy all stream events to clipboard"
            className="flex items-center gap-1 px-2.5 py-1 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-slate-300 rounded border border-slate-700 text-[11px] transition-colors"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
            <span className="hidden md:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>

          <button
            type="button"
            onClick={handleClearLogs}
            disabled={events.length === 0}
            title="Clear terminal buffer"
            className="flex items-center gap-1 p-1 px-2 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-slate-400 hover:text-rose-400 rounded border border-slate-800 text-[11px] transition-colors"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="h-64 overflow-y-auto p-3 space-y-1 bg-[#020617]/95 font-mono text-[11px] leading-relaxed scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent"
        style={{ scrollBehavior: isAutoScroll ? 'auto' : 'smooth' }}
      >
        {filteredEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 text-center select-none py-8">
            <Activity className="w-6 h-6 mb-2 text-slate-700 animate-pulse" />
            <p className="text-xs">Zero Synthetic Events. Real Cryptographic Telemetry will stream here live.</p>
            <p className="text-[10px] text-slate-600 mt-1">Start Protection or Extraction to observe physical operations.</p>
          </div>
        ) : (
          filteredEvents.map((evt, idx) => (
            <div
              key={evt.id}
              className="flex items-start gap-2 hover:bg-slate-900/50 py-0.5 px-1.5 rounded transition-colors group"
            >
              {/* Event Index & Timestamp */}
              <span className="text-slate-600 shrink-0 text-[10px] select-none group-hover:text-slate-500">
                #{String(idx + 1).padStart(3, '0')}
              </span>
              <span className="text-slate-400 shrink-0 text-[10px]">
                [{evt.timestamp}]
              </span>

              {/* Category Badge */}
              <span
                className={`text-[9px] px-1.5 py-0.2 rounded border uppercase font-bold shrink-0 ${getCategoryBadgeClass(
                  evt.category
                )}`}
              >
                {evt.category}
              </span>

              {/* Progress Percentage Badge if present */}
              {evt.percent !== undefined && (
                <span className="text-emerald-400 font-bold shrink-0 text-[10px]">
                  {evt.percent.toFixed(2)}%
                </span>
              )}

              {/* Stage and Technical Message */}
              <span className="text-slate-300 break-all flex-1">
                <strong className="text-slate-200 mr-1.5">[{evt.stage}]</strong>
                <span className="text-slate-300">{evt.message}</span>
              </span>
            </div>
          ))
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Floating Resume Auto-Scroll Pill if paused */}
      {!isAutoScroll && events.length > 0 && (
        <div className="absolute bottom-3 right-4 z-20">
          <button
            type="button"
            onClick={scrollToBottom}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-full shadow-xl border border-emerald-400/80 text-[11px] animate-bounce transition-all"
          >
            <ArrowDownCircle className="w-3.5 h-3.5" />
            <span>Resume Auto-Scroll (Live)</span>
          </button>
        </div>
      )}

      {/* Bottom Status Ticker */}
      <div className="bg-slate-950/90 border-t border-slate-900 px-4 py-1.5 text-[10px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 truncate max-w-[80%]">
          <span className="text-slate-500 uppercase font-semibold">Active Subsystem:</span>
          <span className="text-emerald-400 font-medium truncate">
            {currentStage || (isActive ? 'Executing active streaming pipeline...' : 'System Idle')}
          </span>
        </div>
        <div className="flex items-center gap-3 text-slate-500">
          <span className="flex items-center gap-1">
            <Cpu className="w-3 h-3 text-sky-400" />
            <span>Kyber-1024 / Serpent / AES / XChaCha</span>
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="hidden sm:flex items-center gap-1">
            <Layers className="w-3 h-3 text-emerald-400" />
            <span>RS(255,223)</span>
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="hidden sm:flex items-center gap-1">
            <HardDrive className="w-3 h-3 text-teal-400" />
            <span>OPFS 1MB Paging</span>
          </span>
        </div>
      </div>
    </div>
  );
};
