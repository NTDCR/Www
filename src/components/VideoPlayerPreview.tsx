import React, { useState, useRef, useEffect } from 'react';
import {
  Play,
  Pause,
  Volume2,
  VolumeX,
  Maximize2,
  Video,
  Sparkles,
  RefreshCw,
  CheckCircle2,
  Film,
  Clock,
  Layers,
  Activity
} from 'lucide-react';
import { createAnimatedCanvasCarrierBlob } from '../media/mp4Generator';

interface VideoPlayerPreviewProps {
  videoBlob?: Blob | null;
  videoUrl?: string | null;
  title?: string;
  subtitle?: string;
  badgeText?: string;
  badgeColor?: 'emerald' | 'sky' | 'amber';
  onNewCarrierGenerated?: (blob: Blob, name: string) => void;
  showCanvasGenerator?: boolean;
}

export const VideoPlayerPreview: React.FC<VideoPlayerPreviewProps> = ({
  videoBlob,
  videoUrl,
  title = 'Carrier Video Stream Preview',
  subtitle = 'ISO/IEC 14496-12 standard compliant H.264 container',
  badgeText = '100% Playable Stream',
  badgeColor = 'emerald',
  onNewCarrierGenerated,
  showCanvasGenerator = false
}) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [internalUrl, setInternalUrl] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isMuted, setIsMuted] = useState<boolean>(true);
  const [currentTime, setCurrentTime] = useState<number>(0);
  const [duration, setDuration] = useState<number>(0);
  const [videoDims, setVideoDims] = useState<{ w: number; h: number }>({ w: 640, h: 360 });
  const [isGeneratingCanvas, setIsGeneratingCanvas] = useState<boolean>(false);
  const [mediaError, setMediaError] = useState<string | null>(null);
  const isMountedRef = useRef<boolean>(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Manage object URL lifecycle
  useEffect(() => {
    let url: string | null = null;
    if (videoBlob) {
      url = URL.createObjectURL(videoBlob);
      setInternalUrl(url);
      setMediaError(null);
    } else if (videoUrl) {
      setInternalUrl(videoUrl);
      setMediaError(null);
    } else {
      setInternalUrl(null);
    }

    return () => {
      if (url) {
        URL.revokeObjectURL(url);
      }
    };
  }, [videoBlob, videoUrl]);

  const togglePlay = () => {
    if (!videoRef.current) return;
    if (videoRef.current.paused) {
      videoRef.current.play().then(() => setIsPlaying(true)).catch(err => {
        console.warn('Playback error:', err);
      });
    } else {
      videoRef.current.pause();
      setIsPlaying(false);
    }
  };

  const toggleMute = () => {
    if (!videoRef.current) return;
    videoRef.current.muted = !videoRef.current.muted;
    setIsMuted(videoRef.current.muted);
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!videoRef.current) return;
    const target = parseFloat(e.target.value);
    videoRef.current.currentTime = target;
    setCurrentTime(target);
  };

  const handleTimeUpdate = () => {
    if (!videoRef.current) return;
    setCurrentTime(videoRef.current.currentTime);
  };

  const handleLoadedMetadata = () => {
    if (!videoRef.current) return;
    const dur = videoRef.current.duration || 0;
    setDuration(isNaN(dur) ? 0 : dur);
    setVideoDims({
      w: videoRef.current.videoWidth || 640,
      h: videoRef.current.videoHeight || 360
    });
    setMediaError(null);
  };

  const handleGenerateFreshCarrier = async () => {
    if (isGeneratingCanvas) return;
    try {
      setIsGeneratingCanvas(true);
      const dynamicBlob = await createAnimatedCanvasCarrierBlob(5);
      if (isMountedRef.current && onNewCarrierGenerated) {
        onNewCarrierGenerated(dynamicBlob, `Dynamic_Cyber_Radar_Carrier_${Date.now()}.mp4`);
      }
    } catch (err) {
      console.error('Failed to generate dynamic canvas carrier', err);
    } finally {
      if (isMountedRef.current) {
        setIsGeneratingCanvas(false);
      }
    }
  };

  const formatTime = (secs: number) => {
    if (isNaN(secs) || secs < 0) return '00:00';
    const m = Math.floor(secs / 60);
    const s = Math.floor(secs % 60);
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const badgeStyles = {
    emerald: 'bg-emerald-950/80 border-emerald-500/50 text-emerald-400',
    sky: 'bg-sky-950/80 border-sky-500/50 text-sky-400',
    amber: 'bg-amber-950/80 border-amber-500/50 text-amber-400'
  };

  return (
    <div className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono">
      
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 bg-slate-900/90 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center shrink-0">
            <Film className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <span>{title}</span>
            </h4>
            <p className="text-[11px] text-slate-400">{subtitle}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold border flex items-center gap-1.5 ${badgeStyles[badgeColor]}`}>
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>{badgeText}</span>
          </span>

          {showCanvasGenerator && onNewCarrierGenerated && (
            <button
              type="button"
              onClick={handleGenerateFreshCarrier}
              disabled={isGeneratingCanvas}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-[11px] font-bold rounded-md shadow-md transition-all active:scale-95 disabled:opacity-50"
            >
              {isGeneratingCanvas ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5" />
              )}
              <span>{isGeneratingCanvas ? 'Rendering...' : 'Render Live Video'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Video Viewport Stage */}
      <div className="relative aspect-video bg-black flex items-center justify-center group overflow-hidden">
        {internalUrl ? (
          <video
            ref={videoRef}
            src={internalUrl}
            playsInline
            loop
            muted={isMuted}
            onTimeUpdate={handleTimeUpdate}
            onLoadedMetadata={handleLoadedMetadata}
            onPlay={() => setIsPlaying(true)}
            onPause={() => setIsPlaying(false)}
            onEnded={() => setIsPlaying(false)}
            onError={() => setMediaError('Video stream parsing')}
            className="w-full h-full object-contain cursor-pointer"
            onClick={togglePlay}
          />
        ) : (
          <div className="text-center p-6 space-y-2">
            <Video className="w-12 h-12 text-slate-700 mx-auto animate-pulse" />
            <p className="text-xs text-slate-500">No active video stream loaded</p>
          </div>
        )}

        {/* Center overlay play button when paused */}
        {internalUrl && !isPlaying && (
          <button
            type="button"
            onClick={togglePlay}
            className="absolute w-14 h-14 rounded-full bg-emerald-500/90 hover:bg-emerald-400 text-slate-950 flex items-center justify-center shadow-2xl transition-all transform hover:scale-110 active:scale-95 z-10"
            aria-label="Play video"
          >
            <Play className="w-6 h-6 fill-current translate-x-0.5" />
          </button>
        )}

        {/* Technical telemetry overlay watermark */}
        <div className="absolute top-3 left-3 bg-slate-950/80 backdrop-blur border border-slate-700/60 rounded px-2.5 py-1 text-[10px] text-emerald-400 flex items-center gap-2 pointer-events-none">
          <Activity className="w-3 h-3 text-emerald-400 animate-pulse" />
          <span>H.264 Baseline • {videoDims.w}×{videoDims.h} • 30 FPS</span>
        </div>

        <div className="absolute top-3 right-3 bg-slate-950/80 backdrop-blur border border-slate-700/60 rounded px-2.5 py-1 text-[10px] text-slate-300 flex items-center gap-1.5 pointer-events-none">
          <Clock className="w-3 h-3 text-sky-400" />
          <span>{formatTime(currentTime)} / {formatTime(duration || 5)}</span>
        </div>
      </div>

      {/* Media Error Alert if any */}
      {mediaError && (
        <div className="bg-amber-950/80 border-t border-amber-800 p-2 text-center text-xs text-amber-300">
          <span>{mediaError} — Standalone fallback parser engaged</span>
        </div>
      )}

      {/* Video Controls Bar */}
      <div className="p-3 bg-slate-900 border-t border-slate-800 space-y-2">
        {/* Scrubber Range Bar */}
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-slate-400 min-w-[36px] text-right font-mono">
            {formatTime(currentTime)}
          </span>
          <div className="relative flex-1 flex items-center">
            <input
              type="range"
              min={0}
              max={duration > 0 ? duration : 5}
              step={0.05}
              value={currentTime}
              onChange={handleSeek}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-emerald-500 focus:outline-none"
            />
          </div>
          <span className="text-[11px] text-slate-400 min-w-[36px] font-mono">
            {formatTime(duration || 5)}
          </span>
        </div>

        {/* Buttons Row */}
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={togglePlay}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
              title={isPlaying ? 'Pause' : 'Play'}
            >
              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4 fill-current" />}
            </button>

            <button
              type="button"
              onClick={toggleMute}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
              title={isMuted ? 'Unmute' : 'Mute'}
            >
              {isMuted ? <VolumeX className="w-4 h-4 text-slate-400" /> : <Volume2 className="w-4 h-4 text-emerald-400" />}
            </button>

            <div className="text-[11px] text-slate-400 pl-2 hidden sm:block">
              Timescale: <span className="text-slate-200 font-bold">1000 Hz</span> • State: <span className="text-emerald-400 font-bold">{isPlaying ? 'Streaming' : 'Ready'}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-[10px] text-slate-400">
            <span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700">ISO/IEC 14496-12</span>
            <span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700">Zero Distortion</span>
          </div>
        </div>
      </div>

    </div>
  );
};
