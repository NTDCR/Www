import React, { useState } from 'react';
import { usePWAInstall } from '../hooks/usePWAInstall';
import { Wifi, Download, Smartphone, X, ShieldCheck } from 'lucide-react';

export const PWAInstallButton: React.FC = () => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);
  const [installing, setInstalling] = useState(false);

  // If already running as an installed PWA, hide the button
  if (isInstalled) {
    return (
      <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
        <Wifi className="w-3.5 h-3.5" />
        <span>Standalone Gateway Active</span>
      </div>
    );
  }

  const handleInstallClick = async () => {
    setInstalling(true);
    try {
      await install();
    } finally {
      setInstalling(false);
    }
  };

  // Chromium / Android / Desktop flow
  if (isInstallable) {
    return (
      <button
        id="btn-pwa-install"
        onClick={handleInstallClick}
        disabled={installing}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition shadow-lg shadow-cyan-950/40 hover:scale-[1.02] active:scale-[0.98]"
        title="Install as native Wi-Fi Router Gateway application"
      >
        <Wifi className="w-3.5 h-3.5 text-slate-950" />
        <span>{installing ? 'Installing...' : 'Install App'}</span>
      </button>
    );
  }

  // iOS Safari flow (beforeinstallprompt is not supported by WebKit)
  if (isIOS) {
    return (
      <>
        <button
          id="btn-pwa-install-ios"
          onClick={() => setShowIOSGuide(true)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 font-medium text-xs transition"
          title="Install on iPhone / iPad"
        >
          <Smartphone className="w-3.5 h-3.5" />
          <span>Install on iOS</span>
        </button>

        {showIOSGuide && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
            <div className="w-full max-w-sm rounded-xl bg-slate-900 border border-slate-700 p-6 shadow-2xl text-slate-100">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                    <Wifi className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">WiFi Router App</h3>
                    <p className="text-[11px] text-slate-400 font-mono">Disguise Installation</p>
                  </div>
                </div>
                <button
                  onClick={() => setShowIOSGuide(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="mt-4 space-y-3 text-xs text-slate-300">
                <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500 text-slate-950 font-bold text-[10px]">1</span>
                  <p>Tap the <strong className="text-white">Share</strong> button (box with arrow) at the bottom toolbar of Safari.</p>
                </div>
                <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500 text-slate-950 font-bold text-[10px]">2</span>
                  <p>Scroll down and select <strong className="text-white">Add to Home Screen</strong>.</p>
                </div>
                <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500 text-slate-950 font-bold text-[10px]">3</span>
                  <p>The app will be installed with the discreet <strong className="text-cyan-400">WiFi Router</strong> icon and launcher name.</p>
                </div>
              </div>

              <button
                onClick={() => setShowIOSGuide(false)}
                className="mt-5 w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white transition"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  // Fallback direct installer for browsers without triggered event yet
  return (
    <button
      id="btn-pwa-info"
      onClick={() => {
        alert('To install this app on your device:\n\n• Chrome/Edge: Click the install icon in the address bar (or Menu > Install WiFi Router).\n• Android: Tap Menu (3 dots) > Add to Home Screen.\n• iOS: Tap Share > Add to Home Screen.');
      }}
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 border border-slate-800 hover:border-cyan-500/30 text-xs font-mono transition"
      title="Install as native PWA application"
    >
      <Download className="w-3.5 h-3.5" />
      <span className="hidden sm:inline">Install PWA</span>
    </button>
  );
};
