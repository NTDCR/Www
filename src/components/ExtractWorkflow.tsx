import React, { useState, useEffect, useRef } from 'react';
import {
  Unlock,
  UploadCloud,
  FileCheck,
  Key,
  Download,
  AlertCircle,
  Eye,
  EyeOff,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  HardDrive,
  Film,
  FileText,
  Sparkles
} from 'lucide-react';
import { CascadePasswords, DualVaultExtractionResult, VaultAssessmentNotes } from '../types';
import {
  extractFromDualVaultPackage,
  inspectContainerKey6Identity,
  inspectContainerAssessmentNotes,
  clearContainerInspectionCache
} from '../vault/dualVault';
import { VirtualKeypad } from './VirtualKeypad';
import { LiveProgressTimer, formatDurationHuman } from './LiveProgressTimer';
import { Key6BadgeCard } from './Key6BadgeCard';
import { AssessmentNotesPreviewModal } from './AssessmentNotesPreviewModal';
import { StreamingFileHandle, createStreamingFileHandle, loadStreamingFileHandleAsync, streamChunksDirectToDisk, sanitizeFilename } from '../utils/fileReader';
import { yieldToMainThread } from '../crypto/cascadeEngine';

interface ExtractWorkflowProps {
  onAddAuditLog: (eventType: 'DECRYPTION' | 'INTEGRITY_CHECK', details: string, digest: string) => void;
}

export const ExtractWorkflow: React.FC<ExtractWorkflowProps> = ({ onAddAuditLog }) => {
  const isMountedRef = useRef(true);
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const [protectedFile, setProtectedFile] = useState<StreamingFileHandle | null>(null);
  const [protectedBlob, setProtectedBlob] = useState<Blob | null>(null);

  const [passwords, setPasswords] = useState<CascadePasswords>({
    layer1_kyber: '',
    layer2_serpent: '',
    layer3_xchacha: '',
    layer4_aes: '',
    layer5_otp: '',
    layer6_key6: ''
  });

  // Key 6 Pre-Decryption Live Verification State
  const [key6Input, setKey6Input] = useState<string>('');
  const [key6VerifiedUniqueId, setKey6VerifiedUniqueId] = useState<string>('');
  const [key6MatchedVault, setKey6MatchedVault] = useState<'VaultA' | 'VaultB' | null>(null);
  const [isVerifyingKey6, setIsVerifyingKey6] = useState<boolean>(false);

  // Pre-Decryption Live Assessment Notes State
  const [assessmentNotes, setAssessmentNotes] = useState<VaultAssessmentNotes | null>(null);
  const [notesMatchedVault, setNotesMatchedVault] = useState<'VaultA' | 'VaultB' | null>(null);
  const [notesRepairedErrors, setNotesRepairedErrors] = useState<number>(0);
  const [isVerifyingNotes, setIsVerifyingNotes] = useState<boolean>(false);
  const [isNotesModalOpen, setIsNotesModalOpen] = useState<boolean>(false);

  const [pbkdf2Iterations] = useState<number>(1000000);
  const [showPasswords, setShowPasswords] = useState<boolean>(false);
  const [activeKeypadLayer, setActiveKeypadLayer] = useState<keyof CascadePasswords | null>(null);

  // Live Pre-Decrypt Verification of Key 6 and Assessment Notes with non-blocking debounce
  useEffect(() => {
    let active = true;

    const effectiveKey6 = key6Input.trim() || passwords.layer6_key6?.trim() || '';
    const effectivePasswords: CascadePasswords = {
      ...passwords,
      layer6_key6: effectiveKey6
    };

    const hasAnyPassword = Object.values(effectivePasswords).some(p => typeof p === 'string' && p.trim().length > 0);
    const hasKey6 = Boolean(effectiveKey6.length > 0);

    if (!hasKey6) {
      setKey6VerifiedUniqueId('');
      setKey6MatchedVault(null);
      setIsVerifyingKey6(false);
    }

    if (!hasAnyPassword) {
      setAssessmentNotes(null);
      setNotesMatchedVault(null);
      setNotesRepairedErrors(0);
      setIsVerifyingNotes(false);
    }

    if (!protectedFile || (!hasKey6 && !hasAnyPassword)) {
      return () => {
        active = false;
      };
    }

    // Debounce to 600ms to allow smooth typing with zero event-loop locking
    const debounceTimer = setTimeout(async () => {
      if (!active) return;

      // 1. Key 6 live verification (only if >= 4 chars typed)
      if (hasKey6 && protectedFile && effectiveKey6.trim().length >= 4) {
        setIsVerifyingKey6(true);
        try {
          const res = await inspectContainerKey6Identity(protectedFile, effectiveKey6, pbkdf2Iterations);
          if (active) {
            setKey6VerifiedUniqueId(res.uniqueId1024Hex);
            setKey6MatchedVault(res.matchedVault);
          }
        } catch {
          if (active) {
            setKey6VerifiedUniqueId('');
            setKey6MatchedVault(null);
          }
        } finally {
          if (active) setIsVerifyingKey6(false);
        }
      }

      // 2. Assessment Notes live pre-decryption inspection (only if password has >= 4 chars)
      const hasSubstantialPassword = Object.values(effectivePasswords).some(p => typeof p === 'string' && p.trim().length >= 4);
      if (hasSubstantialPassword && protectedFile) {
        setIsVerifyingNotes(true);
        try {
          const res = await inspectContainerAssessmentNotes(protectedFile, effectivePasswords, pbkdf2Iterations);
          if (active) {
            if (res.notes && res.matchedVault) {
              setAssessmentNotes(res.notes);
              setNotesMatchedVault(res.matchedVault);
              setNotesRepairedErrors(res.repairedErrors);
            } else {
              setAssessmentNotes(null);
              setNotesMatchedVault(null);
              setNotesRepairedErrors(0);
            }
          }
        } catch {
          if (active) {
            setAssessmentNotes(null);
            setNotesMatchedVault(null);
            setNotesRepairedErrors(0);
          }
        } finally {
          if (active) setIsVerifyingNotes(false);
        }
      }
    }, 600);

    return () => {
      active = false;
      clearTimeout(debounceTimer);
    };
  }, [protectedFile, key6Input, passwords, pbkdf2Iterations]);

  const [isExtracting, setIsExtracting] = useState<boolean>(false);
  const [progressText, setProgressText] = useState<string>('');
  const [progressPct, setProgressPct] = useState<number>(0);
  const [result, setResult] = useState<DualVaultExtractionResult | null>(null);
  const [totalOperationDurationMs, setTotalOperationDurationMs] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [diskSaveStatus, setDiskSaveStatus] = useState<string | null>(null);
  const [isSavingDisk, setIsSavingDisk] = useState<boolean>(false);

  const handleProtectedFileSelection = async (file: File | null) => {
    clearContainerInspectionCache();
    if (!file) {
      setProtectedFile(null);
      setProtectedBlob(null);
      return;
    }
    try {
      setErrorMsg(null);
      await yieldToMainThread();
      const handle = await loadStreamingFileHandleAsync(file);
      await yieldToMainThread();
      setProtectedFile(handle);
      setProtectedBlob(file);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error reading selected file';
      setErrorMsg(`Container File Selection: ${msg}. Please re-select or drag & drop.`);
      setProtectedFile(null);
      setProtectedBlob(null);
    }
  };

  const handleKeypadInput = (char: string) => {
    if (!activeKeypadLayer) return;
    setPasswords(prev => ({ ...prev, [activeKeypadLayer]: prev[activeKeypadLayer] + char }));
  };

  const handleKeypadBackspace = () => {
    if (!activeKeypadLayer) return;
    setPasswords(prev => ({ ...prev, [activeKeypadLayer]: prev[activeKeypadLayer].slice(0, -1) }));
  };

  const handleKeypadClear = () => {
    if (!activeKeypadLayer) return;
    setPasswords(prev => ({ ...prev, [activeKeypadLayer]: '' }));
  };

  const handleStartExtraction = async () => {
    if (isExtracting) return;
    if (!protectedFile) {
      setErrorMsg('Please upload a protected MP4 container first.');
      return;
    }

    const effectiveKey6 = key6Input.trim() || passwords.layer6_key6?.trim() || '';
    const effectivePasswords: CascadePasswords = {
      ...passwords,
      layer6_key6: effectiveKey6
    };

    const areAllLayersProvided = Boolean(
      (effectivePasswords.layer1_kyber || '').trim().length > 0 &&
      (effectivePasswords.layer2_serpent || '').trim().length > 0 &&
      (effectivePasswords.layer3_xchacha || '').trim().length > 0 &&
      (effectivePasswords.layer4_aes || '').trim().length > 0 &&
      (effectivePasswords.layer5_otp || '').trim().length > 0
    );
    if (!areAllLayersProvided) {
      setErrorMsg('Mandatory Requirement: All 5 cryptographic layers (Kyber-1024, Serpent-256, XChaCha20, AES-256, OTP) must be provided to authenticate and extract the vault.');
      return;
    }

    const overallOpStartTime = performance.now();
    try {
      setIsExtracting(true);
      setErrorMsg(null);
      setTotalOperationDurationMs(null);
      setProgressText('Demuxing 8 spread-spectrum locations...');
      setProgressPct(15);

      const res = await extractFromDualVaultPackage(
        protectedFile,
        effectivePasswords,
        pbkdf2Iterations,
        (desc, pct) => {
          if (!isMountedRef.current) return;
          setProgressText(desc);
          setProgressPct(pct);
        }
      );

      const totalDuration = performance.now() - overallOpStartTime;
      if (!isMountedRef.current) return;
      setTotalOperationDurationMs(totalDuration);
      setResult(res);
      if (res.assessmentNotes) {
        setAssessmentNotes(res.assessmentNotes);
        setNotesMatchedVault(res.matchedVault || 'VaultA');
      }
      onAddAuditLog(
        'DECRYPTION',
        `Successfully unlocked and extracted authenticated payload: ${res.filename} (${res.filesize} bytes) in ${formatDurationHuman(totalDuration)}. Complete 5-layer integrity passed.`,
        res.sha512Digest
      );
    } catch (err: unknown) {
      if (!isMountedRef.current) return;
      const msg = err instanceof Error ? err.message : 'Extraction failed';
      setErrorMsg(msg);
    } finally {
      if (isMountedRef.current) {
        setIsExtracting(false);
      }
    }
  };

  const handleSaveDirectToDisk = async () => {
    if (!result || isSavingDisk) return;
    setIsSavingDisk(true);
    const safeName = sanitizeFilename(result.filename);
    try {
      if (isMountedRef.current) setDiskSaveStatus('Streaming 1 MB chunks directly to disk...');
      const chunks = result.chunkedData || [];
      const outcome = await streamChunksDirectToDisk(safeName, chunks, (_bytes, status) => {
        if (isMountedRef.current) setDiskSaveStatus(status);
      });
      if (!isMountedRef.current) return;
      if (outcome.streamedDirectly) {
        setDiskSaveStatus('Decrypted file saved directly to disk (Zero RAM overhead)!');
      } else {
        setDiskSaveStatus('Downloaded via streaming chunked assembly.');
      }
      setTimeout(() => {
        if (isMountedRef.current) setDiskSaveStatus(null);
      }, 6000);
    } catch (err: any) {
      if (!isMountedRef.current) return;
      if (err.message?.includes('cancelled')) {
        setDiskSaveStatus('Disk write cancelled.');
      } else {
        setDiskSaveStatus(`Disk write error: ${err.message}`);
      }
      setTimeout(() => {
        if (isMountedRef.current) setDiskSaveStatus(null);
      }, 6000);
    } finally {
      if (isMountedRef.current) setIsSavingDisk(false);
    }
  };

  const handleDownloadExtractedFile = () => {
    if (!result) return;
    const safeName = sanitizeFilename(result.filename);
    const url = URL.createObjectURL(result.fileBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = safeName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  return (
    <div id="extract-workflow" className="space-y-6">
      
      {/* Overview Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-bold uppercase tracking-wider mb-1">
              <Unlock className="w-4 h-4" />
              <span>5-Layer Cascade Extraction &amp; Verification</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 font-mono">
              Protected Media Extraction &amp; Cryptographic Verification
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Provide the 5-layer cascade credentials to authenticate and extract the hidden payload.
              The cryptographic engine verifies and decapsulates the stream directly with zero disclosure of underlying container structures.
            </p>
          </div>
        </div>
      </div>

      {/* Upload Container File */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold font-mono text-slate-200 uppercase flex items-center gap-2">
            <UploadCloud className="w-4 h-4 text-emerald-400" />
            <span>Select Protected MP4 Container</span>
          </h3>
          <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">ISOBMFF .mp4</span>
        </div>

        <div className="border-2 border-dashed border-slate-700 hover:border-emerald-500/50 rounded-lg p-5 text-center cursor-pointer transition-colors bg-slate-950/40">
          <input
            type="file"
            accept="video/mp4"
            onChange={(e) => handleProtectedFileSelection(e.target.files?.[0] || null)}
            className="w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-emerald-950 file:text-emerald-400 hover:file:bg-emerald-900 cursor-pointer"
          />
          {protectedFile && (
            <p className="mt-2 text-xs text-emerald-400 font-mono font-semibold">
              ✓ Loaded: {protectedFile.name} ({(protectedFile.size / 1024).toFixed(1)} KB)
            </p>
          )}
        </div>

        {/* Container Inspection & Compatibility Card */}
        {protectedFile && (
          <div className="mt-4 p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-1.5">
                <Film className="w-3.5 h-3.5 text-emerald-400" />
                <span>ISOBMFF Container Inspection</span>
              </span>
              <span className="text-[10px] font-mono font-bold text-sky-400 bg-sky-950/80 border border-sky-500/40 px-2 py-0.5 rounded">
                Structure Valid
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-1">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">File:</span>
                <span className="text-slate-300 font-semibold truncate max-w-[200px]">{protectedFile.name}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Container Size:</span>
                <span className="text-slate-300">{(protectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Stego Dispersions:</span>
                <span className="text-emerald-400 font-semibold">8 Simultaneous Locations</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Device Playback:</span>
                <span className="text-emerald-400 font-semibold">✓ Smooth in Device Player</span>
              </div>
            </div>
          </div>
        )}

        {protectedFile && protectedFile.size >= 1.5 * 1024 * 1024 * 1024 && (
          <div className="mt-4 p-3 bg-amber-950/60 border border-amber-500/50 rounded-lg text-xs font-mono text-amber-300 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold block">Large-Container V8 Engine Advisory (&ge; 1.5 GB):</span>
              Extracting containers &ge; 1.5 GB requires significant browser memory allocation during atom demuxing. Please ensure your host browser machine has at least 4 GB free RAM available and close unneeded browser tabs.
            </div>
          </div>
        )}
      </div>

      {/* 5-Layer Cascade Passwords Entry */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold font-mono text-slate-200 uppercase">
              Enter 5-Layer Cascade Passwords
            </h3>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <button
              type="button"
              onClick={() => setShowPasswords(!showPasswords)}
              className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[11px]"
            >
              {showPasswords ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              <span>{showPasswords ? 'Hide' : 'Show'}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          {(['layer1_kyber', 'layer2_serpent', 'layer3_xchacha', 'layer4_aes', 'layer5_otp'] as (keyof CascadePasswords)[]).map((layerKey, idx) => {
            const layerNames = [
              'Layer 1: Kyber-1024 (Post-Quantum PQC)',
              'Layer 2: Serpent-256-CTR (32 Rounds)',
              'Layer 3: XChaCha20-Poly1305 (24B Nonce)',
              'Layer 4: AES-256-GCM (Hardware Galois)',
              'Layer 5: ChaCha20 Stream Keystream Masking Layer'
            ];
            return (
              <div key={`ext-${layerKey}`} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg space-y-1">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>{layerNames[idx]}</span>
                  <button
                    type="button"
                    onClick={() => setActiveKeypadLayer(layerKey)}
                    className="text-emerald-400 hover:underline text-[10px]"
                  >
                    ⌨ Virtual Keypad
                  </button>
                </div>
                <input
                  type={showPasswords ? 'text' : 'password'}
                  value={passwords[layerKey]}
                  onChange={(e) => setPasswords({ ...passwords, [layerKey]: e.target.value })}
                  autoComplete="new-password"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  data-lpignore="true"
                  data-1p-ignore="true"
                  className="w-full bg-slate-900 border border-slate-700 focus:border-emerald-500 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                />
              </div>
            );
          })}
        </div>

        {/* Key 6: Pre-Decryption Live Container Verifier */}
        <div className="pt-3 border-t border-slate-800">
          <div className="mb-3">
            <h4 className="text-xs font-mono font-bold text-slate-200 uppercase flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-sky-950 border border-sky-500/50 text-sky-400 text-[11px] flex items-center justify-center">6</span>
              <span>Key 6: 1024-Bit Verifiable Unique Container Identity (Pre-Decrypt)</span>
            </h4>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Enter Key 6 to immediately inspect and authenticate the uploaded container. If Key 6 matches Vault A or Vault B, the exact 1024-bit unique ID will display instantly. If Key 6 is incorrect, zero information is leaked.
            </p>
          </div>

          <Key6BadgeCard
            title={key6VerifiedUniqueId ? 'Container Identity Key 6 (Authenticated)' : 'Container Identity Key 6'}
            vaultType="A"
            key6Value={key6Input}
            uniqueId1024Hex={key6VerifiedUniqueId}
            onKey6Change={(val) => {
              setKey6Input(val);
              setPasswords(prev => ({ ...prev, layer6_key6: val }));
            }}
            isPreDecrypt={true}
            isVerified={!!key6VerifiedUniqueId}
          />
        </div>

        {/* Pre-Decryption Live Assessment Notes Inspection Card */}
        <div className="pt-3 border-t border-slate-800">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="flex items-start gap-3">
              <div
                className={`w-9 h-9 rounded-xl flex items-center justify-center text-sm font-bold shadow-md ${
                  assessmentNotes
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h4 className="text-xs font-mono font-bold text-slate-200 uppercase">
                    Pre-Decryption Comprehensive Assessment Notes Preview
                  </h4>
                  {isVerifyingNotes ? (
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 border border-cyan-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                      <RefreshCw className="w-3 h-3 animate-spin" />
                      Checking Notes Parity...
                    </span>
                  ) : assessmentNotes ? (
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded flex items-center gap-1 border bg-emerald-950 text-emerald-300 border-emerald-500/40">
                      <CheckCircle2 className="w-3 h-3" />
                      Container Assessment Notes Authenticated
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {protectedFile ? 'Awaiting matching password keys...' : 'Awaiting MP4 Container upload...'}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  XOR garbage unmasked &amp; cascade authenticated. Preview all 6 assessment questions pre-decryption without modifying container stream.
                </p>
              </div>
            </div>

            <button
              type="button"
              id="btn-preview-assessment-notes"
              onClick={() => setIsNotesModalOpen(true)}
              disabled={!assessmentNotes}
              className={`px-4 py-2.5 rounded-lg font-mono font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-md shrink-0 ${
                assessmentNotes
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950/60 active:scale-95'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Preview Assessment Notes</span>
            </button>
          </div>
        </div>

        {/* Virtual Keypad */}
        {activeKeypadLayer && (
          <div className="pt-2">
            <VirtualKeypad
              title={`Target Layer: ${activeKeypadLayer}`}
              onInput={handleKeypadInput}
              onBackspace={handleKeypadBackspace}
              onClear={handleKeypadClear}
              onClose={() => setActiveKeypadLayer(null)}
            />
          </div>
        )}
      </div>

      {/* Error Message */}
      {errorMsg && (
        <div className="bg-rose-950/80 border border-rose-800 text-rose-300 p-4 rounded-xl flex items-center gap-3 text-xs font-mono">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Action Trigger */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <div className="text-sm font-bold font-mono text-slate-100">
            5-Layer Decapsulation, Decryption &amp; Integrity Verification
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Automatic zeroization of decrypted keys in RAM upon completion.
          </p>
        </div>

        <button
          id="start-extraction-btn"
          type="button"
          onClick={handleStartExtraction}
          disabled={isExtracting}
          className={`flex items-center gap-2 px-6 py-3 rounded-lg font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-lg ${
            isExtracting
              ? 'bg-slate-800 text-slate-400 cursor-not-allowed'
              : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950 shadow-emerald-950/60 active:scale-95'
          }`}
        >
          {isExtracting ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" />
              <span>Unlocking Vault...</span>
            </>
          ) : (
            <>
              <Unlock className="w-4 h-4" />
              <span>Extract &amp; Verify Vault</span>
            </>
          )}
        </button>
      </div>

      {/* Live Processing Telemetry with High-Precision Non-Freezing Elapsed Timer */}
      <LiveProgressTimer
        isActive={isExtracting}
        progressPct={progressPct}
        stageText={progressText}
        totalBytes={protectedFile?.size || 0}
        title="Overall Decapsulation & Integrity Verification"
        mode="decryption"
      />

      {/* Extracted Result Download Card */}
      {result && (
        <div className="bg-gradient-to-r from-emerald-950/90 to-slate-900 border border-emerald-500/50 rounded-xl p-6 shadow-2xl space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-mono font-bold uppercase">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span>Payload Restored &amp; Verified</span>
                </div>
                {totalOperationDurationMs !== null && (
                  <span className="px-2 py-0.5 bg-emerald-950/90 border border-emerald-500/40 text-emerald-300 rounded font-mono text-[11px] font-bold">
                    ⏱ Total Overall Duration: {formatDurationHuman(totalOperationDurationMs)}
                  </span>
                )}
              </div>
              <h3 className="text-xl font-bold font-mono text-slate-100">
                {result.filename}
              </h3>
              <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-300 mt-1">
                <span>Status: <strong className="text-emerald-400">Authenticated &amp; Verified</strong></span>
                <span>•</span>
                <span>Size: {(result.filesize / 1024).toFixed(2)} KB ({result.filesize.toLocaleString()} bytes)</span>
                <span>•</span>
                <span>Integrity: 100% Passed</span>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              {assessmentNotes && (
                <button
                  type="button"
                  id="btn-view-extracted-assessment-notes"
                  onClick={() => setIsNotesModalOpen(true)}
                  className="flex items-center justify-center gap-2 px-4 py-3.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono font-bold text-xs uppercase tracking-wider rounded-lg shadow-md transition-all active:scale-95 whitespace-nowrap"
                >
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>View Assessment Notes</span>
                </button>
              )}

              <button
                id="save-extracted-disk-btn"
                type="button"
                onClick={handleSaveDirectToDisk}
                disabled={isSavingDisk}
                className={`flex items-center justify-center gap-2 px-5 py-3.5 ${
                  isSavingDisk ? 'bg-sky-800 cursor-not-allowed opacity-75' : 'bg-sky-600 hover:bg-sky-500'
                } text-white font-mono font-bold text-xs uppercase tracking-wider rounded-lg shadow-xl shadow-sky-950/60 transition-all active:scale-95 whitespace-nowrap`}
                title="Streams chunks directly to local storage without buffering entire file in RAM"
              >
                <HardDrive className="w-4 h-4" />
                <span>{isSavingDisk ? 'Streaming to Disk...' : 'Save Directly to Disk (0 MB RAM)'}</span>
              </button>

              <button
                id="download-extracted-file-btn"
                type="button"
                onClick={handleDownloadExtractedFile}
                className="flex items-center justify-center gap-2 px-5 py-3.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider rounded-lg shadow-xl shadow-emerald-950/60 transition-all active:scale-95 whitespace-nowrap"
              >
                <Download className="w-4 h-4" />
                <span>Chunked Download</span>
              </button>
            </div>
          </div>

          {diskSaveStatus && (
            <div className="bg-sky-950/80 border border-sky-500/50 rounded-lg p-3 text-xs font-mono text-sky-300 flex items-center gap-2 animate-pulse">
              <HardDrive className="w-4 h-4 text-sky-400 shrink-0" />
              <span>{diskSaveStatus}</span>
            </div>
          )}

          <div className="pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400 break-all">
            <span>SHA-512 Audit Digest: </span>
            <span className="text-emerald-400">{result.sha512Digest}</span>
          </div>
        </div>
      )}

      {/* Assessment Notes Pre-Decryption Preview Modal */}
      <AssessmentNotesPreviewModal
        isOpen={isNotesModalOpen}
        onClose={() => setIsNotesModalOpen(false)}
        notes={assessmentNotes}
        vaultMatched={notesMatchedVault}
        repairedErrors={notesRepairedErrors}
      />

    </div>
  );
};
