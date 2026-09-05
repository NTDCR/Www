import React, { useState } from 'react';
import {
  FileText,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  X,
  Lock,
  Layers,
  Sparkles,
  Printer,
  Download
} from 'lucide-react';
import { VaultAssessmentNotes } from '../types';
import { ASSESSMENT_QUESTIONS, AssessmentQuestionDef } from '../crypto/notesEngine';
import { secureCopyToClipboard } from '../security/clipboard';

interface AssessmentNotesPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  notes: VaultAssessmentNotes | null;
  vaultMatched: 'VaultA' | 'VaultB' | null;
  repairedErrors?: number;
}

export const AssessmentNotesPreviewModal: React.FC<AssessmentNotesPreviewModalProps> = ({
  isOpen,
  onClose,
  notes,
  vaultMatched,
  repairedErrors = 0
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState<boolean>(false);

  if (!isOpen || !notes) return null;

  const isVaultA = vaultMatched === 'VaultA';
  const vaultTitle = 'Security Assessment Record';

  const handleCopyField = async (id: string, text: string) => {
    await secureCopyToClipboard(text, 45);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleCopyAll = async () => {
    let fullReport = `=== ContentGuard Pro MAX - Pre-Decryption Assessment Notes Report ===\n`;
    fullReport += `Record Status: Authenticated & Integrity Verified\n`;
    fullReport += `Date Created: ${notes.createdAt || 'N/A'}\n`;
    fullReport += `Reed-Solomon RS(255,223) Error Correction: ${repairedErrors} symbols repaired\n`;
    fullReport += `Cascade Verification: AES-256-GCM + XChaCha20-Poly1305 + Serpent-256 Authenticated\n\n`;

    ASSESSMENT_QUESTIONS.forEach(q => {
      fullReport += `[Question ${q.number}]: ${q.title}\n`;
      fullReport += `${notes[q.id] || '(No response recorded)'}\n\n`;
    });

    await secureCopyToClipboard(fullReport, 45);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2500);
  };

  const handleDownloadReport = () => {
    let fullReport = `=== ContentGuard Pro MAX - Pre-Decryption Assessment Notes Report ===\n`;
    fullReport += `Record Status: Authenticated & Integrity Verified\n`;
    fullReport += `Date Created: ${notes.createdAt || 'N/A'}\n`;
    fullReport += `Reed-Solomon RS(255,223) Error Correction: ${repairedErrors} symbols repaired\n\n`;

    ASSESSMENT_QUESTIONS.forEach(q => {
      fullReport += `------------------------------------------------------------\n`;
      fullReport += `QUESTION ${q.number}: ${q.title}\n`;
      fullReport += `------------------------------------------------------------\n`;
      fullReport += `${notes[q.id] || '(No response recorded)'}\n\n`;
    });

    const blob = new Blob([fullReport], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Assessment_Notes_Report_${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  return (
    <div
      id="assessment-preview-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        id="assessment-preview-modal"
        className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm shadow-md bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  Pre-Decryption Assessment Notes Preview
                </h2>
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider border bg-emerald-500/20 text-emerald-300 border-emerald-500/30">
                  {vaultTitle}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Cascade K1-K6 Decrypted • XOR Unmasked • Reed-Solomon RS(255,223) Verified
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyAll}
              id="btn-copy-all-assessment-notes"
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors font-medium"
            >
              {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedAll ? 'Report Copied!' : 'Copy Full Report'}</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadReport}
              id="btn-download-assessment-notes"
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export .TXT</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              id="btn-close-assessment-modal"
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Verification Status Banner */}
        <div className="px-6 py-2.5 bg-slate-950/60 border-b border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-300 gap-2">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              HMAC-SHA256 Authenticated
            </span>
            <span className="text-slate-500">|</span>
            <span className="flex items-center gap-1.5 text-cyan-300">
              <Layers className="w-3.5 h-3.5" />
              FEC Parity: {repairedErrors === 0 ? 'Clean (0 bit errors)' : `${repairedErrors} symbols repaired`}
            </span>
          </div>
          {notes.createdAt && (
            <span className="text-slate-400 text-[11px]">
              Encrypted: {new Date(notes.createdAt).toLocaleString()}
            </span>
          )}
        </div>

        {/* Modal Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 max-h-[calc(90vh-140px)] custom-scrollbar">
          {ASSESSMENT_QUESTIONS.map((q: AssessmentQuestionDef) => {
            const answer = (notes[q.id] as string) || '';
            const isCopied = copiedId === q.id;

            return (
              <div
                key={q.id}
                id={`preview-block-${q.id}`}
                className="rounded-xl p-4 bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-start gap-2.5">
                    <span
                      className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold mt-0.5 ${
                        isVaultA
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                      }`}
                    >
                      {q.number}
                    </span>
                    <div>
                      <h4 className="text-sm font-semibold text-slate-100">
                        {q.title}
                      </h4>
                      <p className="text-[11px] text-slate-400 mt-0.5">{q.shortLabel}</p>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopyField(q.id, answer)}
                    className="text-xs px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 flex items-center gap-1 transition-colors"
                    title="Copy this answer"
                  >
                    {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span className="text-[11px]">{isCopied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                {/* Answer Content */}
                <div className="mt-3 p-3.5 rounded-lg bg-slate-900/90 border border-slate-800/80 text-xs text-slate-200 leading-relaxed font-sans whitespace-pre-wrap">
                  {answer.trim().length > 0 ? (
                    answer
                  ) : (
                    <span className="italic text-slate-500">No response provided in this assessment field.</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between bg-slate-950/80">
          <span className="text-xs text-slate-400">
            Independent metadata block verified without modifying underlying payload.
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            Close Preview
          </button>
        </div>
      </div>
    </div>
  );
};
