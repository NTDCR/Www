import React, { useState } from 'react';
import {
  FileText,
  Info,
  CheckCircle2,
  AlertCircle,
  ShieldCheck,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  Lock
} from 'lucide-react';
import { VaultAssessmentNotes, isAssessmentNotesComplete, createEmptyAssessmentNotes } from '../types';
import { ASSESSMENT_QUESTIONS, AssessmentQuestionDef } from '../crypto/notesEngine';

export function generatePlausibleDecoyTemplate(): VaultAssessmentNotes {
  const scenarios = [
    {
      company: ['Apex Meridian Systems Ltd.', 'Vantage Cloud Technologies', 'Zenith Infrastructure Partners'][Math.floor(Math.random() * 3)],
      group: 'Enterprise Cloud Operations & Compliance Oversight',
      data: `Quarterly system health audit records, automated container cluster metrics (${Math.floor(Math.random() * 80 + 20)} nodes), and routine SSL/TLS certificate rotation verification logs.`,
      method: `Automated telemetry collector script executed via internal operational pipeline from datacenter cluster DC-${Math.floor(Math.random() * 8 + 1)} during scheduled maintenance window.`,
      action: 'Retain in internal compliance archive under 90-day data retention policy; disclose only to certified security auditors upon formal regulatory inquiry.',
      details: 'Contains sanitized CPU/memory threshold reports, HTTP request latencies, network throughput statistics, and patch verification checksums. Zero PII or proprietary code included.',
      precautions: 'Stored on restricted operational storage volume with role-based access control and audited access logging.'
    },
    {
      company: ['Horizon Financial Advisors Group', 'Sterling Asset Management Inc.', 'Vanguard Capital Compliance'][Math.floor(Math.random() * 3)],
      group: 'Corporate Accounting & Internal Revenue Reconciliation',
      data: `Routine fiscal reconciliation worksheets, depreciated asset amortization tables (FY-${new Date().getFullYear()}), and routine corporate tax compliance workpapers.`,
      method: 'Exported from secure enterprise ERP ledger system by senior accounting analyst during standard quarterly financial close review.',
      action: 'Maintain in corporate records repository under 7-year statutory financial retention guidelines; submit to external auditors during annual GAAP compliance review.',
      details: 'Aggregated line-item expense ledger entries, vendor payment confirmations, routine amortization schedules, and reconciled bank statement references.',
      precautions: 'Confidential corporate financial record; restricted to authorized finance department personnel with multi-factor authentication.'
    },
    {
      company: ['TransPacific Cargo Networks', 'Meridian Freight & Logistics Ltd.', 'Atlantic Global Forwarding'][Math.floor(Math.random() * 3)],
      group: 'Supply Chain Operations & International Freight Compliance',
      data: `Commercial freight manifests, intermodal container routing logs (Shipment ID #${Math.floor(Math.random() * 900000 + 100000)}), and customs declaration clearance records.`,
      method: 'Extracted from international port logistics management terminal during routine container dispatch and bill-of-lading verification.',
      action: 'Archive according to international maritime and freight compliance standards; present to port authority inspectors when requested.',
      details: 'Standardized bill of lading documents, freight weight certificates, carrier route coordinates, and scheduled delivery timestamp records.',
      precautions: 'Standard commercial logistics record; protected by transportation management system operational credentials.'
    },
    {
      company: ['BioVance Diagnostics Technologies', 'Apex MedTech Solutions', 'Helix Laboratory Systems'][Math.floor(Math.random() * 3)],
      group: 'Medical Device Calibration & Laboratory Quality Assurance',
      data: `Laboratory analyzer baseline calibration curves (Instrument #${Math.floor(Math.random() * 9000 + 1000)}), sensor drift verification telemetry, and scheduled maintenance checklists.`,
      method: 'Downloaded via diagnostic calibration interface during routine bi-weekly laboratory equipment performance validation.',
      action: 'Preserve in quality assurance system archives per ISO 13485 regulatory compliance; provide to QA inspection teams during audit cycles.',
      details: 'Diagnostic reference voltages, reagent temperature stability curves, optical sensor baseline readouts, and technician validation sign-offs.',
      precautions: 'Quality assurance technical record; accessible solely by certified biomedical equipment technicians.'
    }
  ];

  const s = scenarios[Math.floor(Math.random() * scenarios.length)];
  return {
    q1_relatedEntities: `${s.company}, ${s.group}`,
    q2_dataContents: s.data,
    q3_obtainedMethod: s.method,
    q4_disclosureAction: s.action,
    q5_comprehensiveDetails: s.details,
    q6_precautionsAndSafety: s.precautions,
    createdAt: new Date().toISOString()
  };
}

export const PLAUSIBLE_DECOY_TEMPLATE: VaultAssessmentNotes = generatePlausibleDecoyTemplate();

interface AssessmentNotesEditorProps {
  vaultType: 'VaultA' | 'VaultB';
  vaultTitle: string;
  notes: VaultAssessmentNotes;
  onChange: (updated: VaultAssessmentNotes) => void;
  accentColor?: 'emerald' | 'amber';
}

export const AssessmentNotesEditor: React.FC<AssessmentNotesEditorProps> = ({
  vaultType,
  vaultTitle,
  notes,
  onChange,
  accentColor = vaultType === 'VaultA' ? 'emerald' : 'amber'
}) => {
  const [activeInfoId, setActiveInfoId] = useState<string | null>(null);

  const completedCount = ASSESSMENT_QUESTIONS.filter(
    q => notes[q.id] && (notes[q.id] as string).trim().length > 0
  ).length;
  const isComplete = completedCount === ASSESSMENT_QUESTIONS.length;

  const handleFieldChange = (field: keyof VaultAssessmentNotes, val: string) => {
    const enc = new TextEncoder();
    if (enc.encode(val).length > 40000) {
      const dec = new TextDecoder('utf-8');
      const bytes = enc.encode(val).subarray(0, 40000);
      val = dec.decode(bytes);
    }
    onChange({
      ...notes,
      [field]: val
    });
  };

  const toggleInfo = (id: string) => {
    setActiveInfoId(prev => (prev === id ? null : id));
  };

  const handleClearAll = () => {
    onChange(createEmptyAssessmentNotes());
  };

  const isEmerald = accentColor === 'emerald';

  return (
    <div
      id={`assessment-editor-${vaultType}`}
      className={`rounded-2xl border transition-all duration-200 overflow-hidden ${
        isComplete
          ? isEmerald
            ? 'bg-emerald-950/20 border-emerald-500/40 shadow-sm'
            : 'bg-amber-950/20 border-amber-500/40 shadow-sm'
          : 'bg-slate-900/60 border-slate-700/80 shadow-inner'
      }`}
    >
      {/* Header Banner */}
      <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-900/80">
        <div className="flex items-center gap-3">
          <div
            className={`w-9 h-9 rounded-xl flex items-center justify-center font-bold text-sm shadow-md ${
              isEmerald
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
            }`}
          >
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                {vaultTitle} — Comprehensive Assessment Notes
              </h3>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                Mandatory (Manual Entry)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Encrypted independently with K1-K6 Cascade + XOR Garbage Masking + Reed-Solomon RS(255,223)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {vaultType === 'VaultB' && (
            <button
              type="button"
              onClick={() => onChange(generatePlausibleDecoyTemplate())}
              id="btn-load-decoy-template"
              className="text-xs px-2.5 py-1 rounded-lg bg-amber-950/70 hover:bg-amber-900/90 text-amber-300 hover:text-amber-100 border border-amber-500/50 flex items-center gap-1.5 transition-colors font-mono font-semibold"
              title="Load standard plausible decoy compliance template"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
              <span>Load Plausible Decoy Template</span>
            </button>
          )}

          {completedCount > 0 && (
            <button
              type="button"
              onClick={handleClearAll}
              id={`btn-clear-${vaultType}`}
              className="text-xs px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
              title="Clear all text fields for this vault"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Clear Fields</span>
            </button>
          )}

          <div
            className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${
              isComplete
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
            }`}
          >
            {isComplete ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>6/6 Completed</span>
              </>
            ) : (
              <>
                <AlertCircle className="w-3.5 h-3.5" />
                <span>{completedCount}/6 Answered (Mandatory)</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Questions Form Body */}
      <div className="p-5 space-y-6">
        {ASSESSMENT_QUESTIONS.map((q: AssessmentQuestionDef) => {
          const value = (notes[q.id] as string) || '';
          const isFieldFilled = value.trim().length > 0;
          const isInfoOpen = activeInfoId === q.id;

          return (
            <div
              key={q.id}
              id={`question-block-${vaultType}-${q.id}`}
              className={`rounded-xl p-4 border transition-colors ${
                isFieldFilled
                  ? 'bg-slate-900/40 border-slate-700/60'
                  : 'bg-slate-950/40 border-slate-800'
              }`}
            >
              {/* Question Header */}
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-start gap-2.5 flex-1">
                  <span
                    className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold mt-0.5 ${
                      isFieldFilled
                        ? isEmerald
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {q.number}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <label
                        htmlFor={`input-${vaultType}-${q.id}`}
                        className="text-sm font-semibold text-slate-200 cursor-pointer"
                      >
                        {q.title}
                      </label>
                      <span className="text-rose-400 text-xs font-bold">*</span>

                      {/* Info (i) Icon Button */}
                      <button
                        type="button"
                        id={`btn-info-${vaultType}-${q.id}`}
                        onClick={() => toggleInfo(q.id)}
                        className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md transition-all ${
                          isInfoOpen
                            ? 'bg-indigo-600 text-white shadow-sm'
                            : 'bg-slate-800 text-slate-400 hover:text-cyan-300 hover:bg-slate-700'
                        }`}
                        title="Click to view detailed question scope and guidance instructions"
                        aria-expanded={isInfoOpen}
                      >
                        <Info className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="text-[11px] font-medium">Guidance</span>
                        {isInfoOpen ? (
                          <ChevronUp className="w-3 h-3 ml-0.5" />
                        ) : (
                          <ChevronDown className="w-3 h-3 ml-0.5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>

                {isFieldFilled && (
                  <span className="text-[11px] text-emerald-400 flex items-center gap-1 font-medium bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                    <CheckCircle2 className="w-3 h-3" />
                    Saved
                  </span>
                )}
              </div>

              {/* Expandable Guidance Box (Shown only when (i) clicked) */}
              {isInfoOpen && (
                <div
                  id={`guidance-${vaultType}-${q.id}`}
                  className="my-3 p-3.5 rounded-xl bg-slate-950/90 border border-cyan-500/30 text-xs text-slate-300 leading-relaxed shadow-lg backdrop-blur-sm animate-in fade-in duration-200"
                >
                  <div className="flex items-center gap-1.5 text-cyan-300 font-semibold mb-2">
                    <HelpCircle className="w-4 h-4 text-cyan-400" />
                    <span>Instructions & Assessment Scope (Question {q.number})</span>
                  </div>
                  <div className="whitespace-pre-line text-slate-300 font-normal pl-2 border-l-2 border-cyan-500/40">
                    {q.description}
                  </div>
                </div>
              )}

              {/* Multiline UTF-8 Text Area */}
              <div className="relative mt-2">
                <textarea
                  id={`input-${vaultType}-${q.id}`}
                  value={value}
                  onChange={e => handleFieldChange(q.id, e.target.value)}
                  placeholder={q.placeholder}
                  rows={3}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  data-lpignore="true"
                  data-1p-ignore="true"
                  maxLength={40000}
                  className={`w-full px-3.5 py-2.5 text-xs text-slate-100 bg-slate-950/80 rounded-xl border focus:outline-none transition-all resize-y font-sans ${
                    isFieldFilled
                      ? isEmerald
                        ? 'border-emerald-500/30 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/30'
                        : 'border-amber-500/30 focus:border-amber-400 focus:ring-1 focus:ring-amber-400/30'
                      : 'border-slate-700/80 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30'
                  }`}
                />
                <div className="flex justify-between items-center mt-1 px-1 text-[11px] text-slate-500">
                  <span>UTF-8 Multiline Assessment Record</span>
                  {(() => {
                    const byteLen = new TextEncoder().encode(value).length;
                    return (
                      <span className={byteLen > 38000 ? 'text-amber-400 font-mono font-bold' : 'text-slate-500 font-mono'}>
                        {byteLen.toLocaleString()} / 40,000 bytes max
                      </span>
                    );
                  })()}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
