import React, { useState, useEffect, useRef } from 'react';
import { FileText, Download, Copy, Check, ShieldCheck } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { secureCopyToClipboard } from '../security/clipboard';

interface AuditLogViewerProps {
  logs: AuditLogEntry[];
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({ logs }) => {
  const [copied, setCopied] = useState<boolean>(false);
  const activeBlobUrlsRef = useRef<string[]>([]);

  useEffect(() => {
    return () => {
      for (const u of activeBlobUrlsRef.current) {
        try { URL.revokeObjectURL(u); } catch {}
      }
      activeBlobUrlsRef.current = [];
    };
  }, []);

  const exportAsJson = () => {
    if (logs.length === 0) return;
    const jsonStr = JSON.stringify(logs, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    activeBlobUrlsRef.current.push(url);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ContentGuard_Audit_Trail_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch {}
      activeBlobUrlsRef.current = activeBlobUrlsRef.current.filter(u => u !== url);
    }, 120000);
  };

/**
 * Sanitizes CSV cell values to neutralize CSV Formula / DDE Command Injection (CWE-1236).
 * If a cell string starts with =, +, -, @, \t, \r, or %, it is prefixed with a single quote (')
 * to force spreadsheet parsers (Excel, Calc, Sheets) to treat it strictly as literal text.
 */
function sanitizeCsvCell(cell: string | undefined | null): string {
  const str = String(cell ?? '');
  const trimmed = str.trimStart();
  const startsWithFormulaChar = /^[\t\r]/.test(str) || /^[\=\+\-\@%\|\;]/.test(trimmed);
  const safeStr = startsWithFormulaChar ? `'${str}` : str;
  return `"${safeStr.replace(/"/g, '""')}"`;
}

  const exportAsCsv = () => {
    if (logs.length === 0) return;
    const headers = ['ID', 'Timestamp', 'Event Type', 'Compliance Standard', 'Target Vault', 'SHA-512 Digest', 'Status', 'Details'];
    const rows = logs.map(l => [
      sanitizeCsvCell(l.id),
      sanitizeCsvCell(l.timestamp),
      sanitizeCsvCell(l.eventType),
      sanitizeCsvCell(l.complianceRef),
      sanitizeCsvCell(l.vaultTarget),
      sanitizeCsvCell(l.sha512Digest),
      sanitizeCsvCell(l.status),
      sanitizeCsvCell(l.details)
    ].join(','));
    const csvContent = [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    activeBlobUrlsRef.current.push(url);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ContentGuard_Audit_Trail_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch {}
      activeBlobUrlsRef.current = activeBlobUrlsRef.current.filter(u => u !== url);
    }, 120000);
  };

  const handleCopy = async () => {
    if (logs.length === 0) return;
    let summary = `=== ContentGuard Pro MAX - Cryptographic Audit Trail ===\n`;
    summary += `Total Events: ${logs.length} | Exported: ${new Date().toISOString()}\n\n`;
    logs.forEach((l, idx) => {
      summary += `[#${idx + 1}] ${l.timestamp} | ${l.eventType} | ${l.complianceRef} | ${l.vaultTarget} | Status: ${l.status}\n`;
      summary += `Digest: ${l.sha512Digest || 'N/A'}\n`;
      if (l.details) summary += `Details: ${l.details}\n`;
      summary += `--------------------------------------------------------\n`;
    });
    await secureCopyToClipboard(summary, 45);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div id="audit-log-viewer" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold font-mono text-slate-100 uppercase">
              Immutable Audit Trail &amp; Chain-of-Custody (FINRA 17a-4 / HIPAA / GDPR)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic SHA-512 event chain recorded in memory and IndexedDB storage.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
            Total Events: {logs.length}
          </span>
          <button
            type="button"
            onClick={handleCopy}
            disabled={logs.length === 0}
            className="flex items-center gap-1 text-[11px] font-mono px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors disabled:opacity-50"
            title="Copy audit log report to clipboard"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            type="button"
            onClick={exportAsJson}
            disabled={logs.length === 0}
            className="flex items-center gap-1 text-[11px] font-mono px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors disabled:opacity-50"
            title="Export full log as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
          <button
            type="button"
            onClick={exportAsCsv}
            disabled={logs.length === 0}
            className="flex items-center gap-1 text-[11px] font-mono px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors disabled:opacity-50"
            title="Export full log as CSV"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 px-3">Timestamp</th>
              <th className="py-2 px-3">Event Type</th>
              <th className="py-2 px-3">Compliance Standard</th>
              <th className="py-2 px-3">Target Vault</th>
              <th className="py-2 px-3">SHA-512 Digest</th>
              <th className="py-2 px-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-6 text-center text-slate-500 italic">
                  No cryptographic events recorded in this session yet.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-950/40 transition-colors">
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                  <td className="py-2.5 px-3 font-semibold text-emerald-400">{log.eventType}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800/60 text-[10px] font-bold">
                      {log.complianceRef}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{log.vaultTarget}</td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px] font-mono">
                    {log.sha512Digest ? `${log.sha512Digest.slice(0, 16)}...${log.sha512Digest.slice(-8)}` : 'N/A'}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
