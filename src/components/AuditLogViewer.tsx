import React from 'react';
import { ShieldCheck, FileText, CheckCircle, Clock, ExternalLink } from 'lucide-react';
import { AuditLogEntry } from '../types';

interface AuditLogViewerProps {
  logs: AuditLogEntry[];
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({ logs }) => {
  return (
    <div id="audit-log-viewer" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
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
        <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
          Total Events: {logs.length}
        </span>
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
            {logs.map((log) => (
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
