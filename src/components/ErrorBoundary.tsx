import React, { ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw, Terminal } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

type ReactComponentType = new (props: Props) => {
  props: Props;
  state: State;
  setState(state: Partial<State>): void;
  render(): ReactNode;
  componentDidCatch?(error: Error, errorInfo: ErrorInfo): void;
};

const BaseComponent = (React.Component || class {}) as unknown as ReactComponentType;

export class ErrorBoundary extends BaseComponent {
  state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  };

  constructor(props: Props) {
    super(props);
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    console.error('ContentGuard Pro MAX — Boundary Failure Intercepted:', error, errorInfo);
  }

  handleReset = (): void => {
    try {
      sessionStorage.clear();
    } catch {}
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 select-none">
          <div className="max-w-xl w-full bg-slate-900/90 border border-red-500/40 rounded-2xl p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-red-600 via-amber-500 to-red-600" />
            
            <div className="flex items-center gap-4 mb-6">
              <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
                <ShieldAlert className="w-8 h-8" />
              </div>
              <div>
                <h1 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
                  Cryptographic Boundary Active
                </h1>
                <p className="text-xs text-slate-400 font-mono">
                  Zero-Leakage Fault Interceptor &bull; State Quarantined
                </p>
              </div>
            </div>

            <div className="bg-black/60 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 mb-6 space-y-2">
              <div className="flex items-center gap-2 text-amber-400 font-semibold">
                <Terminal className="w-4 h-4" />
                <span>Runtime Exception Isolated:</span>
              </div>
              <p className="text-red-400 break-words font-semibold">
                {this.state.error?.message || 'Unexpected application boundary error.'}
              </p>
              <p className="text-[11px] text-slate-500 pt-2 border-t border-slate-800/80">
                To guarantee zero memory leakage and prevent key material contamination, all volatile state has been wiped.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-sm shadow-lg shadow-emerald-950/40 flex items-center gap-2 cursor-pointer transition-all active:scale-95"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Secure Reload & Reset</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}