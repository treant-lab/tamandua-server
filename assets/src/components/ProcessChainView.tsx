import { useState } from 'react';
import { ChevronRight, AlertTriangle, Terminal, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ProcessChainNode } from '@/types';

interface ProcessChainViewProps {
  chain: ProcessChainNode[];
}

export default function ProcessChainView({ chain }: ProcessChainViewProps) {
  if (!chain || chain.length === 0) {
    return (
      <div className="text-center py-8 text-slate-500">
        <Terminal className="h-10 w-10 mx-auto mb-2 opacity-50" />
        <p>No process chain available</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {chain.map((process, index) => (
        <div key={`${process.pid}-${index}`} className="flex items-start gap-2">
          {/* Indentation based on level */}
          <div style={{ width: `${process.level * 24}px` }} className="shrink-0" />

          {/* Arrow connector */}
          {index > 0 && (
            <ChevronRight className="h-4 w-4 text-slate-500 mt-3 shrink-0" />
          )}

          {/* Process card */}
          <div className={cn(
            "flex-1 p-3 rounded-lg border",
            process.is_malicious
              ? "bg-red-900/20 border-red-500/50"
              : "bg-slate-800/50 border-slate-700"
          )}>
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              {process.is_malicious && (
                <AlertTriangle className="h-4 w-4 text-red-400" />
              )}
              <span className={cn(
                "font-medium",
                process.is_malicious ? "text-red-400" : "text-white"
              )}>
                {process.name}
              </span>
              <span className="text-xs text-slate-500">PID: {process.pid}</span>
              {process.is_elevated && (
                <span className="text-xs px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 rounded">
                  Elevated
                </span>
              )}
              {process.is_signed && (
                <span className="text-xs px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded">
                  Signed
                </span>
              )}
            </div>

            {process.path && (
              <div className="text-xs text-slate-400 font-mono truncate">
                {process.path}
              </div>
            )}

            {(process.cmdline || process.command_line || process.command) && (
              <ProcessCommandLine value={process.cmdline || process.command_line || process.command || ''} />
            )}

            {process.user && (
              <div className="text-xs text-slate-500 mt-1">
                User: {process.user}
              </div>
            )}

            {process.signer && (
              <div className="text-xs text-slate-500 mt-1">
                Signer: {process.signer}
              </div>
            )}

            {process.start_time && (
              <div className="text-xs text-slate-600 mt-1">
                Started: {new Date(process.start_time).toLocaleString()}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function ProcessCommandLine({ value }: { value: string }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const isLong = value.length > 180;

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="mt-1 min-w-0">
      <div
        className={cn(
          'text-xs text-slate-500 font-mono whitespace-pre-wrap',
          !expanded ? 'max-h-12 overflow-hidden' : 'max-h-48 overflow-auto'
        )}
        style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}
        title={value}
      >
        {value}
      </div>
      <div className="mt-1 flex items-center gap-3">
        {isLong && (
          <button
            type="button"
            onClick={() => setExpanded(current => !current)}
            className="text-[11px] text-slate-500 hover:text-slate-200"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}
        <button
          type="button"
          onClick={handleCopy}
          className="text-[11px] text-slate-500 hover:text-slate-200 flex items-center gap-1"
        >
          {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  );
}
