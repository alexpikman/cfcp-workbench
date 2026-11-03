import React, { useState } from 'react';
import {
  FileCode,
  Copy,
  Check,
  Download,
  FolderTree,
  Terminal,
  Shield,
  Layers,
  Cpu,
} from 'lucide-react';
import { GO_FILES, GoFileRecord } from '../../data/goCodeFiles';

interface GoCodeExplorerProps {
  onDownloadZip: () => void;
}

export const GoCodeExplorer: React.FC<GoCodeExplorerProps> = ({ onDownloadZip }) => {
  const [selectedFile, setSelectedFile] = useState<GoFileRecord>(GO_FILES[0]);
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(selectedFile.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = selectedFile.code.split('\n').length;

  return (
    <div className="space-y-4">
      {/* Overview & Quick Command Strip */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FolderTree className="w-4 h-4 text-indigo-400" />
              Go Source Codebase Explorer
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Production-grade Go implementation of CFCP with ChaCha20-Poly1305 AEAD, timed Anti-DoS MessageAssembler, and SHA-256 integrity verification.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleCopy}
              className="cursor-pointer flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy File</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={onDownloadZip}
              className="cursor-pointer flex items-center gap-2 px-4 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Go Package (.zip)</span>
            </button>
          </div>
        </div>

        {/* Quick Shell Guide */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px] mb-1 font-sans flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-emerald-400" />
              <span>Run Automated Unit Tests</span>
            </div>
            <code className="text-emerald-300 text-xs">go test -v ./pkg/protocol/...</code>
          </div>

          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px] mb-1 font-sans flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-indigo-400" />
              <span>Start Server with 6s Anti-DoS</span>
            </div>
            <code className="text-indigo-300 text-xs">go run ./cmd/server/main.go</code>
          </div>

          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px] mb-1 font-sans flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-amber-400" />
              <span>Launch Client with Jitter & Loss</span>
            </div>
            <code className="text-amber-300 text-xs">go run ./cmd/client/main.go -loss 10</code>
          </div>
        </div>
      </div>

      {/* Code Browser Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* File Navigation Sidebar */}
        <div className="lg:col-span-4 bg-[#0f1422] rounded-xl border border-slate-800 p-4 space-y-2">
          <div className="text-xs font-semibold text-slate-400 px-2 py-1 uppercase tracking-wider">
            Files ({GO_FILES.length})
          </div>

          <div className="space-y-1">
            {GO_FILES.map((file) => {
              const isSelected = selectedFile.path === file.path;
              return (
                <button
                  key={file.path}
                  type="button"
                  onClick={() => setSelectedFile(file)}
                  className={`cursor-pointer w-full text-left p-2.5 rounded-lg border transition-all text-xs flex flex-col gap-0.5 ${
                    isSelected
                      ? 'bg-indigo-950/40 border-indigo-500/50 text-indigo-200'
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center gap-2 font-mono font-medium">
                    <FileCode
                      className={`w-3.5 h-3.5 shrink-0 ${
                        isSelected ? 'text-indigo-400' : 'text-slate-500'
                      }`}
                    />
                    <span className="truncate">{file.path}</span>
                  </div>
                  <span className="text-[11px] text-slate-500 truncate pl-5">
                    {file.description}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Code Editor Preview Window */}
        <div className="lg:col-span-8 bg-[#0f1422] rounded-xl border border-slate-800 overflow-hidden flex flex-col">
          {/* File Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800 text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300">
              <span className="text-indigo-400 font-semibold">{selectedFile.filename}</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-500">{lineCount} lines</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-500">{new Blob([selectedFile.code]).size} bytes</span>
            </div>

            <button
              type="button"
              onClick={handleCopy}
              className="cursor-pointer text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5"
            >
              {copied ? (
                <span className="text-emerald-400 font-medium">Copied!</span>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>

          {/* Syntax Highlighted Code Viewer */}
          <div className="p-4 bg-slate-950/90 overflow-x-auto text-xs font-mono leading-relaxed h-[600px] overflow-y-auto">
            <pre className="text-slate-300 select-text">
              {selectedFile.code.split('\n').map((line, idx) => (
                <div key={idx} className="table-row">
                  <span className="table-cell select-none text-slate-600 pr-4 text-right tabular-nums w-8">
                    {idx + 1}
                  </span>
                  <span className="table-cell whitespace-pre">{line}</span>
                </div>
              ))}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
