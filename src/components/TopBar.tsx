import React from 'react';
import { Download, Play, RefreshCw, ShieldAlert, Cpu } from 'lucide-react';

interface TopBarProps {
  activeTab: 'graph' | 'simulator' | 'proxy' | 'antidos' | 'explorer' | 'spec';
  setActiveTab: (tab: 'graph' | 'simulator' | 'proxy' | 'antidos' | 'explorer' | 'spec') => void;
  onRunSimulation: () => void;
  isRunning: boolean;
  onDownloadZip: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  setActiveTab,
  onRunSimulation,
  isRunning,
  onDownloadZip,
}) => {
  return (
    <header className="sticky top-0 z-40 flex items-center justify-between gap-8 px-6 py-3.5 bg-[#090d16]/95 backdrop-blur-md border-b border-slate-800/80">
      {/* Zone 1: Brand Wordmark (Single text element in display face) */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/40 text-indigo-400">
          <Cpu className="w-4 h-4" />
        </div>
        <span className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0">
          CFCP Transport Engine
        </span>
      </div>

      {/* Zone 2: 6 single-line text navigation links */}
      <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-slate-400">
        <button
          type="button"
          onClick={() => setActiveTab('graph')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'graph' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Live Graph & Swarm
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('simulator')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'simulator' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Protocol Simulator
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('proxy')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'proxy' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Stealth Proxy Lab
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('antidos')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'antidos' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Anti-DoS Stress Lab
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('explorer')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'explorer' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Go Source Explorer
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('spec')}
          className={`cursor-pointer transition-colors whitespace-nowrap shrink-0 hover:text-slate-100 ${
            activeTab === 'spec' ? 'text-indigo-400 font-semibold border-b-2 border-indigo-500 pb-0.5' : ''
          }`}
        >
          Wire Spec & Docs
        </button>
      </nav>

      {/* Zone 3: Primary action button & quick export */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          type="button"
          onClick={onDownloadZip}
          title="Download complete Go project with tests and README"
          className="cursor-pointer flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Go (.zip)</span>
        </button>

        <button
          type="button"
          onClick={onRunSimulation}
          disabled={isRunning}
          className={`cursor-pointer flex items-center gap-2 px-4 py-1.5 text-xs font-semibold text-white rounded-md shadow-sm transition-colors whitespace-nowrap shrink-0 ${
            isRunning
              ? 'bg-indigo-600/50 cursor-not-allowed text-slate-300'
              : 'bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700'
          }`}
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Transmitting...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Cascade Transfer</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
};
