import React, { useState } from 'react';
import {
  Activity,
  ArrowDownUp,
  Clock,
  HardDrive,
  Radio,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Trash2,
} from 'lucide-react';
import { TelemetryStats, ProtocolLogEntry } from '../../types/protocol';

interface TelemetryDashboardProps {
  stats: TelemetryStats;
  logs: ProtocolLogEntry[];
  onClearLogs: () => void;
}

export const TelemetryDashboard: React.FC<TelemetryDashboardProps> = ({
  stats,
  logs,
  onClearLogs,
}) => {
  const [filter, setFilter] = useState<string>('all');

  const filteredLogs = logs.filter((log) => {
    if (filter === 'all') return true;
    return log.type === filter;
  });

  return (
    <div className="space-y-4">
      {/* High-Density Metric Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Messages Completed */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Completed Msg</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-emerald-400">
            {stats.messagesCompleted}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            {stats.messagesSent} initiated
          </span>
        </div>

        {/* Fragments Transmitted */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Fragments Sent</span>
            <ArrowDownUp className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-indigo-300">
            {stats.fragmentsTransmitted}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            {stats.fragmentsDelivered} arrived
          </span>
        </div>

        {/* Drops / Loss */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Simulated Drops</span>
            <Radio className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-rose-400">
            {stats.simulatedDrops}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            {stats.fragmentsTransmitted > 0
              ? `${((stats.simulatedDrops / stats.fragmentsTransmitted) * 100).toFixed(1)}% drop rate`
              : '0.0% drop rate'}
          </span>
        </div>

        {/* Duplicates Dropped */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Duplicates Dropped</span>
            <ShieldAlert className="w-3.5 h-3.5 text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-sky-400">
            {stats.duplicatesDropped}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Suppressed safely</span>
        </div>

        {/* Avg Assembly Time */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Assembly Time</span>
            <Clock className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-amber-400">
            {stats.avgAssemblyDurationMs.toFixed(1)}ms
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Cascade latency</span>
        </div>

        {/* Memory Buffer Load */}
        <div className="p-3 bg-[#0f1422] rounded-lg border border-slate-800">
          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
            <span>Buffer Memory</span>
            <HardDrive className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-purple-300">
            {(stats.currentMemoryBytes / 1024).toFixed(1)} KB
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Anti-DoS bound</span>
        </div>
      </div>

      {/* Structured Telemetry Terminal Log */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Structured Protocol Telemetry & Event Stream
            </h3>
          </div>

          <div className="flex items-center gap-2">
            {/* Filter Tabs */}
            <div className="flex items-center gap-1 p-0.5 bg-slate-950 rounded-lg border border-slate-800">
              {(['all', 'crypto', 'network', 'assembler', 'antidos'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setFilter(cat)}
                  className={`cursor-pointer px-2.5 py-1 text-[11px] font-medium rounded capitalize transition-colors ${
                    filter === cat
                      ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={onClearLogs}
              title="Clear event log"
              className="cursor-pointer p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Log Viewer Container */}
        <div className="h-44 overflow-y-auto space-y-1 font-mono text-[11px] bg-slate-950/80 p-3 rounded-lg border border-slate-800/80">
          {filteredLogs.length === 0 ? (
            <div className="text-slate-600 text-center py-8">
              No protocol events logged yet.
            </div>
          ) : (
            filteredLogs.map((entry) => {
              let badgeColor = 'text-slate-400';
              if (entry.type === 'crypto') badgeColor = 'text-emerald-400';
              if (entry.type === 'network') badgeColor = 'text-indigo-400';
              if (entry.type === 'assembler') badgeColor = 'text-amber-400';
              if (entry.type === 'antidos') badgeColor = 'text-rose-400';
              if (entry.type === 'error') badgeColor = 'text-rose-500 font-bold';

              return (
                <div key={entry.id} className="flex items-start gap-2 py-0.5 leading-relaxed">
                  <span className="text-slate-600 shrink-0 tabular-nums">
                    [{entry.timestamp}]
                  </span>
                  <span className={`shrink-0 uppercase font-semibold ${badgeColor}`}>
                    [{entry.type}]
                  </span>
                  <span className="text-slate-300 break-all">{entry.message}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
