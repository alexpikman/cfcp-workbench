import React, { useState, useEffect } from 'react';
import { ShieldAlert, RefreshCw, Trash2, Zap, AlertTriangle, Clock, HardDrive, CheckCircle } from 'lucide-react';
import { generateRandomMessageId } from '../../utils/cryptoSim';

interface StressSession {
  id: string;
  messageId: string;
  totalFrags: number;
  receivedFrags: number;
  allocatedBytes: number;
  ttlRemainingMs: number;
  initialTtlMs: number;
  attackerIp: string;
  createdAt: number;
}

export const AntiDosStressLab: React.FC = () => {
  const [sessions, setSessions] = useState<StressSession[]>([]);
  const [timeoutSec, setTimeoutSec] = useState<number>(5);
  const [floodIntensity, setFloodIntensity] = useState<number>(20);
  const [isAttacking, setIsAttacking] = useState<boolean>(false);
  const [evictedCount, setEvictedCount] = useState<number>(0);
  const [reaperRuns, setReaperRuns] = useState<number>(0);

  // Background Reaper simulation loop: runs every 500ms
  useEffect(() => {
    const reaperInterval = setInterval(() => {
      setReaperRuns((prev) => prev + 1);

      setSessions((currentSessions) => {
        let purged = 0;
        const now = Date.now();
        const surviving: StressSession[] = [];

        for (const session of currentSessions) {
          const age = now - session.createdAt;
          const remaining = Math.max(0, session.initialTtlMs - age);

          if (remaining <= 0) {
            purged++;
          } else {
            surviving.push({
              ...session,
              ttlRemainingMs: remaining,
            });
          }
        }

        if (purged > 0) {
          setEvictedCount((prev) => prev + purged);
        }

        return surviving;
      });
    }, 500);

    return () => clearInterval(reaperInterval);
  }, []);

  const handleLaunchFloodAttack = () => {
    setIsAttacking(true);
    const newSessions: StressSession[] = [];
    const now = Date.now();
    const ttlMs = timeoutSec * 1000;

    for (let i = 0; i < floodIntensity; i++) {
      const msgId = generateRandomMessageId();
      const total = Math.floor(Math.random() * 8) + 4;
      const received = Math.floor(Math.random() * 2) + 1; // stalled: only 1 or 2 frags arrive
      const bytes = received * 320 + 64;
      const randomOctet = Math.floor(Math.random() * 254) + 1;

      newSessions.push({
        id: `flood-${Date.now()}-${i}`,
        messageId: msgId,
        totalFrags: total,
        receivedFrags: received,
        allocatedBytes: bytes,
        ttlRemainingMs: ttlMs,
        initialTtlMs: ttlMs,
        attackerIp: `198.51.100.${randomOctet}`,
        createdAt: now,
      });
    }

    setSessions((prev) => [...prev, ...newSessions]);
    setTimeout(() => setIsAttacking(false), 800);
  };

  const handleClearAll = () => {
    setSessions([]);
  };

  const totalMemoryBytes = sessions.reduce((sum, s) => sum + s.allocatedBytes, 0);
  const maxMemoryBytes = 64 * 1024 * 1024; // 64 MB pool
  const memoryPct = ((totalMemoryBytes / (1024 * 1024)) / 64) * 100;

  return (
    <div className="space-y-6">
      {/* Header and explanation */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              <h2 className="text-base font-bold text-slate-100">
                Anti-DoS Buffer & Memory Protection Workbench
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Under UDP transport, adversaries can flood servers with forged Message IDs and incomplete fragments to exhaust RAM. CFCP enforces strict session TTLs, automatic background reaper eviction, and hard memory bounds.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleClearAll}
              disabled={sessions.length === 0}
              className="cursor-pointer flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-lg transition-colors disabled:opacity-50"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Flush Buffer</span>
            </button>

            <button
              type="button"
              onClick={handleLaunchFloodAttack}
              disabled={isAttacking}
              className="cursor-pointer flex items-center gap-2 px-4 py-1.5 text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 rounded-lg transition-colors shadow-sm"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>Simulate Fragment Flood Attack</span>
            </button>
          </div>
        </div>

        {/* Attack Parameters & Live Indicators */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          {/* Active Sessions */}
          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Active Sessions</span>
              <Clock className="w-3.5 h-3.5 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
              {sessions.length}
            </div>
            <span className="text-[11px] text-slate-500">Currently occupying RAM</span>
          </div>

          {/* Timed Out Evictions */}
          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Purged by Reaper</span>
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-rose-400">
              {evictedCount}
            </div>
            <span className="text-[11px] text-slate-500">Stalled sessions evicted</span>
          </div>

          {/* Memory Occupied */}
          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Buffer Memory Used</span>
              <HardDrive className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {(totalMemoryBytes / 1024).toFixed(1)} KB
            </div>
            <span className="text-[11px] text-slate-500">Capped at 64 MB ceiling</span>
          </div>

          {/* Reaper Sweeps */}
          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Reaper Sweeps</span>
              <RefreshCw className="w-3.5 h-3.5 text-sky-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-sky-400">
              {reaperRuns}
            </div>
            <span className="text-[11px] text-slate-500">Tick frequency: 500ms</span>
          </div>
        </div>

        {/* Sliders for attack intensity and timeout */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-slate-400">Anti-DoS Eviction Timeout:</span>
              <span className="text-amber-400 font-mono font-bold tabular-nums">{timeoutSec} seconds</span>
            </div>
            <input
              type="range"
              min={2}
              max={15}
              step={1}
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(Number(e.target.value))}
              className="w-full accent-amber-500 cursor-pointer"
            />
          </div>

          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-slate-400">Flood Batch Size:</span>
              <span className="text-indigo-400 font-mono font-bold tabular-nums">{floodIntensity} forged sessions</span>
            </div>
            <input
              type="range"
              min={5}
              max={50}
              step={5}
              value={floodIntensity}
              onChange={(e) => setFloodIntensity(Number(e.target.value))}
              className="w-full accent-indigo-500 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Active Sessions Live Table */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              MessageAssembler Active Session Table
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {sessions.length} sessions in RAM
          </span>
        </div>

        {sessions.length === 0 ? (
          <div className="py-12 text-center text-slate-500 space-y-2">
            <CheckCircle className="w-8 h-8 mx-auto text-emerald-500/50" />
            <p className="text-xs text-slate-400">
              Assembler buffer is clean. No abandoned sessions detected.
            </p>
            <p className="text-[11px] text-slate-500">
              Click &quot;Simulate Fragment Flood Attack&quot; above to witness automatic Anti-DoS eviction.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5 font-medium">Session ID</th>
                  <th className="pb-2.5 font-medium">Attacker Origin</th>
                  <th className="pb-2.5 font-medium">Fragments Stalled</th>
                  <th className="pb-2.5 font-medium">Allocated RAM</th>
                  <th className="pb-2.5 font-medium text-right">TTL Remaining</th>
                  <th className="pb-2.5 font-medium text-right w-36">Countdown</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {sessions.map((s) => {
                  const ttlSec = (s.ttlRemainingMs / 1000).toFixed(1);
                  const progressPct = Math.max(0, (s.ttlRemainingMs / s.initialTtlMs) * 100);

                  return (
                    <tr key={s.id} className="hover:bg-slate-900/40">
                      <td className="py-2.5 text-indigo-300 font-semibold">0x{s.messageId}</td>
                      <td className="py-2.5 text-slate-400">{s.attackerIp}</td>
                      <td className="py-2.5 text-amber-300">
                        {s.receivedFrags} / {s.totalFrags} received (incomplete)
                      </td>
                      <td className="py-2.5 text-slate-300 tabular-nums">{s.allocatedBytes} bytes</td>
                      <td className="py-2.5 text-right font-bold tabular-nums text-amber-400">
                        {ttlSec}s
                      </td>
                      <td className="py-2.5 text-right pl-4">
                        <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                          <div
                            className={`h-full transition-all duration-300 ${
                              progressPct < 25
                                ? 'bg-rose-500'
                                : progressPct < 50
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${progressPct}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
