import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Lock,
  Hash,
  Layers,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Server,
  Send,
  Clock,
  Eye,
  AlertOctagon,
} from 'lucide-react';
import { PacketFragment, AssemblyResult, ActiveSession, COLOR_MAP } from '../../types/protocol';

interface CascadeVisualizerProps {
  fragments: PacketFragment[];
  expectedDigest: string;
  actualDigest: string;
  assemblyResult: AssemblyResult | null;
  activeSession: ActiveSession | null;
  isRunning: boolean;
  pskHex: string;
}

export const CascadeVisualizer: React.FC<CascadeVisualizerProps> = ({
  fragments,
  expectedDigest,
  actualDigest,
  assemblyResult,
  activeSession,
  isRunning,
  pskHex,
}) => {
  const [selectedFragment, setSelectedFragment] = useState<PacketFragment | null>(null);

  if (fragments.length === 0) {
    return (
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-8 text-center text-slate-500">
        <Layers className="w-10 h-10 mx-auto text-slate-600 mb-3" />
        <h3 className="text-sm font-semibold text-slate-300 mb-1">No Active Cascade Session</h3>
        <p className="text-xs max-w-md mx-auto text-slate-400">
          Configure payload parameters and click <span className="text-indigo-400 font-medium">Run Cascade Transfer</span> above to initiate UDP datagram transmission.
        </p>
      </div>
    );
  }

  const deliveredCount = fragments.filter((f) => f.status === 'delivered').length;
  const droppedCount = fragments.filter((f) => f.status === 'dropped').length;
  const duplicateCount = fragments.filter((f) => f.status === 'duplicate').length;

  return (
    <div className="space-y-5">
      {/* 1. Cryptographic Envelope & Digest Header */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1 font-sans">
              <Hash className="w-3.5 h-3.5 text-indigo-400" />
              <span>Full Message SHA-256 Digest (Client Generated)</span>
            </div>
            <div className="text-indigo-300 break-all select-all text-[11px] leading-relaxed">
              {expectedDigest || 'Computing...'}
            </div>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1 font-sans">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>AEAD Pre-Shared Key (256-bit PSK)</span>
            </div>
            <div className="text-emerald-300 break-all select-all text-[11px] leading-relaxed">
              {pskHex}
            </div>
          </div>
        </div>
      </div>

      {/* 2. Cascade Color-Fragmented Pipeline */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Color-Fragment Cascade (Out-of-Order Flight)
            </h3>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="text-slate-400">
              Total: <strong className="text-slate-200">{fragments.length}</strong>
            </span>
            <span className="text-emerald-400">
              Delivered: <strong className="tabular-nums">{deliveredCount}</strong>
            </span>
            {droppedCount > 0 && (
              <span className="text-rose-400">
                Dropped: <strong className="tabular-nums">{droppedCount}</strong>
              </span>
            )}
            {duplicateCount > 0 && (
              <span className="text-sky-400">
                Duplicates: <strong className="tabular-nums">{duplicateCount}</strong>
              </span>
            )}
          </div>
        </div>

        {/* Fragment Cards Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5">
          {fragments.map((frag) => {
            const colorCfg = COLOR_MAP[frag.color] || COLOR_MAP.cyan;
            const isDelivered = frag.status === 'delivered';
            const isDropped = frag.status === 'dropped';
            const isDuplicate = frag.status === 'duplicate';
            const isCorruptAead = frag.status === 'corrupt-aead';

            return (
              <button
                key={frag.id}
                type="button"
                onClick={() => setSelectedFragment(frag)}
                className={`cursor-pointer relative p-3 rounded-lg border text-left transition-all ${
                  selectedFragment?.id === frag.id
                    ? 'ring-2 ring-indigo-500 bg-slate-900'
                    : 'bg-slate-950/60 hover:bg-slate-900/80'
                } ${
                  isDropped
                    ? 'border-rose-900/50 opacity-60'
                    : isCorruptAead
                    ? 'border-rose-600/70 bg-rose-950/20'
                    : `${colorCfg.border}`
                }`}
              >
                {/* Header: Color badge and fragment index */}
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ backgroundColor: colorCfg.hex }}
                    />
                    <span className="text-xs font-mono font-semibold text-slate-200">
                      #{frag.index + 1}/{frag.total}
                    </span>
                  </div>

                  {isDelivered && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                  {isDropped && <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />}
                  {isCorruptAead && <AlertOctagon className="w-3.5 h-3.5 text-rose-500 shrink-0" />}
                  {frag.status === 'in-flight' && (
                    <span className="w-2 h-2 rounded-full bg-indigo-400 animate-ping shrink-0" />
                  )}
                </div>

                {/* Plaintext snippet */}
                <div className="text-[11px] font-mono text-slate-300 truncate mb-1.5">
                  {frag.plaintext || '<empty>'}
                </div>

                {/* Status indicator */}
                <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                  <span>{frag.sizeBytes}B</span>
                  <span
                    className={
                      isDelivered
                        ? 'text-emerald-400'
                        : isDropped
                        ? 'text-rose-400'
                        : isDuplicate
                        ? 'text-sky-400'
                        : isCorruptAead
                        ? 'text-rose-500 font-bold'
                        : 'text-indigo-400'
                    }
                  >
                    {frag.status}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Fragment Inspection Drawer */}
        {selectedFragment && (
          <div className="mt-4 p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-3 animate-in fade-in">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="font-semibold text-slate-200 flex items-center gap-2">
                <Eye className="w-4 h-4 text-indigo-400" />
                Fragment #{selectedFragment.index + 1} Inspection (Message ID: 0x{selectedFragment.messageId})
              </span>
              <button
                type="button"
                onClick={() => setSelectedFragment(null)}
                className="cursor-pointer text-slate-400 hover:text-slate-200 text-xs"
              >
                Close ✕
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <span className="text-slate-500 block mb-1">Plaintext Content:</span>
                <div className="p-2 bg-slate-900 rounded border border-slate-800 text-slate-200 break-all">
                  {selectedFragment.plaintext}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">
                  Derived 96-bit Nonce (MessageID:8B || FragIndex:4B):
                </span>
                <div className="p-2 bg-slate-900 rounded border border-slate-800 text-indigo-300 break-all select-all">
                  {selectedFragment.nonceHex}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">ChaCha20 Ciphertext (Hex):</span>
                <div className="p-2 bg-slate-900 rounded border border-slate-800 text-slate-300 break-all select-all max-h-24 overflow-y-auto">
                  {selectedFragment.ciphertextHex}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Poly1305 Authenticator MAC Tag (16 Bytes):</span>
                <div className="p-2 bg-slate-900 rounded border border-slate-800 text-emerald-300 break-all select-all">
                  {selectedFragment.poly1305TagHex}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 3. Server MessageAssembler Buffer & Anti-DoS State */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Server MessageAssembler (Anti-DoS Protected Buffer)
            </h3>
          </div>

          {activeSession && (
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-amber-400" />
                Session TTL:
              </span>
              <span className="text-amber-400 font-bold tabular-nums">
                {(activeSession.ttlRemainingMs / 1000).toFixed(1)}s
              </span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400">
                Memory: <span className="text-slate-200 font-bold">{activeSession.allocatedBytes}B</span>
              </span>
            </div>
          )}
        </div>

        {/* Slot Array representation */}
        {activeSession && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Assembly Slots ({activeSession.receivedCount}/{activeSession.totalFragments} filled)</span>
              <span>Arrival Sequence: [{activeSession.arrivalSequence.map((i) => `#${i + 1}`).join(' → ')}]</span>
            </div>

            <div className="grid grid-cols-6 sm:grid-cols-8 md:grid-cols-12 gap-1.5">
              {activeSession.slots.map((slot, idx) => (
                <div
                  key={idx}
                  className={`h-9 rounded border flex items-center justify-center font-mono text-xs font-semibold ${
                    slot
                      ? `${COLOR_MAP[slot.color].bg} ${COLOR_MAP[slot.color].border} ${COLOR_MAP[slot.color].text}`
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-600'
                  }`}
                  title={slot ? `Slot #${idx + 1}: Received (${slot.sizeBytes}B)` : `Slot #${idx + 1}: Waiting...`}
                >
                  #{idx + 1}
                </div>
              ))}
            </div>

            {/* TTL Expiration Progress Bar */}
            <div className="space-y-1 pt-1">
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 transition-all duration-200"
                  style={{
                    width: `${Math.min(100, (activeSession.ttlRemainingMs / 6000) * 100)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 4. Integrity Check & Assembled Output */}
      {assemblyResult && (
        <div
          className={`rounded-xl border p-5 space-y-3 animate-in fade-in ${
            assemblyResult.status === 'success'
              ? 'bg-emerald-950/20 border-emerald-500/40'
              : 'bg-rose-950/20 border-rose-500/40'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {assemblyResult.status === 'success' ? (
                <>
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-emerald-300">
                    Whole-Message Assembly Succeeded & Verified
                  </h3>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                  <h3 className="text-sm font-semibold text-rose-300">
                    Assembly Rejected: {assemblyResult.errorMessage}
                  </h3>
                </>
              )}
            </div>

            <div className="text-xs font-mono text-slate-300">
              Assembly Latency:{' '}
              <span className="font-bold tabular-nums text-white">
                {assemblyResult.assemblyDurationMs.toFixed(2)} ms
              </span>
            </div>
          </div>

          {/* Digest comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block mb-1">Expected SHA-256 Digest:</span>
              <span className="text-slate-300 break-all select-all text-[11px]">
                {assemblyResult.expectedDigest}
              </span>
            </div>

            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block mb-1">Calculated SHA-256 Digest:</span>
              <span
                className={`break-all select-all text-[11px] ${
                  assemblyResult.digestMatch ? 'text-emerald-400' : 'text-rose-400 font-bold'
                }`}
              >
                {assemblyResult.actualDigest}
              </span>
            </div>
          </div>

          {/* Reconstructed payload */}
          {assemblyResult.status === 'success' && (
            <div>
              <span className="text-xs font-medium text-slate-400 block mb-1.5">
                Reconstructed Plaintext (Materialized after SHA-256 verification):
              </span>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-emerald-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                {assemblyResult.assembledText}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
