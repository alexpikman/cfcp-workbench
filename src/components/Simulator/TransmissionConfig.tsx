import React from 'react';
import { Sliders, Shield, AlertTriangle, Radio, Shuffle, Clock, FileCode } from 'lucide-react';
import { SimulationParams } from '../../types/protocol';

interface TransmissionConfigProps {
  params: SimulationParams;
  onChange: (updated: Partial<SimulationParams>) => void;
  isRunning: boolean;
}

const PRESETS = [
  {
    name: 'Short Text',
    type: 'text' as const,
    content: 'CFCP Color-Fragmented Cascade Protocol datagram payload over UDP.',
  },
  {
    name: 'JSON Telemetry',
    type: 'json' as const,
    content: JSON.stringify(
      {
        telemetry: 'mission_control_v4',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'alpha-1', role: 'cascade-relay', latency_ms: 12.4, status: 'synced' },
          { id: 'beta-2', role: 'assembler-node', buffer_pct: 34.2, status: 'synced' },
          { id: 'gamma-3', role: 'udp-egress', drops_rate: 0.002, status: 'synced' },
        ],
        checksum_algorithm: 'sha256',
        cipher: 'chacha20-poly1305',
      },
      null,
      2
    ),
  },
  {
    name: 'Binary Sensor Stream',
    type: 'binary' as const,
    content:
      'HEX_DUMP::4346435001040100f983a1c87e41b2100000000300000008000000a0' +
      '8f1b2c4d9a6e3f0194827150aebcdeff128394a5b6c7d8e9f0a1b2c3d4e5f607' +
      'a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8' +
      '8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677' +
      'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2' +
      '7766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa9988',
  },
];

export const TransmissionConfig: React.FC<TransmissionConfigProps> = ({
  params,
  onChange,
  isRunning,
}) => {
  const estimatedFragments = Math.max(1, Math.ceil(params.payload.length / params.chunkSize));

  return (
    <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-5">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-indigo-400" />
          <h2 className="text-sm font-semibold text-slate-200">Transmission & Network Controls</h2>
        </div>
        <span className="text-xs text-slate-400 font-mono tabular-nums">
          Payload: {params.payload.length}B · ~{estimatedFragments} Frags
        </span>
      </div>

      {/* Preset Payload Selectors */}
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-2">Payload Preset</label>
        <div className="grid grid-cols-3 gap-2">
          {PRESETS.map((preset) => (
            <button
              key={preset.name}
              type="button"
              disabled={isRunning}
              onClick={() =>
                onChange({
                  payload: preset.content,
                  payloadType: preset.type,
                })
              }
              className={`cursor-pointer px-3 py-2 text-xs font-medium rounded-lg border text-left transition-colors truncate ${
                params.payload === preset.content
                  ? 'bg-indigo-600/15 border-indigo-500/50 text-indigo-300 font-semibold'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {preset.name}
            </button>
          ))}
        </div>
      </div>

      {/* Custom Payload Input */}
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-1.5">
          Plaintext Payload
        </label>
        <textarea
          rows={3}
          value={params.payload}
          disabled={isRunning}
          onChange={(e) => onChange({ payload: e.target.value })}
          className="w-full px-3 py-2 text-xs font-mono bg-slate-950/80 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-indigo-500 transition-colors resize-none"
          placeholder="Enter message to slice and encrypt..."
        />
      </div>

      {/* Sliders Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Fragment Chunk Size */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">Fragment MTU Chunk</span>
            <span className="text-indigo-400 font-mono tabular-nums font-semibold">{params.chunkSize} bytes</span>
          </div>
          <input
            type="range"
            min={48}
            max={512}
            step={16}
            disabled={isRunning}
            value={params.chunkSize}
            onChange={(e) => onChange({ chunkSize: Number(e.target.value) })}
            className="w-full accent-indigo-500 cursor-pointer"
          />
        </div>

        {/* Anti-DoS Timeout */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              Anti-DoS Session Timeout
            </span>
            <span className="text-amber-400 font-mono tabular-nums font-semibold">{params.antiDosTimeoutSec}s</span>
          </div>
          <input
            type="range"
            min={2}
            max={15}
            step={1}
            disabled={isRunning}
            value={params.antiDosTimeoutSec}
            onChange={(e) => onChange({ antiDosTimeoutSec: Number(e.target.value) })}
            className="w-full accent-amber-500 cursor-pointer"
          />
        </div>

        {/* Packet Loss */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-rose-400" />
              Simulated UDP Packet Loss
            </span>
            <span className="text-rose-400 font-mono tabular-nums font-semibold">{params.packetLossPercent}%</span>
          </div>
          <input
            type="range"
            min={0}
            max={50}
            step={5}
            disabled={isRunning}
            value={params.packetLossPercent}
            onChange={(e) => onChange({ packetLossPercent: Number(e.target.value) })}
            className="w-full accent-rose-500 cursor-pointer"
          />
        </div>

        {/* Duplicate Packets */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">Simulated Duplicate Datagrams</span>
            <span className="text-sky-400 font-mono tabular-nums font-semibold">{params.duplicatePercent}%</span>
          </div>
          <input
            type="range"
            min={0}
            max={40}
            step={5}
            disabled={isRunning}
            value={params.duplicatePercent}
            onChange={(e) => onChange({ duplicatePercent: Number(e.target.value) })}
            className="w-full accent-sky-500 cursor-pointer"
          />
        </div>
      </div>

      {/* Network Toggles & Adversary Simulation */}
      <div className="pt-2 border-t border-slate-800/80 space-y-2.5">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span className="font-medium text-slate-300">Network Delivery & Security Invariants</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {/* Out of order delivery */}
          <button
            type="button"
            disabled={isRunning}
            onClick={() => onChange({ shuffleOrder: !params.shuffleOrder })}
            className={`cursor-pointer flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
              params.shuffleOrder
                ? 'bg-indigo-950/40 border-indigo-500/40 text-indigo-300'
                : 'bg-slate-900/50 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shuffle className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Out-of-Order Delivery: {params.shuffleOrder ? 'ON' : 'OFF'}</span>
          </button>

          {/* Adversary: Corrupt Ciphertext */}
          <button
            type="button"
            disabled={isRunning}
            onClick={() => onChange({ tamperCiphertext: !params.tamperCiphertext })}
            className={`cursor-pointer flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
              params.tamperCiphertext
                ? 'bg-rose-950/40 border-rose-500/50 text-rose-300'
                : 'bg-slate-900/50 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-400" />
            <span className="truncate">Tamper Ciphertext (AEAD Test)</span>
          </button>

          {/* Adversary: Corrupt SHA-256 Digest */}
          <button
            type="button"
            disabled={isRunning}
            onClick={() => onChange({ tamperDigest: !params.tamperDigest })}
            className={`cursor-pointer flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
              params.tamperDigest
                ? 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                : 'bg-slate-900/50 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-3.5 h-3.5 shrink-0 text-amber-400" />
            <span className="truncate">Tamper SHA-256 (Integrity Test)</span>
          </button>
        </div>
      </div>
    </div>
  );
};
