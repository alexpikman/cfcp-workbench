export type ColorTag = 'red' | 'amber' | 'emerald' | 'cyan' | 'blue' | 'purple' | 'pink';

export const COLOR_MAP: Record<ColorTag, { bg: string; text: string; border: string; hex: string }> = {
  red: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30', hex: '#f43f5e' },
  amber: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30', hex: '#f59e0b' },
  emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', hex: '#10b981' },
  cyan: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30', hex: '#06b6d4' },
  blue: { bg: 'bg-sky-500/10', text: 'text-sky-400', border: 'border-sky-500/30', hex: '#0ea5e9' },
  purple: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30', hex: '#a855f7' },
  pink: { bg: 'bg-pink-500/10', text: 'text-pink-400', border: 'border-pink-500/30', hex: '#ec4899' },
};

export const COLOR_LIST: ColorTag[] = ['red', 'amber', 'emerald', 'cyan', 'blue', 'purple', 'pink'];

export interface PacketFragment {
  id: string;
  messageId: string; // Hex 64-bit ID
  index: number;
  total: number;
  color: ColorTag;
  plaintext: string;
  ciphertextHex: string;
  nonceHex: string; // 12 bytes = 24 hex chars (MessageID || FragIndex)
  poly1305TagHex: string; // 16 bytes = 32 hex chars
  digestHex: string; // 32 bytes SHA-256
  sizeBytes: number;
  status: 'pending' | 'in-flight' | 'delivered' | 'dropped' | 'duplicate' | 'corrupt-aead' | 'corrupt-hash';
  dropReason?: string;
  arrivalOrder?: number;
}

export interface SimulationParams {
  payload: string;
  payloadType: 'text' | 'json' | 'binary';
  chunkSize: number;
  packetLossPercent: number;
  duplicatePercent: number;
  jitterMs: number;
  shuffleOrder: boolean;
  antiDosTimeoutSec: number;
  tamperCiphertext: boolean;
  tamperDigest: boolean;
}

export interface ActiveSession {
  messageId: string;
  totalFragments: number;
  receivedCount: number;
  createdAt: number;
  lastActivityAt: number;
  ttlRemainingMs: number;
  allocatedBytes: number;
  slots: (PacketFragment | null)[];
  arrivalSequence: number[];
  isFloodAttack?: boolean;
}

export interface AssemblyResult {
  messageId: string;
  assembledText: string;
  expectedDigest: string;
  actualDigest: string;
  digestMatch: boolean;
  assemblyDurationMs: number;
  arrivalOrder: number[];
  status: 'success' | 'aead-failed' | 'hash-failed' | 'timed-out';
  errorMessage?: string;
}

export interface ProtocolLogEntry {
  id: string;
  timestamp: string;
  type: 'info' | 'crypto' | 'network' | 'assembler' | 'antidos' | 'error';
  message: string;
  details?: Record<string, string | number | boolean>;
}

export interface TelemetryStats {
  messagesSent: number;
  messagesCompleted: number;
  fragmentsTransmitted: number;
  fragmentsDelivered: number;
  simulatedDrops: number;
  duplicatesDropped: number;
  corruptAeadDropped: number;
  hashFailures: number;
  antiDosEvictions: number;
  avgAssemblyDurationMs: number;
  currentMemoryBytes: number;
}
