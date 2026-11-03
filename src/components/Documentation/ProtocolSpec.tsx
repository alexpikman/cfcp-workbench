import React from 'react';
import { BookOpen, Shield, Cpu, Lock, Layers, Zap, Clock, Terminal } from 'lucide-react';

export const ProtocolSpec: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Intro Hero */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-6 space-y-3">
        <div className="flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-indigo-400" />
          <h2 className="text-base font-bold text-slate-100">
            CFCP Wire Protocol & Security Architecture Specification
          </h2>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
          CFCP (Color-Fragmented Cascade Protocol) is a connectionless datagram transport system operating over UDP. It is engineered to bypass TCP head-of-line blocking, deliver cryptographic confidentiality and authentication per fragment, enforce strict Anti-DoS memory bounds, and ensure whole-message integrity.
        </p>
      </div>

      {/* Wire Frame Diagram */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          Binary Wire Layout (60-Byte Fixed Header + Variable Ciphertext)
        </h3>

        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 overflow-x-auto text-[11px] font-mono leading-relaxed text-indigo-300">
          <pre>{` 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Magic "CFCP" (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |   ColorTag    |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Message ID (Bytes 0-3)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Message ID (Bytes 4-7)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Fragment Index (uint32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Total Fragments (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Length (uint32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Message SHA-256 Digest                      +
|                         (32 bytes)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Encrypted Payload (ChaCha20 Ciphertext + 16B Poly1305 MAC) |
|                         ... variable ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`}</pre>
        </div>
      </div>

      {/* Core Architectural Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Pillar 1: ChaCha20-Poly1305 AEAD */}
        <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Lock className="w-4 h-4" />
            <h4 className="text-xs font-bold uppercase tracking-wider">01. Cryptographic AEAD</h4>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Every fragment is authenticated and encrypted before hitting the wire using RFC 8439 ChaCha20-Poly1305.
          </p>
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1.5">
            <div className="text-emerald-400 font-semibold font-sans">96-bit Nonce Construction:</div>
            <div>[0:8]  MessageID (uint64 BigEndian)</div>
            <div>[8:12] FragmentIndex (uint32 BigEndian)</div>
            <div className="text-slate-500 pt-1 text-[10px]">
              Guarantees strict uniqueness without wire nonce transmission overhead.
            </div>
          </div>
        </div>

        {/* Pillar 2: Anti-DoS Protection */}
        <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-amber-400">
            <Clock className="w-4 h-4" />
            <h4 className="text-xs font-bold uppercase tracking-wider">02. Anti-DoS Protection</h4>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Mitigates memory exhaustion from spoofed UDP fragment floods via sliding eviction timers and active garbage collection.
          </p>
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1.5">
            <div>• TTL Timeout: 5–10s sliding window</div>
            <div>• Reaper Loop: background ticker sweeps</div>
            <div>• Per-Session Cap: 4 MB max</div>
            <div>• Total Pool Cap: 64 MB max</div>
            <div className="text-slate-500 pt-1 text-[10px]">
              Stalled sessions purged automatically without memory leaks.
            </div>
          </div>
        </div>

        {/* Pillar 3: SHA-256 Integrity */}
        <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-indigo-400">
            <Shield className="w-4 h-4" />
            <h4 className="text-xs font-bold uppercase tracking-wider">03. Integrity Control</h4>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Guarantees whole-message semantic consistency across out-of-order reassembly before payload materialization.
          </p>
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1.5">
            <div>1. Client hashes full payload (SHA-256)</div>
            <div>2. Hash embedded into authenticated header</div>
            <div>3. Server glues slots in index order</div>
            <div>4. Server recalculates & verifies hash</div>
            <div className="text-slate-500 pt-1 text-[10px]">
              Rejects any corruption before passing to app layer.
            </div>
          </div>
        </div>

        {/* Pillar 4: Port Defense & Anti-DPI */}
        <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sky-400">
            <Zap className="w-4 h-4" />
            <h4 className="text-xs font-bold uppercase tracking-wider">04. Port Defense & Anti-DPI</h4>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Prevents firewalls and DPI from tracking fixed ports or identifying proxy protocol signatures.
          </p>
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1.5">
            <div>• Dynamic Synchronized Port Hopping</div>
            <div>• QUIC (443) / WebRTC (3478) Masquerade</div>
            <div>• Zero-Signature Header Keystream Masking</div>
            <div>• Variable Random Dummy Padding (0-128B)</div>
            <div className="text-slate-500 pt-1 text-[10px]">
              Entropy ~7.99 / 8.00 bits (indistinguishable from white noise).
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
