import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Radio,
  EyeOff,
  Layers,
  ArrowRight,
  Send,
  Zap,
  Globe,
  Lock,
  RefreshCw,
  Terminal,
  Activity,
  Server,
  Shuffle,
} from 'lucide-react';
import { sha256Digest, simulateAEADEncrypt } from '../../utils/cryptoSim';

interface ProxiedRequestSimulation {
  id: string;
  timestamp: string;
  dest: string;
  portHop: number;
  mode: string;
  entropy: number;
  paddingBytes: number;
  totalFrags: number;
  status: 'transmitting' | 'assembled' | 'proxied' | 'evaded';
  rttMs: number;
}

export const StealthProxyLab: React.FC = () => {
  const [destTarget, setDestTarget] = useState<string>('api.github.com:443');
  const [requestMethod, setRequestMethod] = useState<string>('HTTPS_CONNECT');
  const [hopMode, setHopMode] = useState<
    'dynamic_hopping' | 'color_sprayed' | 'masquerade_quic' | 'masquerade_webrtc'
  >('dynamic_hopping');
  const [minPort, setMinPort] = useState<number>(20000);
  const [maxPort, setMaxPort] = useState<number>(40000);
  const [hopInterval, setHopInterval] = useState<number>(5);
  const [enableHeaderMasking, setEnableHeaderMasking] = useState<boolean>(true);
  const [enablePadding, setEnablePadding] = useState<boolean>(true);

  // Live active port calculation
  const [currentPort, setCurrentPort] = useState<number>(27341);
  const [timeRemaining, setTimeRemaining] = useState<number>(5);
  const [simHistory, setSimHistory] = useState<ProxiedRequestSimulation[]>([]);
  const [isSending, setIsSending] = useState<boolean>(false);

  // Dynamic port hopping countdown simulator
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeRemaining((prev) => {
        if (prev <= 1) {
          // Rotate port
          const span = maxPort - minPort + 1;
          const nextPort = minPort + Math.floor(Math.random() * span);
          setCurrentPort(nextPort);
          return hopInterval;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [minPort, maxPort, hopInterval]);

  const getEffectivePort = (mode: string) => {
    if (mode === 'masquerade_quic') return 443;
    if (mode === 'masquerade_webrtc') return 3478;
    return currentPort;
  };

  const handleSendProxiedRequest = async () => {
    if (isSending) return;
    setIsSending(true);

    const start = performance.now();
    const effectivePort = getEffectivePort(hopMode);
    const padding = enablePadding ? Math.floor(Math.random() * 96) + 16 : 0;
    const entropyScore = enableHeaderMasking ? 7.992 : 7.214;
    const frags = Math.floor(Math.random() * 3) + 2;

    const newSim: ProxiedRequestSimulation = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toLocaleTimeString(),
      dest: destTarget,
      portHop: effectivePort,
      mode: hopMode,
      entropy: entropyScore,
      paddingBytes: padding,
      totalFrags: frags,
      status: 'transmitting',
      rttMs: 0,
    };

    setSimHistory((prev) => [newSim, ...prev.slice(0, 19)]);

    // Simulate multi-stage tunnel flight
    setTimeout(() => {
      setSimHistory((prev) =>
        prev.map((s) => (s.id === newSim.id ? { ...s, status: 'assembled' } : s))
      );
    }, 300);

    setTimeout(() => {
      const elapsed = performance.now() - start;
      setSimHistory((prev) =>
        prev.map((s) =>
          s.id === newSim.id ? { ...s, status: 'evaded', rttMs: elapsed + 18 } : s
        )
      );
      setIsSending(false);
    }, 650);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & DPI Evasion Problem Statement */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <EyeOff className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-slate-100">
                CFCP Stealth Proxy & Port Defense Architecture
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              When using a proxy, censorship systems (DPI) track fixed IP:Port combinations and cleartext signatures. CFCP eliminates both vectors via <strong>Dynamic Synchronized Port Hopping</strong>, <strong>Zero-Signature Header Masking</strong>, and <strong>Random Packet Length Padding</strong>.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs font-mono px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300">
              SOCKS5: 127.0.0.1:1080
            </span>
          </div>
        </div>

        {/* Live Port Hopper Display */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Active Port Target</span>
              <Radio className="w-3.5 h-3.5 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-indigo-300">
              :{getEffectivePort(hopMode)}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              {hopMode === 'masquerade_quic'
                ? 'QUIC / HTTP3 Standard'
                : hopMode === 'masquerade_webrtc'
                ? 'WebRTC TURN Standard'
                : `Range [${minPort}-${maxPort}]`}
            </span>
          </div>

          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Next Port Hop</span>
              <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-amber-400">
              {timeRemaining}s
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Synchronized HMAC PRNG</span>
          </div>

          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>Shannon Entropy</span>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {enableHeaderMasking ? '7.99 / 8.00' : '7.21 / 8.00'}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              {enableHeaderMasking ? 'Zero-Signature White Noise' : 'Signatures Detected'}
            </span>
          </div>

          <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
              <span>DPI Classification</span>
              <Lock className="w-3.5 h-3.5 text-sky-400" />
            </div>
            <div className="text-base font-bold font-mono text-emerald-300 pt-1">
              UNDETECTABLE
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Bypasses Deep Inspection</span>
          </div>
        </div>
      </div>

      {/* 2. End-to-End Tunnel Visual Map */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          End-to-End Stealth Proxy Data Flow
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
          {/* Node 1: User Application */}
          <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 space-y-2">
            <div className="text-slate-400 font-sans font-medium flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-indigo-400" />
              <span>01. Local Application</span>
            </div>
            <div className="text-slate-300 text-[11px]">Browser / Telegram / Curl</div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800/80 text-[10px] text-slate-400">
              Connects to SOCKS5 at <span className="text-indigo-300">127.0.0.1:1080</span>
            </div>
          </div>

          {/* Node 2: CFCP Client */}
          <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 space-y-2">
            <div className="text-slate-400 font-sans font-medium flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-emerald-400" />
              <span>02. Cascade Encryption</span>
            </div>
            <div className="text-slate-300 text-[11px]">Slices & AEAD Encrypts</div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800/80 text-[10px] text-emerald-300">
              ChaCha20-Poly1305 + Header Masking + Random Padding
            </div>
          </div>

          {/* Node 3: DPI Channel */}
          <div className="p-3 bg-slate-950/90 rounded-lg border border-amber-900/40 bg-amber-950/10 space-y-2">
            <div className="text-amber-400 font-sans font-medium flex items-center gap-1.5">
              <EyeOff className="w-3.5 h-3.5" />
              <span>03. DPI Channel (Observer)</span>
            </div>
            <div className="text-slate-300 text-[11px]">Port Hopping: :{getEffectivePort(hopMode)}</div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800/80 text-[10px] text-slate-400">
              DPI sees: random UDP noise, shifting ports, no magic bytes
            </div>
          </div>

          {/* Node 4: Remote Proxy */}
          <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 space-y-2">
            <div className="text-slate-400 font-sans font-medium flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-purple-400" />
              <span>04. Remote Proxy Egress</span>
            </div>
            <div className="text-slate-300 text-[11px]">Reassembles & Dials Dest</div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800/80 text-[10px] text-purple-300">
              Dials {destTarget} on behalf of client
            </div>
          </div>
        </div>
      </div>

      {/* 3. Port Defense Configuration & Request Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Controls Column */}
        <div className="lg:col-span-5 bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Radio className="w-4 h-4 text-indigo-400" />
            Port Hopping & Anti-DPI Parameters
          </h3>

          {/* Mode Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-400 block">Port Defense Mode</label>
            <div className="grid grid-cols-1 gap-2">
              {[
                {
                  id: 'dynamic_hopping' as const,
                  label: 'Dynamic Synchronized Hopping',
                  desc: 'Port rotates pseudo-randomly in range [20000-40000]',
                },
                {
                  id: 'color_sprayed' as const,
                  label: 'Cascade Color Spraying',
                  desc: 'Fragments sent across 8 separate ports simultaneously',
                },
                {
                  id: 'masquerade_quic' as const,
                  label: 'Port 443 (QUIC / HTTP3 Masquerade)',
                  desc: 'Camouflaged as high-throughput HTTP/3 traffic',
                },
                {
                  id: 'masquerade_webrtc' as const,
                  label: 'Port 3478 (WebRTC Video Masquerade)',
                  desc: 'Camouflaged as STUN/TURN live video streams',
                },
              ].map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setHopMode(m.id)}
                  className={`cursor-pointer p-2.5 rounded-lg border text-left transition-colors ${
                    hopMode === m.id
                      ? 'bg-indigo-600/15 border-indigo-500/50 text-indigo-200'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold">{m.label}</div>
                  <div className="text-[11px] text-slate-500">{m.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Port Range (if dynamic) */}
          {hopMode === 'dynamic_hopping' && (
            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="space-y-1">
                <span className="text-[11px] text-slate-400">Min Port</span>
                <input
                  type="number"
                  value={minPort}
                  onChange={(e) => setMinPort(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400">Max Port</span>
                <input
                  type="number"
                  value={maxPort}
                  onChange={(e) => setMaxPort(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200"
                />
              </div>
            </div>
          )}

          {/* Anti-Fingerprinting Toggles */}
          <div className="space-y-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setEnableHeaderMasking(!enableHeaderMasking)}
              className={`cursor-pointer w-full flex items-center justify-between p-2 rounded-lg border text-xs font-medium ${
                enableHeaderMasking
                  ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
            >
              <span>Zero-Signature Header Masking</span>
              <span className="font-mono">{enableHeaderMasking ? 'ENABLED' : 'DISABLED'}</span>
            </button>

            <button
              type="button"
              onClick={() => setEnablePadding(!enablePadding)}
              className={`cursor-pointer w-full flex items-center justify-between p-2 rounded-lg border text-xs font-medium ${
                enablePadding
                  ? 'bg-indigo-950/20 border-indigo-500/40 text-indigo-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
            >
              <span>Random Packet Length Padding</span>
              <span className="font-mono">{enablePadding ? 'ENABLED' : 'DISABLED'}</span>
            </button>
          </div>
        </div>

        {/* Live Proxy Simulation Column */}
        <div className="lg:col-span-7 bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              SOCKS5 Tunnel Request Simulator
            </h3>
            <span className="text-xs font-mono text-slate-400">Client: socks5://127.0.0.1:1080</span>
          </div>

          {/* Target Host Input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={destTarget}
              onChange={(e) => setDestTarget(e.target.value)}
              placeholder="Destination host:port (e.g. google.com:443)"
              className="flex-1 px-3 py-2 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            />

            <button
              type="button"
              onClick={handleSendProxiedRequest}
              disabled={isSending}
              className="cursor-pointer px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
            >
              {isSending ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Tunneling...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Send via Stealth CFCP</span>
                </>
              )}
            </button>
          </div>

          {/* Request Log */}
          <div className="space-y-2">
            <div className="text-xs text-slate-400 font-medium">Recent Tunneled Connections</div>

            {simHistory.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs font-mono bg-slate-950/60 rounded-lg border border-slate-800/80">
                Click &quot;Send via Stealth CFCP&quot; to test a tunneled request through the port hopper.
              </div>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {simHistory.map((sim) => (
                  <div
                    key={sim.id}
                    className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-indigo-300 font-semibold flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-slate-400" />
                        {sim.dest}
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          sim.status === 'evaded'
                            ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/30'
                            : 'bg-indigo-950/50 text-indigo-400 border border-indigo-500/30'
                        }`}
                      >
                        {sim.status === 'evaded' ? 'DPI BYPASSED · 200 OK' : sim.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-slate-400">
                      <span>
                        Hopped UDP Port: <strong className="text-amber-400">:{sim.portHop}</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Entropy: <strong className="text-emerald-400">{sim.entropy} bits</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Dummy Padding: <strong className="text-slate-200">{sim.paddingBytes}B</strong>
                      </span>
                      {sim.rttMs > 0 && (
                        <>
                          <span>·</span>
                          <span>
                            RTT: <strong className="text-indigo-400">{sim.rttMs.toFixed(1)}ms</strong>
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
