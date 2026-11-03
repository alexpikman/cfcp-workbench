import React, { useState, useEffect, useRef, useCallback } from 'react';
import JSZip from 'jszip';
import { TopBar } from './components/TopBar';
import { TransmissionConfig } from './components/Simulator/TransmissionConfig';
import { CascadeVisualizer } from './components/Simulator/CascadeVisualizer';
import { TelemetryDashboard } from './components/Simulator/TelemetryDashboard';
import { AntiDosStressLab } from './components/Simulator/AntiDosStressLab';
import { StealthProxyLab } from './components/Proxy/StealthProxyLab';
import { CascadeGraphVisualizer } from './components/Graph/CascadeGraphVisualizer';
import { GoCodeExplorer } from './components/CodeExplorer/GoCodeExplorer';
import { ProtocolSpec } from './components/Documentation/ProtocolSpec';
import { GO_FILES } from './data/goCodeFiles';
import {
  SimulationParams,
  PacketFragment,
  ActiveSession,
  AssemblyResult,
  TelemetryStats,
  ProtocolLogEntry,
  COLOR_LIST,
} from './types/protocol';
import {
  sha256Digest,
  deriveDeterministicNonce,
  generateRandomMessageId,
  simulateAEADEncrypt,
  simulateAEADDecrypt,
} from './utils/cryptoSim';

const DEFAULT_PSK_HEX =
  '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';

export default function App() {
  const [activeTab, setActiveTab] = useState<'graph' | 'simulator' | 'antidos' | 'proxy' | 'explorer' | 'spec'>('graph');
  const [isRunning, setIsRunning] = useState<boolean>(false);

  // Configuration
  const [params, setParams] = useState<SimulationParams>({
    payload:
      'CFCP Color-Fragmented Cascade Protocol datagram payload over UDP with ChaCha20-Poly1305 AEAD and Anti-DoS timed assembly.',
    payloadType: 'text',
    chunkSize: 128,
    packetLossPercent: 0,
    duplicatePercent: 0,
    jitterMs: 15,
    shuffleOrder: true,
    antiDosTimeoutSec: 6,
    tamperCiphertext: false,
    tamperDigest: false,
  });

  // Protocol Simulation State
  const [fragments, setFragments] = useState<PacketFragment[]>([]);
  const [expectedDigest, setExpectedDigest] = useState<string>('');
  const [actualDigest, setActualDigest] = useState<string>('');
  const [assemblyResult, setAssemblyResult] = useState<AssemblyResult | null>(null);
  const [activeSession, setActiveSession] = useState<ActiveSession | null>(null);

  // Telemetry & Logs
  const [stats, setStats] = useState<TelemetryStats>({
    messagesSent: 0,
    messagesCompleted: 0,
    fragmentsTransmitted: 0,
    fragmentsDelivered: 0,
    simulatedDrops: 0,
    duplicatesDropped: 0,
    corruptAeadDropped: 0,
    hashFailures: 0,
    antiDosEvictions: 0,
    avgAssemblyDurationMs: 0,
    currentMemoryBytes: 0,
  });

  const [logs, setLogs] = useState<ProtocolLogEntry[]>([]);

  const addLog = useCallback((type: ProtocolLogEntry['type'], message: string) => {
    const entry: ProtocolLogEntry = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + '.' + String(Date.now() % 1000).padStart(3, '0'),
      type,
      message,
    };
    setLogs((prev) => [entry, ...prev.slice(0, 199)]);
  }, []);

  // Background TTL ticker for active session
  useEffect(() => {
    const timer = setInterval(() => {
      setActiveSession((current) => {
        if (!current) return null;
        const remaining = current.ttlRemainingMs - 100;
        if (remaining <= 0) {
          addLog('antidos', `Anti-DoS Reaper evicted session 0x${current.messageId} after ${params.antiDosTimeoutSec}s timeout`);
          setStats((s) => ({
            ...s,
            antiDosEvictions: s.antiDosEvictions + 1,
            currentMemoryBytes: Math.max(0, s.currentMemoryBytes - current.allocatedBytes),
          }));
          return null;
        }
        return {
          ...current,
          ttlRemainingMs: remaining,
        };
      });
    }, 100);

    return () => clearInterval(timer);
  }, [addLog, params.antiDosTimeoutSec]);

  // Run Cascade Simulation
  const handleRunSimulation = async () => {
    if (isRunning) return;
    setIsRunning(true);
    setAssemblyResult(null);

    const startTime = performance.now();
    const msgId = generateRandomMessageId();
    addLog('info', `Initiating CFCP message session 0x${msgId} (${params.payload.length} bytes)`);

    // 1. Calculate Whole-Message SHA-256 Digest
    const rawDigest = await sha256Digest(params.payload);
    const clientDigest = params.tamperDigest
      ? rawDigest.replace(/^../, 'ee') // Tamper digest if test enabled
      : rawDigest;

    setExpectedDigest(clientDigest);
    addLog('crypto', `SHA-256 Digest generated: ${clientDigest.slice(0, 16)}...`);

    // 2. Slice into Fragments
    const chunkSize = params.chunkSize;
    const rawText = params.payload;
    const totalFragments = Math.max(1, Math.ceil(rawText.length / chunkSize));
    const newFragments: PacketFragment[] = [];

    addLog('network', `Slicing payload into ${totalFragments} cascade fragments (MTU: ${chunkSize}B)`);

    // 3. Encrypt Each Fragment with ChaCha20-Poly1305
    for (let i = 0; i < totalFragments; i++) {
      const start = i * chunkSize;
      const end = Math.min(rawText.length, start + chunkSize);
      const chunkPlaintext = rawText.slice(start, end);
      const color = COLOR_LIST[i % COLOR_LIST.length];

      const nonceHex = deriveDeterministicNonce(msgId, i);
      const aadHex = `CFCP:01:01:00:${msgId}:${i}:${totalFragments}`;

      const { ciphertextHex, poly1305TagHex } = await simulateAEADEncrypt(
        chunkPlaintext,
        nonceHex,
        aadHex,
        DEFAULT_PSK_HEX
      );

      // If user enabled ciphertext tampering, flip first byte of fragment 0
      const finalCiphertext =
        params.tamperCiphertext && i === 0
          ? (ciphertextHex.startsWith('aa') ? 'bb' : 'aa') + ciphertextHex.slice(2)
          : ciphertextHex;

      newFragments.push({
        id: `frag-${msgId}-${i}`,
        messageId: msgId,
        index: i,
        total: totalFragments,
        color,
        plaintext: chunkPlaintext,
        ciphertextHex: finalCiphertext,
        nonceHex,
        poly1305TagHex,
        digestHex: clientDigest,
        sizeBytes: chunkPlaintext.length,
        status: 'pending',
      });
    }

    setFragments(newFragments);
    setStats((s) => ({
      ...s,
      messagesSent: s.messagesSent + 1,
      fragmentsTransmitted: s.fragmentsTransmitted + totalFragments,
    }));

    // 4. Initialize Server Assembly Session
    const initialTtlMs = params.antiDosTimeoutSec * 1000;
    const session: ActiveSession = {
      messageId: msgId,
      totalFragments,
      receivedCount: 0,
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
      ttlRemainingMs: initialTtlMs,
      allocatedBytes: 0,
      slots: new Array(totalFragments).fill(null),
      arrivalSequence: [],
    };
    setActiveSession(session);
    addLog('assembler', `Server Assembler allocated session 0x${msgId} with ${params.antiDosTimeoutSec}s Anti-DoS timeout`);

    // 5. Build Delivery Schedule (with optional out-of-order shuffle)
    const deliveryOrder = newFragments.map((_, idx) => idx);
    if (params.shuffleOrder && totalFragments > 1) {
      for (let i = deliveryOrder.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [deliveryOrder[i], deliveryOrder[j]] = [deliveryOrder[j], deliveryOrder[i]];
      }
      addLog('network', `Cascade out-of-order flight order: [${deliveryOrder.map((idx) => `#${idx + 1}`).join(', ')}]`);
    }

    // 6. Transmit Fragments Across Simulated UDP Flight
    let currentSession = { ...session };
    let deliveredCount = 0;
    let duplicateCount = 0;
    let dropCount = 0;

    for (let step = 0; step < deliveryOrder.length; step++) {
      const fragIdx = deliveryOrder[step];
      const frag = newFragments[fragIdx];

      // Simulated packet loss check
      if (params.packetLossPercent > 0 && Math.random() * 100 < params.packetLossPercent) {
        frag.status = 'dropped';
        frag.dropReason = 'Simulated UDP loss';
        dropCount++;
        addLog('network', `[DROP] Fragment #${frag.index + 1} dropped by UDP loss simulation`);
        setFragments([...newFragments]);
        continue;
      }

      // Small delay to simulate flight and jitter
      if (params.jitterMs > 0) {
        await new Promise((r) => setTimeout(r, Math.random() * params.jitterMs + 20));
      }

      // Server Reception & Poly1305 Decryption
      const aadHex = `CFCP:01:01:00:${msgId}:${frag.index}:${totalFragments}`;
      const decryptRes = await simulateAEADDecrypt(
        frag.ciphertextHex,
        frag.poly1305TagHex,
        frag.nonceHex,
        aadHex,
        DEFAULT_PSK_HEX
      );

      if (!decryptRes.success) {
        frag.status = 'corrupt-aead';
        frag.dropReason = decryptRes.error;
        addLog('error', `[AEAD REJECT] Fragment #${frag.index + 1}: ${decryptRes.error}`);
        setFragments([...newFragments]);
        setStats((s) => ({ ...s, corruptAeadDropped: s.corruptAeadDropped + 1 }));
        continue;
      }

      // Successful slot insertion
      frag.status = 'delivered';
      frag.arrivalOrder = currentSession.arrivalSequence.length + 1;
      currentSession.slots[frag.index] = frag;
      currentSession.receivedCount++;
      currentSession.lastActivityAt = Date.now();
      currentSession.arrivalSequence = [...currentSession.arrivalSequence, frag.index];
      currentSession.allocatedBytes += frag.sizeBytes + 64;
      deliveredCount++;

      addLog('assembler', `Server buffered Fragment #${frag.index + 1} into Slot #${frag.index + 1}`);

      // Simulated duplicate delivery
      if (params.duplicatePercent > 0 && Math.random() * 100 < params.duplicatePercent) {
        duplicateCount++;
        addLog('assembler', `[DUPLICATE] Server recognized and discarded duplicate for Fragment #${frag.index + 1}`);
      }

      setActiveSession({ ...currentSession });
      setFragments([...newFragments]);
    }

    setStats((s) => ({
      ...s,
      fragmentsDelivered: s.fragmentsDelivered + deliveredCount,
      simulatedDrops: s.simulatedDrops + dropCount,
      duplicatesDropped: s.duplicatesDropped + duplicateCount,
      currentMemoryBytes: currentSession.allocatedBytes,
    }));

    // 7. Check if all fragments arrived & Reassemble
    if (currentSession.receivedCount === totalFragments) {
      const assemblyDuration = performance.now() - startTime;
      let assembledText = '';
      for (let i = 0; i < totalFragments; i++) {
        assembledText += currentSession.slots[i]?.plaintext || '';
      }

      // Verify SHA-256 Digest BEFORE Releasing
      const serverCalculatedDigest = await sha256Digest(assembledText);
      setActualDigest(serverCalculatedDigest);

      const digestMatch = serverCalculatedDigest.toLowerCase() === clientDigest.toLowerCase();

      if (!digestMatch) {
        addLog('error', `[INTEGRITY FAILURE] SHA-256 Digest mismatch! Expected: ${clientDigest.slice(0, 8)}..., Calculated: ${serverCalculatedDigest.slice(0, 8)}...`);
        setAssemblyResult({
          messageId: msgId,
          assembledText,
          expectedDigest: clientDigest,
          actualDigest: serverCalculatedDigest,
          digestMatch: false,
          assemblyDurationMs: assemblyDuration,
          arrivalOrder: currentSession.arrivalSequence,
          status: 'hash-failed',
          errorMessage: 'SHA-256 Whole-Message Digest Mismatch (Corrupted or Tampered)',
        });
        setStats((s) => ({ ...s, hashFailures: s.hashFailures + 1 }));
      } else {
        addLog('crypto', `[VERIFIED] SHA-256 Integrity Verified! Message 0x${msgId} successfully assembled in ${assemblyDuration.toFixed(2)}ms`);
        addLog('network', `[ACK] Server emitted ACK datagram for Message 0x${msgId}`);

        setAssemblyResult({
          messageId: msgId,
          assembledText,
          expectedDigest: clientDigest,
          actualDigest: serverCalculatedDigest,
          digestMatch: true,
          assemblyDurationMs: assemblyDuration,
          arrivalOrder: currentSession.arrivalSequence,
          status: 'success',
        });

        setStats((s) => ({
          ...s,
          messagesCompleted: s.messagesCompleted + 1,
          avgAssemblyDurationMs:
            s.messagesCompleted === 0
              ? assemblyDuration
              : (s.avgAssemblyDurationMs * s.messagesCompleted + assemblyDuration) / (s.messagesCompleted + 1),
          currentMemoryBytes: 0,
        }));

        // Assembly completed: session reclaimed from server RAM
        setActiveSession(null);
      }
    } else {
      addLog('antidos', `Session 0x${msgId} incomplete (${currentSession.receivedCount}/${totalFragments} frags). Waiting for timeout reaper...`);
    }

    setIsRunning(false);
  };

  // Export full Go codebase as a .zip file
  const handleDownloadZip = async () => {
    const zip = new JSZip();
    const rootFolder = zip.folder('cfcp');

    if (!rootFolder) return;

    for (const file of GO_FILES) {
      rootFolder.file(file.path, file.code);
    }

    const content = await zip.generateAsync({ type: 'blob' });
    const url = URL.createObjectURL(content);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cfcp-go-protocol.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addLog('info', 'Exported full Go CFCP project as cfcp-go-protocol.zip');
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      {/* Top Bar Contract (1-line wordmark, nav links, 1 primary action) */}
      <TopBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRunSimulation={handleRunSimulation}
        isRunning={isRunning}
        onDownloadZip={handleDownloadZip}
      />

      {/* Main Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {activeTab === 'graph' && <CascadeGraphVisualizer />}

        {activeTab === 'simulator' && (
          <div className="space-y-6">
            {/* Top Config & Controls */}
            <TransmissionConfig
              params={params}
              onChange={(updated) => setParams((prev) => ({ ...prev, ...updated }))}
              isRunning={isRunning}
            />

            {/* Visualizer: Color fragments, AEAD encryption, out-of-order slots */}
            <CascadeVisualizer
              fragments={fragments}
              expectedDigest={expectedDigest}
              actualDigest={actualDigest}
              assemblyResult={assemblyResult}
              activeSession={activeSession}
              isRunning={isRunning}
              pskHex={DEFAULT_PSK_HEX}
            />

            {/* High-density Telemetry and Terminal Log */}
            <TelemetryDashboard
              stats={stats}
              logs={logs}
              onClearLogs={() => setLogs([])}
            />
          </div>
        )}

        {activeTab === 'proxy' && <StealthProxyLab />}

        {activeTab === 'antidos' && <AntiDosStressLab />}

        {activeTab === 'explorer' && (
          <GoCodeExplorer onDownloadZip={handleDownloadZip} />
        )}

        {activeTab === 'spec' && <ProtocolSpec />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 px-6 py-4 text-center text-xs text-slate-400">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 max-w-7xl mx-auto">
          <span>CFCP (Color-Fragmented Cascade Protocol) — UDP Datagram Transport Architecture</span>
          <div className="flex items-center gap-4 font-mono text-[11px] text-slate-400">
            <span>AEAD: ChaCha20-Poly1305</span>
            <span aria-hidden="true">·</span>
            <span>Integrity: SHA-256</span>
            <span aria-hidden="true">·</span>
            <span>Anti-DoS: Timed Active Reaper</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
