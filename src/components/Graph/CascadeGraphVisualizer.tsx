import React, { useRef, useEffect, useState, useCallback } from 'react';
import {
  Activity,
  Play,
  Pause,
  RefreshCw,
  Radio,
  ShieldCheck,
  ShieldAlert,
  Layers,
  Sparkles,
  Zap,
  Lock,
  Unlock,
  AlertTriangle,
  Clock,
  Terminal,
} from 'lucide-react';

interface GraphNode {
  id: number;
  label: string;
  role: string;
  color: string;
  x: number;
  y: number;
  unlocked: boolean;
  fragIndex: number;
  sizeBytes: number;
  cipherHex: string;
  poly1305Tag: string;
  payloadText: string;
}

interface GraphEdge {
  from: number;
  to: number;
}

interface SwarmParticle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: string;
  size: number;
  pulsePhase: number;
}

interface EventLog {
  id: string;
  timestamp: string;
  category: 'cascade' | 'hop' | 'crypto' | 'antidos' | 'integrity';
  title: string;
  desc: string;
}

const INITIAL_NODES: GraphNode[] = [
  {
    id: 0,
    label: 'ROOT (Blue)',
    role: 'Source Header & Envelope',
    color: '#38bdf8',
    x: 100,
    y: 210,
    unlocked: true,
    fragIndex: 0,
    sizeBytes: 128,
    cipherHex: '4346435001040000a1b2c3d4...',
    poly1305Tag: '9f8e7d6c5b4a392817263544...',
    payloadText: 'CFCP_INIT_SESSION::STREAM_ID_0x7FE9',
  },
  {
    id: 1,
    label: 'Green',
    role: 'Cascade Stream Alpha',
    color: '#10b981',
    x: 230,
    y: 110,
    unlocked: true,
    fragIndex: 1,
    sizeBytes: 256,
    cipherHex: '8877665544332211aabbccdd...',
    poly1305Tag: '1234567890abcdef12345678...',
    payloadText: 'DATA_CHUNK_ALPHA::PAYLOAD_PART_1',
  },
  {
    id: 2,
    label: 'Red (Backup)',
    role: 'Cascade Parity & Redundancy',
    color: '#f43f5e',
    x: 230,
    y: 310,
    unlocked: true,
    fragIndex: 2,
    sizeBytes: 256,
    cipherHex: 'ffeeddccbbaa998877665544...',
    poly1305Tag: 'abcdef0123456789abcdef01...',
    payloadText: 'DATA_PARITY_RED::FEC_BACKUP_STREAM',
  },
  {
    id: 3,
    label: 'Yellow',
    role: 'Intermediate Relay A',
    color: '#eab308',
    x: 380,
    y: 70,
    unlocked: true,
    fragIndex: 3,
    sizeBytes: 256,
    cipherHex: '0123456789abcdef01234567...',
    poly1305Tag: 'a1b2c3d4e5f67890a1b2c3d4...',
    payloadText: 'DATA_CHUNK_BETA::PAYLOAD_PART_2',
  },
  {
    id: 4,
    label: 'Orange',
    role: 'Convergence Cascade Node',
    color: '#f97316',
    x: 380,
    y: 210,
    unlocked: false,
    fragIndex: 4,
    sizeBytes: 256,
    cipherHex: '99887766554433221100ffee...',
    poly1305Tag: 'fedcba9876543210fedcba98...',
    payloadText: 'DATA_CONVERGENCE::PAYLOAD_PART_3',
  },
  {
    id: 5,
    label: 'Violet',
    role: 'Intermediate Relay B',
    color: '#a855f7',
    x: 380,
    y: 350,
    unlocked: false,
    fragIndex: 5,
    sizeBytes: 256,
    cipherHex: '112233445566778899aabbcc...',
    poly1305Tag: '112233445566778899aabbcc...',
    payloadText: 'DATA_CHUNK_GAMMA::PAYLOAD_PART_4',
  },
  {
    id: 6,
    label: 'Cyan',
    role: 'Multiplex Stage 3',
    color: '#06b6d4',
    x: 530,
    y: 140,
    unlocked: false,
    fragIndex: 6,
    sizeBytes: 256,
    cipherHex: 'ddeeff001122334455667788...',
    poly1305Tag: '99887766554433221100ffee...',
    payloadText: 'DATA_STAGE3_CYAN::PAYLOAD_PART_5',
  },
  {
    id: 7,
    label: 'Pink',
    role: 'Multiplex Stage 3 (Sub-stream)',
    color: '#ec4899',
    x: 530,
    y: 280,
    unlocked: false,
    fragIndex: 7,
    sizeBytes: 256,
    cipherHex: '5566778899aabbccddeeff00...',
    poly1305Tag: '7766554433221100ffeeddcc...',
    payloadText: 'DATA_STAGE3_PINK::PAYLOAD_PART_6',
  },
  {
    id: 8,
    label: 'END (Silver)',
    role: 'Final Assembler & SHA-256 Verifier',
    color: '#cbd5e1',
    x: 680,
    y: 210,
    unlocked: false,
    fragIndex: 8,
    sizeBytes: 64,
    cipherHex: '00112233445566778899aabb...',
    poly1305Tag: '33445566778899aabbccddeeff...',
    payloadText: 'CFCP_TERMINAL_SYNC::SHA256_VERIFIED',
  },
];

const EDGES: GraphEdge[] = [
  { from: 0, to: 1 },
  { from: 0, to: 2 },
  { from: 1, to: 3 },
  { from: 1, to: 4 },
  { from: 2, to: 4 },
  { from: 2, to: 5 },
  { from: 3, to: 6 },
  { from: 4, to: 6 },
  { from: 4, to: 7 },
  { from: 5, to: 7 },
  { from: 6, to: 8 },
  { from: 7, to: 8 },
];

export const CascadeGraphVisualizer: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const [nodes, setNodes] = useState<GraphNode[]>(INITIAL_NODES);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(INITIAL_NODES[0]);
  const [currentPort, setCurrentPort] = useState<number>(31482);
  const [portTtl, setPortTtl] = useState<number>(5);
  const [autoStream, setAutoStream] = useState<boolean>(true);
  const [swarmDensity, setSwarmDensity] = useState<number>(35);
  const [events, setEvents] = useState<EventLog[]>([
    {
      id: 'e1',
      timestamp: '13:30:01',
      category: 'cascade',
      title: 'Инициализация графа каскада CFCP',
      desc: 'Построена топология 9 цветных узлов. Корневые узлы Blue, Green, Red и Yellow активны.',
    },
    {
      id: 'e2',
      timestamp: '13:30:02',
      category: 'hop',
      title: 'Синхронизированный порт UDP установлен',
      desc: 'Вычислен порт :31482 через HMAC(PSK, Epoch). Рой датаграмм направлен в сокет.',
    },
    {
      id: 'e3',
      timestamp: '13:30:03',
      category: 'crypto',
      title: 'Аутентификация AEAD ChaCha20-Poly1305',
      desc: 'Вычислен 96-битный nonce с привязкой ID сообщения и индекса пакета. Маскирование активно.',
    },
  ]);

  const addEvent = useCallback((category: EventLog['category'], title: string, desc: string) => {
    const time = new Date().toLocaleTimeString();
    const newEv: EventLog = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: time,
      category,
      title,
      desc,
    };
    setEvents((prev) => [newEv, ...prev.slice(0, 49)]);
  }, []);

  // Port Hop countdown ticker
  useEffect(() => {
    const interval = setInterval(() => {
      setPortTtl((prev) => {
        if (prev <= 1) {
          const nextPort = 20000 + Math.floor(Math.random() * 20000);
          setCurrentPort(nextPort);
          addEvent(
            'hop',
            `Ротация порта -> :${nextPort}`,
            `Тайм-слот окна завершен. Клиент и сервер синхронно переключили UDP порт на :${nextPort}.`
          );
          return 5;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [addEvent]);

  // Automated cascade progress stream
  useEffect(() => {
    if (!autoStream) return;

    const streamInterval = setInterval(() => {
      setNodes((prevNodes) => {
        const locked = prevNodes.filter((n) => !n.unlocked);
        if (locked.length > 0) {
          const target = locked[0];
          addEvent(
            'cascade',
            `Разблокирован узел ${target.label}`,
            `Получен фрагмент #${target.fragIndex + 1}. Проверена подпись Poly1305, полезная нагрузка дешифрована.`
          );
          return prevNodes.map((n) => (n.id === target.id ? { ...n, unlocked: true } : n));
        } else {
          // Reset cycle after brief pause
          addEvent(
            'integrity',
            'Сообщение полностью собрано (9/9)',
            'SHA-256 хэш успешно верифицирован. Запущен новый каскадный цикл передачи.'
          );
          return prevNodes.map((n) => (n.id > 3 ? { ...n, unlocked: false } : n));
        }
      });
    }, 2800);

    return () => clearInterval(streamInterval);
  }, [autoStream, addEvent]);

  // Canvas render animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let particles: SwarmParticle[] = [];

    // Initialize particle swarm
    for (let i = 0; i < swarmDensity; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 3,
        vy: (Math.random() - 0.5) * 3,
        color: INITIAL_NODES[Math.floor(Math.random() * INITIAL_NODES.length)].color,
        size: Math.random() * 2 + 1.2,
        pulsePhase: Math.random() * Math.PI * 2,
      });
    }

    let pulseTime = 0;

    const render = () => {
      pulseTime += 0.05;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // 1. Grid background aesthetics
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < canvas.width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      // 2. Draw Edges between nodes
      EDGES.forEach((edge) => {
        const n1 = nodes[edge.from];
        const n2 = nodes[edge.to];
        const isBothUnlocked = n1.unlocked && n2.unlocked;

        ctx.beginPath();
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);

        if (isBothUnlocked) {
          ctx.strokeStyle = '#38bdf8';
          ctx.lineWidth = 2.5;
          ctx.shadowColor = '#38bdf8';
          ctx.shadowBlur = 8;
        } else {
          ctx.strokeStyle = 'rgba(51, 65, 85, 0.6)';
          ctx.lineWidth = 1;
          ctx.shadowBlur = 0;
        }
        ctx.stroke();
        ctx.shadowBlur = 0; // reset shadow

        // Animated energy pulses across unlocked edges
        if (isBothUnlocked) {
          const t = (pulseTime * 0.8 + edge.from * 0.4) % 1;
          const px = n1.x + (n2.x - n1.x) * t;
          const py = n1.y + (n2.y - n1.y) * t;

          ctx.beginPath();
          ctx.arc(px, py, 3, 0, Math.PI * 2);
          ctx.fillStyle = '#f8fafc';
          ctx.shadowColor = '#38bdf8';
          ctx.shadowBlur = 6;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // 3. Draw Particle Swarm ("рой датаграмм в канале")
      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
      });

      // 4. Draw Graph Nodes
      nodes.forEach((node) => {
        const isSelected = selectedNode?.id === node.id;

        // Outer glow on unlocked or selected
        if (node.unlocked) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);
          ctx.fillStyle = `${node.color}15`;
          ctx.fill();
        }

        // Selection ring
        if (isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, 24, 0, Math.PI * 2);
          ctx.strokeStyle = '#f8fafc';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }

        // Node circle background
        ctx.beginPath();
        ctx.arc(node.x, node.y, 16, 0, Math.PI * 2);
        ctx.fillStyle = node.unlocked ? '#0b1120' : '#1e293b';
        ctx.fill();

        // Node border
        ctx.strokeStyle = node.unlocked ? node.color : '#475569';
        ctx.lineWidth = node.unlocked ? 3 : 1.5;
        if (node.unlocked) {
          ctx.shadowColor = node.color;
          ctx.shadowBlur = 10;
        }
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Inner nucleus
        if (node.unlocked) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, 6, 0, Math.PI * 2);
          ctx.fillStyle = node.color;
          ctx.fill();
        }

        // Label below
        ctx.fillStyle = node.unlocked ? '#f8fafc' : '#64748b';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + 30);
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [nodes, selectedNode, swarmDensity]);

  // Handle canvas click to select node
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    for (const node of nodes) {
      const dist = Math.hypot(node.x - clickX, node.y - clickY);
      if (dist <= 24) {
        setSelectedNode(node);
        addEvent(
          'cascade',
          `Выбран узел ${node.label}`,
          `Фрагмент #${node.fragIndex + 1} (${node.sizeBytes} байт). Роль: ${node.role}.`
        );
        break;
      }
    }
  };

  const unlockedCount = nodes.filter((n) => n.unlocked).length;

  return (
    <div className="space-y-6">
      {/* 1. Header & Live Indicator Banner */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-slate-100">
                CFCP Live Swarm & Cascade Dependency Graph
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Интерактивная визуализация графа дешифрования цветных фрагментов и роя датаграмм в реальном времени. Информирует о разблокировке блоков, ротации портов и целостности.
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setAutoStream(!autoStream)}
              className={`cursor-pointer flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg border transition-colors ${
                autoStream
                  ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {autoStream ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>Авто-поток: ВКЛ</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Авто-поток: ВЫКЛ</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => {
                const nextPort = 20000 + Math.floor(Math.random() * 20000);
                setCurrentPort(nextPort);
                setPortTtl(5);
                addEvent(
                  'hop',
                  `Ручная смена порта -> :${nextPort}`,
                  'Пользователь принудительно переключил UDP сокет.'
                );
              }}
              className="cursor-pointer flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors"
            >
              <Radio className="w-3.5 h-3.5 text-amber-400" />
              <span>Сменить порт</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setNodes((prev) => {
                  const locked = prev.filter((n) => !n.unlocked);
                  if (locked.length > 0) {
                    const target = locked[0];
                    addEvent('cascade', `Разблокирован ${target.label}`, 'Шаг выполнен вручную.');
                    return prev.map((n) => (n.id === target.id ? { ...n, unlocked: true } : n));
                  }
                  return prev;
                });
              }}
              className="cursor-pointer flex items-center gap-2 px-4 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors shadow-sm"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>Шаг каскада</span>
            </button>
          </div>
        </div>

        {/* Live Status Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-500 block">Статус сети</span>
              <span className="text-emerald-400 font-bold">ACTIVE HOPPING</span>
            </div>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>

          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-500 block">Разблокировано узлов</span>
              <span className="text-indigo-300 font-bold tabular-nums">
                {unlockedCount} / {nodes.length}
              </span>
            </div>
            <Unlock className="w-4 h-4 text-indigo-400" />
          </div>

          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-500 block">Текущий порт UDP</span>
              <span className="text-amber-400 font-bold tabular-nums">:{currentPort}</span>
            </div>
            <Radio className="w-4 h-4 text-amber-400" />
          </div>

          <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-500 block">До смены порта</span>
              <span className="text-slate-200 font-bold tabular-nums">{portTtl}s</span>
            </div>
            <Clock className="w-4 h-4 text-slate-400" />
          </div>
        </div>
      </div>

      {/* 2. Interactive Canvas Visualizer */}
      <div className="bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-2">
          <span className="font-medium text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            Интерактивный холст (Кликните на любой узел для детальной инспекции)
          </span>
          <div className="flex items-center gap-3">
            <span>Плотность роя:</span>
            <input
              type="range"
              min={10}
              max={60}
              step={5}
              value={swarmDensity}
              onChange={(e) => setSwarmDensity(Number(e.target.value))}
              className="w-24 accent-indigo-500 cursor-pointer"
            />
            <span className="font-mono tabular-nums text-slate-200">{swarmDensity}</span>
          </div>
        </div>

        <div className="flex justify-center bg-[#090d16] rounded-lg p-2 border border-slate-900 overflow-x-auto">
          <canvas
            ref={canvasRef}
            width={800}
            height={420}
            onClick={handleCanvasClick}
            className="cursor-pointer max-w-full h-auto"
            title="Кликните на узел для просмотра криптографических метаданных"
          />
        </div>
      </div>

      {/* 3. Bottom Grid: Node Inspector + Real-time Event Stream ("Что происходит") */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Selected Node Inspector */}
        <div className="lg:col-span-5 bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              Инспектор узла каскада
            </h3>
            {selectedNode && (
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                  selectedNode.unlocked
                    ? 'bg-emerald-950/40 border border-emerald-500/30 text-emerald-300'
                    : 'bg-slate-900 border border-slate-800 text-slate-500'
                }`}
              >
                {selectedNode.unlocked ? 'UNLOCKED / VERIFIED' : 'WAITING'}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Метка узла:</span>
                  <span className="text-slate-100 font-bold" style={{ color: selectedNode.color }}>
                    {selectedNode.label}
                  </span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Роль в графе:</span>
                  <span className="text-slate-300">{selectedNode.role}</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Индекс фрагмента:</span>
                  <span className="text-indigo-300 font-bold">
                    #{selectedNode.fragIndex + 1} of 9
                  </span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Объем полезной нагрузки:</span>
                  <span className="text-slate-300">{selectedNode.sizeBytes} байт</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Полезная нагрузка фрагмента:</span>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-slate-300 text-[11px] break-all">
                  {selectedNode.payloadText}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Шифротекст ChaCha20 (Hex):</span>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-indigo-300 text-[11px] break-all select-all">
                  {selectedNode.cipherHex}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Тег аутентификации Poly1305 (MAC):</span>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-emerald-300 text-[11px] break-all select-all">
                  {selectedNode.poly1305Tag}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center text-slate-500 text-xs font-mono">
              Выберите узел на холсте выше для просмотра состояния.
            </div>
          )}
        </div>

        {/* Right: Live Event Stream ("Что сейчас происходит") */}
        <div className="lg:col-span-7 bg-[#0f1422] rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-indigo-400" />
              Журнал событий: что происходит прямо сейчас
            </h3>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {events.length} записей
            </span>
          </div>

          <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
            {events.map((ev) => {
              let categoryBadge = 'bg-slate-900 text-slate-400 border-slate-800';
              if (ev.category === 'cascade')
                categoryBadge = 'bg-indigo-950/40 text-indigo-300 border-indigo-500/30';
              if (ev.category === 'hop')
                categoryBadge = 'bg-amber-950/40 text-amber-300 border-amber-500/30';
              if (ev.category === 'crypto')
                categoryBadge = 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30';
              if (ev.category === 'integrity')
                categoryBadge = 'bg-sky-950/40 text-sky-300 border-sky-500/30';

              return (
                <div
                  key={ev.id}
                  className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 text-xs space-y-1 animate-in fade-in"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200 flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${categoryBadge}`}
                      >
                        {ev.category}
                      </span>
                      <span>{ev.title}</span>
                    </span>
                    <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                      {ev.timestamp}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed pl-1">
                    {ev.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
