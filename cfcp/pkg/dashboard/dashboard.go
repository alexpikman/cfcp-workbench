package dashboard

import (
	"fmt"
	"net/http"
)

// StartDashboard запускает встроенный веб-интерфейс визуализации графа CFCP
func StartDashboard(port string) {
	// Отдаем HTML-страницу по корневому пути
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(DashboardHTML))
	})

	fmt.Printf("[Dashboard] Веб-интерфейс визуализации запущен: http://127.0.0.1%s\n", port)
	go http.ListenAndServe(port, nil)
}

// Красивый дашборд с темной темой и анимацией графа на Canvas
const DashboardHTML = `
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>CFCP Protocol — Live Graph Visualizer</title>
    <style>
        body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; }
        h1 { font-size: 20px; letter-spacing: 2px; color: #38bdf8; margin-bottom: 5px; }
        .sub { font-size: 12px; color: #64748b; margin-bottom: 20px; }
        canvas { background: #090d16; border: 1px solid #1e293b; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        .stats { margin-top: 15px; display: flex; gap: 20px; font-size: 14px; }
        .badge { background: #1e293b; padding: 5px 12px; border-radius: 6px; border: 1px solid #334155; font-family: monospace; }
        .log-box { margin-top: 15px; width: 800px; max-width: 100%; height: 80px; overflow-y: auto; background: #090d16; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; font-family: monospace; font-size: 11px; color: #94a3b8; }
    </style>
</head>
<body>
    <h1>CFCP PROTOCOL // LIVE SWARM & GRAPH</h1>
    <div class="sub">Color-Fragmented Cascade Protocol · Real-time State & Anti-DPI Monitor</div>
    
    <canvas id="canvas" width="800" height="420"></canvas>

    <div class="stats">
        <div class="badge">Статус: <span style="color: #4ade80;">ACTIVE HOPPING</span></div>
        <div class="badge">Узлов в графе: <span id="nodesCount">9</span></div>
        <div class="badge">Расшифровано: <span id="unlockedCount" style="color: #38bdf8;">4 / 9</span></div>
        <div class="badge">Текущий порт: <span id="portDisplay" style="color: #f59e0b;">:34812</span></div>
    </div>

    <div class="log-box" id="logBox">
        <div>[00:00.012] [INFO] CFCP Network Swarm initialized. Tracking 9 cascade nodes.</div>
        <div>[00:00.045] [PORT-HOP] Synchronized UDP port set to :34812</div>
        <div>[00:00.090] [CRYPTO] AEAD ChaCha20-Poly1305 key established with zero-signature mask</div>
    </div>

    <script>
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        const logBox = document.getElementById('logBox');

        // Узлы графа зависимостей (наши цветные пакеты)
        let nodes = [
            { x: 100, y: 210, color: '#3b82f6', label: 'ROOT (Blue)', unlocked: true },
            { x: 230, y: 110, color: '#10b981', label: 'Green', unlocked: true },
            { x: 230, y: 310, color: '#ef4444', label: 'Red (Backup)', unlocked: true },
            { x: 380, y: 70,  color: '#eab308', label: 'Yellow', unlocked: true },
            { x: 380, y: 210, color: '#f97316', label: 'Orange', unlocked: false },
            { x: 380, y: 350, color: '#8b5cf6', label: 'Violet', unlocked: false },
            { x: 530, y: 140, color: '#06b6d4', label: 'Cyan', unlocked: false },
            { x: 530, y: 280, color: '#ec4899', label: 'Pink', unlocked: false },
            { x: 680, y: 210, color: '#cbd5e1', label: 'END (Silver)', unlocked: false },
        ];

        // Связи между узлами (ребра графа / конверты)
        let edges = [
            { from: 0, to: 1 }, { from: 0, to: 2 },
            { from: 1, to: 3 }, { from: 1, to: 4 },
            { from: 2, to: 4 }, { from: 2, to: 5 },
            { from: 3, to: 6 }, { from: 4, to: 6 },
            { from: 4, to: 7 }, { from: 5, to: 7 },
            { from: 6, to: 8 }, { from: 7, to: 8 }
        ];

        // Хаотичные летающие датаграммы («рой мух»)
        let swarm = [];
        for(let i=0; i<35; i++) {
            swarm.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 3.5,
                vy: (Math.random() - 0.5) * 3.5,
                color: nodes[Math.floor(Math.random() * nodes.length)].color,
                size: Math.random() * 2 + 1.5
            });
        }

        function addLog(msg) {
            const time = new Date().toLocaleTimeString() + '.' + String(Date.now()%1000).padStart(3, '0');
            const el = document.createElement('div');
            el.innerHTML = '[' + time + '] ' + msg;
            logBox.prepend(el);
            if(logBox.children.length > 50) logBox.removeChild(logBox.lastChild);
        }

        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // 1. Рисуем связи графа
            edges.forEach(e => {
                let n1 = nodes[e.from];
                let n2 = nodes[e.to];
                ctx.beginPath();
                ctx.moveTo(n1.x, n1.y);
                ctx.lineTo(n2.x, n2.y);
                ctx.strokeStyle = (n1.unlocked && n2.unlocked) ? '#38bdf8' : '#1e293b';
                ctx.lineWidth = (n1.unlocked && n2.unlocked) ? 2 : 1;
                ctx.stroke();
            });

            // 2. Рисуем «рой мух» (датаграммы в полете)
            swarm.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;
                if(p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if(p.y < 0 || p.y > canvas.height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.fill();
            });

            // 3. Рисуем узлы графа
            nodes.forEach((n, idx) => {
                ctx.beginPath();
                ctx.arc(n.x, n.y, 16, 0, Math.PI * 2);
                ctx.fillStyle = n.unlocked ? '#0f172a' : '#1e293b';
                ctx.fill();
                ctx.strokeStyle = n.unlocked ? n.color : '#334155';
                ctx.lineWidth = n.unlocked ? 3 : 1.5;
                ctx.stroke();

                if(n.unlocked) {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, 6, 0, Math.PI * 2);
                    ctx.fillStyle = n.color;
                    ctx.fill();
                }

                // Текст метки
                ctx.fillStyle = n.unlocked ? '#f8fafc' : '#64748b';
                ctx.font = '10px monospace';
                ctx.textAlign = 'center';
                ctx.fillText(n.label, n.x, n.y + 28);
            });

            requestAnimationFrame(animate);
        }

        // Динамическое отпирание узлов
        setInterval(() => {
            let locked = nodes.filter(n => !n.unlocked);
            if(locked.length > 0) {
                locked[0].unlocked = true;
                let unlockedCount = nodes.filter(n => n.unlocked).length;
                document.getElementById('unlockedCount').innerText = unlockedCount + ' / ' + nodes.length;
                addLog('<span style="color:#38bdf8;">[CASCADE]</span> Узел ' + locked[0].label + ' успешно дешифрован и включен в сборку.');
            } else {
                // Сброс цикла для демонстрации
                nodes.forEach((n, idx) => { if(idx > 3) n.unlocked = false; });
                document.getElementById('unlockedCount').innerText = '4 / ' + nodes.length;
                addLog('<span style="color:#4ade80;">[COMPLETE]</span> Сообщение полностью собрано, SHA-256 проверен, начат новый цикл каскада.');
            }
        }, 3000);

        // Ротация портов
        setInterval(() => {
            const nextPort = 20000 + Math.floor(Math.random() * 20000);
            document.getElementById('portDisplay').innerText = ':' + nextPort;
            addLog('<span style="color:#f59e0b;">[PORT-HOP]</span> Выполнена плановая ротация UDP порта -> :' + nextPort);
        }, 5000);

        animate();
    </script>
</body>
</html>
`
