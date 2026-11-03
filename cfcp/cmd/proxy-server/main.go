package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cfcp/protocol/pkg/assembler"
	"github.com/cfcp/protocol/pkg/porthopper"
	"github.com/cfcp/protocol/pkg/proxy"
	"github.com/cfcp/protocol/pkg/server"
)

const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

type ProxyServerManager struct {
	hopper       *porthopper.PortHopper
	activeConns  map[uint64]net.Conn
	mu           sync.RWMutex
	psk          []byte
	servers      map[int]*server.Server
	serversMu    sync.Mutex
}

func main() {
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Pre-Shared Key in Hex format")
	hopMode := flag.String("hop-mode", "dynamic_hopping", "Port defense mode: dynamic_hopping | masquerade_quic | masquerade_webrtc | fixed_port")
	minPort := flag.Int("min-port", 20000, "Port hopping range minimum")
	maxPort := flag.Int("max-port", 40000, "Port hopping range maximum")
	hopInterval := flag.Int("hop-interval", 5, "Port hopping interval in seconds")
	timeoutSec := flag.Int("timeout", 6, "Anti-DoS session timeout in seconds")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be a 64-character hexadecimal string (32 bytes)")
	}

	hopperCfg := porthopper.Config{
		Mode:           porthopper.Mode(*hopMode),
		PSK:            psk,
		MinPort:        *minPort,
		MaxPort:        *maxPort,
		DefaultPort:    9099,
		WindowDuration: time.Duration(*hopInterval) * time.Second,
	}

	hopper, err := porthopper.NewPortHopper(hopperCfg)
	if err != nil {
		log.Fatalf("Failed to initialize PortHopper: %v", err)
	}

	fmt.Println("=================================================================")
	fmt.Println("       CFCP Stealth Proxy Server (Egress Relay & Anti-DPI)       ")
	fmt.Println("=================================================================")
	fmt.Printf(" [CRYPTO] AEAD Engine       : ChaCha20-Poly1305 (256-bit PSK)\n")
	fmt.Printf(" [ANTI-DOS] Buffer Timeout  : %d seconds with active reaper\n", *timeoutSec)
	fmt.Printf(" [DEFENSE] Port Hopping     : Mode: %s | Range: [%d-%d]\n", *hopMode, *minPort, *maxPort)
	fmt.Println("=================================================================")

	mgr := &ProxyServerManager{
		hopper:      hopper,
		activeConns: make(map[uint64]net.Conn),
		psk:         psk,
		servers:     make(map[int]*server.Server),
	}

	// Function to bind server to a specific port
	bindPort := func(port int) {
		mgr.serversMu.Lock()
		defer mgr.serversMu.Unlock()

		if _, exists := mgr.servers[port]; exists {
			return
		}

		srvCfg := server.ServerConfig{
			ListenAddr: fmt.Sprintf("0.0.0.0:%d", port),
			PSK:        psk,
			AssemblerConfig: assembler.AssemblerConfig{
				SessionTimeout:        time.Duration(*timeoutSec) * time.Second,
				CleanupInterval:       1 * time.Second,
				MaxConcurrentSessions: 1024,
				MaxSessionMemoryBytes: 4 * 1024 * 1024,
				MaxTotalMemoryBytes:   64 * 1024 * 1024,
			},
		}

		srv, err := server.NewServer(srvCfg)
		if err != nil {
			return
		}

		srv.OnMessage(func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr) {
			mgr.handleTunnelMessage(msg.Payload, srv, remoteAddr)
		})

		if err := srv.Start(); err == nil {
			mgr.servers[port] = srv
			fmt.Printf(" \033[32m[PORT-BIND]\033[0m Listening on UDP port \033[36m:%d\033[0m\n", port)
		}
	}

	// Initial port binding
	initialPorts := hopper.GetListeningPorts(time.Now())
	for _, p := range initialPorts {
		bindPort(p)
	}

	// Port hopping maintenance ticker
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			activePorts := hopper.GetListeningPorts(time.Now())
			for _, p := range activePorts {
				bindPort(p)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down CFCP proxy server...")
	mgr.serversMu.Lock()
	for _, s := range mgr.servers {
		_ = s.Stop()
	}
	mgr.serversMu.Unlock()
}

func (m *ProxyServerManager) handleTunnelMessage(payload []byte, srv *server.Server, clientAddr *net.UDPAddr) {
	tMsg, err := proxy.UnmarshalTunnelMessage(payload)
	if err != nil {
		return
	}

	switch tMsg.Command {
	case proxy.TunnelCmdConnect:
		fmt.Printf(" \033[35m[TUNNEL CONNECT]\033[0m Dialing egress destination: %s\n", tMsg.DestAddr)
		targetConn, err := net.DialTimeout("tcp", tMsg.DestAddr, 5*time.Second)
		if err != nil {
			fmt.Printf(" \033[31m[EGRESS FAILED]\033[0m Could not connect to %s: %v\n", tMsg.DestAddr, err)
			return
		}

		m.mu.Lock()
		m.activeConns[tMsg.StreamID] = targetConn
		m.mu.Unlock()

		// Start relaying response data from target host back to client
		go func(streamID uint64, conn net.Conn) {
			defer func() {
				conn.Close()
				m.mu.Lock()
				delete(m.activeConns, streamID)
				m.mu.Unlock()
			}()

			buf := make([]byte, 2048)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					// In a full implementation, the response is sliced and encrypted back via CFCP
				}
				if err != nil {
					return
				}
			}
		}(tMsg.StreamID, targetConn)

	case proxy.TunnelCmdData:
		m.mu.RLock()
		targetConn, exists := m.activeConns[tMsg.StreamID]
		m.mu.RUnlock()

		if exists && targetConn != nil && len(tMsg.Payload) > 0 {
			_, _ = targetConn.Write(tMsg.Payload)
		}

	case proxy.TunnelCmdClose:
		m.mu.Lock()
		if targetConn, exists := m.activeConns[tMsg.StreamID]; exists {
			_ = targetConn.Close()
			delete(m.activeConns, tMsg.StreamID)
		}
		m.mu.Unlock()
	}
}
